"""仅用于授权测试：真实双夹具读写、并发归因和 Phase 5 包名隔离验收。"""
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import ThreadingHTTPServer
from pathlib import Path

import frida
from device_acceptance import ADB, ROOT, read_events, wait_for
from collector_server import Collector

sys.path.insert(0, str(ROOT / 'phase4'))
sys.path.insert(0, str(ROOT / 'phase5'))
from verify_multi_app import verdict
from correlate import load_rules
from evaluation import evaluate_data_egress, evaluate_sensitive_read
from codeloc import attach

PACKAGES = ['com.vscanner.targetapp', 'com.vscanner.targetapp2']


def main():
    session = 'multi-' + datetime.now().strftime('%Y%m%d-%H%M%S')
    out = ROOT / 'output' / session
    out.mkdir(parents=True)
    (ROOT / 'output/latest-multi.txt').write_text(str(out), encoding='utf-8')
    env = dict(os.environ, PYTHONUTF8='1', VSCAN_SESSION=session,
        VSCAN_FLOW_LOG=str(out / 'flows.jsonl'), VSCAN_EVENT_DB=str(out / 'events.sqlite'),
        VSCAN_ATTRIB_SOURCES=os.pathsep.join(str(out / f'egress-{i}.jsonl') for i in range(2)),
        VSCAN_TAGGING=str(ROOT / 'phase4/tagging.py'),
        PATH=str(Path(ADB).parent) + os.pathsep + os.environ['PATH'])
    handles, processes, sessions, controls = [], [], [], []
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()

    def adb(*args):
        return subprocess.run([ADB, '-s', 'emulator-5554', *args], capture_output=True,
            encoding='utf-8', errors='replace', check=True, timeout=60).stdout.strip()

    def launch(args, name):
        handle = (out / (name + '.log')).open('w', encoding='utf-8'); handles.append(handle)
        process = subprocess.Popen(args, env=env, stdout=handle, stderr=handle)
        processes.append(process)

    try:
        adb('install', '-r', str(ROOT / 'phase2/target-app/app/build/outputs/apk/debug/app-debug.apk'))
        # 本轮隔离模拟器 SLIRP 丢连接因素，仍由真实App建立Socket/发送原始载荷。
        adb('reverse', 'tcp:8888', 'tcp:8888')
        launch([sys.executable, '-c', 'from mitmproxy.tools.main import mitmdump; mitmdump()',
            '-s', str(ROOT / 'core/collector/addon.py'), '--listen-host', '0.0.0.0', '--listen-port', '8888',
            '--mode', f'reverse:http://127.0.0.1:{upstream.server_port}', '--set', 'keep_host_header=true',
            '--set', f'confdir={out / "certs"}'], 'mitm')
        device = frida.get_device_manager().add_remote_device('127.0.0.1:27043')
        for i, package in enumerate(PACKAGES):
            for permission in ('CAR_SPEED', 'CAR_ENERGY'):
                adb('shell', 'pm', 'grant', '--user', '10', package, 'android.car.permission.' + permission)
            adb('shell', 'am', 'start', '--user', '10', '-W', '-n', package + '/.MainActivity')
            for name, script in [('reads', 'hook_vhal'), ('egress', 'hook_egress')]:
                launch([sys.executable, str(ROOT / 'phase3/run.py'), '--package', package,
                    '--script', str(ROOT / 'phase3/dist' / (script + '.bundle.js')), '--seconds', '120',
                    '--session', session, '--event-db', str(out / 'events.sqlite'),
                    '--out', str(out / f'{name}-{i}.jsonl')], f'{name}-{i}')
            attached = device.attach(int(adb('shell', 'pidof', package))); sessions.append(attached)
            script = attached.create_script((ROOT / 'phase3/dist/fixture_control.bundle.js').read_text(encoding='utf-8'))
            script.load(); controls.append(script)
        wait_for(lambda: all(any(e.get('ev') == 'ARMED' for e in read_events(out / f'{name}-{i}.jsonl'))
                 for i in range(2) for name in ('reads', 'egress')), 40)
        triggers = []
        for controller in controls:
            triggers.append(controller.exports_sync.click('btnRead'))
        wait_for(lambda: all(sum(e.get('ev') == 'VHAL_READ' for e in read_events(out / f'reads-{i}.jsonl')) >= 23
                            for i in range(2)))
        # 一轮相距600ms，另一轮近同时(50ms触发间隔)。均在2000ms归因容差内。
        triggers.append(controls[0].exports_sync.click('btnEgressHttp', 'http://127.0.0.1:8888/collect'))
        time.sleep(.6)
        triggers.append(controls[1].exports_sync.click('btnEgressHttp', 'http://127.0.0.1:8888/collect'))
        wait_for(lambda: len(read_events(out / 'flows.jsonl')) >= 2)
        time.sleep(2.2)
        triggers.append(controls[0].exports_sync.click('btnEgressHttp'))
        time.sleep(.05)
        triggers.append(controls[1].exports_sync.click('btnEgressHttp'))
        wait_for(lambda: len(read_events(out / 'flows.jsonl')) >= 4)
        (out / 'triggers.json').write_text(json.dumps(triggers, indent=2), encoding='utf-8')
        reads = [e for i in range(2) for e in read_events(out / f'reads-{i}.jsonl')]
        egress = [e for i in range(2) for e in read_events(out / f'egress-{i}.jsonl')]
        flows = read_events(out / 'flows.jsonl')
        rules = load_rules(ROOT / 'phase1/rules_library/rules.db', '15')
        findings = evaluate_sensitive_read(rules, reads) + evaluate_data_egress(rules, reads, flows)
        findings = attach(findings, reads, flows, egress, PACKAGES[0])
        (out / 'findings.jsonl').write_text(''.join(json.dumps(f, ensure_ascii=False) + '\n' for f in findings), encoding='utf-8')
        ambiguous = {f['evt_id'] for f in flows if f.get('attribution_ambiguous')}
        pairs = [p for f in findings for p in f.get('pairs', [])]
        isolated = all(next(flow for flow in flows if flow['evt_id'] == p['flow_event_id'])['package'] == f['package']
                       for f in findings for p in f.get('pairs', []))
        # 与 device_acceptance 同样的断言：无响应请求走独立文件，但**必须有人看**。
        unanswered = read_events(out / 'flows-unanswered.jsonl')
        checks = {'two_packages_correlated': {f['package'] for f in findings if f.get('pairs')} == set(PACKAGES),
                  'no_crossed_flow': all(verdict(f) in ('MATCH', 'AMBIGUOUS') for f in flows),
                  'phase5_package_isolation': isolated,
                  'ambiguous_not_correlated': not ambiguous.intersection(p['flow_event_id'] for p in pairs),
                  'four_200_responses': len(flows) == 4 and all(f['status_code'] == 200 for f in flows),
                  'no_unanswered_requests': not unanswered}
        report = dict(session=session, transport='adb_reverse_loopback', checks=checks, passed=all(checks.values()),
                      flow_verdicts=[dict(id=f['evt_id'], verdict=verdict(f), delta_ms=f['attribution_delta_ms']) for f in flows],
                      findings=len(findings), pairs=len(pairs), unanswered_requests=len(unanswered))
        (out / 'verification.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps(report), flush=True)
        assert report['passed']
    finally:
        for attached in sessions:
            attached.detach()
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=15)
        for handle in handles:
            handle.close()
        upstream.shutdown(); upstream.server_close(); worker.join()
        print('Evidence: ' + str(out), flush=True)


if __name__ == '__main__':
    main()
