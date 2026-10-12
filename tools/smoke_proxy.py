"""仅用于授权测试：本机 HTTP/HTTPS 真代理链路验收，归因事件是明确标注的合成输入。"""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'phase4'))
from collector_server import Collector


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def main():
    out = ROOT / 'output/host-smoke'
    out.mkdir(parents=True, exist_ok=True)
    flows = out / 'flows.jsonl'
    if flows.exists():
        raise FileExistsError('请使用新的验收目录，禁止追加混合会话')
    events = out / 'egress.jsonl'
    events.write_text('', encoding='utf-8')
    upstream = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True)
    worker.start()
    port = free_port()
    env = dict(os.environ, VSCAN_FLOW_LOG=str(flows), VSCAN_ATTRIB_SOURCES=str(events),
               VSCAN_SESSION='host-smoke-synthetic-events', PYTHONUTF8='1')
    with (out / 'mitm.log').open('w', encoding='utf-8') as log:
        proc = subprocess.Popen([sys.executable, '-c',
            'from mitmproxy.tools.main import mitmdump; mitmdump()',
            '-s', str(ROOT / 'phase4/addon.py'), '--listen-host', '127.0.0.1',
            '--listen-port', str(port), '--mode', f'reverse:http://127.0.0.1:{upstream.server_port}',
            '--set', f'confdir={out / "certs"}'], env=env, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError('proxy 启动失败，见 mitm.log')
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.2)
            else:
                raise TimeoutError('proxy readiness timeout')
            for index, scheme in enumerate(('http', 'https'), 1):
                event = dict(src='egress', ev='EGRESS_CONNECT', evt_id=index,
                             package='com.vscanner.targetapp', host_received_ts=int(time.time()*1000),
                             session_id='host-smoke-synthetic-events', synthetic=True)
                with events.open('a', encoding='utf-8') as handle:
                    handle.write(json.dumps(event) + '\n')
                body = json.dumps({'fixture': 'synthetic host smoke, not device evidence',
                                   'GEAR_SELECTION': 4, 'padding': 'x' * 1000}).encode()
                request = Request(f'{scheme}://127.0.0.1:{port}/collect', data=body,
                                  headers={'Content-Type': 'application/json'})
                # 仅此验收客户端信任其临时代理证书，不修改系统或应用信任库。
                with urlopen(request, context=ssl._create_unverified_context(), timeout=10) as response:
                    assert response.status == 200
                    assert json.load(response)['received_bytes'] == len(body)
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    records = [json.loads(l) for l in flows.read_text(encoding='utf-8').splitlines()] if flows.exists() else []
                    if len(records) >= index:
                        break
                    time.sleep(.1)
                else:
                    raise AssertionError('流未落盘')
            assert all(f['package'] == 'com.vscanner.targetapp' for f in records)
            assert all(f['status_code'] == 200 and 'GEAR_SELECTION' in f['request_tokens'] for f in records)
            assert all(len(f['request_payload']['text']) > 400 for f in records)
            assert any(f['intercepted_tls'] for f in records)
            summary = {'status': 'PASS', 'flows': len(records), 'tls_plaintext': True,
                       'full_payload': True, 'attribution_input': 'synthetic', 'device_test': False}
            (out / 'verification.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
            print(json.dumps(summary))
        finally:
            # 所有预期流落盘后仅终止本脚本创建的子进程；不停止其他代理。
            proc.terminate()
            proc.wait(timeout=15)
            upstream.shutdown(); upstream.server_close(); worker.join()


if __name__ == '__main__':
    main()
