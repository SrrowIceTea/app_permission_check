"""One real APK: web static/JADX, local policy, root capture, correlation, AI, PDF.

仅用于授权测试。Requires a passing real fixture self-test, never synthetic events.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlsplit
from mobile.lab.root_runtime import save
from mobile.policy.policy_library import DEFAULT_STORE, load_policy
from mobile.workbench.core_publish import publish
from mobile.workbench.store import Store
from mobile.lab.nonroot_identity import validate_capture
from mobile.lab.core_task_binding import bind, check_cancel, Cancelled, static_snapshot

ROOT = Path(__file__).resolve().parents[2]


def request(server, method, path, apk=None):
    url = urlsplit(server)
    if url.scheme != 'http' or url.hostname not in ('127.0.0.1', 'localhost'):
        raise ValueError('use the local workbench HTTP service')
    connection = http.client.HTTPConnection(url.hostname, url.port or 8772, timeout=120)
    try:
        connection.putrequest(method, path)
        if apk:
            connection.putheader('Content-Length', str(apk.stat().st_size))
            connection.putheader('Content-Type', 'application/vnd.android.package-archive')
        connection.endheaders()
        if apk:
            with apk.open('rb') as handle:
                while block := handle.read(1024 * 1024):
                    connection.send(block)
        response = connection.getresponse()
        value = json.loads(response.read())
        if response.status >= 400:
            raise RuntimeError(f'Workbench HTTP {response.status}: {value}')
        return value
    finally:
        connection.close()


def wait_static(server, task_id, deadline=900):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        task = request(server, 'GET', '/api/tasks/' + task_id)
        if task['state'] not in ('queued', 'running'):
            stages = task['stages']
            if task['state'] not in ('done', 'partial') or stages['static']['state'] != 'done':
                raise RuntimeError('Static analysis failed: ' + json.dumps(stages, ensure_ascii=False))
            if stages['decompile']['state'] == 'partial':
                raw = request(server, 'GET', '/api/tasks/' + task_id + '/static')
                if not (raw.get('decompile') or {}).get('classes_written'):
                    raise RuntimeError('JADX produced no usable source; complete core test blocked')
            elif stages['decompile']['state'] != 'done':
                raise RuntimeError('JADX did not run: ' + json.dumps(stages, ensure_ascii=False))
            return task
        time.sleep(1)
    raise TimeoutError('uploaded task did not complete static/JADX within 900 seconds')


def command(arguments, log, timeout=900, cancel_file=None):
    check_cancel(cancel_file)
    process = subprocess.run([sys.executable, '-B', *map(str, arguments)], cwd=ROOT,
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
    log.write_text(process.stdout + '\n' + process.stderr, encoding='utf-8')
    check_cancel(cancel_file)
    if process.returncode:
        raise RuntimeError(f'{Path(str(arguments[0])).name} failed; see {log}')


def check_selftest(path, serial, mode=None):
    value = json.loads(path.read_text(encoding='utf-8'))
    if (value.get('state') != 'done' or value.get('scenario') != 'fixture'
            or value.get('real_privacy_reads', 0) < 1 or value.get('flows', 0) < 1
            or value.get('device', {}).get('serial') != serial
            or not value.get('checks') or not all(check is True for check in value['checks'].values())):
        raise ValueError('real fixture self-test failed or does not match the selected device')
    if mode == 'nonroot-gadget' and validate_capture(value, value.get('apk_sha256'), value.get('package'), serial) != mode:
        raise ValueError('non-root capture requires a passing Gadget-mode fixture self-test')
    return value


def matching_rule_version(captured, task):
    actual = str(captured.get('device', {}).get('android_api') or '')
    rules = str(task.get('rules', {}).get('version') or '36')
    if not actual or actual != rules:
        raise ValueError(f'Actual Android API {actual or "unknown"} differs from available rules API {rules}; '
                         'retain capture evidence, but do not claim cross-version formal assessment')
    return actual


def static_input(store, task, out):
    """Only original static gaps, never task.gaps overwritten by a previous audit."""
    path = static_snapshot(store, task, out)
    gaps = json.loads(path.read_text(encoding='utf-8')).get('gaps', [])
    if not isinstance(gaps, list):
        raise ValueError('original static snapshot gaps must be a list')
    return path, list(gaps)


def run(args):
    apk, out = args.apk.resolve(), args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'output'):
        raise ValueError('use a new project output directory')
    if not args.authorize:
        raise ValueError('--authorize required for this selected APK and dedicated emulator')
    check_cancel(getattr(args, 'cancel_file', None))
    source = getattr(args, 'capture_source', None)
    capture_mode = json.loads((source / 'verification.json').read_text(encoding='utf-8')).get('mode') if source else None
    check_selftest(args.selftest, args.serial, capture_mode)
    out.mkdir(parents=True)
    target = out / 'out'
    target.mkdir()
    verification = {'passed': False, 'apk': str(apk), 'stages': {}, 'started_at': time.time()}
    stage = 'static'
    task_id = None
    try:
        print('START static: original workbench upload and JADX', flush=True)
        if getattr(args, 'task_id', None):
            if getattr(args, 'static_source', None):
                raise ValueError('--task-id and --static-source cannot be combined')
            task = bind(args.storage, args.task_id, apk)
            task_id = task['id']
            save(out / 'upload.json', {'task_id': task_id, 'source': 'same original uploaded task, no new upload'})
        elif getattr(args, 'static_source', None):
            from mobile.workbench.core_static_task import create
            task = create(apk, args.static_source, args.storage)
            task_id = task['id']
            save(out / 'static-source.json', {'path': str(args.static_source), 'task_id': task_id,
                'source_decompile': 'not_requested', 'whole_dex': 'verified retained facts + mobile supplement'})
        else:
            uploaded = request(args.server, 'POST', '/api/apk?name=' + quote(apk.name), apk)
            task_id = uploaded['task_id']
            save(out / 'upload.json', uploaded)
            task = wait_static(args.server, task_id)
        save(out / 'static-task.json', task)
        app = task['apk']
        digest = hashlib.sha256(apk.read_bytes()).hexdigest()
        if app['sha256'] != digest:
            raise ValueError('workbench upload APK identity mismatch')
        verification.update(task_id=task_id, package=app['package'], apk_sha256=digest)
        verification['stages'][stage] = {'state': 'done', 'decompile_state': task['stages']['decompile']['state']}
        static_path, static_gaps = static_input(Store(args.storage), task, out)
        verification['quality_gaps'] = list(static_gaps)
        stage = 'policy'
        policy = load_policy(args.policy_store, package=app['package'], version_code=app.get('version_code'), apk_sha256=digest)
        if not policy.get('available'):
            verification['quality_gaps'].append({'kind': 'policy_unavailable', 'details': policy.get('gaps', [])})
        elif not policy.get('association_verified'):
            raise ValueError('local policy is not bound to this APK')
        save(out / 'policy-selection.json', {k: v for k, v in policy.items() if k != 'text'})
        verification['stages'][stage] = {'state': 'done', 'available': bool(policy.get('available')), 'chars': len(policy.get('text') or ''), 'source': policy.get('source')}
        check_cancel(getattr(args, 'cancel_file', None))
        stage = 'capture'
        store = Store(args.storage)
        store.patch(task_id, state='running', core_run={'state': 'running', 'source_run': str(out)})
        store.stage(task_id, 'dynamic', 'running', '原始 APK 绑定的实际采集（按保留的采集模式验收）')
        print('START capture: bound actual observation session', flush=True)
        from mobile.lab.core_capture import capture
        capture_root = out / 'capture'
        if getattr(args, 'capture_source', None):
            capture_root = args.capture_source.resolve()
            if not capture_root.is_relative_to(ROOT / 'output'):
                raise ValueError('capture source must be a project-owned run')
            captured = json.loads((capture_root / 'verification.json').read_text(encoding='utf-8'))
            capture_mode = validate_capture(captured, digest, app['package'], args.serial)
            save(out / 'capture-source.json', {'path': str(capture_root), 'source': 'previous actual immutable capture, not a new device run'})
        else:
            captured = capture(apk, app['package'], capture_root, serial=args.serial,
                               scenario=args.scenario, seconds=args.seconds)
            capture_mode = 'root-emulator'
        if captured['state'] != 'done' or not all(captured['checks'].values()):
            raise RuntimeError('actual capture failed; inspect bound capture verification.json')
        verification['capture'] = {'mode': capture_mode, 'capture_apk_sha256': digest,
            'instrumented_apk_sha256': captured.get('instrumented_apk_sha256'),
            'original_bytes_installed': captured.get('original_bytes_installed', True),
            'source_capture': str(capture_root), 'traffic': captured.get('traffic'),
            'device_android_api': captured.get('device', {}).get('android_api')}
        verification['stages'][stage] = {'state': 'done', 'reads': captured['real_privacy_reads'], 'flows': captured['flows']}
        stage = 'correlate'
        rule_api = matching_rule_version(captured, task)
        session = capture_root / 'session'
        permissions = target / 'requested-permissions.txt'
        permissions.write_text('\n'.join(app.get('permissions', [])) + '\n', encoding='utf-8')
        common = ['--session', session, '--package', app['package'], '--apk-sha256', digest,
                  '--version-code', app['version_code'], '--version', rule_api, '--policy-store', args.policy_store]
        if args.app_category:
            common += ['--app-category', args.app_category]
        command(['mobile/analyze/correlate_mobile.py', *common, '--permissions', permissions,
                 '--replay-inputs', out / 'replay-inputs',
                 '--out', target / 'findings.jsonl', '--summary', target / 'summary.json'], out / 'correlate.log', cancel_file=getattr(args, 'cancel_file', None))
        verification['stages'][stage] = {'state': 'done'}
        stage = 'bundle'
        static_notes = ['--note', 'Static/JADX stage: ' + json.dumps(static_gaps, ensure_ascii=False)] if static_gaps else []
        capture_note = ('Non-root Gadget-instrumented and re-signed derivative; original APK supplies static/policy identity. '
            'No root/server/system CA/proxy modification. Target-filtered VPN packets are retained only if traffic-scope confirms export. '
            'Configured UID filtering does not provide per-packet UID attribution: system DNS/sidecar probes may appear; port 853 handshake-only packets do not prove app business traffic. '
            'Instrumented APK SHA256=' + str(captured.get('instrumented_apk_sha256'))) if capture_mode == 'nonroot-gadget' else 'Root any-interface PCAP retained in the bound capture source.'
        command(['mobile/ai/evidence_bundle.py', *common, *static_notes, '--static-evidence', static_path, '--findings', target / 'findings.jsonl',
                 '--apk', apk, '--device', args.serial, '--note', capture_note,
                 '--note', 'Storage/crypto API observations are consumed by the formal supplemental adapter, not proof of disk persistence or personal-data leakage; TLS plaintext is not universally available.',
                 *[item for gap in captured.get('gaps', []) for item in ('--note', gap)], '--out', target / 'bundle.json'], out / 'bundle.log', cancel_file=getattr(args, 'cancel_file', None))
        bundle = json.loads((target / 'bundle.json').read_text(encoding='utf-8'))
        if not bundle['dynamic']['reads']:
            verification['quality_gaps'].append({'kind': 'no_read_observed', 'details': 'Self-test passed and target hooks healthy, but no sensitive read observed in this finite scenario; not a safety result.'})
        verification['quality_gaps'].extend({'kind': 'capture_scope', 'details': note} for note in captured.get('gaps', []))
        verification['stages'][stage] = {'state': 'done', 'counts': bundle['counts']}
        store.stage(task_id, 'dynamic', 'done', '实际采集已进入原关联引擎与证据包')
        stage = 'ai'
        store.stage(task_id, 'ai', 'running')
        print('START AI: three original policy/behavior/assessment stages', flush=True)
        command(['mobile/ai/ai_review.py', '--bundle', target / 'bundle.json', '--config', args.config,
                 '--out-dir', target / 'ai'], out / 'ai.log', timeout=1800, cancel_file=getattr(args, 'cancel_file', None))
        validations = json.loads((target / 'ai/validation.json').read_text(encoding='utf-8'))
        if set(validations) != {'stage1', 'stage2', 'stage3'} or not all(v['ok'] for v in validations.values()):
            raise ValueError('full three-stage AI did not pass all gates')
        from mobile.ai.review_gates import load_checked_stages
        from mobile.workbench.core_publish import check_live_calls
        accepted, _ = load_checked_stages(target / 'ai', bundle)
        calls = check_live_calls(target / 'ai', accepted, bundle)
        verification['stages'][stage] = {'state': 'done', 'validated_stages': list(validations),
            'request_count': len(calls), 'models': sorted({c['model'] for c in calls})}
        store.stage(task_id, 'ai', 'done', '真实三阶段模型与引用校验通过')
        stage = 'report'
        store.stage(task_id, 'report', 'running')
        command(['mobile/report/report_mobile.py', '--bundle', target / 'bundle.json',
                 '--ai-out-dir', target / 'ai', '--session', out.name, '--out', target / 'mobile-report.pdf'], out / 'report.log', cancel_file=getattr(args, 'cancel_file', None))
        from pypdf import PdfReader
        pages = PdfReader(target / 'mobile-report.pdf').pages
        if not pages or not any('AI' in (p.extract_text() or '') for p in pages):
            raise ValueError('generated PDF missing expected AI report content')
        verification['stages'][stage] = {'state': 'done', 'pages': len(pages)}
        check_cancel(getattr(args, 'cancel_file', None))
        verification.update(passed=True, completed_at=time.time())
        save(out / 'verification.json', verification)
        verification['published'] = publish(args.storage, task_id, out)
    except Exception as exc:
        cancelled = isinstance(exc, Cancelled)
        verification.update(passed=False, cancelled=cancelled, error=f'{type(exc).__name__}: {exc}', failed_stage=stage)
        verification['stages'][stage] = {'state': 'failed', 'reason': str(exc)}
        if task_id:
            store = Store(args.storage)
            store.patch(task_id, state='cancelled' if cancelled else 'failed', core_run={'state': 'cancelled' if cancelled else 'failed', 'source_run': str(out), 'stage': stage})
            failed_stage = 'dynamic' if stage in ('capture', 'correlate', 'bundle') else stage
            if failed_stage in ('dynamic', 'ai', 'report'):
                store.stage(task_id, failed_stage, 'cancelled' if cancelled else 'failed', str(exc))
    finally:
        verification['completed_at'] = time.time()
        save(out / 'verification.json', verification)
    return verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--task-id', help='Continue the same uploaded task; no second static task')
    parser.add_argument('--cancel-file', type=Path, help='Trusted local stop marker, checked between bounded commands')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--selftest', type=Path, required=True)
    parser.add_argument('--static-source', type=Path, help='Use same-APK retained whole-DEX evidence without claiming source decompilation')
    parser.add_argument('--capture-source', type=Path, help='Reuse actual same-APK/device capture with retained provenance')
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--policy-store', type=Path, default=DEFAULT_STORE)
    parser.add_argument('--storage', type=Path, default=ROOT / 'output/mobile-workbench')
    parser.add_argument('--server', default='http://127.0.0.1:8772')
    parser.add_argument('--serial', default='emulator-5562')
    parser.add_argument('--scenario', choices=('libchecker', 'readyou', 'launch'), default='launch')
    parser.add_argument('--seconds', type=int, default=20)
    parser.add_argument('--app-category')
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    result = run(args)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
