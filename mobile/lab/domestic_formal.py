"""Formal three-stage review of retained real domestic APK evidence. 仅用于授权测试。

No device execution, fixture substitution, transport retries, or failed-capture bypass.
Each stage may correct one complete parsed HTTP 200 output that failed its exact gate.
--plan only selects inputs and writes a batch plan without reading model credentials.
"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from mobile.lab.domestic_static import ready_entries
from mobile.lab.root_runtime import save
from mobile.policy.policy_library import DEFAULT_STORE

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = ROOT / 'output/domestic-dynamic-20261018-all'
STATIC = ROOT / 'output/root-benchmark-domestic-20261018'


def now():
    return datetime.now(timezone.utc).isoformat()


def read(path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}


def select_source(entry, roots, kind, serial):
    """Later explicitly supplied roots take precedence, but only with bound complete facts."""
    attempts = []
    for root in reversed(roots):
        folder = root.resolve() / 'samples' / entry['sample_id']
        if not folder.is_relative_to(ROOT / 'output'):
            raise ValueError('source evidence must stay inside project output')
        path = folder / ('verification.json' if kind == 'capture' else 'result.json')
        value = read(path)
        reasons = []
        if not value:
            reasons.append('verification missing or unreadable')
        if value.get('apk_sha256') != entry['sha256'] or value.get('package') != entry['package']:
            reasons.append('APK/package binding absent or different')
        if kind == 'capture':
            checks = value.get('checks') or {}
            if value.get('state') != 'done' or not checks or any(v is not True for v in checks.values()):
                reasons.append('capture not complete: ' + json.dumps({
                    'state': value.get('state'), 'failed_checks': [k for k, v in checks.items() if v is not True],
                    'error': value.get('error')}, ensure_ascii=False))
            if value.get('device', {}).get('serial') != serial:
                reasons.append('capture device differs from passing fixture self-test')
            if not (folder / 'session/reads.jsonl').is_file():
                reasons.append('raw read-event file missing')
        else:
            if (value.get('static_summary') or {}).get('whole_dex_scanned') is not True:
                reasons.append('whole-DEX scan not complete')
            if not all((folder / 'static' / name).is_file() for name in ('static.json', 'dexfacts.json')):
                reasons.append('retained static facts missing')
        attempts.append({'path': str(path), 'accepted': not reasons, 'reasons': reasons})
        if not reasons:
            return folder, attempts
    return None, attempts


def plan_entry(entry, capture_roots, static_roots, serial):
    capture, capture_attempts = select_source(entry, capture_roots, 'capture', serial)
    static, static_attempts = select_source(entry, static_roots, 'static', serial)
    return {'sample_id': entry['sample_id'], 'name': entry['name'], 'package': entry['package'],
        'apk_sha256': entry['sha256'], 'apk': entry['apk_path'],
        'state': 'ready' if capture and static else 'blocked',
        'capture_source': str(capture) if capture else None,
        'static_source': str(static) if static else None,
        'input_checks': {'capture': capture_attempts, 'static': static_attempts},
        'blocked_reason': None if capture and static else 'same-APK complete capture and whole-DEX facts required'}


def run_one(record, args):
    """One new output directory and one three-stage pipeline invocation; never retry a failure."""
    folder = args.out.resolve() / 'samples' / record['sample_id']
    from mobile.ai.llm_client import load_config
    if int(load_config(args.config).get('max_retries', 2)) != 0:
        return {**record, 'state': 'blocked', 'blocked_reason': 'set model max_retries=0; batch permits at most 6 requests per APK'}
    command = [sys.executable, '-B', '-m', 'mobile.lab.core_pipeline', '--apk', record['apk'],
        '--out', str(folder), '--selftest', str(args.selftest), '--config', str(args.config),
        '--capture-source', record['capture_source'], '--static-source', record['static_source'],
        '--policy-store', str(args.policy_store), '--storage', str(args.storage),
        '--server', args.server, '--serial', args.serial, '--authorize']
    log = args.out.resolve() / (record['sample_id'] + '.log')
    started = now()
    with log.open('w', encoding='utf-8') as stream:
        proc = subprocess.Popen(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
            env=dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1'),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
        timeout_error = None
        try:
            proc.wait(timeout=2400)
        except subprocess.TimeoutExpired:
            timeout_error = 'formal worker exceeded 2400 seconds; process tree stopped without retry'
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(proc.pid), '/T', '/F'], capture_output=True, timeout=30)
            else:
                proc.kill()
            proc.wait(timeout=30)
    verification = read(folder / 'verification.json')
    stage3 = read(folder / 'out/ai/stage3.json')
    bundle = read(folder / 'out/bundle.json')
    call_path = folder / 'out/ai/llm-calls.jsonl'
    calls = [json.loads(line) for line in call_path.read_text(encoding='utf-8').split("\n")
             if line.strip()] if call_path.exists() else []
    passed = verification.get('passed') is True and proc.returncode == 0 and not timeout_error
    return {**record, 'state': 'done' if passed else 'failed', 'started_at': started,
        'completed_at': now(), 'worker_exit': proc.returncode, 'verification_path': str(folder / 'verification.json'),
        'error': timeout_error or verification.get('error'), 'failed_stage': verification.get('failed_stage'),
        'task_id': verification.get('task_id'), 'published': verification.get('published'),
        'quality_gaps': verification.get('quality_gaps', []), 'recorded_model_calls': len(calls),
        'validation_repairs': sum(c.get('tag', '').endswith('-repair1') for c in calls),
        'formal_overall_risk': stage3.get('overall_risk') if passed else None,
        'risk_assessment': bundle.get('risk_assessment'),
        'counts': bundle.get('counts'), 'policy_available': bundle.get('policy', {}).get('available'),
        'storage_crypto_risk': bundle.get('dynamic', {}).get('storage_crypto', {}).get('risk_assessment'),
        'report_path': str(folder / 'out/mobile-report.pdf') if passed else None}


def totals(samples):
    return {'planned': len(samples), 'completed': sum(s['state'] == 'done' for s in samples),
        'failed': sum(s['state'] == 'failed' for s in samples),
        'blocked': sum(s['state'] == 'blocked' for s in samples),
        'ready': sum(s['state'] == 'ready' for s in samples),
        'recorded_model_calls': sum(s.get('recorded_model_calls', 0) for s in samples),
        'validation_repairs': sum(s.get('validation_repairs', 0) for s in samples)}


def run_batch(args, worker=run_one):
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'output'):
        raise ValueError('use a new project output directory; existing model runs are never retried implicitly')
    entries = ready_entries(args.manifest)
    if args.sample:
        if set(args.sample) - {e['sample_id'] for e in entries}:
            raise ValueError('requested sample is not a signed corpus APK')
        entries = [entry for entry in entries if entry['sample_id'] in args.sample]
    capture_roots = [CAPTURE, *(args.capture_root or [])]
    static_roots = [STATIC, *(args.static_root or [])]
    samples = [plan_entry(entry, capture_roots, static_roots, args.serial) for entry in entries]
    if not args.plan:
        if not args.authorize:
            raise ValueError('--authorize required for real model review of the selected APK evidence')
        from mobile.lab.core_pipeline import check_selftest
        from mobile.ai.llm_client import load_config
        check_selftest(args.selftest, args.serial)
        if int(load_config(args.config).get('max_retries', 2)) != 0:
            raise ValueError('model max_retries must be 0 for the 6-requests-per-APK limit')
    out.mkdir(parents=True)
    (out / 'samples').mkdir()
    (out / 'results').mkdir()
    for sample in samples:
        save(out / 'results' / (sample['sample_id'] + '.json'), sample)
    batch = {'batch_id': out.name, 'created_at': now(), 'status': 'planned' if args.plan else 'running',
        'scope': 'same-APK retained real evidence → original correlation → full 3-stage AI → PDF → same task publication; no new device execution',
        'max_model_requests_per_apk': 6, 'jobs': args.jobs, 'samples': samples, 'acceptance': totals(samples)}
    save(out / 'batch.json', batch)
    if args.plan:
        return batch
    indexed = {sample['sample_id']: sample for sample in samples}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = {pool.submit(worker, sample, args): sample for sample in samples if sample['state'] == 'ready'}
        for future in as_completed(pending):
            sample = pending[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {**sample, 'state': 'failed', 'error': f'{type(exc).__name__}: {exc}'}
            indexed[sample['sample_id']] = result
            save(out / 'results' / (sample['sample_id'] + '.json'), result)
            batch['samples'] = [indexed[s['sample_id']] for s in samples]
            batch['acceptance'] = totals(batch['samples'])
            save(out / 'batch.json', batch)
            print(json.dumps({'sample_id': result['sample_id'], 'state': result['state'],
                'failed_stage': result.get('failed_stage'), 'formal_overall_risk': result.get('formal_overall_risk')}, ensure_ascii=False), flush=True)
    batch.update(status='completed', completed_at=now())
    save(out / 'batch.json', batch)
    return batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'output/domestic-apk-corpus-20261018/manifest.json')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--capture-root', type=Path, action='append', help='Additional capture batch root; last valid source wins')
    parser.add_argument('--static-root', type=Path, action='append', help='Additional static retry batch root')
    parser.add_argument('--selftest', type=Path, default=ROOT / 'output/core-e2e-fixture-20261018-run3/verification.json')
    parser.add_argument('--config', type=Path, default=Path.home() / 'Desktop/mobile-app-permission-check-deepseek.local.json')
    parser.add_argument('--policy-store', type=Path, default=DEFAULT_STORE)
    parser.add_argument('--storage', type=Path, default=ROOT / 'output/mobile-workbench')
    parser.add_argument('--server', default='http://127.0.0.1:8771')
    parser.add_argument('--serial', default='emulator-5562')
    parser.add_argument('--jobs', type=int, choices=(1, 2), default=2)
    parser.add_argument('--sample', action='append')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    print(json.dumps({'acceptance': run_batch(args)['acceptance']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
