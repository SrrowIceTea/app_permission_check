"""Run every verified domestic APK on the dedicated root emulator, retaining failures.

仅用于授权测试。不登录、购物、发送消息或替换原有应用。One bounded worker per APK.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
from mobile.lab.root_runtime import Android, save
from mobile.tools.device_environment import resolve_adb

ROOT = Path(__file__).resolve().parents[2]


def now():
    return datetime.now(timezone.utc).isoformat()


def run(manifest, out, serial='emulator-5562', seconds=15, samples=None, startup_mode='spawn'):
    out = out.resolve()
    if not out.is_relative_to(ROOT / 'output') or out.exists():
        raise ValueError('use a new project output directory')
    entries = [e for e in json.loads(manifest.read_text(encoding='utf-8'))
               if e.get('download_status') == 'downloaded' and e.get('artifact_checks', {}).get('signature') is True]
    if samples:
        unknown = set(samples) - {e['sample_id'] for e in entries}
        if unknown:
            raise ValueError('unknown signed samples: ' + str(sorted(unknown)))
        entries = [e for e in entries if e['sample_id'] in samples]
    android = Android(str(resolve_adb()), serial)
    profile = android.profile()
    out.mkdir(parents=True)
    batch = {'batch_id': out.name, 'created_at': now(), 'status': 'running', 'environment': profile,
             'planned_sample_count': len(entries), 'samples': [],
             'scope': 'real root installation/startup/privacy/network/storage collection; no account login or transactions'}
    save(out / 'batch.json', batch)
    for entry in entries:
        sid, package = entry['sample_id'], entry['package']
        folder = out / 'samples' / sid
        folder.parent.mkdir(exist_ok=True)
        scenario = {'cn-libchecker': 'libchecker', 'cn-readyou': 'readyou'}.get(sid, 'launch')
        command = [sys.executable, '-B', '-m', 'mobile.lab.core_capture', '--apk', entry['apk_path'],
                   '--package', package, '--out', str(folder), '--serial', serial,
                   '--scenario', scenario, '--seconds', str(seconds), '--startup-mode', startup_mode, '--authorize']
        log = out / (sid + '.log')
        print('START', sid, package, flush=True)
        reason = None
        with log.open('w', encoding='utf-8') as stream:
            process = subprocess.Popen(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT,
                env=dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1'),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
            try:
                process.wait(timeout=300)
            except subprocess.TimeoutExpired:
                reason = 'capture worker exceeded 300 seconds; its process tree terminated'
                if os.name == 'nt':
                    subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'], capture_output=True, timeout=30)
                else:
                    process.kill()
                process.wait(timeout=30)
        result_path = folder / 'verification.json'
        result = json.loads(result_path.read_text(encoding='utf-8')) if result_path.exists() else {
            'state': 'failed', 'error': reason or 'worker exited without verification',
            'package': package, 'checks': {}, 'apk_sha256': entry['sha256']}
        record = {'sample_id': sid, 'name': entry['name'], 'package': package,
                  'apk_sha256': entry['sha256'], 'state': result['state'],
                  'real_privacy_reads': result.get('real_privacy_reads'), 'flows': result.get('flows'),
                  'error': result.get('error'), 'checks': result.get('checks'),
                  'evidence_path': f'samples/{sid}/verification.json', 'worker_exit': process.returncode}
        if reason:
            record.update(state='failed', error=reason)
            # On forced termination stop before touching another app: cleanup is not proven.
            batch['samples'].append(record)
            batch.update(status='cleanup_required', stopped_at=now())
            save(out / 'batch.json', batch)
            return batch
        batch['samples'].append(record)
        save(out / 'batch.json', batch)
        print('END', sid, record['state'], record.get('real_privacy_reads'), record.get('error'), flush=True)
    batch.update(status='completed', completed_at=now())
    batch['acceptance'] = {'attempted': len(batch['samples']),
        'capture_passed': sum(s['state'] == 'done' for s in batch['samples']),
        'capture_failed': sum(s['state'] != 'done' for s in batch['samples'])}
    save(out / 'batch.json', batch)
    return batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'output/domestic-apk-corpus-20261018/manifest.json')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--serial', default='emulator-5562')
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--startup-mode', choices=('spawn', 'attach'), default='spawn')
    parser.add_argument('--sample', action='append', help='Explicit subset for completing or retrying actual attempts')
    parser.add_argument('--authorize', action='store_true')
    args = parser.parse_args()
    if not args.authorize:
        parser.error('--authorize required for the selected corpus on the dedicated emulator')
    result = run(args.manifest, args.out, args.serial, args.seconds, args.sample, args.startup_mode)
    print(json.dumps({'status': result['status'], 'acceptance': result.get('acceptance')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
