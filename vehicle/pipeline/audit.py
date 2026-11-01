"""Reproducible vehicle evidence → correlation → profile → AI → report pipeline.

Authorized tests only. Capture is performed by the existing Frida/collector tools.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.io_utils import load_jsonl
from vehicle.analyze.context_profile import build_profile
from vehicle.analyze.risk_triage import rank_findings


def run_audit(capture, output, package, version='15', scenarios=None, ai_config=None, pdf=True, apk=None):
    capture, output = Path(capture), Path(output)
    output.mkdir(parents=True, exist_ok=False)
    events = output / 'events.jsonl'

    def stage(name, action):
        def emit(status, message=''):
            with events.open('a', encoding='utf-8') as handle:
                handle.write(json.dumps({'ts': time.time(), 'stage': name,
                                         'status': status, 'message': message}) + '\n')
        emit('running')
        try:
            result = action()
        except Exception as error:
            emit('failed', str(error)); raise
        emit('done')
        return result

    def command(args):
        result = subprocess.run([sys.executable, *map(str, args)], cwd=ROOT,
            capture_output=True, encoding='utf-8', errors='replace', timeout=120)
        (output / (Path(args[0]).stem + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode:
            raise RuntimeError(f'{Path(args[0]).name} failed ({result.returncode}); see pipeline log')

    rules = ROOT / 'vehicle/rules/rules_library/rules.db'
    findings, summary = output / 'findings.jsonl', output / 'summary.json'
    reads, flows = load_jsonl(capture / 'reads.jsonl'), load_jsonl(capture / 'flows.jsonl')
    sessions = {e.get('session_id') for e in reads + flows}
    if len(sessions) != 1 or None in sessions:
        raise ValueError('one explicit capture session is required')
    session = next(iter(sessions))
    args = [ROOT / 'vehicle/analyze/correlate.py', '--rules', rules,
        '--reads', capture / 'reads.jsonl', '--flows', capture / 'flows.jsonl',
        '--package', package, '--session', session, '--android-version', version,
        '--out', findings, '--summary', summary]
    for flag, filename in (('--egress', 'egress.jsonl'), ('--permissions', 'requested-permissions.txt')):
        if (capture / filename).exists():
            args.extend([flag, capture / filename])
    stage('correlate', lambda: command(args))
    static_result = None
    if apk:
        from core.static.analysis import scan_static
        apk = Path(apk)
        provenance = capture / 'session-manifest.json'
        if not provenance.exists():
            raise ValueError('APK/static cross-check requires the capture session manifest')
        manifest = json.loads(provenance.read_text(encoding='utf-8'))
        if hashlib.sha256(apk.read_bytes()).hexdigest() != manifest.get('installed_apk_sha256'):
            raise ValueError('APK differs from the version actually installed during capture')
        static_dir = output / 'static'
        static_dir.mkdir()
        static_result = stage('static', lambda: scan_static(apk, rules, version, static_dir))
        if static_result['apk']['package'] != package:
            raise ValueError('static APK package differs from audited package')
    journal = json.loads(Path(scenarios).read_text(encoding='utf-8')) if scenarios else []
    profile = stage('context_profile', lambda: build_profile(
        [r for r in reads if r.get('pkg') == package],
        [f for f in flows if f.get('package') == package], journal))
    document = json.loads(summary.read_text(encoding='utf-8'))
    document['vehicle_profile'] = profile
    document['static_analysis'] = ({'status': 'completed', 'findings': len(static_result['findings']),
        'artifact': 'static/static.json', 'scope': 'candidate_only',
        'apk_sha256': hashlib.sha256(apk.read_bytes()).hexdigest()} if static_result is not None
        else {'status': 'skipped', 'reason': 'APK was not supplied for version-verified static cross-check'})
    document['review_order'] = rank_findings(load_jsonl(findings))
    document['review_order_caveat'] = 'Experimental engineering weights; not calibrated risk probability.'
    document['ai_review'] = {'status': 'skipped', 'reason': 'AI configuration not supplied'}
    if ai_config:
        from vehicle.ai.review import review
        document['ai_review'] = stage('ai_review', lambda: review(
            load_jsonl(findings), profile, Path(ai_config), output / 'ai'))
    summary.write_text(json.dumps(document, ensure_ascii=False, indent=2), encoding='utf-8')
    if pdf:
        stage('report', lambda: command([ROOT / 'vehicle/analyze/report.py', '--findings', findings,
            '--summary', summary, '--rules', rules, '--flows', capture / 'flows.jsonl',
            '--out', output / 'vehicle-audit.pdf']))
    return document


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--android-version', default='15')
    parser.add_argument('--scenarios', type=Path)
    parser.add_argument('--ai-config', type=Path)
    parser.add_argument('--no-pdf', action='store_true')
    parser.add_argument('--apk', type=Path, help='must match capture-time installed APK hash')
    args = parser.parse_args()
    result = run_audit(args.capture, args.out, args.package, args.android_version,
                       args.scenarios, args.ai_config, not args.no_pdf, args.apk)
    print(json.dumps({'status': 'ok', 'findings': result['findings_total'], 'out': str(args.out)}))


if __name__ == '__main__':
    main()
