"""Replay location experiment without changing audit outputs. 仅用于授权测试。"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.privacy import location_fixtures, location_match, location_inputs, location_payload
from vehicle.privacy.evaluation import load_general_rules
from vehicle.analyze import pair_ambiguity

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(capture, package, window_ms):
    manifest_path = capture / 'session-manifest.json'
    manifest_sha256 = digest(manifest_path)
    manifest = location_inputs.read_manifest(manifest_path, package)
    session, user = manifest['session'], manifest['user_id']
    hashes = manifest['input_sha256']
    inputs = {}
    for name in ('reads.jsonl', 'flows.jsonl'):
        path = capture / name
        actual = digest(path)
        if hashes.get(name) != actual:
            raise ValueError('Missing or mismatched capture input digest: ' + name)
        inputs[name] = actual
    version = str(manifest.get('android_version'))
    rules = load_general_rules(version)
    rule = rules.get('VSC-GE-location')
    reads, flows = load_jsonl(capture / 'reads.jsonl'), load_jsonl(capture / 'flows.jsonl')
    location_inputs.bind_user(reads, flows, manifest, package)
    result = location_match.evaluate(reads, flows, package, session, window_ms=window_ms)
    # Re-check after reading: a concurrently growing capture is not a frozen input.
    if digest(manifest_path) != manifest_sha256:
        raise ValueError('Capture manifest changed during replay')
    if any(digest(capture / name) != value for name, value in inputs.items()):
        raise ValueError('Capture inputs changed during replay')
    result.update(input_kind='historical_capture', capture_manifest_sha256=manifest_sha256,
        input_sha256=inputs, android_version=version, user_id=user,
        identity_binding='capture_manifest_user_and_record_uid',
        registered_location_egress_rule=rule,
        capture_health_note='Input hashes checked; this experiment does not certify full capture health.',
        real_validation=('supported_content_observed' if result['pair_count']
                         else 'not_validated_on_supported_real_content'))
    return result


def synthetic(window_ms):
    reports = []
    for case in location_fixtures.cases():
        result = location_match.evaluate(case['reads'], case['flows'], location_fixtures.PACKAGE,
                                         location_fixtures.SESSION, window_ms=window_ms)
        passed = (result['pair_count'] == case['expected_pairs']
                  and result['ambiguous_flows'] == case.get('expected_ambiguous_flows', 0))
        reports.append({'name': case['name'], 'passed': passed,
                        'expected_pairs': case['expected_pairs'], 'result': result})
    return {'input_kind': 'synthetic', 'experimental_only': True, 'emits_rule_findings': False,
            'all_passed': all(c['passed'] for c in reports), 'cases': reports,
            'real_validation': 'not_device_validation'}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument('--capture', type=Path)
    source.add_argument('--synthetic', action='store_true')
    ap.add_argument('--package', help='Explicit authorised package from capture manifest')
    ap.add_argument('--window-ms', type=int, default=30000)
    ap.add_argument('--out', type=Path, required=True, help='New experiment output directory')
    args = ap.parse_args(argv)
    if args.capture and args.out.resolve().is_relative_to(args.capture.resolve()):
        ap.error('Output must be outside capture directory')
    if args.capture and not args.package:
        ap.error('--package required for capture replay')
    if args.window_ms <= 0:
        ap.error('--window-ms must be positive')
    if args.out.exists():
        ap.error('Output already exists; use a new directory')
    args.out.mkdir(parents=True)
    try:
        result = (synthetic(args.window_ms) if args.synthetic
                  else replay(args.capture, args.package, args.window_ms))
        result['implementation_sha256'] = {p.name: digest(p) for p in
            (Path(__file__), Path(location_match.__file__), Path(location_fixtures.__file__),
             Path(location_inputs.__file__), Path(location_payload.__file__))}
        result['implementation_sha256']['pair_ambiguity.py'] = digest(Path(pair_ambiguity.__file__))
        git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
        result['git_head'] = git.stdout.strip() if git.returncode == 0 else None
        result['note'] = 'Only experiment output; default evaluator/rules/Hook/catalog are unchanged.'
        (args.out / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n',
                                               encoding='utf-8')
        return 0 if result.get('all_passed', True) else 1
    except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        (args.out / 'failure.json').write_text(json.dumps(
            {'status': 'experiment_failed', 'error': type(exc).__name__, 'message': str(exc),
             'note': 'No audit success or negative conclusion; failed experiment preserved.'},
            ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
