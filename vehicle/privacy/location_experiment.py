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

# B 周 D3：分层计数只做投影，不改 evaluate() 的任何判定或产物。
# 键与 location_match / location_payload 的 diagnostics 一一对应；新增原因若未登记，
# 会进入 unclassified_rejections 而不是被静默丢掉（由单测守住）。
READ_REJECTIONS = frozenset({
    'no_scoped_general_location_reads', 'location_not_obtained',
    'read_identity_or_clock_unavailable', 'no_usable_location_pair',
    'invalid_primary_location_form', 'invalid_location_forms',
    'primary_location_form_conflict',
})
FLOW_REJECTIONS = frozenset({
    'no_scoped_flows', 'flow_identity_unresolved_or_failed',
    'flow_clock_or_attribution_distance_unavailable', 'request_body_unavailable',
    'request_body_incomplete', 'request_body_not_retained',
    'request_body_unavailable_or_oversized', 'request_text_digest_or_length_mismatch',
    'request_body_digest_or_length_mismatch', 'request_body_invalid_json',
    'request_json_node_limit', 'request_body_invalid_unicode',
})
SHARED_REFERENCE = frozenset({
    'invalid_event_reference', 'conflicting_event_reference', 'duplicate_event_reference',
})


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def layer_accounting(result):
    """从一次 evaluate 结果派生「输入 → 可比 → 候选」每层计数与逐条拒绝原因。

    只读投影：不修改 ``result``、不新增候选、不把「未匹配」写成「未外发」。
    """
    diagnostics = dict(result.get('diagnostics') or {})
    inputs = result.get('inputs') or {}
    known = READ_REJECTIONS | FLOW_REJECTIONS | SHARED_REFERENCE
    unknown = {key: value for key, value in sorted(diagnostics.items()) if key not in known}
    pick = lambda keys: {key: diagnostics[key] for key in sorted(keys) if key in diagnostics}
    return {
        'scoped': {'location_reads': inputs.get('scoped_location_reads'),
                   'flows': inputs.get('scoped_flows')},
        'comparable': {'location_reads': inputs.get('comparable_reads'),
                       'flows': inputs.get('comparable_flows')},
        'candidates': {'pairs': result.get('pair_count'),
                       'ambiguous_flows': result.get('ambiguous_flows'),
                       'matched_forms': dict(result.get('matched_form_counts') or {}),
                       'status': result.get('status')},
        'rejections': {'read_layer': pick(READ_REJECTIONS),
                       'flow_layer': pick(FLOW_REJECTIONS),
                       'shared_reference': pick(SHARED_REFERENCE)},
        'unclassified_rejections': unknown,
        'all_reasons_classified': not unknown,
        'note': ('shared_reference 含去重计数（不是拒绝）；0 候选仅表示本有限方法内未观测到，'
                 '不等于没有定位外发。'),
    }


def summarize_layers(accounts):
    """合并多个 case 的分层计数；只做加法，不产生新的判定。"""
    def total(section, key):
        return sum((a[section][key] or 0) for a in accounts)
    reasons, unknown = {}, {}
    for account in accounts:
        for layer, rows in account['rejections'].items():
            target = reasons.setdefault(layer, {})
            for key, value in rows.items():
                target[key] = target.get(key, 0) + value
        for key, value in account['unclassified_rejections'].items():
            unknown[key] = unknown.get(key, 0) + value
    return {
        'scoped': {'location_reads': total('scoped', 'location_reads'),
                   'flows': total('scoped', 'flows')},
        'comparable': {'location_reads': total('comparable', 'location_reads'),
                       'flows': total('comparable', 'flows')},
        'candidates': {'pairs': sum(a['candidates']['pairs'] or 0 for a in accounts),
                       'ambiguous_flows': sum(a['candidates']['ambiguous_flows'] or 0
                                             for a in accounts)},
        'rejections': reasons,
        'unclassified_rejections': unknown,
        'all_reasons_classified': all(a['all_reasons_classified'] for a in accounts),
        'case_count': len(accounts),
        'note': '六类合成用例的合计；合成输入不是设备采集，也不能据此计算真实 P/R。',
    }


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
    result['layer_accounting'] = layer_accounting(result)
    return result


def synthetic(window_ms):
    reports = []
    for case in location_fixtures.cases():
        result = location_match.evaluate(case['reads'], case['flows'], location_fixtures.PACKAGE,
                                         location_fixtures.SESSION, window_ms=window_ms)
        passed = (result['pair_count'] == case['expected_pairs']
                  and result['ambiguous_flows'] == case.get('expected_ambiguous_flows', 0))
        reports.append({'name': case['name'], 'passed': passed,
                        'expected_pairs': case['expected_pairs'], 'result': result,
                        'layer_accounting': layer_accounting(result)})
    return {'input_kind': 'synthetic', 'experimental_only': True, 'emits_rule_findings': False,
            'all_passed': all(c['passed'] for c in reports), 'cases': reports,
            'layer_accounting': summarize_layers([c['layer_accounting'] for c in reports]),
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
