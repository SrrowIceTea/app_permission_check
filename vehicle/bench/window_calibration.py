"""Replay independently referenced pairs at several windows. 仅用于授权测试。

Windows are experimental overrides in memory. No rules.db mutation. Truth must
include delayed positives outside the current detector window, not its findings.
"""
import argparse
import copy
import json
import sys
from collections import Counter
from pathlib import Path
from core.io_utils import load_jsonl
from vehicle.analyze.batch_pairing import CLAIM_TOLERANCE_MS, FIXTURE_PACKAGE, PAIRING_MODES
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.privacy.evaluation import RULE_DB, evaluate, load_general_rules
from vehicle.bench.ablation_integrity import resolve_rules
from vehicle.bench.metrics import matched_pairs, pair_metrics
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json, write_json
from vehicle.pipeline.evidence_manifest import capture_paths, fingerprints, input_manifest, verify_refs
from vehicle.pipeline.preflight import validate_capture


def supports_token_replay(manifest, label):
    return (manifest.get('packages') == [FIXTURE_PACKAGE]
            and label.get('sample_origin', label.get('sample_class')) == 'owned_fixture'
            and manifest.get('data_scope') != 'general' and bool(manifest.get('input_sha256')))


def calibrate(capture, label_path, windows=(5000, 10000, 30000, 60000, 120000), *,
              pairing='window', rules=None, include_pairs=False):
    if pairing not in PAIRING_MODES:
        raise ValueError('invalid pairing mode')
    capture, label_path = Path(capture), Path(label_path)
    completeness = input_manifest(capture_paths(capture))
    manifest, label = read_json(capture / 'session-manifest.json'), read_json(label_path)
    if 'samples' in label:
        if not isinstance(label['samples'], list) or len(label['samples']) != 1:
            raise ValueError('calibration requires exactly one signed sample')
        label = label['samples'][0]
    verification = read_json(capture / 'verification.json')
    if verification.get('passed') is not True:
        raise ValueError('calibration requires a healthy capture')
    reads, flows = load_jsonl(capture / 'reads.jsonl'), load_jsonl(capture / 'flows.jsonl')
    if len(manifest.get('packages', [])) != 1:
        raise ValueError('calibration requires one explicit target package')
    package = manifest['packages'][0]
    version = str(manifest.get('android_version', '15'))
    database = resolve_rules(ROOT, manifest, explicit=RULE_DB if rules is None else rules)
    validate_capture(capture, package, version, database)
    sha = manifest['installed_apk_sha256']
    session = manifest['session']
    # Validation also checks reference hashes before running a sweep.
    pair_metrics([], label, sha, session)
    if pairing != 'window' and not supports_token_replay(manifest, label):
        raise ValueError('token replay requires sealed VHAL evidence for the owned fixture')
    vhal_rules = load_rules(database, version) if manifest.get('data_scope') != 'general' else []
    rows = []
    for window in windows:
        if type(window) is not int or window <= 0:
            raise ValueError('windows must be positive integer milliseconds')
        findings = []
        if pairing != 'token':
            general = copy.deepcopy(load_general_rules(version, db=database))
            for rule in general.values():
                if rule['rule_type'] == 'data_egress':
                    rule['window_ms'] = window
            findings, _ = evaluate(reads, flows, package, session, version, general)
        vhal = evaluate_data_egress(vhal_rules, reads, flows, window_override_ms=window, pairing=pairing)
        findings.extend(vhal)
        row = {'window_ms': window, **pair_metrics(findings, label, sha, session)}
        if include_pairs:
            row['matched_pairs'] = [list(pair) for pair in sorted(matched_pairs(findings))]
        if pairing != 'window':
            row.update(batch_evidence(vhal, label, sha, session))
        rows.append(row)
    result = {'status': 'agent_initial_evaluation' if label['origin'] == 'agent_review' else 'evaluated',
            'capture': str(capture.resolve()), 'label_sha256': digest(label_path),
            'session_id': session, 'windows': rows, 'rule_database_modified': False,
            'human_signoff': label.get('human_signoff'),
            'scope': 'Reference-labelled pairs only; repeated equal values may have multiple candidate reads.',
            'recommendation': 'Keep 30000ms baseline until independent app traces establish the tradeoff.'}
    if label.get('review_mode'):
        result.update(review_mode=label['review_mode'], subagent_signoff=label.get('subagent_signoff'))
    if pairing != 'window':
        result.update(pairing=pairing, claim_tolerance_ms=CLAIM_TOLERANCE_MS,
                      scope='Sealed owned VHAL fixture. A corroborated request claim is not causal proof.')
    verify_refs(completeness['inputs'])
    result.update(fingerprints(database, version, completeness))
    if result['rules_sha'] != manifest['rules_sha256']:
        raise AuditError('replay_digest_mismatch', '重放期间规则库摘要发生变化。',
                         '恢复与会话匹配的规则库快照后重新执行。')
    return result


def batch_evidence(findings, label, sha, session):
    counts, refs, token_findings = Counter(), [], []
    for finding in findings:
        token_pairs = []
        for pair in finding['pairs']:
            counts[pair['pair_basis']] += 1
            if pair['pair_basis'] != 'token_read_claim':
                continue
            token_pairs.append(pair)
            refs.append({'rule_id': finding['rule_id'], **{key: pair[key] for key in (
                'read_src', 'read_event_id', 'flow_src', 'flow_event_id', 'delta_ms',
                'token_sha256', 'token_role', 'claim_match_ms')}})
        token_findings.append({**finding, 'pairs': token_pairs})
    token_metrics = pair_metrics(token_findings, label, sha, session)
    return {'by_pair_basis': dict(counts), 'corroborated_claims': len(refs),
            'token_aligned': token_metrics['tp'], 'token_missed': token_metrics['fn'],
            'token_extra_candidates': token_metrics['fp'], 'corroborated_refs': refs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--labels', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--pairing', choices=PAIRING_MODES, default='window')
    parser.add_argument('--rules', type=Path, help='与采集清单 SHA-256 匹配的规则库快照')
    parser.add_argument('--include-pairs', action='store_true', help='逐窗口保存命中的规则与事件引用')
    args = parser.parse_args(argv)
    try:
        result = calibrate(args.capture, args.labels, pairing=args.pairing, rules=args.rules,
                           include_pairs=args.include_pairs)
    except AuditError as error:
        print(f'{error.code}: {error} {error.action}', file=sys.stderr)
        return 2
    write_json(args.out, result)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    raise SystemExit(main())
