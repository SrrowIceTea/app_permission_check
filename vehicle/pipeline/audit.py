"""Validated vehicle capture → evidence → context → policy → AI → report.

仅用于授权测试（自有设备与已授权 APK）。 Failed runs retain partial artifacts;
summary.json is committed only after all requested stages succeed.
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.io_utils import load_jsonl
from vehicle.analyze.context_profile import build_profile
from vehicle.analyze.finding_class import classify
from vehicle.analyze.risk_triage import rank_findings
from vehicle.compatibility import os_version
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json
from vehicle.pipeline.bundle import package_evidence
from vehicle.pipeline.execution import Execution
from vehicle.pipeline.evidence_manifest import capture_paths, fingerprints, input_manifest, verify_document, verify_refs
from vehicle.pipeline.preflight import validate_capture
from vehicle.pipeline.scenarios import load_scenarios
from vehicle.policy.assessment import assess_policy


def run_audit(capture, output, package, version='15', scenarios=None, ai_config=None,
              pdf=True, apk=None, policy=None, *, rules_path=None, catalog_snapshot=None):
    capture, output = Path(capture).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    execution = Execution(output)
    snapshot = None
    try:
        snapshot = input_manifest(capture_paths(capture), inspect=False)
        rules = Path(rules_path).resolve() if rules_path is not None else ROOT / 'vehicle/rules/rules_library/rules.db'
        result = _audit(execution, capture, output, package, os_version(version),
                        scenarios, ai_config, pdf, Path(apk) if apk else None, policy, snapshot, rules,
                        Path(catalog_snapshot).resolve() if catalog_snapshot else None)
        execution.run('verify_evidence', lambda: verify_document(result, base=output))
        if pdf:
            (output / 'vehicle-audit.pending.pdf').replace(output / 'vehicle-audit.pdf')
        result['pipeline_status'] = 'completed'
        write_json(output / 'summary.json', result)
        write_json(output / 'run-status.json', {'status': 'completed',
                   'result_status': result['status'], 'gaps': result['capture_validation']['gaps']})
        return result
    except BaseException as error:
        execution.failed(error, snapshot)
        raise


def _audit(execution, capture, output, package, version, scenarios, ai_config, pdf, apk, policy, snapshot, rules,
           catalog_snapshot):
    stage = execution.run
    validated = stage('preflight', lambda: validate_capture(capture, package, version, rules, apk,
                      catalog_snapshot=catalog_snapshot))
    session = validated['session_id']
    journal = stage('scenarios', lambda: load_scenarios(scenarios, capture, package, session))
    from vehicle.coverage.export import export_coverage
    chain = stage('coverage', lambda: export_coverage(output / 'coverage', version, rules_path=rules))
    coverage_file = output / 'coverage/coverage.json'
    findings, correlation = output / 'findings.jsonl', output / 'correlation-summary.json'
    if validated['data_scope'] == 'general':
        from vehicle.privacy.pipeline import initial_summary
        stage('correlate', lambda: initial_summary(capture, output, package, version, session))
    elif validated['target_read_events']:
        args = [ROOT / 'vehicle/analyze/correlate.py', '--rules', rules,
            '--reads', capture / 'reads.jsonl', '--flows', capture / 'flows.jsonl',
            '--package', package, '--session', session, '--android-version', version,
            '--out', findings, '--summary', correlation, '--coverage', coverage_file,
            '--manifest', capture / 'session-manifest.json']
        for flag, name in (('--egress', 'egress.jsonl'), ('--permissions', 'requested-permissions.txt')):
            if (capture / name).exists():
                args.extend([flag, capture / name])
        stage('correlate', lambda: execution.command(args))
    else:
        from vehicle.pipeline.empty_observation import analyze_empty
        stage('correlate', lambda: analyze_empty(capture, output, package, version, rules, session))
    document = read_json(correlation)
    from vehicle.privacy.pipeline import append_general
    document, privacy_refs = stage('general_privacy', lambda: append_general(document, output, capture, package, session, version,
                     rules_path=rules, catalog_snapshot=catalog_snapshot))
    document['capture_validation'] = {k: v for k, v in validated.items() if k not in ('manifest', 'evidence_artifacts')}
    document['rules_sha256'] = validated['manifest']['rules_sha256']
    document['target_scope'] = 'ordinary_third_party_app'
    document['coverage_chain'] = {'artifact': 'coverage/coverage.json',
        'sha256': digest(coverage_file),
        'rows': len(chain['rows']), 'profile': chain['profile'],
        'unconnected_types': [r['data_type'] for r in chain['rows']
                              if r['hook_coverage']['status'] != 'implemented']}
    document['static_analysis'] = {'status': 'skipped', 'reason': '未提供装机版本对应 APK。'}
    if apk and validated['data_scope'] == 'general':
        from vehicle.privacy.pipeline import scan_general_manifest
        document['static_analysis'] = stage('static', lambda: scan_general_manifest(apk, output / 'static', package))
    elif apk:
        from core.static.analysis import scan_static
        static_dir = output / 'static'
        static_dir.mkdir()
        static = stage('static', lambda: scan_static(apk, rules, version, static_dir))
        if static['apk']['package'] != package:
            raise AuditError('static_package_mismatch', '静态 APK 包名与目标不一致。', '提供本轮 APK。')
        static['findings'] = [classify({**finding, 'evidence_kind': 'static'}) for finding in static['findings']]
        write_json(static_dir / 'static.json', static)
        document['static_analysis'] = {'status': 'completed', 'findings': len(static['findings']),
            'artifact': 'static/static.json', 'scope': 'candidate_only',
            'apk_sha256': validated['manifest']['installed_apk_sha256']}
    reads = [r for r in load_jsonl(capture / 'reads.jsonl') if r.get('pkg') == package]
    flows = [f for f in load_jsonl(capture / 'flows.jsonl') if f.get('package') == package]
    profile = stage('context_profile', lambda: build_profile(reads, flows, journal))
    document['vehicle_profile'] = profile
    records = load_jsonl(findings)
    document['findings_by_class'] = dict(Counter(row['finding_class'] for row in records))
    document['evidence_counts'] = {
        'manifest_permission_candidates': sum(r.get('evidence_kind') == 'manifest_permission' for r in records),
        'runtime_read_findings': sum(r.get('evidence_kind') == 'read_event' for r in records),
        'runtime_content_correlations': sum(r.get('evidence_kind') == 'read_then_egress'
            and any(pair.get('value_match') is True for pair in r.get('pairs', [])) for r in records),
        'static_candidates': document['static_analysis'].get('findings'),
    }
    document['policy_assessment'] = stage('policy', lambda: assess_policy(policy, package,
        validated['manifest']['installed_apk_sha256'], records, output / 'policy'))
    completeness = input_manifest(capture_paths(capture))
    verify_refs(snapshot['inputs'])
    completeness.update({
        'capture_integrity': 'sealed' if validated['manifest'].get('input_sha256') else 'legacy_unsealed',
        'apk': 'verified' if apk else 'not_supplied',
        'static': document['static_analysis']['status'], 'policy': document['policy_assessment']['status'],
        'scenarios': 'supplied' if scenarios else 'not_supplied',
        'proxy_body_observation': 'available' if any((f.get('request_payload') or {}).get('text') for f in flows)
                                  else 'no_text_observed',
    })
    document.update(fingerprints(rules, version, completeness, coverage=coverage_file, findings=findings))
    document['evidence_artifacts'].update(validated['evidence_artifacts'])
    document['evidence_artifacts'].update(privacy_refs)
    if document['rules_sha'] != document['rules_sha256']:
        raise AuditError('rules_mismatch', '审计期间规则库摘要发生变化。', '核对规则库后重试。')
    # New products become self-contained and relocatable; historical products keep
    # their absolute paths and verify_bundle reports them as legacy.
    stage('bundle', lambda: package_evidence(document, output))
    write_json(correlation, document)
    document['review_order'] = rank_findings(records)
    document['review_order_caveat'] = 'Experimental engineering weights; not calibrated risk probability.'
    document['ai_review'] = {'status': 'skipped', 'reason': 'AI configuration not supplied'}
    if ai_config:
        from vehicle.ai.review import review
        document['ai_review'] = stage('ai_review', lambda: review(records, profile,
            Path(ai_config), output / 'ai', policy=document['policy_assessment']))
    if pdf:
        report_input = output / 'report-input.json'
        write_json(report_input, document)
        stage('report', lambda: execution.command([ROOT / 'vehicle/analyze/report.py',
            '--findings', findings, '--summary', report_input, '--rules', rules,
            '--flows', capture / 'flows.jsonl', '--out', output / 'vehicle-audit.pending.pdf']))
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--android-version', default='15')
    parser.add_argument('--scenarios', type=Path)
    parser.add_argument('--ai-config', type=Path)
    parser.add_argument('--no-pdf', action='store_true')
    parser.add_argument('--apk', type=Path)
    parser.add_argument('--policy', type=Path, help='APK-bound local policy metadata JSON')
    parser.add_argument('--capture-catalog', type=Path, help='封存的隐私目录 JSON，旁边须有配套政策与签名文件')
    args = parser.parse_args(argv)
    try:
        result = run_audit(args.capture, args.out, args.package, args.android_version,
            args.scenarios, args.ai_config, not args.no_pdf, args.apk, args.policy,
            catalog_snapshot=args.capture_catalog)
    except (AuditError, OSError, ValueError) as error:
        detail = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        print(json.dumps({'status': 'failed', 'error': detail}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['pipeline_status'], 'findings': result['findings_total'],
                      'out': str(args.out)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
