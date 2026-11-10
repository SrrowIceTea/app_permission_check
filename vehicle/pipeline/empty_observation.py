"""Healthy observation without VHAL events is a limited result, never all-clear.

仅用于授权测试。 The direct correlation CLI keeps rejecting unobserved input;
only the health-validated pipeline can construct this explicit limited summary.
"""
from collections import Counter
from core.collector.parse_stats import body_parse_totals
from core.io_utils import load_jsonl
from vehicle.analyze.correlate import load_rules, body_scan_totals
from vehicle.analyze.evaluation import evaluate_over_permission, coverage
from vehicle.analyze.method_evidence import attach as attach_method_evidence
from vehicle.pipeline.contracts import digest, write_json
import json


def analyze_empty(capture, output, package, version, rules, session):
    permissions_file = capture / 'requested-permissions.txt'
    permissions = permissions_file.read_text(encoding='utf-8').splitlines() if permissions_file.exists() else []
    loaded, flows = load_rules(rules, version), load_jsonl(capture / 'flows.jsonl')
    flows = [flow for flow in flows if flow.get('package') == package and flow.get('session_id') == session]
    findings = evaluate_over_permission(loaded, permissions, package)
    (output / 'findings.jsonl').write_text(''.join(json.dumps(f) + '\n' for f in findings), encoding='utf-8')
    summary = {
        'status': 'no_target_vehicle_reads', 'package': package, 'android_version': version,
        'session_id': session, 'findings_total': len(findings),
        'findings_by_conclusion_level': dict(Counter(f['conclusion_level'] for f in findings)),
        'inputs': {'reads': 0, 'proxy_flows': len(flows), 'requested_permissions': len(permissions),
                   'reads_path_sha256': digest(capture / 'reads.jsonl'),
                   'flows_path_sha256': digest(capture / 'flows.jsonl'),
                   'parsing': body_parse_totals(flows), **body_scan_totals(flows)},
        'rules_sha256': digest(rules), 'coverage': coverage(loaded, []),
        'clock_basis': 'host_received_ts',
        'caveat': 'Healthy hooks, but no covered vehicle-property read observed. Not a privacy clearance.'}
    # 空观测路径已经过 preflight 健康校验（见本文件 docstring），因此采集健康条件
    # 可以显式给出；其余问题仍按各自必要条件分别判定，绝不因「没读到」而变成通过。
    summary = attach_method_evidence(
        summary, reads=[], flows=flows, findings=findings, capture=capture,
        enabled_properties=coverage(loaded, [])['enabled_read_properties'],
        collector_health={'status': 'completed', 'errors': [],
                          'source': 'preflight_health_validated_empty_observation'})
    write_json(output / 'correlation-summary.json', summary)
