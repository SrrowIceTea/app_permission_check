"""Integrate general sources into the vehicle report contract. 授权测试专用。"""
import json
from collections import Counter
from core.evidence import codeloc
from core.collector.parse_stats import body_parse_totals
from core.io_utils import load_jsonl
from vehicle.analyze.finding_class import classify
from vehicle.privacy.evaluation import evaluate
from vehicle.privacy.catalog import AAID_POLICY, AAID_SIGNATURES, catalog_hash, general_profile, contract, HERE
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.privacy import ha_contract
from vehicle.privacy import ha_socket_evidence as ha_socket
from vehicle.privacy import mg4_contract as mg4
from vehicle.privacy import abs_contract as abs_scope


def scan_general_manifest(apk, output, package):
    from core.static import apkmeta, toolchain
    from vehicle.pipeline.contracts import AuditError, digest
    metadata = apkmeta.collect(toolchain.android_build_tool('aapt2'), apk)
    if metadata.get('package') != package or metadata.get('gaps'):
        raise AuditError('general_manifest_invalid', 'APK 清单解析失败或包名不符。', '核对本轮装机 APK。')
    output.mkdir()
    write_json(output / 'apk-manifest.json', metadata)
    return {'status': 'manifest_only', 'artifact': 'static/apk-manifest.json', 'apk_sha256': digest(apk),
        'reason': '通用范围核对清单与 APK 身份；未执行 VHAL 静态规则或通用 DEX API 全面扫描。'}


def initial_summary(capture, output, package, version, session):
    flows = [flow for flow in load_jsonl(capture / 'flows.jsonl')
             if flow.get('package') == package and flow.get('session_id') == session]
    summary = {'status': 'no_target_general_reads', 'package': package, 'android_version': version,
        'session_id': session, 'findings_total': 0, 'findings_by_conclusion_level': {},
        'inputs': {'reads': 0, 'proxy_flows': len(flows), 'parsing': body_parse_totals(flows),
            'requested_permissions': len((capture / 'requested-permissions.txt').read_text(encoding='utf-8').split())
                if (capture / 'requested-permissions.txt').is_file() else 0,
            'reads_path_sha256': digest(capture / 'reads.jsonl')[:16],
            'flows_path_sha256': digest(capture / 'flows.jsonl')[:16]},
        'coverage': {'enabled_read_properties': [], 'observed_properties_without_rule': []},
        'clock_basis': 'host_received_ts', 'privacy_catalog_sha256': catalog_hash(),
        'version_profile': general_profile(version),
        'caveat': 'General Android privacy sources only; no VHAL rule fallback or privacy clearance.'}
    (output / 'findings.jsonl').write_text('', encoding='utf-8')
    write_json(output / 'correlation-summary.json', summary)


def append_general(summary, output, capture, package, session, version='15'):
    manifest = read_json(capture / 'session-manifest.json')
    revision = 1 if manifest.get('privacy_catalog_sha256') == catalog_hash(1) else 2
    (output / 'privacy-catalog.json').write_text(json.dumps(contract(revision), ensure_ascii=False) + '\n',
                                                  encoding='utf-8')
    (output / 'privacy-policy.md').write_bytes((HERE / 'POLICY.md').read_bytes())
    (output / 'privacy-sdk36-signatures.json').write_bytes((HERE / 'sdk36-signatures.json').read_bytes())
    if revision == 2:
        for name in (AAID_POLICY, AAID_SIGNATURES):
            (output / name).write_bytes((HERE / name).read_bytes())
    reads, flows = load_jsonl(capture / 'reads.jsonl'), load_jsonl(capture / 'flows.jsonl')
    records, stats = evaluate(reads, flows, package, session, version, catalog_revision=revision)
    records = codeloc.attach(records, reads, flows, load_jsonl(capture / 'egress.jsonl'), package)
    summary['privacy_catalog_sha256'] = catalog_hash(revision)
    if manifest.get('data_scope') == 'general':
        summary['inputs']['reads'] = stats['events']
        summary['version_profile'] = general_profile(version, revision)
    if manifest.get('ha_webhook_contract_sha256') == ha_contract.contract_hash():
        from vehicle.privacy.ha_evaluation import evaluate as evaluate_ha
        ha_records, summary['ha_webhook'] = evaluate_ha(reads, session, manifest['user_id'])
        records.extend(ha_records)
        summary['inputs']['reads'] += summary['ha_webhook']['power_field_events']
    if manifest.get(ha_socket.MANIFEST_KEY) == ha_socket.contract_hash():
        from vehicle.privacy.ha_socket_diagnostics import add_capture_gaps
        user = manifest['user_id']
        summary['ha_websocket'] = add_capture_gaps(ha_socket.summarize(reads, session, user),
                                                  reads, session, user)
    if manifest.get(mg4.MANIFEST_KEY) == mg4.contract_hash():
        summary['mg4_webview'] = {'request_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in reads
            if r.get('src') == 'mg4_webview' and r.get('ev') == 'WEBVIEW_POST_REQUEST'
            and r.get('pkg') == package and r.get('session_id') == session],
            'scope': 'app_process_request_metadata_requires_separate_server_receipt'}
    if manifest.get(abs_scope.MANIFEST_KEY) == abs_scope.contract_hash():
        from vehicle.privacy.abs_runtime import audit_requests
        summary['abs_native_send'] = audit_requests(capture, reads, session, manifest['user_id'])
    findings = output / 'findings.jsonl'
    previous = [classify(f) for f in load_jsonl(findings)]
    records = [classify(f) for f in records]
    findings.write_text(''.join(json.dumps(f, ensure_ascii=False) + '\n' for f in previous + records),
                        encoding='utf-8')
    summary['general_privacy'] = stats
    summary['general_privacy']['catalog_artifact'] = 'privacy-catalog.json'
    summary['findings_total'] = len(previous) + len(records)
    summary['findings_by_conclusion_level'] = dict(Counter(f['conclusion_level'] for f in previous + records))
    summary['code_locs'] = codeloc.summarize(previous + records)
    if records and summary['status'] in ('no_target_general_reads', 'no_target_vehicle_reads'):
        summary['status'] = 'observed_general_privacy'
    return summary
