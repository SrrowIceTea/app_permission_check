"""Replay sealed authorized AAOS evidence with explicit review provenance."""
import math
import re
from datetime import datetime, timezone
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.bench.metrics import observation_stats, stratified_metrics
from vehicle.bench.review_packet import FIXTURE_ID, PAIR_CASE, fixture_entry, review_entry, write_benchmark
from vehicle.bench.review_policy import DEFAULT_REVIEW_MODE, signoff_fields
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import ROOT, SCHEMA_VERSION, AuditError, digest, read_json, write_json
from vehicle.pipeline.evidence_manifest import artifact_ref


def _artifact(ref, root):
    relative = Path(ref['path'])
    path = (root / relative).resolve()
    if (relative.is_absolute() or not path.is_relative_to(root) or not path.is_file()
            or digest(path) != ref.get('sha256')):
        raise AuditError('suite_artifact_mismatch', '基准输入缺失或摘要不匹配。', '恢复清单指定的原始证据。',
                         artifact=ref['path'])
    return path


def _playback(case, files, business, row):
    identity = business['sample_identity']
    requests = read_json(files['syncs'])
    session = business['server_session']['id']
    total = sum(request['body']['timeListened'] for request in requests)
    checks = business.get('checks', {})
    verified = (identity['installed_apk_sha256'] == case['apk']['sha256']
                and identity['package'] == case['package'] and identity['device_sdk'] == 35
                and identity['application_class'] == 'ordinary_third_party'
                and business.get('verification_status') == 'playback_progress_aligned' and checks
                and all(v is True for v in checks.values()) and requests
                and len(requests) == business['sync_request_count']
                and {r['session_id'] for r in requests} == {session}
                and math.isclose(total, business['request_timeListened_total'])
                and total > 0 and abs(total - business['server_timeListening_delta']) <= 2
                and abs(business['server_progress_after']['currentTime'] - requests[-1]['body']['currentTime']) <= 2
                and abs(business['server_progress_at_pause'] - business['server_progress_paused_6s_later']) < .5)
    if not verified:
        raise ValueError('playback evidence does not agree with sealed requests and service results')
    row.update(replay='artifacts_cross_checked', business='completed',
               capture_health='bounded_loopback_capture_completed',
               identity_attribution='apk_and_server_session', body_match='session_payload_aligned',
               scope='isolated_loopback_no_per_flow_uid', capture_session_id=None,
               request_count=len(requests))
    row.update(schema_version=SCHEMA_VERSION, generated_at=datetime.now(timezone.utc).isoformat(),
               rules_sha=None, coverage_sha=None, fingerprint_gap='isolated_receipts_without_rule_replay',
               input_completeness={'complete': False, 'inputs': {key: artifact_ref(files[key])
                   for key in ('business', 'syncs')}, 'missing': [
                   {'input': 'manifest', 'reason': '回环实验独立回执，没有常规采集会话清单'}]})


def _replay(case, files, business, output, row, rules_path):
    manifest = read_json(files['capture_manifest'])
    capture = files['capture_manifest'].parent
    if manifest['session'] != case.get('capture_session_id'):
        raise ValueError('capture manifest belongs to another session')
    result = run_audit(capture, output / 'audit', case['package'],
                       version=str(manifest['android_version']), apk=files['apk'], pdf=False, rules_path=rules_path)
    findings = load_jsonl(output / 'audit/findings.jsonl')
    reads = load_jsonl(capture / 'reads.jsonl')
    flows = load_jsonl(capture / 'flows.jsonl')
    row.update(replay='audit_replayed', capture_session_id=manifest['session'],
               capture_health='passed', rule_db_sha256=manifest['rules_sha256'],
               hook_bundles=manifest['hook_bundles'],
               observations=observation_stats(reads, flows, findings))
    row.update({key: result[key] for key in ('schema_version', 'generated_at', 'rules_sha',
        'coverage_sha', 'input_completeness', 'evidence_artifacts')})
    kind = case['kind']
    if kind == 'ha_battery' and business.get('passed') is True and len(business['steps']) == 2:
        body = result['ha_webhook']
        levels = {int(s['server']['state']) for s in business['steps']
                  if str(s['emulator_level']) == s['server']['state']}
        seen = {p['battery_percent'] for f in findings if f.get('rule_id') == 'VSC-LAB-HA-BATTERY-HTTP-001'
                for p in f['pairs']}
        if len(levels) != 2 or seen != levels or body['matched_requests'] != 2:
            raise ValueError('battery audit does not reproduce both confirmed requests')
        row.update(business='completed', identity_attribution='app_process_uid',
                   body_match='value_correlated', scope='sample_specific_okhttp')
    elif kind == 'ha_control' and business.get('passed') is True:
        ws = result['ha_websocket']
        if (business['session'] != manifest['session'] or len(ws['controls']) != 2
                or not ws['pairs'] or not business['states_linked_to_subscription']):
            raise ValueError('HA control and subscription audit evidence incomplete')
        snapshot = business.get('reconnect_snapshot') or {}
        connection = business.get('new_connection_id')
        if (business.get('reconnect_verified') is not True
                or not business.get('reconnected_app_sockets')
                or type(connection) is not int or connection in set(snapshot.get('connections', []))
                or type(business.get('new_subscription_host_received_ts')) is not int
                or type(business.get('kill_ts')) is not int
                or business['new_subscription_host_received_ts'] <= business['kill_ts']
                or business.get('old_sockets_closed') is not True
                or not any(p['command'] == 'subscribe_entities' and p['connection_id'] == connection
                           for p in ws['pairs'])):
            raise ValueError('HA reconnect was not proven on a brand-new connection')
        row.update(business='completed', identity_attribution='app_process_uid',
                   body_match='control_and_subscription_observed', scope='sample_specific_okhttp')
    elif kind == 'ha_control_failure' and business.get('passed') is True:
        ws = result['ha_websocket']
        if ws['controls'] or not any(g.get('http_status') == 503 for g in ws['control_gaps']):
            raise ValueError('HA negative control did not reproduce the captured HTTP 503')
        row.update(business='expected_rejection', identity_attribution='app_process_uid',
                   body_match='failed_request_observed', scope='sample_specific_okhttp')
    elif (kind == 'mg4_post' and business.get('status') == 'post_body_attribution_gap'
          and business.get('capture_healthy') is True and business.get('post_marker_matched') is True
          and business.get('post_flow_attributed') == 0):
        row.update(business='completed', identity_attribution='unresolved', body_match='gap',
                   scope='server_receipt_only')
    elif kind == 'mg4_webview_post' and business.get('status') == 'webview_receipt_linked':
        from vehicle.lab.browser_run import matching_webview_request
        marker = business['marker']
        receipts = [r for r in business['server_receipts'] if r.get('method') == 'POST'
                    and r.get('path') == f'/submit?vscan_id={marker}']
        uid = business['webview_package_uid']
        linked = [r for r in reads if matching_webview_request(r, business['server_host'], marker,
                  receipts[0], manifest['session'], business['submitted_ms'], uid)] if len(receipts) == 1 else []
        if (len(linked) != 1 or not business['proxy_observed_post'] or uid is None
                or result['mg4_webview']['request_refs'] != business['webview_request_refs']):
            raise ValueError('WebView evidence does not reproduce the same owned fixture POST')
        row.update(business='completed', identity_attribution='app_request_and_fixture_marker',
                   body_match='server_receipt_body_aligned', scope='owned_webview_form_not_proxy_flow_uid')
    elif kind == 'yaabsa_send' and business.get('passed') is True:
        native = result['abs_native_send']
        if (native['status'] != 'uid_verified' or not native['verified_requests']
                or not native['unresolved_requests_discarded']):
            raise ValueError('YAABSA audit did not reproduce both verified writes and the discarded control')
        row.update(business='sample_http_requests_observed', identity_attribution='app_process_uid',
                   body_match='native_write_and_wire_body_aligned', scope=native['scope'],
                   native_requests=native['verified_requests'],
                   unresolved_requests_discarded=native['unresolved_requests_discarded'])
    else:
        raise ValueError('case outcome does not meet its recorded evidence contract')
    return findings


def replay_suite(suite_path, output, labels_path=None, root=ROOT, *, fixture=None, rules_path=None):
    root, output = Path(root).resolve(), Path(output)
    suite = read_json(suite_path)
    if suite.get('schema') != 1:
        raise AuditError('suite_schema_unknown', '不支持此基准清单版本。', '使用本仓库的 schema=1 清单。')
    cases = suite['cases']
    ids = [case['id'] for case in cases]
    if not ids or len(set(ids)) != len(ids) or not all(re.fullmatch('[a-z0-9-]+', key) for key in ids):
        raise ValueError('suite requires unique safe case IDs')
    labels = read_json(labels_path)['samples'] if labels_path else []
    signed = {label['id']: label for label in labels}
    allowed_labels = set(ids) | ({FIXTURE_ID} if fixture else set())
    if len(signed) != len(labels) or set(signed) - allowed_labels or (fixture and FIXTURE_ID in ids):
        raise ValueError('labels must reference unique suite cases')
    output.mkdir(parents=True, exist_ok=False)
    results, review = [], []
    for case in cases:
        key = case['id']
        mode = signed.get(key, {}).get('review_mode',
            'human' if key in signed and signed[key].get('origin') == 'independent_review' else DEFAULT_REVIEW_MODE)
        row = {'id': key, 'family': case['family'], 'package': case['package'],
               'kind': case['kind'], 'status': 'failed', **signoff_fields(mode, 'pending'),
               'metrics': stratified_metrics([], None, None, None, 'independent', gap='case_replay_failed')}
        results.append(row)
        try:
            if not case.get('authorization') or case['apk'].get('signature_verified') is not True:
                raise ValueError('authorized scope and verified APK signature are required')
            files = {name: _artifact(ref, root) for name, ref in case['artifacts'].items()}
            files['apk'] = _artifact(case['apk'], root)
            row['apk'] = case['apk']
            row['authorization'] = case['authorization']
            row['artifacts'] = case['artifacts']
            business = read_json(files['business'])
            if case['kind'] == 'yaabsa_playback':
                _playback(case, files, business, row)
                findings = []
            else:
                findings = _replay(case, files, business, output / key, row, rules_path)
            eligible = case['kind'] == PAIR_CASE
            if key in signed and not eligible:
                raise ValueError('workflow review is separate from rule/read/flow pair scoring')
            row['metrics'] = stratified_metrics(findings, signed.get(key), case['apk']['sha256'],
                row['capture_session_id'], 'independent', refs=[case['artifacts']['business']], root=root,
                capture=files['capture_manifest'].parent if eligible else None,
                gap='independent_review_pending' if eligible else 'workflow_evidence_without_pair_ground_truth',
                paths=(('lab_power', 'ha_transport'),) if eligible else ())
            if key in signed:
                row.update(signoff_fields(mode, 'signed'))
            entry = review_entry(case, row)
            if eligible:
                entry['controls'] = business['negative_controls']
            review.append(entry)
            row['status'] = 'evaluated'
        except (KeyError, TypeError, ValueError, OSError, SystemExit) as error:
            row['error'] = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        write_json(output / (key + '.json'), row)
        sample_folder = output / key
        sample_folder.mkdir(exist_ok=True)
        write_json(sample_folder / 'metrics.json', row['metrics'])
    result = {'generated_at': datetime.now(timezone.utc).isoformat(), 'suite_sha256': digest(suite_path),
              'families': len({case['family'] for case in cases}),
              'evaluated_cases': sum(r['status'] == 'evaluated' for r in results),
              'independently_signed_cases': sum(r['human_signoff'] == 'signed' for r in results),
              'subagent_signed_cases': sum(r['subagent_signoff'] == 'signed' for r in results),
              'signed_cases': sum(r['signoff_status'] == 'signed' for r in results),
              'completion': 'complete' if all(r['status'] == 'evaluated' for r in results) else 'partial',
              'cases': results}
    write_json(output / 'evaluation.json', result)
    metric_rows = list(results)
    if fixture:
        entry, row = fixture_entry(*fixture, output, signed=signed.get(FIXTURE_ID), root=root)
        review.append(entry)
        metric_rows.append(row)
        folder = output / FIXTURE_ID
        folder.mkdir()
        write_json(folder / 'metrics.json', row['metrics'])
    write_json(output / 'review-packet.json', {'samples': review, 'schema_version': 1,
        'independent_labels_required': True, 'status': 'review_material_ready'})
    write_benchmark(output, metric_rows)
    return result
