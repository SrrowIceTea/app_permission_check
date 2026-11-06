"""Allowlisted evidence projections for the two sealed AAOS 35 workflows."""
import json
from urllib.parse import urlsplit

from core.evidence.codeloc import frames_of
from core.io_utils import load_jsonl
from vehicle.bench.blind_evidence import Sources, pick
from vehicle.lab import owntracks_run as ot_run
from vehicle.pipeline.contracts import digest, read_json
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy import ha_contract as ha, ha_evaluation, owntracks_contract as ot

HA_FIELDS = ('src', 'ev', 'evt_id', 'pkg', 'session_id', 'uid', 'user_id', 'pid', 'tid', 'ts',
             'field', 'value', 'fallback', 'method', 'endpoint', 'payload_type', 'sensor_id',
             'request_started_ts', 'request_bytes', 'status', 'state', 'body_complete')
OT_READ_FIELDS = ('src', 'ev', 'evt_id', 'pkg', 'session_id', 'uid', 'user_id', 'pid',
                  'host_received_ts', 'location_time_ms', 'coordinate_sha256_16')
OT_FLOW_FIELDS = ('src', 'evt_id', 'package', 'session_id', 'uid', 'user_id', 'ts', 'method',
                  'attribution', 'attribution_delta_ms', 'attribution_ambiguous', 'status_code')
TEST_ENDPOINT = urlsplit('http://198.18.0.1:18145/owntracks/redacted')


def artifact(path, root):
    return {'path': path.resolve().relative_to(root.resolve()).as_posix(), 'sha256': digest(path)}


def capture_metadata(capture, manifest, rules, catalog, root):
    result = pick(manifest, 'session', 'device_sdk', 'device_fingerprint', 'application_class',
                  'user_id', 'data_scope', 'capture_mode', 'installed_apk_sha256', 'hook_bundles')
    result.update(health='passed', manifest=artifact(capture / 'session-manifest.json', root),
                  verification=artifact(capture / 'verification.json', root), rules=artifact(rules, root),
                  privacy_catalog=artifact(catalog, root), privacy_catalog_sha256=manifest['privacy_catalog_sha256'])
    return result


def ha_material(case, rules, root):
    source = Sources(case, root)
    catalog = source.capture.parent / 'audit/privacy-catalog.json'
    validate_capture(source.capture, case['package'], '15', rules, root / case['apk']['path'],
                     catalog_snapshot=catalog)
    receipts = [{'level': step['emulator_level'], 'state': step['server']['state'],
                 'observed_at': step['server']['last_changed']} for step in source.business['steps']]
    if source.business.get('passed') is not True:
        raise ValueError('sealed HA battery workflow did not pass')
    events = []
    for row in source.events('reads.jsonl'):
        if (row.get('src'), row.get('ev')) not in (('lab_power', 'ANDROID_POWER_EXTRA'),
                                                  ('ha_transport', 'HA_SENSOR_HTTP')):
            continue
        projected = dict(pick(row, *HA_FIELDS), device_serial='lab-device')
        if row['src'] == 'lab_power':
            projected['app_frames'] = [frame for frame in frames_of(row)
                                       if frame.startswith(ha_evaluation.BATTERY_METHOD)]
        events.append(projected)
    entry = {'id': case['id'], 'family': case['family'], 'package': case['package'],
             'classification': 'native_aaos', 'apk': case['apk'], 'source_artifacts': source.refs,
             'capture': capture_metadata(source.capture, source.manifest, rules, catalog, root),
             'labels': {'human_signoff': 'pending', 'metrics': 'not_measured', 'eligibility': 'ha_battery_pair_pilot'},
             'gaps': ['sample_specific_battery_http_path', 'independent_reviews_pending']}
    return entry, {'events': events, 'receipts': receipts}


def project_flow(flow, endpoint, test_keys):
    payload = flow.get('request_payload') or {}
    if (flow.get('path') != endpoint.path or flow.get('host') != endpoint.hostname
            or flow.get('target_port') != endpoint.port):
        return None
    raw = payload.get('text')
    summary = ot_run.summarize_body(raw)
    if summary.get('coordinate_sha256_16') not in test_keys:
        return None
    parsed = json.loads(raw)
    fields = pick(parsed, '_type', 'lat', 'lon', 'tst')
    body = dict(pick(payload, 'raw_sha256', 'raw_truncated', 'text_truncated', 'decode_error'),
                text=json.dumps(fields, separators=(',', ':')))
    return dict(pick(flow, *OT_FLOW_FIELDS), path=TEST_ENDPOINT.path, host=TEST_ENDPOINT.hostname,
                target_port=TEST_ENDPOINT.port, request_payload=body)


def owntracks_material(run, config, acquisition, rules, root):
    catalog = read_json(acquisition)
    sample, = [row for row in catalog['samples'] if row['package'] == ot.PACKAGE]
    apk = acquisition.parent / ot.PACKAGE / 'sample.apk'
    if sample['apk_sha256'] != ot.APK_SHA256 or sample['signature']['verified'] is not True:
        raise ValueError('OwnTracks acquisition identity mismatch')
    capture = run / 'capture'
    catalog_path = root / 'output/o6-device-acceptance-20261104/aaid-audit/privacy-catalog.json'
    checked = validate_capture(capture, ot.PACKAGE, '15', rules, apk, catalog_snapshot=catalog_path)
    session = checked['session_id']
    endpoint = urlsplit(read_json(config)['url'])
    summary = read_json(run / 'verification.json')
    if (summary.get('passed') is not True or summary.get('session') != session
            or summary.get('capture_manifest_sha256') != digest(capture / 'session-manifest.json')):
        raise ValueError('OwnTracks workflow identity mismatch')
    reads, flows = (load_jsonl(capture / (name + '.jsonl')) for name in ('reads', 'flows'))
    receipts = read_json(run / 'receiver-receipts.json')
    test_keys = {ot_run.coordinate_digest(point) for point in ot_run.TEST_POINTS}
    if {s['coordinate_sha256_16'] for s in summary['steps']} != test_keys:
        raise ValueError('OwnTracks evidence must bind the known synthetic test points')
    for step in summary['steps']:
        verified = ot_run.pairs(reads, flows, receipts, session, endpoint, step)
        if len(verified) != 1 or verified != step['verified_pairs']:
            raise ValueError('OwnTracks sealed workflow does not reproduce')
    projected = {'reads': [pick(r, *OT_READ_FIELDS) for r in reads if r.get('src') == 'owntracks_location'
                           and r.get('ev') == 'OWNTRACKS_LOCATION' and r.get('coordinate_sha256_16') in test_keys],
                 'flows': [filtered for f in flows if (filtered := project_flow(f, endpoint, test_keys))],
                 'receipts': [dict(pick(r, 'ts', 'body_sha256', 'coordinate_sha256_16', 'location_timestamp_seconds'),
                                   path=TEST_ENDPOINT.path) for r in receipts if r['path'] == endpoint.path
                              and r.get('coordinate_sha256_16') in test_keys],
                 'steps': [pick(s, 'index', 'ts', 'coordinate_sha256_16') for s in summary['steps']]}
    entry = {'id': 'owntracks-location-http', 'family': 'owntracks', 'package': ot.PACKAGE,
             'classification': 'aaos_sideload_comparison',
             'apk': artifact(apk, root) | pick(sample, 'version_name', 'version_code', 'download_url',
                                               'license', 'signature'),
             'capture': capture_metadata(capture, checked['manifest'], rules, catalog_path, root),
             'source_artifacts': {path.name: artifact(path, root) for path in (acquisition,
                 run / 'verification.json', run / 'receiver-receipts.json', capture / 'reads.jsonl', capture / 'flows.jsonl')}
                 | {'earlier_failed_rounds': [artifact(run.parent / name / 'verification.json', root)
                                             for name in ('run-001', 'run-002')]},
             'labels': {'human_signoff': 'pending', 'metrics': 'not_measured', 'eligibility': 'workflow_only',
                        'reason': 'location_callback_and_numeric_http_pair_outside_enabled_rule_evaluator'},
             'gaps': ['fixed_apk_isolated_http', 'tls_and_other_versions_unverified']}
    return entry, projected


def replay_case(entry, evidence):
    session, user = entry['capture']['session'], entry['capture']['user_id']
    if entry['id'] == 'ha-battery':
        findings, stats = ha_evaluation.evaluate(evidence['events'], session, user)
        pairs = [pair for finding in findings if finding['rule_id'] == ha.BODY_RULE for pair in finding['pairs']]
        levels = {receipt['level'] for receipt in evidence['receipts']
                  if str(receipt['level']) == str(receipt['state']) and receipt.get('observed_at')}
        if len(levels) != 2 or stats['matched_requests'] != 2 or {p['battery_percent'] for p in pairs} != levels:
            raise ValueError('HA paired battery levels and independent receipts disagree')
        return {'status': 'aligned', 'observations': stats['matched_requests'], 'rule_id': ha.BODY_RULE}
    if entry['id'] == 'owntracks-location-http':
        steps = evidence['steps']
        result = [ot_run.pairs(evidence['reads'], evidence['flows'], evidence['receipts'], session, TEST_ENDPOINT, step)
                  for step in steps]
        if (user != 10 or len(steps) != 2 or len({s['coordinate_sha256_16'] for s in steps}) != 2
                or any(len(matches) != 1 for matches in result)
                or len({matches[0]['flow_ref']['evt_id'] for matches in result}) != 2):
            raise ValueError('OwnTracks same-session read, flow and receipt do not agree')
        return {'status': 'aligned', 'observations': len(result), 'rule_id': None}
    raise ValueError('unknown handoff case')
