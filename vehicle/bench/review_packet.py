"""Build review templates and publish human/subagent strata separately."""
from datetime import datetime, timezone

from vehicle.bench.labels import LABEL_SCHEMA
from vehicle.bench.metrics import aggregate_strata, stratified_metrics
from vehicle.bench.review_policy import DEFAULT_REVIEW_MODE, SUBAGENT_LIMITS, signoff_fields
from vehicle.pipeline.contracts import ROOT, SCHEMA_VERSION, digest, read_json, write_json

PAIR_CASE = 'ha_battery'
FIXTURE_ID = 'o2-owned-vhal-fixture'


def review_entry(case, row):
    """Leave independent decisions empty. Use reference evidence, not detector output."""
    artifacts = case['artifacts']
    refs = [artifacts[key] for key in ('business', 'syncs') if key in artifacts]
    entry = {
        'id': case['id'], 'schema_version': LABEL_SCHEMA, 'pair_schema': 2,
        'apk_sha256': case['apk']['sha256'], 'package': case['package'],
        'session_id': row.get('capture_session_id'), 'sample_origin': 'independent',
        'origin': 'subagent_review' if row['review_mode'] == 'subagent' else 'independent_review',
        **signoff_fields(row['review_mode'], row['signoff_status']),
        'reference_evidence': refs, 'capture_manifest': artifacts.get('capture_manifest'),
        'metrics_eligible': case['kind'] == PAIR_CASE,
        'identity_attribution': row['identity_attribution'], 'body_match': row['body_match'],
        'scope': row['scope'], 'observed_outcome': row['business'],
        'not_measured_reasons': row['metrics'].get('not_measured_reasons', []),
        'reviewer': None, 'reviewed_at': None, 'universe': [], 'reviews': [],
        'adjudication': None,
    }
    return entry


def fixture_entry(capture, labels, output, *, signed=None, root=ROOT):
    from vehicle.bench.window_calibration import calibrate

    replay = calibrate(capture, labels, pairing='token')
    replay_path = output / 'owned-fixture-replay.json'
    write_json(replay_path, replay)
    label_ref = {'path': str(labels.resolve()), 'sha256': digest(labels)}
    initial = read_json(labels)
    refs = [{'path': ref['file'], 'sha256': ref['sha256']} for ref in initial['reference_evidence']
            if not ref['file'].replace('\\', '/').endswith(('/primary-reference-review.json', '/labels.json'))]
    row = next(row for row in replay['windows'] if row['window_ms'] == 30000)
    findings = [{'rule_id': pair['rule_id'], 'evidence_kind': 'read_then_egress', 'pairs': [pair]}
                for pair in row['corroborated_refs']]
    metrics = stratified_metrics(findings, signed, initial['apk_sha256'], replay['session_id'], 'owned_fixture',
        refs=refs, root=root, capture=capture, gap='agent_reference_pending_independent_review',
        paths=(('vhal', 'proxy'),))
    mode = signed.get('review_mode', 'human') if signed else DEFAULT_REVIEW_MODE
    return {'id': FIXTURE_ID, 'sample_origin': 'owned_fixture', 'schema_version': LABEL_SCHEMA,
            'pair_schema': 2, 'origin': 'subagent_review' if mode == 'subagent' else 'independent_review',
            'apk_sha256': initial['apk_sha256'], 'session_id': replay['session_id'],
            **signoff_fields(mode, 'signed' if signed else 'pending'),
            'metric_unit': 'rule_read_flow_pair', 'metrics_eligible': True,
            'reference_evidence': refs,
            'initial_reference': label_ref,
            'initial_replay': {'path': str(replay_path), 'sha256': digest(replay_path)},
            'universe': [], 'reviews': [], 'adjudication': None,
            'not_measured_reasons': metrics['not_measured_reasons']}, {
                'id': FIXTURE_ID, 'metrics': metrics, 'rules_sha': replay['rules_sha'],
                'coverage_sha': replay['coverage_sha']}


def write_benchmark(output, rows):
    bindings = {row['id']: {key: row.get(key) for key in ('rules_sha', 'coverage_sha')} for row in rows}
    strata = aggregate_strata(rows)
    measured = [row for row in strata if row['status'] == 'measured'
                and row['sample_origin'] == 'independent']
    measured_ids = {key for row in measured for key in row['measured_samples']}
    apps = len({row['package'] for row in rows if row['id'] in measured_ids})
    reference_pairs = sum(row['tp'] + row['fn'] for row in measured)
    human = [row for row in measured if row['label_origin'] == 'independent_review']
    agents = [row for row in measured if row['label_origin'] == 'subagent_review']
    def app_count(strata):
        ids = {key for row in strata for key in row['measured_samples']}
        return len({row['package'] for row in rows if row['id'] in ids})
    def acceptance(strata):
        gaps = []
        if app_count(strata) < 10:
            gaps.append('fewer_than_10_independently_reviewed_apps')
        if sum(row['tp'] + row['fn'] for row in strata) < 100:
            gaps.append('fewer_than_100_independent_reference_pairs')
        if strata and any(row['cohens_kappa'] is None or row['cohens_kappa'] < .80 for row in strata):
            gaps.append('inter_reviewer_kappa_below_gate_or_undefined')
        if strata and any(row['negative_control_fp_rate'] is None
                          or row['negative_control_fp_rate'] > .10 for row in strata):
            gaps.append('negative_control_rate_above_gate_or_undefined')
        return {'status': 'pending' if gaps else 'passed', 'gaps': gaps}
    gates = {'human': acceptance(human), 'subagent': acceptance(agents)}
    gate_mode = 'subagent' if agents or not human else 'human'
    document = {'schema_version': SCHEMA_VERSION, 'generated_at': datetime.now(timezone.utc).isoformat(),
        'bindings_by_sample': bindings, 'strata': strata,
        'samples': {row['id']: row['metrics'] for row in rows},
        'independent_apps_measured': apps, 'independent_reference_pairs_measured': reference_pairs,
        'human_reviewed_apps_measured': app_count(human),
        'subagent_reviewed_apps_measured': app_count(agents),
        'human_reference_pairs_measured': sum(row['tp'] + row['fn'] for row in human),
        'subagent_reference_pairs_measured': sum(row['tp'] + row['fn'] for row in agents),
        'human_reference_metrics': 'measured_by_stratum' if human else 'not_measured',
        'subagent_reference_metrics': 'measured_by_stratum' if agents else 'not_measured',
        'review_sources': sorted({row['label_origin'] for row in measured}),
        'review_limits': SUBAGENT_LIMITS if agents else [],
        'accuracy': 'measured_by_stratum' if measured else 'not_measured',
        'benchmark_acceptance': gates[gate_mode]['status'],
        'benchmark_acceptance_review_mode': gate_mode,
        'benchmark_acceptance_by_review_mode': gates,
        'benchmark_acceptance_gaps': gates[gate_mode]['gaps'],
        'caveat': 'Wilson intervals describe reviewed pairs. Subagent agreement does not establish human ground truth.'}
    for key in ('rules_sha', 'coverage_sha'):
        available = {ref[key] for ref in bindings.values() if ref[key]}
        document[key] = next(iter(available)) if len(available) == 1 else None
    write_json(output / 'benchmark-metrics.json', document)
