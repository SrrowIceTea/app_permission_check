"""Controlled ablation for observation-condition-gated, ambiguity-aware association.

仅用于授权测试（自有设备与自有夹具）。 All experiments are OFFLINE replays of a
sealed capture; no device, no rule DB mutation, no modification of the frozen
evidence. Fault injection lives in ``ablation_faults.py``, input/rule binding in
``ablation_integrity.py``.

Four arms, in the order an ablation should be read:
  fixed_window_property_name -- 30s window + property-name hit only (weak baseline)
  fixed_window_value_match   -- 30s window + property-bound value match
  long_window_value_match    -- 120s window + value match (delay/ambiguity tradeoff)
  candidate_set_method       -- 30s + value match + source candidate sets +
                                per-question observation-condition gating

Pair-level precision/recall use ``vehicle.bench.metrics.pair_metrics`` with the
same frozen reference labels for every arm. The new method is NOT expected to
win on raw precision. Its contribution is refusing to state a single source
when several reads are plausible, and refusing to answer a question whose
observation conditions failed -- reported separately, always together with
decidable/abstain ratios so abstention cannot masquerade as accuracy.

LABEL LIMIT: the frozen labels are an agent initial review with
human_signoff=pending, NOT independent expert ground truth. Fixture replay and
passive third-party observation must be reported separately; these numbers
must never be merged into one accuracy figure.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.analyze import batch_alignment
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.method_evidence import attach
from vehicle.bench.ablation_faults import (
    COLLECTION_CONDITIONS, DESIGN_GAPS, EXPECTED_GAPS, FAULTS,
    METHOD_SCOPE_CONDITIONS, NEGATIVE_CONTROLS, inject_fault, run_faults)
from vehicle.bench import label_gate, strata_report
from vehicle.bench.ablation_baselines import (property_marker_hit, unique_source_sets,
                                             weak_findings)
from vehicle.bench.ablation_integrity import resolve_rules, verify_replay
from vehicle.bench.metrics import pair_metrics
from vehicle.pipeline.contracts import digest, read_json, write_json

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CAPTURE = ROOT / 'output/vehicle-offline-window-20261103-002/capture'
DEFAULT_LABELS = ROOT / 'output/o2-batch-pairing-20261103/primary-labels.json'

ARMS = (
    ('fixed_window_property_name', 30000, False),
    ('fixed_window_value_match', 30000, True),
    ('long_window_value_match', 120000, True),
    ('candidate_set_method', 30000, True),
)


def run_arm(name, window_ms, value_match, reads, flows, rules, label, sha, session,
            *, collector_health=None, enable_batch=False):
    findings = (evaluate_data_egress(rules, reads, flows, window_override_ms=window_ms,
                                     pairing='window') if value_match else
                weak_findings(reads, flows, rules, window_ms))
    metrics = pair_metrics(findings, label, sha, session)
    # Arms must differ in ONE thing (window / value match). Batch evidence is a
    # separate section, otherwise every arm inherits the same extra signal and
    # the comparison stops being an ablation.
    document = attach({'status': 'ablation'}, reads=reads, flows=flows,
                      findings=findings, collector_health=collector_health,
                      enable_batch=enable_batch)
    cand = document['source_candidates']
    conditions = document['observation_conditions']
    pairs = sum(len(f.get('pairs') or []) for f in findings)
    ambiguous_pairs = sum(len(s['candidate_ids']) for s in cand['sets']
                          if s['state'] == 'multiple_candidates')
    # Review P1-3: measure the baseline's ACTUAL uniqueness claims, in the same
    # flow+rule unit as the candidate sets. The old "pairs - unique_candidate"
    # assumed every pair claimed a unique source; a later version mixed pair and
    # set units. Both are wrong. This compares like with like.
    baseline_claims = unique_source_sets(findings)
    method_claims = cand['unique_candidate']
    return {
        'arm': name, 'window_ms': window_ms, 'value_match': value_match,
        'pair_metrics': metrics, 'findings': len(findings), 'pairs': pairs,
        'source_candidate_sets': cand['candidate_sets'],
        'unique_source_candidates': method_claims,
        'marker_only_candidates': cand['marker_only_candidate'],
        'ambiguous_source_sets': cand['multiple_candidates'],
        'ambiguity_rate': cand['ambiguity_rate'],
        'ambiguous_source_pairs': ambiguous_pairs,
        'baseline_unique_source_claims': baseline_claims,
        'method_unique_source_claims': method_claims,
        'unique_source_claim_delta': baseline_claims - method_claims,
        'pairs_without_unique_source_claim': pairs - baseline_claims,
        'claim_unit': 'flow_rule_set',
        'claim_metric_basis': 'flow+rule groups where the baseline claims one source',
        'candidate_coverage': conditions['candidate_coverage'],
        'decidability': conditions['rates'],
        'fault_as_clean_signals': conditions['fault_as_clean_signals'],
        'method_arm': name == 'candidate_set_method',
    }


def run(capture=DEFAULT_CAPTURE, labels=DEFAULT_LABELS, rules_db=None):
    capture, labels = Path(capture), Path(labels)
    manifest = read_json(capture / 'session-manifest.json')
    label = read_json(labels)
    tier = label_gate.classify_label(label)
    sha, session = manifest['installed_apk_sha256'], manifest['session']
    version = str(manifest.get('android_version', '15'))
    database = resolve_rules(ROOT, manifest, rules_db)
    integrity = verify_replay(ROOT, capture, labels, database)
    rules = load_rules(database, version)
    reads = load_jsonl(capture / 'reads.jsonl')
    flows = load_jsonl(capture / 'flows.jsonl')
    health = read_json(capture / 'collector-health.json')
    arms = [run_arm(name, window, match, reads, flows, rules, label, sha, session,
                    collector_health=health) for name, window, match in ARMS]
    faults = run_faults(reads, flows, rules, health)
    batch = batch_alignment.report(reads, flows)
    method = arms[-1]
    # What batch evidence does when it IS enabled (reported separately, never
    # folded into the arm comparison).
    method_findings = evaluate_data_egress(rules, reads, flows,
                                           window_override_ms=30000, pairing='window')
    with_batch = attach({'status': 'batch'}, reads=reads, flows=flows,
                        findings=method_findings, collector_health=health,
                        enable_batch=True)
    conflicting = sum(1 for row in with_batch['source_candidates']['sets']
                      if (row.get('batch_alignment') or {}).get('status') == 'conflicting')
    return {
        'generated_by': 'vehicle/bench/ablation.py::run',
        'schema_version': 2, 'status': 'offline_replay_only',
        'scope': 'owned_fixture_sealed_replay_only',
        'capture': str(capture.resolve()), 'label_sha256': digest(labels),
        'label_origin': label.get('origin'), 'human_signoff': label.get('human_signoff'),
        'independent_human_review': False,
        'label_tier': tier,
        'replay_integrity': integrity,
        'strata': strata_report.report([strata_report.row_from_metrics(
            method['pair_metrics'], sample_class_name=strata_report.OWNED_FIXTURE,
            label_tier=tier, source=str(capture))]),
        'negative_controls': [*NEGATIVE_CONTROLS, *sorted(DESIGN_GAPS)],
        'pair_metric_unit': 'rule_read_flow_pair',
        'arms': arms, 'fault_experiments': faults,
        'batch_alignment': {**{key: batch[key] for key in (
            'aligned_flows', 'unaligned_flows', 'by_basis',
            'aligned_outside_window', 'aligned_outside_window_flows', 'caveats')},
            'effect_on_source_location': {
                'unique_candidates_without_batch': method['method_unique_source_claims'],
                'unique_candidates_with_batch':
                    with_batch['source_candidates']['unique_candidate'],
                'conflicting_sets': conflicting,
                'note': '批次证据只用于暴露冲突；conflicting 时降级为多来源，不制造唯一性。'}},
        'comparison': {
            'method_arm': method['arm'],
            'method_precision': method['pair_metrics']['precision'],
            'method_recall': method['pair_metrics']['recall'],
            'baseline_precision': arms[1]['pair_metrics']['precision'],
            'baseline_recall': arms[1]['pair_metrics']['recall'],
            'answerable_ratio': method['decidability']['answerable_ratio'],
            'abstain_ratio': method['decidability']['abstain_ratio'],
            'ambiguity_rate': method['ambiguity_rate'],
            'baseline_unique_source_claims': method['baseline_unique_source_claims'],
            'method_unique_source_claims': method['method_unique_source_claims'],
            'unique_source_claim_delta': method['unique_source_claim_delta'],
            'condition_gate_faults': sum(r['experiment_kind'] == 'condition_gate'
                                         for r in faults),
            'faults_with_identified_gap': sum(bool(r['gap_identified']) for r in faults),
            'faults_with_silent_absence_risk': sum(bool(r['silent_absence_risk'])
                                                   for r in faults),
            'faults_diagnosed_by_method': sum(bool(r['abstention_diagnosed'])
                                              for r in faults),
            'faults_misread_as_clean_by_baseline': sum(bool(r['fault_misread_as_clean'])
                                                       for r in faults),
        },
        'caveats': [
            '离线重放冻结夹具证据，不是真机新实验；已逐文件校验 input_sha256、采集健康、'
            'verification 与采集时绑定的规则库快照（replay_integrity）。',
            '当前工作区 rules.db 与采集时规则摘要不同，重放使用历史绑定快照；'
            '若找不到匹配快照则直接失败，不用当前规则库冒充。',
            f'标签层级={tier["tier"]}，usable_as_gold={tier["usable_as_gold"]}：'
            + '；'.join(tier['reasons']) + '。不是独立专家金标准。',
            '样品类别分层见 strata：夹具与第三方被动观测不得合并成一个准确率；'
            '本轮只有 owned_fixture，passive_third_party 记 not_measured。',
            '夹具实验结果与普通第三方被动观测必须分别报告，不能合并成一个准确率。',
            '配对指标只衡量匹配，不衡量违规成立或因果传播。',
            '此前把全部配对算作「过度声明」并给出 24 的减少量没有依据：基线本来就用 '
            'source_read_unique 标记来源歧义。现改为实测两组各自实际声明的唯一来源数，'
            '差值只是计数差，不宣称方法增益。',
            '新方法不靠删配对提升 precision；其贡献是拒绝指定单一来源与拒绝越界结论，'
            '必须与可判定比例一起解读。',
            '四个 arm 只差窗口长度与是否值匹配，均不含批次证据；批次对齐单独列在 '
            'batch_alignment：它能对齐窗口外批次，但重复同值时两种方法可能指向不同批次，'
            '不能据此声称提高检测率。',
            '窗口内命中不等于完整来源集合：候选完整性按同属性、时序可能的成功读取逐条核对，'
            '缺读取时「来源已定位」必须弃判。',
            '属性名基线在本夹具上区分度有限：夹具把全部 16 个属性 ID/名称都写进了 '
            'request_tokens，因此属性名检查不会减少配对数。该结论不可外推到第三方 App。',
            '低错误率若伴随高弃判率，不构成方法有效性证据。',
            'fault_misread_as_clean 采用严格口径：仅在「采集条件已破坏、基线仍输出肯定结论」时计数；'
            '方法范围限制（候选集合只覆盖窗口内命中）与设计性缺口（无同意通道、待人工政策复核）'
            '都不计入故障，否则健康负控会被误报。',
            '基线在采集故障下多为静默零配对（silent_absence_risk），并非已被证实误判；'
            '方法的可验证增益是显式给出不可判原因与恢复所需条件。',
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, default=DEFAULT_CAPTURE)
    parser.add_argument('--labels', type=Path, default=DEFAULT_LABELS)
    parser.add_argument('--rules', type=Path, default=None,
                        help='采集时绑定的 rules.db；默认按 rules_sha256 自动匹配已知快照')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    result = run(args.capture, args.labels, args.rules)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.out, result)
    print(json.dumps(result['comparison'], ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
