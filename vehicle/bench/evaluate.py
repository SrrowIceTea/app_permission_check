"""Static + optional captured sample evaluation, with explicit coverage gaps.

仅用于授权测试。 Single-device captures must be serial. Never promote static facts
to runtime evidence or score unlabelled independent apps as true negatives.
"""
import argparse
import json
import re
import time
from pathlib import Path
from core.io_utils import load_jsonl
from core.static.analysis import scan_static
from vehicle.bench.metrics import observation_stats, stratified_metrics
from vehicle.bench.review_packet import write_benchmark
from vehicle.coverage.export import build_coverage
from vehicle.pipeline.audit import run_audit
from vehicle.pipeline.contracts import ROOT, AuditError, digest, read_json, write_json
from vehicle.pipeline.prepare import new_output


def evaluate_samples(manifest_path, output, captures=None, labels=None):
    manifest_path, output = Path(manifest_path).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source = read_json(manifest_path)
    bindings = {r['id']: r for r in (read_json(captures)['samples'] if captures else [])}
    labelled = {r['id']: r for r in (read_json(labels)['samples'] if labels else [])}
    results = []
    for sample in source['samples']:
        if not re.fullmatch('[a-z0-9-]+', sample['id']):
            raise AuditError('invalid_sample_id', '样本 ID 不是安全的本地目录名。', '使用下载清单中的样本 ID。')
        row = {'id': sample['id'], 'family': sample['family'], 'status': 'failed',
               'classification': sample['classification'], 'metrics': stratified_metrics(
                   [], None, None, None, 'independent', gap='no_validated_dynamic_capture'), 'gaps': []}
        results.append(row)
        folder = output / sample['id']
        folder.mkdir()
        if sample.get('status') != 'downloaded':
            row.update(status='download_unavailable', gaps=['官方样本未下载成功，未评估。'])
            write_json(folder / 'metrics.json', row['metrics'])
            continue
        start = time.monotonic()
        try:
            apk = manifest_path.parent / sample['id'] / sample['apk_file']
            apk.resolve().relative_to(manifest_path.parent)
            if digest(apk) != sample['apk_sha256']:
                raise AuditError('sample_hash_mismatch', '样本文件与下载清单不一致。', '重新下载并保留原清单。')
            static_dir = folder / 'static'
            static_dir.mkdir()
            static = scan_static(apk, ROOT / 'vehicle/rules/rules_library/rules.db', '15', static_dir)
            row.update(static_findings=len(static['findings']), apk_sha256=sample['apk_sha256'],
                       package=static['apk']['package'], static_scope='candidate_only')
            row['gaps'].extend(static.get('apk_gaps', []) + static.get('dex_gaps', []))
            binding = bindings.get(sample['id'])
            if binding:
                capture = Path(binding['capture']).resolve()
                captured = read_json(capture / 'session-manifest.json')
                if captured.get('application_class') != 'ordinary_third_party':
                    raise AuditError('benchmark_scope_unverified', '样本未核实为普通第三方安装。', '使用新版 capture 入口采集。')
                result = run_audit(capture, folder / 'audit', row['package'], apk=apk,
                    scenarios=binding.get('scenarios'), policy=binding.get('policy'), pdf=False)
                findings = load_jsonl(folder / 'audit/findings.jsonl')
                supplied = labelled.get(sample['id'])
                sample_origin = 'owned_fixture' if sample['classification'] == 'owned_fixture' else 'independent'
                row['metrics'] = stratified_metrics(findings,
                    supplied if supplied and supplied.get('origin') == 'independent_review' else None,
                    sample['apk_sha256'], captured['session'], sample_origin, capture=capture)
                row.update(rules_sha=result['rules_sha'], coverage_sha=result['coverage_sha'],
                           input_completeness=result['input_completeness'])
                row['observations'] = observation_stats(load_jsonl(capture / 'reads.jsonl'),
                    load_jsonl(capture / 'flows.jsonl'), findings)
                row.update(status='runtime_evaluated', policy_status=result['policy_assessment']['status'])
                row['exploration_scope'] = binding.get('exploration_scope', 'not_documented')
                row['gaps'].extend(binding.get('gaps', []))
            else:
                row.update(status='static_only', runtime_status='not_run')
                row['gaps'].append('无 AAOS 35 动态会话；不能报告误报/漏报或真实场景覆盖。')
        except (Exception, SystemExit) as error:
            row['error'] = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        row['analysis_wall_time_s'] = round(time.monotonic() - start, 3)
        write_json(folder / 'evaluation.json', row)
        write_json(folder / 'metrics.json', row['metrics'])
        print(json.dumps({'sample': row['id'], 'status': row['status']}, ensure_ascii=False), flush=True)
    document = {'samples': results, 'coverage': build_coverage(),
        'downloaded_families': len({s['family'] for s in source['samples'] if s.get('status') == 'downloaded'}),
        'runtime_evaluated': sum(r['status'] == 'runtime_evaluated' for r in results),
        'independent_labelled': sum(r['metrics'].get('label_origin') == 'independent_review' for r in results),
        'agent_reviewed': sum(labelled.get(r['id'], {}).get('origin') == 'agent_review' for r in results),
        'completion': 'complete' if results and all(r['status'] == 'runtime_evaluated' for r in results) else 'partial',
        'caveat': '夹具、公开样本静态结果与独立标注动态结果分别计数；不混算准确率。'}
    write_json(output / 'evaluation.json', document)
    write_benchmark(output, results)
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--manifest', type=Path)
    inputs.add_argument('--suite', type=Path, help='重放已有授权样本的封存证据')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--captures', type=Path)
    parser.add_argument('--labels', type=Path)
    parser.add_argument('--rules', type=Path, help='与封存会话摘要匹配的历史规则库，仅供 --suite 重放')
    parser.add_argument('--fixture-capture', type=Path)
    parser.add_argument('--fixture-labels', type=Path)
    args = parser.parse_args(argv)
    if args.rules and not args.suite:
        parser.error('--rules requires --suite')
    if bool(args.fixture_capture) != bool(args.fixture_labels) or (args.fixture_capture and not args.suite):
        parser.error('--fixture-capture and --fixture-labels require --suite and must be supplied together')
    if args.suite:
        if args.captures:
            parser.error('--suite 已绑定采集输入，不接受 --captures')
        from vehicle.bench.suite import replay_suite
        out = args.out or new_output('vehicle-suite')
        fixture = (args.fixture_capture, args.fixture_labels) if args.fixture_capture else None
        result = replay_suite(args.suite, out, args.labels, fixture=fixture, rules_path=args.rules)
        print(json.dumps({k: result[k] for k in ('completion', 'families', 'evaluated_cases')}
                         | {'out': str(out)}, ensure_ascii=False))
        return int(result['completion'] != 'complete')
    out = args.out or new_output('vehicle-benchmark')
    result = evaluate_samples(args.manifest, out, args.captures, args.labels)
    print(json.dumps({'completion': result['completion'], 'out': str(out)}, ensure_ascii=False))
    return int(any(r['status'] == 'failed' for r in result['samples']))


if __name__ == '__main__':
    raise SystemExit(main())
