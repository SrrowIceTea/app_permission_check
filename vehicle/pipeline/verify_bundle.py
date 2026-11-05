"""Verify a relocated audit evidence bundle. 仅用于授权测试（自有设备与自有 APK）。

用法：
  python -m vehicle.pipeline.verify_bundle <证据包目录或 summary.json> [--report]

逐项检查必需文件、文件 SHA-256、rules/coverage/hook bundle 摘要是否与 summary
记录一致。任一不符返回非零退出。``--report`` 在相对路径下重新生成 PDF。
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from vehicle.pipeline.bundle import BUNDLE_VERSION  # noqa: E402
from vehicle.pipeline.contracts import AuditError, digest, read_json  # noqa: E402
from vehicle.pipeline.evidence_manifest import INPUT_NAMES, ref_path  # noqa: E402


def locate(target):
    target = Path(target).resolve()
    if target.is_dir():
        return target, target / 'summary.json'
    return target.parent, target


def _check_refs(root, artifacts, inputs, failures, checked):
    for group, refs in (('evidence_artifacts', artifacts), ('input_completeness.inputs', inputs)):
        for name, ref in refs.items():
            path = ref_path(ref, root)
            record = {'group': group, 'artifact': name, 'path': ref.get('path'),
                      'expected': ref.get('sha256')}
            checked.append(record)
            if ref.get('exists') is False:
                record['status'] = 'declared_missing'
                if path is not None and path.exists():
                    failures.append({'code': 'declared_missing_but_present',
                                     'message': f'摘要声明缺失但文件存在：{name}',
                                     'artifact': name, 'path': str(path)})
                continue
            if path is None or not path.is_file():
                record['status'] = 'missing'
                failures.append({'code': 'missing_file', 'artifact': name,
                                 'message': f'缺少必需文件：{name}',
                                 'path': ref.get('path')})
                continue
            actual = digest(path)
            record['actual'], record['status'] = actual, 'ok'
            if actual != ref.get('sha256'):
                record['status'] = 'digest_mismatch'
                failures.append({'code': 'digest_mismatch', 'artifact': name,
                                 'message': f'SHA-256 不符：{name}', 'path': ref.get('path'),
                                 'expected': ref.get('sha256'), 'actual': actual})


def _summary_checks(root, summary, artifacts, inputs, failures):
    rules, coverage = artifacts.get('rules') or {}, artifacts.get('coverage') or {}
    if rules:
        if summary.get('rules_sha') != rules.get('sha256'):
            failures.append({'code': 'summary_rules_mismatch', 'artifact': 'rules',
                             'message': 'summary.rules_sha 与规则库证据摘要不一致。',
                             'expected': rules.get('sha256'), 'actual': summary.get('rules_sha')})
        if summary.get('rules_sha256') not in (None, summary.get('rules_sha')):
            failures.append({'code': 'rules_sha256_mismatch', 'artifact': 'rules',
                             'message': 'summary.rules_sha256 与 rules_sha 不一致。',
                             'expected': summary.get('rules_sha'),
                             'actual': summary.get('rules_sha256')})
    if coverage:
        if summary.get('coverage_sha') != coverage.get('sha256'):
            failures.append({'code': 'summary_coverage_mismatch', 'artifact': 'coverage',
                             'message': 'summary.coverage_sha 与覆盖矩阵证据摘要不一致。',
                             'expected': coverage.get('sha256'), 'actual': summary.get('coverage_sha')})
        chain = (summary.get('coverage_chain') or {}).get('sha256')
        if chain is not None and chain != coverage.get('sha256'):
            failures.append({'code': 'coverage_chain_mismatch', 'artifact': 'coverage',
                             'message': 'coverage_chain.sha256 与覆盖矩阵证据摘要不一致。',
                             'expected': coverage.get('sha256'), 'actual': chain})
        path = ref_path(coverage, root)
        if path is not None and path.is_file():
            data = read_json(path)
            if data.get('rules_sha256') != rules.get('sha256'):
                failures.append({'code': 'coverage_rules_mismatch', 'artifact': 'coverage',
                                 'message': '覆盖矩阵记录的规则库摘要与证据清单不一致。',
                                 'expected': rules.get('sha256'), 'actual': data.get('rules_sha256')})
    manifest_ref = inputs.get('manifest') or {}
    path = ref_path(manifest_ref, root)
    if path is None or not path.is_file():
        return
    manifest = read_json(path)
    hooks = manifest.get('hook_bundles') or {}
    for name, ref in artifacts.items():
        if not name.startswith('hook/'):
            continue
        bundle_name = name.split('/', 1)[1]
        if hooks.get(bundle_name) != ref.get('sha256'):
            failures.append({'code': 'hook_bundle_mismatch', 'artifact': name,
                             'message': f'会话清单记录的钩子摘要不一致：{bundle_name}',
                             'expected': hooks.get(bundle_name), 'actual': ref.get('sha256')})
    for name, file_name in INPUT_NAMES.items():
        recorded, ref = (manifest.get('input_sha256') or {}).get(file_name), inputs.get(name)
        if ref and recorded is not None and recorded != ref.get('sha256'):
            failures.append({'code': 'manifest_input_mismatch', 'artifact': name,
                             'message': f'会话清单记录的输入摘要不一致：{file_name}',
                             'expected': recorded, 'actual': ref.get('sha256')})


def verify(target):
    root, summary_file = locate(target)
    failures, checked = [], []
    if not summary_file.is_file():
        return {'status': 'failed', 'root': str(root), 'checked': [], 'failures': [
            {'code': 'missing_summary', 'message': f'缺少 summary.json：{summary_file}'}]}
    summary = read_json(summary_file)
    if (summary.get('bundle') or {}).get('format') != BUNDLE_VERSION:
        failures.append({'code': 'legacy_format',
                         'message': '历史格式：summary 未记录相对路径契约，不能跨目录复核。',
                         'bundle': summary.get('bundle')})
    artifacts = summary.get('evidence_artifacts') or {}
    inputs = (summary.get('input_completeness') or {}).get('inputs') or {}
    if not artifacts:
        failures.append({'code': 'missing_manifest', 'message': 'summary 缺少证据清单 evidence_artifacts。'})
    if not inputs:
        failures.append({'code': 'missing_inputs',
                         'message': 'summary 缺少输入清单 input_completeness.inputs。'})
    _check_refs(root, artifacts, inputs, failures, checked)
    _summary_checks(root, summary, artifacts, inputs, failures)
    return {'status': 'failed' if failures else 'passed', 'root': str(root),
            'bundle_format': (summary.get('bundle') or {}).get('format'),
            'checked': len(checked), 'failures': failures, 'entries': checked}


def render(root, summary):
    artifacts = summary['evidence_artifacts']
    inputs = summary['input_completeness']['inputs']
    out = root / 'vehicle-audit-recheck.pdf'
    args = [sys.executable, str(ROOT / 'vehicle/analyze/report.py'),
            '--findings', str(ref_path(artifacts['findings'], root)),
            '--summary', str(root / 'summary.json'),
            '--rules', str(ref_path(artifacts['rules'], root)),
            '--flows', str(ref_path(inputs['flows'], root)), '--out', str(out)]
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True,
                          encoding='utf-8', timeout=180)
    return {'status': 'completed' if proc.returncode == 0 else 'failed',
            'returncode': proc.returncode, 'pdf': str(out),
            'stderr': proc.stderr[-400:] if proc.returncode else ''}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', type=Path, help='证据包目录或 summary.json')
    parser.add_argument('--report', action='store_true', help='校验通过后重新生成 PDF')
    args = parser.parse_args(argv)
    try:
        result = verify(args.target)
        if args.report:
            if result['status'] != 'passed':
                result['report'] = {'status': 'skipped', 'reason': '校验未通过'}
            else:
                root, _ = locate(args.target)
                result['report'] = render(root, read_json(root / 'summary.json'))
                if result['report']['status'] != 'completed':
                    result['status'] = 'failed'
    except (AuditError, OSError, ValueError, KeyError, TypeError) as error:
        details = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        print(json.dumps({'status': 'failed', 'error': details}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
