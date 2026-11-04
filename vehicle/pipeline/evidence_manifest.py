"""Shared artifact fingerprints for audit, replay and rendering. 仅用于授权测试。"""
import hashlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core.collector.parse_stats import body_parse_totals
from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import AuditError, SCHEMA_VERSION, digest

INPUT_NAMES = {'reads': 'reads.jsonl', 'flows': 'flows.jsonl', 'egress': 'egress.jsonl',
               'permissions': 'requested-permissions.txt', 'manifest': 'session-manifest.json'}
MISSING = {'reads': '读取未采集', 'flows': '外发未采集', 'egress': '缺少出站连接日志',
           'permissions': '缺少权限快照', 'manifest': '缺少会话清单'}


def capture_paths(folder):
    return {name: Path(folder) / file for name, file in INPUT_NAMES.items()}


def artifact_ref(path):
    path = Path(path).resolve() if path is not None else None
    exists = path is not None and path.is_file()
    return {'path': str(path) if path else None, 'exists': exists,
            'sha256': digest(path) if exists else None}


def input_manifest(paths, *, inspect=True):
    refs = {name: artifact_ref(paths.get(name)) for name in INPUT_NAMES}
    missing = [{'input': name, 'reason': MISSING[name]} for name, ref in refs.items() if not ref['exists']]
    if inspect:
        for name in ('reads', 'flows', 'egress', 'permissions'):
            ref = refs[name]
            if not ref['exists']:
                ref['count'] = None
                continue
            path = Path(ref['path'])
            if name == 'permissions':
                ref['count'] = len([line for line in path.read_text(encoding='utf-8').splitlines() if line.strip()])
                continue
            rows = load_jsonl(path)
            ref['count'] = len(rows)
            if name == 'reads':
                ref['parse_status_totals'] = dict(Counter(
                    row.get('parse_status') or 'not_applicable' for row in rows))
            elif name == 'flows':
                ref['parse_status_totals'] = body_parse_totals(rows)
                ref['unattributed'] = sum(bool(row.get('unattributed')) or row.get('attribution') in
                                          ('unresolved', 'ambiguous') for row in rows)
    return {'inputs': refs, 'complete': not missing, 'missing': missing}


def verify_refs(refs):
    for name, ref in refs.items():
        current = artifact_ref(ref['path'])
        if current['exists'] != ref['exists'] or current['sha256'] != ref['sha256']:
            raise AuditError('artifact_digest_mismatch', '证据文件缺失或摘要发生变化。',
                             '核对原始产物后新建一轮审计。', artifact=name)


def fingerprints(rules, version, completeness, *, coverage=None, findings=None):
    from vehicle.coverage.export import build_coverage, coverage_bytes
    rule_ref = artifact_ref(rules)
    refs = {'rules': rule_ref}
    coverage_sha = hashlib.sha256(coverage_bytes(build_coverage(version, rules))).hexdigest()
    if coverage is not None:
        refs['coverage'] = artifact_ref(coverage)
        if refs['coverage']['sha256'] != coverage_sha:
            raise AuditError('coverage_digest_mismatch', '覆盖矩阵与当前规则及 Hook 覆盖不一致。', '重新生成覆盖矩阵。')
    if findings is not None:
        refs['findings'] = artifact_ref(findings)
    return {'schema_version': SCHEMA_VERSION, 'generated_at': datetime.now(timezone.utc).isoformat(),
            'rules_sha': rule_ref['sha256'], 'coverage_sha': coverage_sha, 'coverage_version': version,
            'input_completeness': completeness, 'evidence_artifacts': refs}


def verify_document(document, *, rules=None, findings=None, flows=None):
    """Render only the evidence referenced by a versioned audit document."""
    if document.get('status') == 'failed':
        raise AuditError('report_source_failed', '本轮分析失败，无法生成正常报告。', '检查失败摘要。')
    if document.get('schema_version') is None and not document.get('evidence_artifacts'):
        return
    if document.get('schema_version') != SCHEMA_VERSION:
        raise AuditError('report_schema_unknown', '报告证据契约版本不受支持。', '使用本轮完整摘要。')
    refs = document['evidence_artifacts']
    inputs = document['input_completeness']['inputs']
    verify_refs(refs)
    verify_refs(inputs)
    for name, path, ref in (('rules', rules, refs['rules']), ('findings', findings, refs.get('findings')),
                            ('flows', flows, inputs['flows'])):
        if path is not None and (not ref or artifact_ref(path)['sha256'] != ref['sha256']):
            raise AuditError('report_input_mismatch', '报告输入与证据摘要不一致。', '使用本轮封存文件。', artifact=name)
    expected_coverage = (refs['coverage']['sha256'] if 'coverage' in refs else fingerprints(
        refs['rules']['path'], document['coverage_version'], document['input_completeness'])['coverage_sha'])
    if (document['rules_sha'] != refs['rules']['sha256'] or document['coverage_sha'] != expected_coverage
            or document.get('rules_sha256', document['rules_sha']) != document['rules_sha']):
        raise AuditError('report_digest_mismatch', '摘要字段与证据清单不一致。', '重新生成审计摘要。')
