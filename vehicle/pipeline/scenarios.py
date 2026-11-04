"""Bind scenario context to evidence, package/session/user and time. 授权测试专用。"""
from pathlib import Path
from vehicle.pipeline.contracts import read_json, digest, AuditError

CONTEXTS = ('consent', 'vehicle_state', 'network', 'foreground', 'user_id')


def load_scenarios(path, capture, package, session):
    if path is None:
        return []
    path = Path(path).resolve()
    rows = read_json(path)
    if not isinstance(rows, list):
        raise AuditError('invalid_scenarios', '场景清单必须是列表。', '按场景契约导出执行记录。')
    for row in rows:
        if (row.get('package') != package or row.get('session_id') != session
                or not isinstance(row.get('start_ms'), (int, float))
                or not isinstance(row.get('end_ms'), (int, float))
                or row['end_ms'] < row['start_ms']):
            raise AuditError('scenario_identity_mismatch', '场景缺少有效时间/包名或属于其他会话。',
                             '提供本次实际执行的场景记录。')
        context, refs = row.get('context', {}), row.get('context_evidence', {})
        for key in CONTEXTS:
            value = context.get(key)
            if value is None or value in ('unknown', 'not_injected'):
                continue
            reference = refs.get(key)
            # Old foreground/permission fixtures remain usable but visibly unverified.
            if not reference:
                row.setdefault('context_gaps', []).append(f'{key}: context artifact not supplied')
                if key in ('consent', 'vehicle_state', 'network'):
                    raise AuditError('scenario_evidence_missing', f'{key} 场景没有执行证据。',
                                     '提供带摘要的执行记录；不能凭标签推断状态。')
                continue
            artifact = (path.parent / reference.get('file', '')).resolve()
            try:
                artifact.relative_to(path.parent)
            except ValueError as error:
                raise AuditError('scenario_path_outside', '场景证据超出记录目录。', '使用本轮相对路径。') from error
            if not artifact.is_file() or digest(artifact) != reference.get('sha256'):
                raise AuditError('scenario_artifact_mismatch', '场景执行证据缺失或摘要不符。', '保留失败轮次并重跑。')
            if reference.get('kind') not in ('owned_fixture_receipt', 'adb_state', 'ui_observation', 'synthetic_control'):
                raise AuditError('scenario_evidence_kind', '未知场景证据来源。', '明确使用实际执行证据或合成对照。')
        synthetic = row.get('source') == 'synthetic_control' or any(
            r and r.get('kind') == 'synthetic_control' for r in refs.values())
        row['context_validation'] = 'synthetic_only' if synthetic else 'artifact_checked'
    return rows
