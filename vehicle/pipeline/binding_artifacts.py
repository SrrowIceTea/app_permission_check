"""Collect sealed capture dependencies for export/handoff. 仅用于授权测试。"""
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import AuditError, digest
from vehicle.pipeline.session_binding import ACTIONS_FILE, BINDING_FILE, verify_binding


def capture_dependencies(capture, manifest):
    """Preserve relative capture paths; declared missing evidence never becomes legacy."""
    capture = Path(capture)
    checked = verify_binding(capture, manifest=manifest)
    if checked['status'] == 'failed':
        raise AuditError('session_binding_invalid', '会话绑定及其依赖不完整。',
                         '保留原始证据，重新采集；不要删除绑定字段以降级。', failures=checked['failures'])
    result = {}
    def include(name, expected=None):
        path = capture / name
        if not path.resolve().is_relative_to(capture.resolve()) or not path.is_file():
            raise ValueError('capture dependency missing or outside capture: ' + name)
        actual = digest(path)
        if expected is not None and actual != expected:
            raise ValueError('capture dependency digest mismatch: ' + name)
        result[name] = actual
    if (capture / BINDING_FILE).is_file():
        include(BINDING_FILE, manifest.get('session_binding_sha256'))
        if (capture / ACTIONS_FILE).is_file():
            include(ACTIONS_FILE)
            for row in load_jsonl(capture / ACTIONS_FILE):
                name = row.get('receipt')
                if not isinstance(name, str) or Path(name).name != name:
                    raise ValueError('invalid capture receipt name')
                include(name, row['receipt_sha256'])
    identity = manifest.get('hook_bundle') or {}
    for name in manifest.get('used_hook_bundles', []):
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError('invalid capture hook name')
        relative = 'hook-bundles/' + name
        if (capture / relative).is_file():
            include(relative, (manifest.get('hook_bundles') or {}).get(name))
        proof = relative + '.sha256.json'
        expected = identity.get('archived_manifest_sha256') if identity.get('bundle') == name else None
        if expected is not None or (capture / proof).is_file():
            include(proof, expected)
    return result
