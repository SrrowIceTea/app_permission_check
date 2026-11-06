"""Relocatable audit evidence bundle. 仅用于授权测试（自有设备与自有 APK）。

新一轮审计在 summary.json 旁写入自包含的 ``bundle/`` 目录：外部输入（采集文件、
规则库、钩子 bundle）被复制进去，所有引用路径改为相对证据包根目录。绝对路径保留
在 ``source_path`` 中，仅用于本机回放；跨机器复核只认相对路径。

历史产物不改动：它们的 ref 只有绝对路径，由 ``verify_bundle`` 明确报为历史格式。
"""
import shutil
from pathlib import Path

from vehicle.pipeline.contracts import AuditError, digest
from vehicle.pipeline.evidence_manifest import INPUT_NAMES

BUNDLE_VERSION = 'relative_v1'
BUNDLE_DIR = 'bundle'


def _inside(path, root):
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return None


def _target(key, path):
    """Map a manifest key to a location inside the bundle."""
    if key == 'rules':
        return f'{BUNDLE_DIR}/rules.db'
    if key in INPUT_NAMES:
        return f'{BUNDLE_DIR}/capture/{path.name}'
    return f'{BUNDLE_DIR}/{key}'


def _copy(source, target, expected):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    if expected is not None and digest(target) != expected:
        raise AuditError('bundle_copy_mismatch', '复制进证据包后摘要不一致。',
                         '检查来源文件是否在审计期间被改动。', artifact=source.name)


def _relativize(ref, output, key):
    path = ref.get('path')
    if not path:
        return
    source = Path(path).resolve()
    inside = _inside(source, output)
    if ref.get('exists') is False:
        ref['path'] = inside if inside is not None else _target(key, source)
        ref['source_path'] = str(source)
        return
    if inside is not None:
        ref['path'] = inside
        ref['source_path'] = str(source)
        return
    relative = _target(key, source)
    _copy(source, output / relative, ref.get('sha256'))
    ref['path'] = relative
    ref['source_path'] = str(source)


def package_evidence(document, output):
    """Rewrite every evidence reference relative to the bundle root."""
    output = Path(output).resolve()
    artifacts = document.get('evidence_artifacts')
    inputs = (document.get('input_completeness') or {}).get('inputs')
    if not artifacts or not inputs:
        return document
    for key, ref in artifacts.items():
        _relativize(ref, output, key)
    for key, ref in inputs.items():
        _relativize(ref, output, key)
    document['bundle'] = {'format': BUNDLE_VERSION, 'root': '.',
                          'external_dir': BUNDLE_DIR, 'relocatable': True,
                          'entries': len(artifacts) + len(inputs)}
    return document
