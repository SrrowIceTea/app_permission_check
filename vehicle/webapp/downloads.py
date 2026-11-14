"""Download a verified audit package, never a recursive job-directory archive."""
import tempfile
import zipfile
from pathlib import Path
from vehicle.pipeline.contracts import AuditError, read_json
from vehicle.pipeline.verify_bundle import verify


def send(handler, audit):
    audit = Path(audit).resolve()
    checked = verify(audit)
    if checked['status'] != 'passed':
        raise AuditError('bundle_invalid', '审计证据包完整性校验失败。', '保留原始文件，检查摘要；不能导出为正常证据。')
    summary = read_json(audit / 'summary.json')
    names = {'summary.json'}
    for refs in (summary.get('evidence_artifacts', {}), summary.get('input_completeness', {}).get('inputs', {})):
        for ref in refs.values():
            if ref.get('exists', True) and ref.get('path'):
                path = (audit / ref['path']).resolve()
                if not path.is_relative_to(audit):
                    raise AuditError('bundle_path_outside', '证据引用超出当前审计包。', '重新生成可搬移证据包。')
                names.add(path.relative_to(audit).as_posix())
    names.update(n for n in ('vehicle-audit.pdf', 'dashboard.html') if (audit / n).is_file())
    # The temporary ZIP is owned by this response; it is removed after streaming.
    with tempfile.TemporaryDirectory(prefix='vehicle-export-') as folder:
        target = Path(folder) / 'evidence.zip'
        with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            for name in sorted(names):
                archive.write(audit / name, name)
        handler.file(target, 'application/zip')
