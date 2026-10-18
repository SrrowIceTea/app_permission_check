"""Resume the uploaded task, not another APK/task. 仅用于授权测试。"""
from __future__ import annotations
import hashlib
from pathlib import Path
import re
import zipfile
from mobile.workbench.store import Store, read_json
from mobile.workbench.store import write_json


def bind(storage: Path, task_id: str, apk: Path) -> dict:
    store = Store(storage)
    task = store.get(task_id)
    if not task or task.get('origin') != 'uploaded_apk':
        raise ValueError('core task must be the existing original APK upload')
    cache = store.cache_dir(task)
    if cache is None or (cache / 'uploaded.apk').resolve() != apk.resolve():
        raise ValueError('selected APK is not this task-owned uploaded cache file')
    with apk.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != task['apk'].get('sha256') or not task['apk'].get('package'):
        raise ValueError('uploaded APK identity changed or static metadata missing')
    if task['stages']['static']['state'] != 'done':
        raise ValueError('uploaded task static scan has not completed')
    raw = read_json(cache / 'workbench-static.json', {})
    facts = read_json(cache / 'dexfacts.json', {})
    with zipfile.ZipFile(apk) as archive:
        expected = {n for n in archive.namelist() if re.fullmatch(r'classes\d*\.dex', n)}
    if (not expected or facts.get('gaps') or raw.get('gaps') and
            any(isinstance(g, dict) and g.get('kind') == 'dex_parse' for g in raw['gaps'])
            or expected != set(facts.get('per_dex_lines') or {})):
        raise ValueError('complete core audit requires actual facts for every original DEX')
    static = read_json(cache / 'static.json', {})
    if static.get('dex_gaps'):
        raise ValueError('original static DEX extraction has gaps')
    dec = task['stages']['decompile']['state']
    if dec not in ('done', 'partial') or not (raw.get('decompile') or {}).get('classes_written'):
        raise ValueError('original uploaded task has no usable actual JADX output')
    return task


class Cancelled(RuntimeError):
    """Current bounded command completed; downstream execution stopped."""


def check_cancel(path=None):
    if path and Path(path).is_file():
        raise Cancelled('audit cancellation requested; retained current command output, no further stages or publication')


def static_snapshot(store, task, out):
    """Whole DEX proof accompanies the actual original candidates, not a guessed flag."""
    cache = store.cache_dir(task)
    source = (cache or store.task_dir(task['id'])) / 'workbench-static.json'
    value = read_json(source)
    if not isinstance(value, dict):
        raise ValueError('retained original static evidence is missing')
    if cache:
        facts_path = cache / 'dexfacts.json'
        facts = read_json(facts_path, {})
        with zipfile.ZipFile(cache / 'uploaded.apk') as archive:
            expected = {n for n in archive.namelist() if re.fullmatch(r'classes\d*\.dex', n)}
        complete = bool(expected) and expected == set(facts.get('per_dex_lines') or {}) and not facts.get('gaps')
        if not complete or read_json(cache / 'static.json', {}).get('dex_gaps'):
            raise ValueError('static snapshot lacks complete original DEX facts')
        value['whole_dex_scanned'] = True
        value['whole_dex_proof'] = {'dex_entries': sorted(expected),
            'facts_sha256': hashlib.sha256(facts_path.read_bytes()).hexdigest(),
            'original_apk_sha256': task['apk']['sha256']}
    value['retained_static_source'] = {'name': source.name,
        'sha256': hashlib.sha256(source.read_bytes()).hexdigest()}
    destination = out / 'static-evidence.json'
    write_json(destination, value)
    return destination
