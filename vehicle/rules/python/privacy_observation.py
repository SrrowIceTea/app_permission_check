"""Freeze verified general-source device evidence for offline rebuilds. 授权测试专用。"""
import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from core.io_utils import load_jsonl
from core.privacy.semantics import read_state
from vehicle.privacy.catalog import catalog_hash, contract

DEFAULT_OBSERVATION = ROOT / 'vehicle/privacy/device-observation.json'
BASE_TYPES = contract(1)['types']


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def reference(path):
    path = Path(path).resolve()
    try:
        name = path.relative_to(ROOT).as_posix()
    except ValueError:
        name = str(path)
    return {'path': name, 'sha256': digest(path)}


def validate(document):
    if (document.get('schema_version') != 1 or document.get('device_api_level') != 35
            or ':15/' not in document.get('device_fingerprint', '')
            or document.get('privacy_catalog_sha256') not in (catalog_hash(1), catalog_hash())):
        raise ValueError('通用来源观测版本/设备/契约无效，不能使用 VHAL 校准替代')
    captures = document.get('captures')
    if not isinstance(captures, list) or not captures:
        raise ValueError('通用来源观测缺少采集身份与摘要')
    for capture in captures:
        if (not capture.get('session_id') or capture.get('device_fingerprint') != document['device_fingerprint']):
            raise ValueError('通用来源观测混合了不同设备或缺少会话')
        for key in ('manifest', 'reads', 'verification'):
            ref = capture.get(key, {})
            if not ref.get('path') or len(ref.get('sha256', '')) != 64:
                raise ValueError('通用来源观测缺少源文件摘要')
    for dtype in BASE_TYPES:
        counts = document.get('observed_states', {}).get(dtype, {})
        if (not counts.get('obtained') or any(type(n) is not int or n < 0 for n in counts.values())
                or set(counts) - {'obtained', 'empty', 'call_only', 'unknown', 'denied', 'error'}):
            raise ValueError(f'通用来源 {dtype} 缺少实际取得数据的正控或状态无效')
    return document


def load_observation(path=DEFAULT_OBSERVATION):
    document = validate(read_json(path))
    return {**document, 'snapshot': reference(path)}


def freeze(captures, output):
    snapshots, states, fingerprints, apks = [], {d: Counter() for d in BASE_TYPES}, set(), set()
    for folder in map(Path, captures):
        manifest = read_json(folder / 'session-manifest.json')
        verification = read_json(folder / 'verification.json')
        checks = verification.get('checks', {})
        if verification.get('passed') is not True or not checks or any(v is not True for v in checks.values()):
            raise ValueError('失败/空验收不能冻结为设备观测')
        if manifest.get('device_sdk') != 35 or manifest.get('privacy_catalog_sha256') != catalog_hash():
            raise ValueError('采集 API 或通用规则契约不符')
        session = manifest.get('session')
        if not session or verification.get('session') != session:
            raise ValueError('验收与采集会话不一致')
        for name in ('reads.jsonl', 'verification.json'):
            if digest(folder / name) != manifest.get('input_sha256', {}).get(name):
                raise ValueError('采集输入摘要不符：' + name)
        reads = load_jsonl(folder / 'reads.jsonl')
        if not reads or any(r.get('session_id') != session for r in reads):
            raise ValueError('读取证据混合会话或为空')
        if not any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
                and r.get('privacy_catalog_sha256') == catalog_hash() for r in reads):
            raise ValueError('缺少通用隐私 Hook 就绪证据')
        for read in reads:
            if read.get('ev') != 'PRIVACY_READ':
                continue
            if read.get('pkg') not in manifest.get('packages', []):
                raise ValueError('通用读取不属于本次白名单')
            for dtype in read.get('data_types', []):
                if dtype in states:
                    states[dtype][read_state(read)] += 1
        fingerprints.add(manifest['device_fingerprint']); apks.add(manifest['installed_apk_sha256'])
        snapshots.append({'session_id': session, 'device_fingerprint': manifest['device_fingerprint'],
            'manifest': reference(folder / 'session-manifest.json'),
            'reads': reference(folder / 'reads.jsonl'), 'verification': reference(folder / 'verification.json')})
    if len(fingerprints) != 1 or len(apks) != 1:
        raise ValueError('同一基线只能冻结同设备/同 APK 的正反例')
    document = validate({'schema_version': 1, 'device_api_level': 35,
        'device_fingerprint': fingerprints.pop(), 'apk_sha256': apks.pop(),
        'privacy_catalog_sha256': catalog_hash(), 'captures': snapshots,
        'observed_states': {d: dict(sorted(counts.items())) for d, counts in states.items()},
        'scope': 'captured_fixture_evidence_not_OEM_or_other_API_validation'})
    Path(output).write_text(json.dumps(document, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return document


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    freeze(args.capture, args.out)
