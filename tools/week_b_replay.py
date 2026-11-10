"""B 周 D3：从封存会话的**只读副本**重放定位实验并记录分层状态。

仅用于授权测试。不跑设备、不改原产物、不改默认规则、不写 findings。
每个会话：复制 manifest/reads/flows 到新 staging 目录 → 用原始 CLI 重放 →
记录每层计数、逐条拒绝原因与尝试状态；前后校验两份 sha256 证明只读。

历史封存副本不是本周新会话，不能充当设备正控或第三方有效性验收。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

CAPTURES = [
    {'id': 'thirdparty-owntracks-004', 'workflow': 'owntracks-location',
     'kind': '授权第三方定位工作流尝试（历史副本）',
     'source': 'output/vehicle-thirdparty-20261105-173730/owntracks-scenarios-004/capture'},
    {'id': 'thirdparty-trailsense-nofix3', 'workflow': 'owntracks-location',
     'kind': '授权第三方定位补充样本（历史副本）',
     'source': 'output/vehicle-observed-e2e/trail-sense-nofix3/audit/bundle/capture'},
    {'id': 'owned-general-001', 'workflow': None,
     'kind': '自有受控历史会话（边界核验）',
     'source': 'output/vehicle-api34-20261103/general-001/capture'},
    {'id': 'frozen-mg4-post', 'workflow': 'mg4-post',
     'kind': '优先工作流 1 的冻结采集（边界核验）',
     'source': 'output/real-detection-20261110/mg4-post/bundle/capture'},
]
FILES = ('session-manifest.json', 'reads.jsonl', 'flows.jsonl')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def stage(source, target):
    """只复制三个输入文件；记录复制前后摘要，绝不写回原目录。"""
    if target.resolve().is_relative_to(source.resolve()):
        raise ValueError('staging_output_inside_source_capture')
    target.mkdir(parents=True, exist_ok=False)
    before = {name: sha(source / name) for name in FILES}
    for name in FILES:
        (target / name).write_bytes((source / name).read_bytes())
    staged = {name: sha(target / name) for name in FILES}
    return {'before': before, 'staged': staged,
            'byte_identical': before == staged,
            'source_unchanged_after': {name: sha(source / name) for name in FILES}}


def attempt_status(result, failure):
    """只按实验已产生的字段分类，不把「未观测」写成「未发生」。"""
    if failure:
        return 'replay_failed_before_interpretation', failure.get('message')
    layers = result.get('layer_accounting') or {}
    scoped, comparable = layers.get('scoped') or {}, layers.get('comparable') or {}
    pairs = (layers.get('candidates') or {}).get('pairs')
    if pairs:
        return 'content_candidate_observed', '仅有内容候选；不证明来源因果、收件或违规'
    if not scoped.get('location_reads'):
        return 'missing_general_location_read_input', '没有本模块需要的通用 PRIVACY_READ/location 读取'
    if not comparable.get('location_reads'):
        return 'unsupported_read_format_or_state', '读取存在但缺形态表/未取得/身份或时钟不可用'
    if not scoped.get('flows'):
        return 'no_scoped_outgoing_flow_input', '同会话没有可用的外发流量记录'
    if not comparable.get('flows'):
        return 'request_body_unavailable_or_unsupported_format', '正文不可用、截断或格式不受支持'
    return 'no_match_within_supported_scope', '本有限方法范围内无候选，不等于没有定位外发'


def layer_view(result, failure, manifest):
    layers = result.get('layer_accounting') or {}
    rejections = layers.get('rejections') or {}
    scoped, comparable = layers.get('scoped') or {}, layers.get('comparable') or {}
    candidates = layers.get('candidates') or {}
    pairs = result.get('pairs') or []
    return {
        'read': {'scoped': scoped.get('location_reads'),
                 'comparable': comparable.get('location_reads'),
                 'rejections': rejections.get('read_layer') or {}},
        'identity': {'manifest_user_id': manifest.get('user_id'),
                     'replay_user_id': result.get('user_id'),
                     'binding': result.get('identity_binding'),
                     'conflict': bool(failure)},
        'body': {'scoped_flows': scoped.get('flows'),
                 'comparable_flows': comparable.get('flows'),
                 'rejections': rejections.get('flow_layer') or {}},
        'format': {'matched_forms': candidates.get('matched_forms') or {},
                   'supported': '完整请求 JSON 字符串叶子内的 5 种整对坐标形态',
                   'unsupported_note': '数字叶子、分离坐标、其他精度、表单/Protobuf 不在范围内'},
        'association': {'pairs': candidates.get('pairs'),
                        'ambiguous_flows': candidates.get('ambiguous_flows'),
                        'status': candidates.get('status'),
                        'origin_proven': False if pairs else None,
                        'invalid_origin_claims': sum(p.get('origin_proven') is not False for p in pairs),
                        'evidence_level': 'content_match_candidate' if pairs else None},
    }


def run_one(spec, out_root):
    source = ROOT / spec['source']
    record = {'id': spec['id'], 'workflow': spec['workflow'], 'kind': spec['kind'],
              'source': spec['source'], 'new_session_this_week': False,
              'device_collection_this_week': False}
    if not source.is_dir() or any(not (source / name).is_file() for name in FILES):
        record['status'] = 'source_missing'
        return record
    manifest = json.loads((source / 'session-manifest.json').read_text(encoding='utf-8-sig'))
    package = (manifest.get('packages') or [None])[0]
    record['package'] = package
    record['session_id'] = manifest.get('session')
    record['android_version'] = manifest.get('android_version')
    staged_dir = out_root / 'readonly' / spec['id']
    out_dir = out_root / 'replay' / spec['id']
    if staged_dir.exists() or out_dir.exists():
        record['status'] = 'output_dir_exists_use_new_directory'
        return record
    staging = stage(source, staged_dir)
    try:
        proc = subprocess.run(
            [sys.executable, '-m', 'vehicle.privacy.location_experiment',
             '--capture', str(staged_dir), '--package', str(package), '--out', str(out_dir)],
            cwd=ROOT, capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=120)
    except subprocess.TimeoutExpired as exc:
        # 评审 F3：超时不能让整份 index 丢失；原样保留失败，不产出半份结果。
        staging['source_unchanged_after'] = {name: sha(source / name) for name in FILES}
        staging['source_readonly_verified'] = (staging['before'] == staging['source_unchanged_after'])
        record['staging'] = staging
        record['cli_returncode'] = None
        record['cli_timeout'] = {'seconds': 120, 'error': type(exc).__name__}
        record['attempt_status'] = 'replay_failed_before_interpretation'
        record['attempt_note'] = '重放超过 120 秒被终止；保留 staging 证据，不产出 result.json。'
        return record
    staging['source_unchanged_after'] = {name: sha(source / name) for name in FILES}
    staging['source_readonly_verified'] = (staging['before'] == staging['source_unchanged_after'])
    staging['staged_unchanged_after_replay'] = all(
        sha(staged_dir / name) == staging['before'][name] for name in FILES)
    record['staging'] = staging
    record['cli_returncode'] = proc.returncode
    record['cli_stdout'] = (proc.stdout or '').strip()
    result_path, failure_path = out_dir / 'result.json', out_dir / 'failure.json'
    result = json.loads(result_path.read_text(encoding='utf-8')) if result_path.is_file() else {}
    failure = json.loads(failure_path.read_text(encoding='utf-8')) if failure_path.is_file() else None
    if proc.returncode != 0 or not result and failure is None:
        failure = failure or {'message': 'CLI failed or produced no result',
                              'stderr': (proc.stderr or '')[-1000:]}
    record['result_path'] = str(result_path) if result else None
    record['failure'] = failure
    if result:
        record.update({
            'git_head': result.get('git_head'),
            'input_kind': result.get('input_kind'),
            'real_validation': result.get('real_validation'),
            'emits_rule_findings': result.get('emits_rule_findings'),
            'registered_location_egress_rule': result.get('registered_location_egress_rule'),
            'layer_accounting': result.get('layer_accounting'),
            'layers': layer_view(result, failure, manifest),
        })
    status, note = attempt_status(result, failure)
    record['attempt_status'] = status
    record['attempt_note'] = note
    record['conclusion'] = (
        '历史封存副本的离线重放记录，不是本周设备正控，也不能证明第三方定位外发能力。')
    return record


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, default=ROOT / 'output/week-b-20261110')
    args = ap.parse_args(argv)
    args.out = args.out.resolve()
    if any(args.out.is_relative_to((ROOT / s['source']).resolve()) for s in CAPTURES):
        ap.error('Output must be outside every source capture')
    args.out.mkdir(parents=True, exist_ok=True)
    records = [run_one(spec, args.out) for spec in CAPTURES]
    index = {
        'generated_by': 'tools/week_b_replay.py',
        'role': 'B D3：只读副本重放、每层计数与拒绝原因',
        'captures': records,
        'succeeded': [r['id'] for r in records if r.get('result_path')],
        'failed': [r['id'] for r in records if not r.get('result_path')],
        'third_party_attempts': [r for r in records if r['id'].startswith('thirdparty-')],
        'boundaries': [
            '只读副本；原目录与 staging 的 sha256 前后一致才记为只读。',
            '实验候选一律 content_match_candidate，origin_proven=false，不产 findings。',
            '没有本周新会话/新采集；旧标签不迁移，不能据此计算 P/R 或宣称设备验收通过。',
            '设备正控与第三方有效性分开签收：缺真实输入只交尝试/限制。',
        ],
    }
    (args.out / 'replay-index.json').write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'out': str(args.out),
                      'attempts': [(r['id'], r.get('attempt_status')) for r in records],
                      'readonly_verified': all(r.get('staging', {}).get('source_readonly_verified')
                                               for r in records)},
                     ensure_ascii=False))
    return 0 if not index['failed'] and all(
        r.get('cli_returncode') == 0 and r.get('staging', {}).get('source_readonly_verified')
        and r['staging'].get('staged_unchanged_after_replay') for r in records) else 2


if __name__ == '__main__':
    raise SystemExit(main())
