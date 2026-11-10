"""B（关联与验收）D1：固定当前基线、两个工作流与输入验收检查表。

仅用于授权测试。只读 git / 规则库 / 已构建 bundle 摘要 / ``adb devices -l``；
不启动采集、不安装应用、不改任何源码或产物。设备在线不等于样本、后端、
Hook 或业务动作已就绪；检查表是待 A 执行的验收条件，不是已完成的观测。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vehicle.privacy.evaluation import load_general_rules  # noqa: E402

WORKFLOWS = [
    {'id': 'mg4-post', 'priority': 1, 'kind': '自有 MG4 POST',
     'owner': 'A（采集/设备）', 'b_role': '只核对该 case 的命题状态、计分与报告投影',
     'packing': 'output/real-detection-20261110/mg4-post/（历史冻结轮，不是本周新会话）',
     'status': 'frozen_input_only',
     'note': '本周无新设备采集；旧标签不沿用于新证据，不能据此计算新的 P/R。'},
    {'id': 'owntracks-location', 'priority': 2, 'kind': '授权第三方 OwnTracks 定位',
     'owner': 'A（采集/设备）', 'b_role': '从只读副本重放定位实验，记录缺输入/格式不支持/未触达状态',
     'packing': 'output/vehicle-thirdparty-20261105-173730/owntracks-scenarios-004/capture（历史封存）',
     'status': 'historical_readonly_replay_only',
     'note': '不要求第三方 App 为本实验改变序列化形式；历史会话不能冒充本周新工作流尝试。'},
]

# 每条都是「验收时必须核对的条件」，附唯一实现出处；status 一律由 D3 实测填写。
INPUT_CHECKLIST = [
    {'id': 'IN-01', 'layer': '清单', 'condition': 'session-manifest 是对象；packages 白名单含显式 --package；session 非空；user_id 非负整数；android_version ∈ 13/14/15/16；input_sha256 含两个输入且为 64 位小写 hex',
     'source': 'vehicle/privacy/location_inputs.py:16-37', 'status': 'pending_replay'},
    {'id': 'IN-02', 'layer': '清单', 'condition': '目标包/会话记录的显式 user_id 与 UID 推导用户均等于清单 user_id；双方一致但与清单不符也要拒绝',
     'source': 'vehicle/privacy/location_inputs.py:40-51', 'status': 'pending_replay'},
    {'id': 'IN-03', 'layer': '读取', 'condition': 'ev=PRIVACY_READ、data_types 含 location、collection_state=obtained、non_empty、value_kind=location_pair、主形态 ∈ 5 种成对形态、形态表与主形态一致',
     'source': 'vehicle/privacy/location_match.py:99-120,45-68', 'status': 'pending_replay'},
    {'id': 'IN-04', 'layer': '读取', 'condition': '有效 src/evt_id/pid（正整数）/uid/user_id/host_received_ts/clock_basis；缺 PID 不猜进程身份',
     'source': 'vehicle/privacy/location_match.py:28-37,71-85', 'status': 'pending_replay'},
    {'id': 'IN-05', 'layer': '流量', 'condition': '目标包/会话、明确 uid/user、attribution ∈ 3 类且非歧义/失败/终态、ts 与 attribution_delta_ms 可用',
     'source': 'vehicle/privacy/location_match.py:121-129', 'status': 'pending_replay'},
    {'id': 'IN-06', 'layer': '正文', 'condition': '完整请求 JSON 文本；retention 已知；未截断/无解码错误；wire 与持久化 text 摘要各自校验；不恢复已脱敏坐标',
     'source': 'vehicle/privacy/location_payload.py:24-72', 'status': 'pending_replay'},
    {'id': 'IN-07', 'layer': '冻结', 'condition': '分析前后 session-manifest/reads/flows 的 sha256 不变；输出目录不在 capture 内',
     'source': 'vehicle/privacy/location_experiment.py:20-50,77-84', 'status': 'pending_replay'},
    {'id': 'IN-08', 'layer': '边界', 'condition': '只接受完整整对坐标字符串；数字叶子、分离坐标、其他精度、表单/Protobuf 不支持；未匹配不等于未外发',
     'source': 'vehicle/privacy/location_match.py:12-21', 'status': 'pending_replay'},
    {'id': 'IN-09', 'layer': '报告', 'condition': 'VSC-GE-location 未登记；实验不产 findings、不改默认规则；候选一律 content_match_candidate / origin_proven=false',
     'source': 'vehicle/privacy/location_match.py:157-165', 'status': 'pending_replay'},
]

# 正负控清单：offline_case 指 location_fixtures.cases() 的名字；设备列一律未执行。
DEVICE_CONTROLS = [
    {'id': 'POS-01', 'kind': '设备正控', 'offline_case': 'same_pair',
     'requirement': '真实 collector 输出同时含 PRIVACY_READ/location_forms 与同会话完整请求正文；附收件回执，不宣称来源因果',
     'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'NEG-01', 'kind': '异值负控', 'offline_case': 'different_pair',
     'requirement': '异值坐标对不产生值级候选', 'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'NEG-02', 'kind': '单坐标负控', 'offline_case': 'single_coordinates',
     'requirement': '只有分离的 lat/lon 不产生候选，不能用两个单坐标拼成对',
     'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'NEG-03', 'kind': '身份负控', 'offline_case': 'other_session_identity',
     'requirement': '跨会话/跨 UID/跨 user 不关联；无权限与失败连接单独记录',
     'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'NEG-04', 'kind': '正文负控', 'offline_case': 'empty_or_incomplete',
     'requirement': '截断、解码失败、正文不可用不产生候选，也不当作阴性结论',
     'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'AMB-01', 'kind': '同值歧义', 'offline_case': 'repeated_origin',
     'requirement': '重复同值来源保留多来源与歧义流，不强行选唯一来源',
     'device_status': 'not_run_this_week', 'owner': 'A'},
    {'id': 'PID-01', 'kind': 'PID 同号', 'offline_case': None,
     'requirement': '不同 PID 同 evt_id 不合并；下游 src/evt_id 引用带进程上下文',
     'device_status': 'not_run_this_week', 'owner': 'A'},
]


def sha(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def command(cmd, timeout=15):
    try:
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                              timeout=timeout, encoding='utf-8', errors='replace')
        return {'cmd': ' '.join(cmd), 'returncode': proc.returncode,
                'stdout': (proc.stdout or '').strip(), 'stderr': (proc.stderr or '').strip()}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'cmd': ' '.join(cmd), 'returncode': None, 'error': type(exc).__name__ + ': ' + str(exc)}


def rules_status():
    out = {'db_sha256': sha(ROOT / 'vehicle/rules/rules_library/rules.db'),
           'manifest_sha256': sha(ROOT / 'vehicle/rules/rules_library/rules.manifest.json'),
           'by_android_version': {}}
    for version in ('13', '14', '15', '16'):
        try:
            rules = load_general_rules(version)
            out['by_android_version'][version] = {
                'VSC-GR-location_registered': 'VSC-GR-location' in rules,
                'VSC-GE-location_registered': 'VSC-GE-location' in rules,
                'rule_count': len(rules),
            }
        except (OSError, ValueError, KeyError, TypeError) as exc:
            out['by_android_version'][version] = {'error': type(exc).__name__ + ': ' + str(exc)}
    return out


def bundles():
    dist = ROOT / 'vehicle/hooks/dist'
    names = ('hook_vehicle_all.bundle.js', 'hook_vehicle_ha.bundle.js',
             'hook_vehicle_mg4.bundle.js', 'hook_vehicle_abs_send.bundle.js',
             'hook_privacy.bundle.js')
    return {'dist_dir': str(dist.relative_to(ROOT)),
            'files': {name: sha(dist / name) for name in names},
            'note': '只记录已构建文件摘要；本周未重建、未下发，不证明设备端实际加载的是这些字节。'}


def frozen_inputs():
    base = ROOT / 'output/real-detection-20261110'
    return {'dir': str(base.relative_to(ROOT)),
            'verdicts_sha256': sha(ROOT / 'output/claim-verdicts-20261110/verdicts.json'),
            'cases_present': sorted(p.name for p in base.iterdir() if p.is_dir()) if base.is_dir() else [],
            'note': '2026-11-10 冻结轮；新会话须单独编号，旧标签不迁移。'}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path,
                    default=ROOT / 'output/week-b-20261110')
    args = ap.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)
    git = lambda *a: command(['git', '-C', str(ROOT), *a])
    baseline = {
        'generated_by': 'tools/week_b_baseline.py',
        'generated_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'role': 'B（关联与验收负责人）D1 基线',
        'git_head': git('rev-parse', 'HEAD')['stdout'] or None,
        'git_branch': git('branch', '--show-current')['stdout'] or None,
        'git_status_porcelain': git('status', '--porcelain', '-uall')['stdout'].splitlines(),
        'python': {'executable': sys.executable, 'version': sys.version.split()[0]},
        'device': {'query': command(['adb', 'devices', '-l']),
                   'note': '只读查询。在线不代表后端、样本、Hook 加载或业务动作已就绪；B 本周不跑设备采集。'},
        'rules': rules_status(),
        'bundles': bundles(),
        'frozen_inputs': frozen_inputs(),
        'workflows': WORKFLOWS,
        'input_checklist': INPUT_CHECKLIST,
        'device_controls': DEVICE_CONTROLS,
        'new_device_capture_this_week': False,
        'limits': [
            '没有本周新会话、新标签或新采集；历史封存副本只用于离线重放。',
            '设备定位正控与第三方有效性分开签收：缺任一真实输入即只交尝试/限制。',
            '默认不登记/启用 VSC-GE-location；实验开关状态不放宽。',
        ],
    }
    (args.out / 'baseline.json').write_text(
        json.dumps(baseline, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (args.out / 'input-checklist.json').write_text(
        json.dumps({'workflows': WORKFLOWS, 'checks': INPUT_CHECKLIST,
                    'controls': DEVICE_CONTROLS}, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    print(json.dumps({'out': str(args.out), 'head': baseline['git_head'],
                      'device': baseline['device']['query'].get('stdout', '').replace('\n', ' | '),
                      'ge_location_registered': any(
                          v.get('VSC-GE-location_registered') for v in
                          baseline['rules']['by_android_version'].values())},
                     ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
