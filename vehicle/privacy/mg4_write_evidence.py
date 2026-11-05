"""Recheck native write references before exporting an MG4 audit. 仅用于授权测试。"""
import copy
from core.collector.native_write import NativeWrites
from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import AuditError
from vehicle.privacy.mg4_contract import PACKAGE


def audit(capture, session):
    flows = load_jsonl(capture / 'flows.jsonl')
    replay = copy.deepcopy(flows)
    checker = NativeWrites([capture / 'reads.jsonl'], session, PACKAGE)
    checker.bind(replay)
    verified = []
    for original, checked in zip(flows, replay, strict=True):
        if original.get('attribution') != 'native_http_write':
            continue
        if (not checker.eligible(original) or checked.get('attribution') != 'native_http_write'
                or original.get('package') != checked.get('package')
                or original.get('uid') != checked.get('uid')
                or original.get('user_id') != checked.get('user_id')
                or original.get('native_write_ref') != checked.get('native_write_ref')):
            raise AuditError('mg4_native_write_mismatch', 'MG4 逐流身份无法由本轮实际写入证据复核。',
                             '核对封存的读取事件、代理正文与会话；不能用 WebView 回调代替。')
        verified.append({'flow_ref': {'src': original.get('src', 'proxy'), 'evt_id': original['evt_id']},
                         'write_ref': checked['native_write_ref'], 'uid': checked['uid'],
                         'body_sha256': original['request_payload']['raw_sha256']})
    return {'verified_flows': verified, 'matched_requests': len(verified), 'scoring': 'workflow_only',
            'scope': 'pinned_mg4_synthetic_plain_http_complete_single_write',
            'limits': '分片、TLS、其他 WebView/APK 版本未验证；相同请求重复时弃权。独立回执另行核对。'}
