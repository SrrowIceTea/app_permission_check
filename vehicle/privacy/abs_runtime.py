"""Persist and replay only verified ABS numeric requests. 仅用于授权测试。"""
from vehicle.lab.abs_send_evidence import attribute_writes
from vehicle.pipeline.contracts import AuditError, read_json, write_json
from vehicle.privacy import abs_contract as abs_scope


def seal_requests(output, requests, reads, session, serial, pid, user):
    ready = [r for r in reads if r.get('src') == abs_scope.SOURCE and r.get('ev') == 'ARMED'
             and r.get('pkg') == abs_scope.PACKAGE and r.get('device_serial') == serial
             and r.get('session_id') == session and r.get('pid') == pid and r.get('user_id') == user
             and r.get('caller') == abs_scope.CALLER]
    if len(ready) != 1 or type(ready[0].get('uid')) is not int or ready[0]['uid'] // 100000 != user:
        raise AuditError('abs_send_identity_missing', '缺少唯一的 YAABSA 进程就绪证据。', '检查 reads.log。')
    identity = dict(session=session, serial=serial, package=abs_scope.PACKAGE, pid=pid, uid=ready[0]['uid'])
    attributed = attribute_writes(requests, reads, **identity)
    verified = [r for r, link in zip(requests, attributed) if link['status'] == 'uid_verified']
    write_json(output / abs_scope.INPUT, {'identity': identity, 'requests': verified,
                                         'unresolved_requests_discarded': len(requests) - len(verified)})


def audit_requests(capture, reads, session, user):
    sealed = read_json(capture / abs_scope.INPUT)
    identity = sealed['identity']
    if (identity['session'] != session or identity['package'] != abs_scope.PACKAGE
            or type(identity['uid']) is not int or identity['uid'] // 100000 != user):
        raise AuditError('abs_send_session_mismatch', 'YAABSA 请求与采集身份不一致。', '恢复该会话的封存输入。')
    requests = sealed['requests']
    links = attribute_writes(requests, reads, **identity)
    if any(r['status'] != 'uid_verified' for r in links):
        raise AuditError('abs_send_unmatched', '封存的 YAABSA 请求无法重放发送归因。', '检查原始 Hook 事件。')
    return {'status': 'uid_verified' if links else 'no_verified_requests',
            'request_evidence': abs_scope.INPUT, 'verified_requests': len(links),
            'unresolved_requests_discarded': sealed['unresolved_requests_discarded'],
            'write_refs': [ref for link in links for ref in link['write_refs']],
            'scope': 'pinned_yaabsa_cronet_isolated_abs_http'}
