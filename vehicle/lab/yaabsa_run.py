"""YAABSA playback acceptance against isolated ABS. 仅用于授权测试。"""
import argparse
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import uuid
import zipfile
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.lab.abs_api import request
from vehicle.lab.abs_capture import FIELDS, capture_syncs
from vehicle.lab.abs_send_evidence import SOURCE, attribute_writes, observe_native_send
from vehicle.lab.abs_socket_identity import attribute_requests, observe_sockets
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json, write_json
from vehicle.privacy import abs_contract as abs_scope

PKG = 'de.vito0912.yaabsa'
APK = ROOT / 'output/p1p2-runtime/yaabsa.apk'
ITEM = 'be3f085f-3acf-48b9-8f20-c07668604cc3'


def login(folder):
    creds = json.loads((Path(folder) / 'abs-test-credentials.private.json').read_text(encoding='utf-8'))
    user = request('/login', {k: creds[k] for k in ('username', 'password')})['user']
    return user.get('accessToken') or user['token']


def server_state(token):
    progress = request('/api/me/progress/' + ITEM, token=token)
    sessions = request('/api/me/listening-sessions?itemsPerPage=5', token=token)['sessions']
    return {'progress': {'currentTime': progress.get('currentTime')},
            'sessions': [{k: row.get(k) for k in
                          ('id', 'libraryItemId', 'updatedAt', 'timeListening', 'mediaPlayer', 'clientVersion')}
                         for row in sessions if row.get('libraryItemId') == ITEM]}


def sample_identity(device, user):
    identity = device.ordinary_identity(PKG, user, 'general')
    listing = device.call('shell', 'cmd', 'package', 'list', 'packages', '-U', '--user', user, PKG)
    uid = re.search(rf'(?m)^package:{re.escape(PKG)} uid:(\d+)$', listing)
    if (device.call('shell', 'getprop', 'ro.kernel.qemu') != '1' or not uid
            or int(uid[1]) // 100000 != user or identity['installed_apk_sha256'] != digest(APK)):
        raise AuditError('abs_target_mismatch', 'YAABSA 装机身份与授权夹具不一致。', '核对样本和模拟器。')
    with zipfile.ZipFile(APK) as archive:
        library = archive.read('lib/x86_64/libapp.so')
    needles = ('/api/session/', 'SyncSessionRequest', 'currentTime', 'timeListening', 'just_audio')
    return {**identity, 'package': PKG, 'uid': int(uid[1]), 'sample_apk_sha256': digest(APK),
            'installed_matches_sample': True, 'libapp_sha256': hashlib.sha256(library).hexdigest(),
            'implementation': 'Flutter AOT lib/x86_64/libapp.so',
            'strings': {needle: needle.encode() in library for needle in needles}}


def evaluate(syncs, before, after, paused_progress, paused_again):
    ids = {r['session_id'] for r in syncs}
    previous = {r['id']: r for r in before['sessions']}
    matches = [row for row in after['sessions'] if row['id'] in ids]
    session = matches[0] if len(matches) == 1 and len(ids) == 1 else {}
    baseline = previous.get(session.get('id'), {})
    latest = syncs[-1]['body']['currentTime'] if syncs else None
    listened = sum(row['body']['timeListened'] for row in syncs)
    delta = float(session.get('timeListening') or 0) - float(baseline.get('timeListening') or 0)
    checks = {
        'one_request_session_matches_server_id': bool(session),
        'matched_session_updated': bool(session) and int(session.get('updatedAt') or 0) >
                                   int(baseline.get('updatedAt') or 0),
        'server_progress_matches_request': latest is not None and
            abs(float(after['progress'].get('currentTime') or 0) - latest) <= 2,
        'server_time_listening_delta_matches': bool(session) and delta > 0 and listened > 0
                                               and abs(delta - listened) <= 2,
        'pause_stops_progress': type(paused_progress) in (int, float) and
            type(paused_again) in (int, float) and abs(paused_again - paused_progress) < .5,
    }
    return {'status': 'playback_progress_aligned' if all(checks.values()) else 'playback_progress_gap',
            'checks': checks, 'gaps': [key for key, ok in checks.items() if not ok],
            'latest_sync_currentTime': latest, 'request_timeListened_total': listened,
            'server_timeListening_delta': delta, 'server_session': session,
            'server_progress_at_pause': paused_progress, 'server_progress_paused_6s_later': paused_again}


def check_external_sender(token, session):
    try:
        request(f'/api/session/{session}/sync', {'currentTime': 1.2345, 'duration': 45, 'timeListened': 0},
                token=token)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return error.code
        raise
    raise AuditError('abs_control_not_rejected', '独立发送端的无效会话未被拒绝。', '检查隔离测试服务。')


def verify_native(out, result, native, syncs, external, external_status, device, pid, uid,
                  manifest_path=None):
    evidence = native['evidence']
    events = load_jsonl(evidence)
    if any(r.get('ev') in ('ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR', 'VLOG_FAIL') for r in events):
        raise AuditError('abs_send_observation_error', 'YAABSA 发送观察出现错误。', '检查 send-hook.log。')
    canonical = digest(ROOT / 'vehicle/hooks/dist' / abs_scope.BUNDLE)
    if native['bundle_sha256'] != canonical:
        raise AuditError('abs_send_bundle_contract_mismatch',
                         '发送观察归档的 bundle 与 abs_contract.BUNDLE 不一致。',
                         '用 abs_contract.BUNDLE 同时完成采集与发送观察后重跑。')
    manifest_path = manifest_path or (out / 'session-manifest.json')
    if manifest_path.is_file():
        manifest = read_json(manifest_path)
        if native['bundle_sha256'] not in (manifest.get('hook_bundles') or {}).values():
            raise AuditError('abs_send_bundle_manifest_mismatch',
                             '发送观察归档的 bundle 未出现在采集 manifest 的 hook_bundles 中。',
                             '检查同轮采集与发送观察是否使用同一个 bundle。')
        result['bundle_manifest_verified'] = True
    else:
        # 独立观察轮次没有 capture/session-manifest.json；只能核对规范 bundle 的摘要，
        # 这种缺失登记为缺口，不冒充 manifest 断言。
        result['bundle_manifest_verified'] = False
        result['bundle_manifest_gap'] = 'standalone_send_observation_has_no_session_manifest'
    identity = dict(session=native['session_id'], serial=device.serial, package=PKG, pid=int(pid), uid=uid)
    ownership = attribute_writes(syncs, events, **identity)
    control = attribute_writes(external, events, **identity)
    failed = [dict(r, ev='ABS_SYNC_WRITE_INCOMPLETE', returned_bytes=-1)
              if r.get('ev') == 'ABS_SYNC_WRITE' else r for r in events]
    controls = {
        'external_sender_unattributed': external_status == 404 and len(control) == 1
                                       and not control[0]['write_refs'],
        'failed_write_ignored_replay': bool(syncs) and all(
            not r['write_refs'] for r in attribute_writes(syncs, failed, **identity)),
    }
    reused = {r['connection_id'] for r in ownership if r['status'] == 'uid_verified' and r['connection_id']
              and sum(p['connection_id'] == r['connection_id'] and p['status'] == 'uid_verified'
                      for p in ownership) > 1}
    verified = sum(r['status'] == 'uid_verified' for r in ownership)
    write_json(out / 'send-attribution.json', {
        'identity': identity, 'apk_sha256': result['sample_identity']['installed_apk_sha256'],
        'hook_bundle_name': abs_scope.BUNDLE,
        'hook_bundle_sha256': native['bundle_sha256'], 'write_events_sha256': digest(evidence),
        'requests_sha256': digest(out / 'sync-requests.json'), 'requests': ownership,
        'external_request': external, 'external_sender': control, 'external_http_status': external_status,
        'controls': controls, 'reused_connections': sorted(reused)})
    result.update(send_uid_verified_requests=verified, send_unresolved_requests=len(syncs) - verified,
                  send_identity_status=('verified' if verified and verified == len(syncs) and reused
                                        and all(controls.values()) else 'partial'),
                  capture_scope='isolated_loopback_http_native_send_observation',
                  send_controls=controls, send_reused_connection_count=len(reused),
                  send_write_events=sum(r.get('src') == SOURCE and r.get('ev') == 'ABS_SYNC_WRITE'
                                        for r in events))


def run(out, folder, serial, user, socket_attribution=False, send_attribution=False,
        manifest_path=None):
    out.mkdir(parents=True, exist_ok=False)
    device = Device(serial)
    result = {'family': 'yaabsa-flutter-audiobookshelf', 'status': 'failed',
              'verification_status': 'failed'}
    try:
        result['sample_identity'] = sample_identity(device, user)
        if send_attribution and not abs_scope.supports(PKG, result['sample_identity']):
            raise AuditError('abs_send_target_mismatch', '发送观察与装机样本契约不一致。',
                             '使用固定版本的授权 YAABSA APK 和 AAOS 35 user 10。')
        observe_identity = socket_attribution or send_attribution
        pid = device.call('shell', 'pidof', PKG) if observe_identity else None
        expected_uid = result['sample_identity']['uid']
        if observe_identity:
            expected_uid = result['sample_identity']['uid']
            if not pid.isdecimal() or not re.search(rf'(?m)^Uid:\s+{expected_uid}\s+',
                                                   device.call('shell', 'cat', f'/proc/{pid}/status')):
                raise AuditError('abs_socket_identity_missing', '未能核实 YAABSA 主进程 UID。', '确认装机身份后重试。')
        media = device.call('shell', 'dumpsys', 'media_session')
        if (device.call('shell', 'am', 'get-current-user') != str(user) or not re.search(
                rf'Media button session is {re.escape(PKG)}/[^\n]+\(userId={user}\)', media)):
            raise AuditError('abs_media_not_ready', 'YAABSA 没有取得当前媒体会话。', '打开自有测试音频后重新验收。')
        token = login(folder)
        request('/api/me/progress/' + ITEM, {'currentTime': 5, 'duration': 45}, token=token, method='PATCH')
        before = server_state(token)
        external_session = str(uuid.uuid4()) if send_attribution else None
        external_status = None
        with (observe_sockets(device, socket_attribution) as sockets,
              observe_native_send(out, device, PKG, user, int(pid or 0), expected_uid, send_attribution) as native,
              capture_syncs(device) as captured):
            if external_session:
                external_status = check_external_sender(token, external_session)
            try:
                device.call('shell', 'input', 'keyevent', 126)
                time.sleep(6)
                device.call('shell', 'input', 'keyevent', 127)
                time.sleep(2)
                paused_progress = server_state(token)['progress']['currentTime']
                time.sleep(6)
                paused_again = server_state(token)['progress']['currentTime']
                device.call('shell', 'input', 'keyevent', 126)
                time.sleep(6)
            finally:
                device.call('shell', 'input', 'keyevent', 127)
            time.sleep(4)
        requests = captured.result()
        external = [r for r in requests if r['session_id'] == external_session]
        syncs = [r for r in requests if r['session_id'] != external_session]
        write_json(out / 'sync-requests.json', syncs)
        after = server_state(token)
        result.update(evaluate(syncs, before, after, paused_progress, paused_again))
        result.update(sync_request_count=len(syncs), sync_fields=list(FIELDS) if syncs else [],
                      observed_routes=sorted({f"/api/session/{r['session_id']}/sync" for r in syncs}),
                      server_progress_before=before['progress'], server_progress_after=after['progress'],
                      capture_scope='isolated_device_loopback_http_no_per_flow_uid')
        if observe_identity and device.call('shell', 'pidof', PKG) != pid:
            raise AuditError('abs_socket_process_changed', '采集期间目标进程已更换。', '重新验收同一进程会话。')
        if native:
            verify_native(out, result, native, syncs, external, external_status, device, pid,
                          expected_uid, manifest_path)
        if sockets is not None:
            ownership = attribute_requests(syncs, sockets.result(), int(pid), expected_uid)
            write_json(out / 'socket-attribution.json', ownership)
            verified = sum(r['status'] == 'uid_verified' for r in ownership)
            result.update(socket_uid_verified_requests=verified, socket_unresolved_requests=len(syncs) - verified,
                          socket_identity_status=('verified' if verified and verified == len(syncs) else 'partial'),
                          capture_scope='isolated_loopback_http_socket_uid_observation')
        # 只有走完所有验证步骤才把最终验证状态定稿；异常路径保持 failed。
        result['verification_status'] = result['status']
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result['verification_status'] = 'failed'
        result['error'] = error.record() if isinstance(error, AuditError) else {'type': type(error).__name__}
    finally:
        write_json(out / 'playback-acceptance.json', result)
    return (result['verification_status'] == 'playback_progress_aligned'
            and (not socket_attribution or result.get('socket_identity_status') == 'verified')
            and (not send_attribution or result.get('send_identity_status') == 'verified'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--folder', type=Path, default=ROOT / 'output/p1p2-runtime')
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--user', type=int, default=10)
    parser.add_argument('--manifest', type=Path,
                        help='同轮采集的 session-manifest.json；用于核对发送观察 bundle 摘要')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--socket-attribution', action='store_true')
    modes.add_argument('--send-attribution', action='store_true')
    args = parser.parse_args()
    raise SystemExit(0 if run(args.out.resolve(), args.folder, args.serial, args.user,
                              args.socket_attribution, args.send_attribution,
                              args.manifest.resolve() if args.manifest else None) else 1)
