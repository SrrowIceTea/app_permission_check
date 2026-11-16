"""仅用于授权测试。固定版 YAABSA 的隔离播放、套接字归属与回执验收。"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from vehicle.lab.abs_api import request
from vehicle.lab.abs_capture import capture_syncs
from vehicle.lab.abs_socket_identity import attribute_requests, observe_sockets
from vehicle.lab.business_receipts import seal_playback_steps
from vehicle.lab.ui import UI
from vehicle.pipeline.capture_device import wait_until
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json, write_json
from vehicle.pipeline.device_state import ensure_wifi
from vehicle.pipeline.session_binding import verify_binding


PACKAGE = 'de.vito0912.yaabsa'
MEDIA = 'com.android.car.media/'
HOME = 'com.android.car.carlauncher/'
APK_SHA = '5a00d0962d61f3aae2669e8802d23bf5ce819b7aa55f10204dad300d04f58873'


def process_identity(device):
    pid = device.call('shell', 'pidof', PACKAGE)
    if not pid.isdecimal():
        raise AuditError('yaabsa_pid_unverified', '无法确认单一运行进程。', '打开指定的 YAABSA 播放器后重试。')
    status = device.call('shell', 'cat', f'/proc/{pid}/status')
    package_list = device.call('shell', 'cmd', 'package', 'list', 'packages', '-U', '--user', 10, PACKAGE)
    uid = re.search(r'(?m)^Uid:\s+(\d+)\s+\1\s+\1\s+\1\s*$', status)
    if not uid or int(uid[1]) // 100000 != 10 or f'package:{PACKAGE} uid:{uid[1]}' not in package_list.splitlines():
        raise AuditError('yaabsa_uid_unverified', '无法确认 YAABSA 进程属于 user 10。', '重新核对装机身份。')
    start = device.call('shell', 'cat', f'/proc/{pid}/stat').rsplit(')', 1)[1].split()[19]
    return int(pid), int(uid[1]), start


def pause_evidence(step, requests, server_session_id):
    """Require both playback-position and final REST values in the pause window."""
    candidates = [row for row in requests
                  if row.get('session_id') == server_session_id
                  and 0 <= row['device_ts_ms'] - step['pause_requested_ms'] <= 3000]
    positive = any(row['body']['timeListened'] > 0 and
                   abs(row['body']['currentTime'] * 1000 - step['media_paused']['position_ms']) <= 1000
                   for row in candidates)
    final = any(abs(row['body']['currentTime'] - step['after']['progress']) <= .001
                for row in candidates)
    return {'playback_position_request': positive, 'server_progress_request': final}


def run(runtime, out, apk):
    out.mkdir(parents=True, exist_ok=False)
    ui = UI(out / 'ui')
    result = {'passed': False, 'scope': 'owned_aaos_yaabsa_1_17_loopback',
              'apk_sha256': APK_SHA, 'steps': [], 'human_signoff': 'pending'}
    try:
        exercise(runtime, out, apk, ui, result)
    except Exception as error:  # noqa: BLE001 - 验收失败必须保留结构化结果
        result['error'] = error.record() if isinstance(error, AuditError) else {
            'type': type(error).__name__, 'message': str(error)}
    write_json(out / 'verification.json', result)
    return result['passed']


def exercise(runtime, out, apk, ui, result):
    device = ui.device
    call = device.call
    identity = device.ordinary_identity(PACKAGE, 10, 'general')
    if (digest(apk) != APK_SHA or identity['installed_apk_sha256'] != APK_SHA
            or identity['device_sdk'] != 35 or call('shell', 'getprop', 'ro.kernel.qemu') != '1'):
        raise AuditError('yaabsa_sample_mismatch', '装机样本与 YAABSA v1.17.0 隔离验收范围不符。',
                         '使用已核验的单一 APK 与自有 AAOS 35 模拟器。')
    ensure_wifi(call)
    item, = read_json(runtime / 'abs-library.json')['items']
    item_id = item['id']
    credentials = read_json(runtime / 'abs-test-credentials.private.json')
    logged = request('/login', {k: credentials[k] for k in ('username', 'password')})['user']
    token = logged.get('accessToken') or logged['token']

    def server_state():
        progress = request('/api/me/progress/' + item_id, token=token)
        sessions = request('/api/me/listening-sessions?itemsPerPage=20', token=token)['sessions']
        return {'observed_ms': int(time.time() * 1000), 'progress': progress.get('currentTime'),
                'sessions': [{k: row.get(k) for k in ('id', 'timeListening', 'updatedAt')}
                             for row in sessions if row.get('libraryItemId') == item_id]}

    def media(state):
        raw = call('shell', 'dumpsys', 'media_session')
        match = re.search(r'Media button session is de\.vito0912\.yaabsa/[^\n]+\(userId=10\)', raw)
        if not match:
            return None
        target = re.search(r'package=de\.vito0912\.yaabsa\b.*?state=PlaybackState \{state=(\w+)\(\d+\), position=(\d+)[^\n]*?updated=(\d+)', raw, re.S)
        if target and target[1] == state:
            return {'state': state, 'position_ms': int(target[2]), 'last_update_uptime_ms': int(target[3])}
        return None

    def top(activity):
        raw = call('shell', 'dumpsys', 'activity', 'activities')
        return bool(re.search(r'topResumedActivity=.*u10 ' + re.escape(activity), raw))

    def player():
        call('shell', 'am', 'start', '--user', 10, '-W', '-a', 'android.car.intent.action.MEDIA_TEMPLATE',
             '-e', 'android.car.intent.extra.MEDIA_COMPONENT', PACKAGE + '/com.ryanheise.audioservice.AudioService')
        wait_until(lambda: top(MEDIA), 8, 'native player is foreground')

    capture = out / 'capture'
    try:
        player()
        if media('PLAYING'):
            call('shell', 'input', 'keyevent', 127)
        wait_until(lambda: media('PAUSED'), 6, 'initial pause')
        screen = ui.snapshot('01-paused')
        bar, = [n for n in screen.iter('node') if n.get('resource-id') == 'com.android.car.media:id/playback_seek_bar']
        button, = [n for n in screen.iter('node') if n.get('resource-id') == 'com.android.car.media:id/play_pause_container']
        x1, y1, x2, y2 = map(int, re.findall(r'\d+', bar.get('bounds')))
        result['baseline'] = server_state()
        pid, uid, start = process_identity(device)
        with ((out / 'capture.log').open('w', encoding='utf-8') as log,
              observe_sockets(device, True) as sockets, capture_syncs(device) as traffic):
            worker = subprocess.Popen([sys.executable, '-m', 'vehicle.pipeline.capture', '--package', PACKAGE,
                '--serial', 'emulator-5554', '--user', '10', '--scope', 'general', '--preserve-system-proxy',
                '--no-tls-bypass', '--seconds', '130', '--out', str(capture)], cwd=ROOT, stdout=log, stderr=log,
                env=os.environ.copy())
            try:
                def ready():
                    if worker.poll() is not None:
                        raise RuntimeError('general capture stopped before readiness')
                    return '"status": "capturing"' in (out / 'capture.log').read_text(encoding='utf-8')

                wait_until(ready, 35, 'general capture readiness')
                for label, ratio in [('foreground', .09), ('background', .49)]:
                    call('shell', 'input', '-d', 0, 'tap', round(x1+(x2-x1)*ratio), (y1+y2)//2)
                    time.sleep(1)
                    before = server_state()
                    ui.tap_node(button)
                    wait_until(lambda: media('PLAYING'), 7, 'actual playback')
                    if label == 'background':
                        call('shell', 'input', 'keyevent', 3)
                    activity = HOME if label == 'background' else MEDIA
                    wait_until(lambda: top(activity), 7, label + ' activity')
                    initial = media('PLAYING')
                    time.sleep(13)
                    during = media('PLAYING')
                    step = {'phase': label, 'before': before, 'media_initial': initial,
                            'media_playing': during, 'activity_confirmed': top(activity)}
                    result['steps'].append(step)
                    if not initial or not during or not step['activity_confirmed']:
                        raise ValueError('playing state or activity changed')
                    step['pause_requested_ms'] = int(call('shell', 'date', '+%s%3N'))
                    # Compare the previous keycode path with the foreground app's Play/Pause control.
                    if label == 'foreground':
                        ui.tap_node(button)
                    else:
                        call('shell', 'input', 'keyevent', 127)
                    wait_until(lambda: media('PAUSED'), 7, 'actual pause')
                    transition = media('PAUSED')
                    time.sleep(3)
                    after = server_state()
                    pause = media('PAUSED')
                    if label == 'background':
                        player()
                    time.sleep(5)
                    stable = server_state()
                    final_pause = media('PAUSED')
                    def total(snapshot):
                        return sum(row.get('timeListening') or 0 for row in snapshot['sessions'])

                    step.update(after=after, paused_control=stable, media_paused=pause,
                                pause_transition=transition, pause_final=final_pause,
                                listening_delta=total(after) - total(before))
                    if not pause or pause['position_ms'] <= initial['position_ms']:
                        raise ValueError('media position did not advance')
                    if step['listening_delta'] <= 0 or type(after['progress']) not in (float, int):
                        raise ValueError('no independent playback increment')
                    step['server_vs_paused_position_delta_s'] = round(after['progress'] - pause['position_ms']/1000, 3)
                if process_identity(device) != (pid, uid, start):
                    raise AuditError('yaabsa_process_changed', '播放期间目标进程身份变化。', '重开会话复测。')
                actions = seal_playback_steps(capture, result['steps'], package=PACKAGE, user=10, item_id=item_id)
            finally:
                if capture.is_dir():
                    (capture / '.finish-request').touch()
                result['capture_exit'] = worker.wait(timeout=65)
        requests = traffic.result()
        samples = sockets.result()
        ownership = attribute_requests(requests, samples, pid, uid)
        owned_requests = [row for row, owner in zip(requests, ownership, strict=True)
                          if owner['status'] == 'uid_verified']
        write_json(out / 'loopback-sync-requests.json', owned_requests)
        write_json(out / 'socket-samples.json', [row for row in samples if row['pids'] == [pid]])
        for owner in ownership:
            if owner['status'] != 'uid_verified':
                owner.pop('session_id', None)
        if result['capture_exit'] != 0:
            raise AuditError('yaabsa_capture_failed', '通用采集未正常收尾。', '检查 capture.log 后用新会话重跑。')
        binding = verify_binding(capture, package=PACKAGE)
        write_json(out / 'binding-verification.json', binding)
        write_json(out / 'socket-attribution.json', {'capture_session_id': binding.get('session_id'),
                   'package': PACKAGE, 'pid': pid, 'uid': uid, 'process_start': start,
                   'requests_sha256': digest(out / 'loopback-sync-requests.json'),
                   'samples_sha256': digest(out / 'socket-samples.json'), 'requests': ownership})
        from vehicle.pipeline.audit import run_audit
        audit = run_audit(capture, out / 'audit', PACKAGE, '15', apk=apk, pdf=False)
        for step, action in zip(result['steps'], actions, strict=True):
            receipt = read_json(capture / action['receipt'])
            step['pause_evidence'] = pause_evidence(step, owned_requests, receipt['server_session_id'])
        passes = all(all(step['pause_evidence'].values()) for step in result['steps'])
        result.update(passed=passes and binding['status'] == 'binding_consistent' and binding['observed_receipts'] == 2,
                      audit_status=audit['status'], generic_findings=audit.get('findings_by_conclusion_level'),
                      binding_status=binding['status'], observed_receipts=binding['observed_receipts'],
                      attributed_requests=len(owned_requests), unresolved_requests=len(requests) - len(owned_requests),
                      server_position_alignment=all(abs(s['server_vs_paused_position_delta_s']) < 4 for s in result['steps']),
                      alignment_tolerance_s=4)
        if not result['passed']:
            raise AuditError('yaabsa_playback_evidence_gap', '播放回执或请求归属证据不足。',
                             '检查会话绑定和 socket-attribution.json 中逐条原因。')
    finally:
        if media('PLAYING'):
            call('shell', 'input', 'keyevent', 127)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('runtime', 'out', 'apk'):
        parser.add_argument('--' + arg, type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(0 if run(args.runtime.resolve(), args.out.resolve(), args.apk.resolve()) else 1)
