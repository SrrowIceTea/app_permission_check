"""Verify activity state around the owned background read/send controls. 仅用于授权测试。"""
import argparse
import re
import sys
from pathlib import Path

from vehicle.bench.read_send_control import FIXTURE_PACKAGE, MODES, USER, replay as replay_read_send
from vehicle.pipeline.contracts import digest, read_json, write_json


ACTIVITY = FIXTURE_PACKAGE + '/.MainActivity'
CONTEXT = 'activity-context.json'
SNAPSHOTS = ('foreground', 'before-action', 'after-action')
DISPLAY = re.compile(r'^Display #(\d+) \(activities from top to bottom\):$', re.M)
HISTORY = re.compile(r'^[ \t]*\* Hist[ \t]+#\d+: ActivityRecord\{(\w+) u(\d+) ([^\s}]+) t\d+\}', re.M)
RESUMED = re.compile(r'^[ \t]*topResumedActivity=ActivityRecord\{\w+ u(\d+) ([^\s}]+) ', re.M)


def fixture_activity(text):
    """Read the exact fixture's activity record and resumed state on display zero."""
    sections = DISPLAY.split(text)
    primary = [part for number, part in zip(sections[1::2], sections[2::2], strict=True) if number == '0']
    if len(primary) != 1:
        raise ValueError('缺少唯一的主显示屏 Activity 记录。')
    primary = primary[0]
    histories = list(HISTORY.finditer(primary))
    records = []
    for history, following in zip(histories, [*histories[1:], None]):
        record, user, component = history.groups()
        if (user, component) == (str(USER), ACTIVITY):
            end = following.start() if following else len(primary)
            records.append((record, primary[history.end():end]))
    if len(records) != 1:
        raise ValueError('主显示屏缺少唯一的自有夹具 Activity。')
    record, details = records[0]
    state = re.search(r'^[ \t]*state=(\w+)\b', details, re.M)
    visibility = re.search(r'^[ \t]*mVisibleRequested=(true|false) mVisible=(true|false)\b', details, re.M)
    if not state or not visibility:
        raise ValueError('夹具 Activity 状态或可见性缺失。')
    resumed = [component for user, component in RESUMED.findall(primary) if user == str(USER)]
    target_resumed = any(component.split('/', 1)[0] == FIXTURE_PACKAGE
                         for _, component in RESUMED.findall(text))
    return {'activity_record': record, 'state': state[1], 'visible_requested': visibility[1] == 'true',
            'visible': visibility[2] == 'true', 'target_resumed': target_resumed,
            'primary_resumed_activities': resumed}


def is_background(state):
    return (state['state'] == 'STOPPED' and not state['visible_requested'] and not state['visible']
            and not state['target_resumed'] and bool(state['primary_resumed_activities']))


def verify_context(out, arm):
    context = read_json(out / CONTEXT)
    action = read_json(out / 'action.json')
    if (context.get('session_id') != arm['session_id'] or context.get('action_token') != action['token']
            or context.get('package') != FIXTURE_PACKAGE or context.get('user_id') != USER
            or context.get('display_id') != 0):
        raise ValueError('后台状态、夹具动作与采集会话不一致。')
    snapshots = context['snapshots']
    if set(snapshots) != set(SNAPSHOTS):
        raise ValueError('缺少动作前后的三个 Activity 状态快照。')
    states = {}
    previous_end = 0
    for key in SNAPSHOTS:
        ref = snapshots[key]
        path = out / (key + '.txt')
        if (type(ref['start_ms']) is not int or type(ref['end_ms']) is not int
                or not 0 < ref['start_ms'] <= ref['end_ms'] or previous_end > ref['start_ms']
                or digest(path) != ref['sha256']):
            raise ValueError('Activity 快照时间或文件摘要无效。')
        previous_end = ref['end_ms']
        states[key] = fixture_activity(path.read_text(encoding='utf-8'))
    launch, before, after = (states[key] for key in SNAPSHOTS)
    if (launch['state'] != 'RESUMED' or not launch['visible'] or ACTIVITY not in launch['primary_resumed_activities']
            or len({state['activity_record'] for state in states.values()}) != 1
            or not is_background(before) or not is_background(after)
            or not snapshots['before-action']['end_ms'] <= action['start_ms'] < action['end_ms']
            <= snapshots['after-action']['start_ms']):
        raise ValueError('动作缺少同一 Activity 从前台切入后台并在动作两端保持不可见的证据。')
    return {'capture_context': 'background_activity_bracketed', 'display_id': 0,
            'activity': ACTIVITY, 'states': states, 'snapshots': snapshots,
            'context_sha256': digest(out / CONTEXT)}


def replay(source, reference=None):
    source = Path(source)
    report = replay_read_send(source, include_pairing=True)
    for mode, key in zip(MODES, ('read_only', 'positive'), strict=True):
        report[key]['activity_context'] = verify_context(source / mode, report[key])
    if reference is not None and read_json(reference) != report:
        raise ValueError('后台对照重放与已封存参考不一致。')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f'输出文件已存在：{args.out}')
        write_json(args.out, replay(args.source, args.reference))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f'{getattr(error, "code", "background_control_failed")}: {error}', file=sys.stderr)
        return 2
    print('AAOS 后台只读负控与发送对照重放通过。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
