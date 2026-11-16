"""Seal actual UI and server observations before capture finishes. 授权测试专用。"""
import json
import shutil
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import digest, write_json
from vehicle.pipeline.session_binding import ACTIONS_FILE


def _observed_session(capture, package, user):
    sessions = {r.get('session_id') for r in load_jsonl(capture / 'reads.jsonl')
                if r.get('pkg') == package and r.get('user_id') == user}
    if len(sessions) != 1 or not next(iter(sessions)):
        raise ValueError('receipt sealing requires one observed app session')
    return next(iter(sessions))


def _write_actions(capture, rows):
    with (capture / ACTIONS_FILE).open('x', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')
    return rows


def seal_browser(capture, actions, receipts, ui_folder, package, marker):
    """Receipts prove observed UI/HTTP reception; attribution is checked separately."""
    capture, ui_folder = Path(capture), Path(ui_folder)
    session = _observed_session(capture, package, 10)
    rows = []
    for number, action in enumerate(actions):
        source = ui_folder / Path(action['ui_file']).name
        if digest(source) != action['ui_sha256']:
            raise ValueError('UI receipt changed before sealing')
        target = capture / f'business-ui-{number:02d}.xml'
        shutil.copyfile(source, target)
        rows.append({'session_id': session, 'package': package, 'action': action['id'],
            'ts_ms': action['ts_ms'], 'receipt': target.name, 'receipt_sha256': digest(target),
            'receipt_status': 'observed', 'source': 'ui_observation'})
    posts = [r for r in receipts if r.get('method') == 'POST' and r.get('marker') == marker
             and r.get('complete_marker_body') is True and r.get('status') == 200]
    if len(posts) != 1:
        raise ValueError('expected one complete business POST receipt')
    target = capture / 'business-server-post.json'
    write_json(target, {'session_id': session, 'receipt': posts[0],
                       'scope': 'owned server reception; app attribution checked separately'})
    rows.append({'session_id': session, 'package': package, 'action': 'server_post_received',
        'ts_ms': posts[0]['ts_ms'], 'receipt': target.name, 'receipt_sha256': digest(target),
        'receipt_status': 'observed', 'source': 'owned_fixture_receipt'})
    return _write_actions(capture, rows)


def seal_ha_states(capture, steps, *, package, user, entity):
    """Bind the two independently observed HA REST state changes to this capture."""
    capture = Path(capture)
    session = _observed_session(capture, package, user)
    changes = [(step['start_ms'], step['server']) for step in steps]
    if (len(changes) != 2 or changes[0][1]['state'] == changes[1][1]['state']
            or not all(0 < start <= state['observed_ms'] and state['last_changed']
                       for start, state in changes)):
        raise ValueError('expected two distinct, freshly observed HA server states')
    rows = []
    for number, (start, state) in enumerate(changes, 1):
        target = capture / f'business-ha-state-{number:02d}.json'
        with target.open('x', encoding='utf-8') as handle:
            json.dump({'session_id': session, 'entity_id': entity, 'action_start_ms': start,
                       'state': state['state'], 'last_changed': state['last_changed'],
                       'observed_ms': state['observed_ms']}, handle, ensure_ascii=False)
        rows.append({'session_id': session, 'package': package, 'action': 'ha_state_changed',
            'ts_ms': state['observed_ms'], 'receipt': target.name, 'receipt_sha256': digest(target),
            'receipt_status': 'observed', 'source': 'owned_fixture_receipt'})
    return _write_actions(capture, rows)


def seal_playback_steps(capture, steps, *, package, user, item_id):
    """Seal same-item REST progress and a matching listening-session increment."""
    capture = Path(capture)
    session = _observed_session(capture, package, user)
    receipts = []
    if [step['phase'] for step in steps] != ['foreground', 'background']:
        raise ValueError('expected foreground and background playback receipts')
    for step in steps:
        before, after, paused = (step[key] for key in ('before', 'after', 'paused_control'))
        prior = {row['id']: row for row in before['sessions']}
        changed = [row for row in after['sessions']
                   if row['timeListening'] > prior.get(row['id'], {}).get('timeListening', 0)
                   and row['updatedAt'] > prior.get(row['id'], {}).get('updatedAt', 0)]
        if (step['activity_confirmed'] is not True or len(changed) != 1
                or not before['observed_ms'] < after['observed_ms'] < paused['observed_ms']
                or type(after['progress']) not in (int, float) or after['progress'] == before['progress']
                or after['progress'] != paused['progress'] or paused['sessions'] != after['sessions']):
            raise ValueError('playback receipt lacks a fresh, stable same-item server observation')
        row = changed[0]
        receipts.append({'session_id': session, 'item_id': item_id, 'phase': step['phase'],
                         'server_session_id': row['id'], 'server_updated_ms': row['updatedAt'],
                         'listening_delta_s': row['timeListening'] - prior.get(row['id'], {}).get('timeListening', 0),
                         'progress_s': after['progress'], 'observed_ms': after['observed_ms'],
                         'previous_progress_s': before['progress'], 'paused_recheck_ms': paused['observed_ms']})
    rows = []
    for receipt in receipts:
        target = capture / ('business-playback-' + receipt['phase'] + '.json')
        with target.open('x', encoding='utf-8') as handle:
            json.dump(receipt, handle, ensure_ascii=False)
        rows.append({'session_id': session, 'package': package, 'action': 'playback_' + receipt['phase'],
                     'ts_ms': receipt['observed_ms'], 'receipt': target.name, 'receipt_sha256': digest(target),
                     'receipt_status': 'observed', 'source': 'owned_fixture_receipt'})
    return _write_actions(capture, rows)
