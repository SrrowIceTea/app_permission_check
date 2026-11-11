"""Seal actual browser UI/server observations before capture finishes. 授权测试专用。"""
import json
import shutil
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import digest, write_json
from vehicle.pipeline.session_binding import ACTIONS_FILE


def seal_browser(capture, actions, receipts, ui_folder, package, marker):
    """Receipts prove observed UI/HTTP reception; attribution is checked separately."""
    capture, ui_folder = Path(capture), Path(ui_folder)
    sessions = {r.get('session_id') for r in load_jsonl(capture / 'reads.jsonl')
                if r.get('pkg') == package and r.get('user_id') == 10}
    if len(sessions) != 1 or not next(iter(sessions)):
        raise ValueError('browser receipt sealing requires one observed app session')
    session = next(iter(sessions))
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
    with (capture / ACTIONS_FILE).open('x', encoding='utf-8') as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + '\n')
    return rows
