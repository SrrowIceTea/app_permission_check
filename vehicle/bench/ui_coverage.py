"""Score annotated pages and actions against sealed owned-fixture runs."""
import argparse
from pathlib import Path
import sys

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import digest, read_json, write_json

REFERENCE = Path(__file__).with_name('ui-coverage-reference.json')
MULTIPAGE_REFERENCE = Path(__file__).with_name('ui-coverage-multipage.json')
MODES = ('manual', 'automatic')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def metric(items, covered):
    ids = [item['id'] for item in items]
    return {'covered': len(covered), 'annotated': len(ids), 'hits': covered,
            'percentage': round(100 * len(covered) / len(ids), 2),
            'misses': [identity for identity in ids if identity not in covered]}


def score_run(folder, fixture, reference, mode):
    capture = folder / 'capture'
    manifest = read_json(capture / 'session-manifest.json')
    verification = read_json(capture / 'verification.json')
    observation_path = folder / 'ui-observations.json'
    observation = read_json(observation_path)
    session, package, user = manifest['session'], fixture['package'], observation['user']
    require(verification.get('passed') is True and verification.get('session') == session,
            'capture health or session mismatch')
    require(verification.get('tls_bypass') is False and manifest['capture_switches']['tls_bypass'] is False,
            'capture used a different TLS setting')
    require(manifest['packages'] == [package] and observation['package'] == package
            and manifest['installed_apk_sha256'] == observation['apk_sha256'] == fixture['apk_sha256'],
            'package or APK identity mismatch')
    require(manifest['user_id'] == user and observation['session'] == session and observation['mode'] == mode
            and observation['window_seconds'] == reference['window_seconds'],
            'user, session, mode or window mismatch')
    dependencies = ('reads.jsonl', 'verification.json')
    require(all(manifest['input_sha256'][name] == digest(capture / name) for name in dependencies),
            'capture evidence digest mismatch')

    rows = load_jsonl(capture / 'reads.jsonl')
    relevant = [row for row in rows if row.get('session_id') == session]
    require(len(relevant) == len(rows) and rows, 'mixed or empty runtime evidence')
    armed_times = [row['host_received_ts'] for row in relevant
                   if row.get('src') == 'vhal' and row.get('ev') == 'ARMED']
    require(armed_times and observation['finished_ms'] >= min(armed_times), 'invalid capture window')
    start, end = min(armed_times), observation['finished_ms']
    multipage = reference.get('schema') == 2
    if multipage:
        end = min(end, start + reference['window_seconds'] * 1000)
    explorer = verification.get('ui_exploration')
    if mode == 'automatic':
        require(explorer and (explorer['session'], explorer['package'], explorer['user']) == (session, package, user)
                and not observation['manual_actions'], 'automatic run identity or operator actions inconsistent')
        require(explorer['status'] in ('completed', 'stopped'), 'automatic exploration did not complete safely')
        actions = explorer['actions']
    else:
        require(explorer is None, 'manual run contains automatic input')
        actions = observation['manual_actions']
    views = explorer['views'] if multipage and explorer else observation['views']
    require((bool(views) if multipage else len(views) == 2)
            and all(start <= view['ts_ms'] <= end for view in views)
            and views == sorted(views, key=lambda view: view['ts_ms']), 'invalid activity observations')
    require(all(start <= action['ts_ms'] <= end for action in actions), 'action outside capture')
    require(actions == sorted(actions, key=lambda action: action['ts_ms']), 'actions out of order')
    pages = {}
    activities = {page['id']: page['activity'] for page in reference['pages']}
    for page in reference['pages']:
        hit = next((view for view in views if view['activity'] == page['activity']), None)
        if hit:
            pages[page['id']] = hit['ts_ms']
    hits = {}
    for rule in reference['actions']:
        for index, action in enumerate(actions):
            matched = action.get('resource_id') == f"{package}:id/{rule['control']}"
            if not multipage and mode == 'automatic' and 'resource_id' not in action:
                # Older frozen explorer records identify their single fixture tap by label.
                matched = bool(rule.get('automatic_label')) and action.get('label') == rule['automatic_label']
            if not matched or action.get('kind') != 'tap' or action.get('status') != 'sent':
                continue
            ts = action['ts_ms']
            next_ts = actions[index + 1]['ts_ms'] if index + 1 < len(actions) else end + 1
            limit = min(next_ts, ts + 8000)
            if multipage:
                source = activities[rule['page']]
                current = next((view['activity'] for view in reversed(views) if view['ts_ms'] <= ts), None)
                if action.get('activity') != source or current != source:
                    continue
                if 'destination' in rule:
                    arrival = next((view for view in views if ts < view['ts_ms'] < limit), None)
                    if arrival and arrival['activity'] == activities[rule['destination']]:
                        hits[rule['id']] = {'action_ms': ts, 'arrival_ms': arrival['ts_ms'],
                                            'destination_activity': arrival['activity']}
                        break
                    continue
            within = [event for event in relevant if event.get('pkg') == package
                      and ts <= event.get('host_received_ts', -1) < limit]
            prefix = fixture.get('stack_package', package)
            proof = [event for event in within if event.get('ev') in rule['events']
                     and prefix + '.' + rule['stack'] in (event.get('stack') or '')
                     and (not multipage or (event.get('outcome') == 'ok'
                                            and event.get('prop_name') == rule['property']))]
            if proof:
                registrations = rule.get('accepted_registration')
                if registrations:
                    accepted = [event for event in within if event.get('ev') in registrations
                                and event.get('accepted') is True]
                    if not accepted:
                        continue
                    first = min(event['host_received_ts'] for event in accepted)
                    proof = [event for event in proof if event['host_received_ts'] >= first]
                    if not proof:
                        continue
                    proof = accepted + proof
                hits[rule['id']] = {'action_ms': ts, 'event_ids': [event['evt_id'] for event in proof]}
                break
    return {'session': session, 'package': package, 'mode': mode, 'user': user,
            'page_coverage': metric(reference['pages'], pages),
            'action_coverage': metric(reference['actions'], hits),
            'stop_reason': explorer['reason'] if explorer else 'operator_reference_finished',
            'inputs_sha256': {'ui-observations.json': digest(observation_path),
                              **{name: manifest['input_sha256'][name] for name in dependencies}}}


def score(root, reference_path=REFERENCE):
    reference = read_json(reference_path)
    require(reference['schema'] in (1, 2), 'unsupported UI annotation schema')
    runs = {}
    for identity, fixture in reference['fixtures'].items():
        runs[identity] = {mode: score_run(root / f'{identity}-{mode}', fixture, reference, mode)
                          for mode in MODES}
    sessions = [result['session'] for comparison in runs.values() for result in comparison.values()]
    require(len(sessions) == len(set(sessions)), 'comparison reuses a capture session')
    require(all(lane['manual'][metric_name]['covered'] == lane['manual'][metric_name]['annotated']
                for lane in runs.values() for metric_name in ('page_coverage', 'action_coverage')),
            'manual reference did not cover all annotated pages and actions')
    return {'schema': reference['schema'], 'sample_origin': 'owned_fixture', 'reference_sha256': digest(reference_path),
            'window_seconds': reference['window_seconds'], 'runs': runs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--reference', default=REFERENCE, type=Path)
    args = parser.parse_args()
    try:
        result = score(args.root, args.reference)
        write_json(args.out, result)
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f'UI coverage inputs rejected: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
