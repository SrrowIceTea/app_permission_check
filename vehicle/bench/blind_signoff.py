"""Finalize source-labelled subagent or human signoff. 仅用于授权测试。"""
import argparse
from pathlib import Path

from vehicle.bench.blind_round import build_comparison
from vehicle.bench.labels import adjudicated_labels, pair_key
from vehicle.bench.review_policy import AGENT_MODES, reviewer_kind, identity, signoff_fields, validate_agents
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

BINDINGS = ('plan_sha256', 'evidence_sha256', 'review_sha256')


def signoff_request(comparison, label, items):
    mode = comparison.get('review_mode', 'human')
    if not label or any(review.get('reviewer_kind') != reviewer_kind(mode) for review in label['reviews']):
        return None
    return {'schema_version': 1, **{key: comparison[key] for key in BINDINGS},
            'review_mode': mode,
            'reviewer': None, 'reviewer_kind': None, 'reviewed_at': None, 'confirmed': False,
            **({'agent_id': None, 'context_mode': 'fresh', 'review_session_id': None,
                'model_family': None, 'model_id': None}
               if mode in AGENT_MODES else {}),
            'controls': [{'id': item['id'], 'pair': item['pair'], 'negative_control': None, 'reason': None}
                         for item in items],
            'disagreements': [{'id': item['id'], 'pair': item['pair'], 'present': None, 'reason': None}
                              for item in comparison['disagreements'] if 'pair' in item]}


def confirmed_rows(submission, request, key, decision):
    expected = {row['id']: row['pair'] for row in request[key]}
    rows = submission.get(key)
    if not isinstance(rows, list) or len(rows) != len(expected):
        raise ValueError('signoff must cover all ' + key)
    actual = {}
    for row in rows:
        item = row['id']
        if (item not in expected or item in actual or row.get('pair') != expected[item]
                or type(row.get(decision)) is not bool
                or not isinstance(row.get('reason'), str) or not row['reason'].strip()):
            raise ValueError('missing, duplicate or invalid signoff item: ' + str(item))
        actual[item] = row
    return actual


def finalize(private, first, second, signoff, output, root=ROOT):
    comparison, _, label, items = build_comparison(private, first, second, root)
    request = signoff_request(comparison, label, items)
    if request is None:
        raise ValueError('formal signoff needs two declared human reviews or two isolated subagent reviews '
                         'and sufficient pair evidence')
    signoff_hash = digest(signoff)
    submitted = read_json(signoff)
    mode = request['review_mode']
    if (submitted.get('schema_version') != 1 or submitted.get('reviewer_kind') != reviewer_kind(mode)
            or submitted.get('review_mode', 'human') != mode
            or submitted.get('confirmed') is not True or any(submitted.get(key) != request[key] for key in BINDINGS)):
        raise ValueError('signoff does not match the review mode, frozen plan, evidence and answer digests')
    if mode in AGENT_MODES:
        validate_agents([*label['reviews'], submitted],
                        require_distinct_models=(mode == 'cross_model'))
    controls = confirmed_rows(submitted, request, 'controls', 'negative_control')
    disputes = confirmed_rows(submitted, request, 'disagreements', 'present')
    label.update(**signoff_fields(mode, 'signed'), **identity(submitted),
                 adjudication={**identity(submitted),
                               'decisions': list(disputes.values())},
                 universe=list(controls.values()), review_bindings={key: request[key] for key in BINDINGS},
                 signoff_sha256=signoff_hash)
    first_votes = {pair_key(row['pair']): row['present'] for row in label['reviews'][0]['decisions']}
    label['expected_pairs'] = [item['pair'] for item in items if disputes.get(item['id'], {}).get(
        'present', first_votes[pair_key(item['pair'])])]
    adjudicated_labels(label, label['apk_sha256'], label['session_id'], label['sample_origin'], root=root)
    if digest(signoff) != signoff_hash:
        raise ValueError('signoff changed during validation')
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / 'labels-signed.json', {'samples': [label]})
    return output / 'labels-signed.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('organizer', 'review-a', 'review-b', 'signoff', 'out'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    try:
        path = finalize(args.organizer, args.review_a, args.review_b, args.signoff, args.out)
    except (KeyError, TypeError, ValueError, OSError) as error:
        parser.exit(1, f'签核未通过。{error}\n')
    print(path)


if __name__ == '__main__':
    main()
