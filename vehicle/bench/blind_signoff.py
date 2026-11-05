"""Finalize a blind pair label from a separately submitted human signoff."""
import argparse
from pathlib import Path

from vehicle.bench.blind_round import build_comparison
from vehicle.bench.labels import adjudicated_labels, pair_key
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

BINDINGS = ('plan_sha256', 'evidence_sha256', 'review_sha256')


def signoff_request(comparison, label, items):
    if not label or any(review.get('reviewer_kind') != 'human' for review in label['reviews']):
        return None
    return {'schema_version': 1, **{key: comparison[key] for key in BINDINGS},
            'reviewer': None, 'reviewer_kind': None, 'reviewed_at': None, 'confirmed': False,
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
        raise ValueError('formal signoff needs two declared human reviews and sufficient pair evidence')
    signoff_hash = digest(signoff)
    submitted = read_json(signoff)
    if (submitted.get('schema_version') != 1 or submitted.get('reviewer_kind') != 'human'
            or submitted.get('confirmed') is not True or any(submitted.get(key) != request[key] for key in BINDINGS)):
        raise ValueError('human signoff does not match the frozen plan, evidence and answer digests')
    controls = confirmed_rows(submitted, request, 'controls', 'negative_control')
    disputes = confirmed_rows(submitted, request, 'disagreements', 'present')
    label.update(human_signoff='signed', **{key: submitted[key] for key in ('reviewer', 'reviewer_kind', 'reviewed_at')},
                 adjudication={**{key: submitted[key] for key in ('reviewer', 'reviewer_kind', 'reviewed_at')},
                               'decisions': list(disputes.values())},
                 universe=list(controls.values()), review_bindings={key: request[key] for key in BINDINGS},
                 signoff_sha256=signoff_hash)
    first_votes = {pair_key(row['pair']): row['present'] for row in label['reviews'][0]['decisions']}
    label['expected_pairs'] = [item['pair'] for item in items if disputes.get(item['id'], {}).get(
        'present', first_votes[pair_key(item['pair'])])]
    adjudicated_labels(label, label['apk_sha256'], label['session_id'], 'independent', root=root)
    if digest(signoff) != signoff_hash:
        raise ValueError('human signoff changed during validation')
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
