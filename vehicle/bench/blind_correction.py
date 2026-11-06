"""Bind a corrected blind round to the previous AI review without carrying its signoff."""
import argparse
from datetime import datetime
from pathlib import Path

from vehicle.bench.labels import pair_key, reference_identity
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

BROWSER_FIELDS = ('proxy_observed_post', 'post_marker_matched', 'post_flow_attributed')


def frozen_round(path):
    plan_path, evidence_path = path / 'plan.json', path / 'evidence.json'
    plan = read_json(plan_path)
    if digest(evidence_path) != plan['evidence_sha256']:
        raise ValueError('frozen evidence digest mismatch')
    return plan, read_json(evidence_path)


def source_path(ref, root):
    path, = reference_identity([ref], root)
    return path


def binding_ref(path, root):
    return {'path': path.resolve().relative_to(root).as_posix(), 'sha256': digest(path)}


def validate_revision(old, new, old_evidence, new_evidence, root):
    if any(old[key] != new[key] for key in ('suite_sha256', 'cases', 'items')):
        raise ValueError('corrected round changed the frozen cases or questions')
    if len(old_evidence['cases']) != len(new_evidence['cases']):
        raise ValueError('corrected round changed the number of evidence cards')
    for binding, before, after in zip(old['cases'], old_evidence['cases'], new_evidence['cases'], strict=True):
        facts = after['facts']
        if binding['id'] in ('mg4-post', 'mg4-webview-post'):
            business = read_json(source_path(binding['sources']['business'], root))
            if any(key not in facts or key not in business or facts[key] != business[key] for key in BROWSER_FIELDS):
                raise ValueError('corrected browser card does not match sealed proxy and receipt facts')
            facts = {key: value for key, value in facts.items() if key not in BROWSER_FIELDS}
        if before != (after | {'facts': facts}):
            raise ValueError('unexpected changes to frozen evidence card: ' + binding['id'])


def pair_material(old_label, binding, items, controls):
    label = old_label.copy()
    if any(label[key] != binding[key] for key in ('id', 'apk_sha256', 'session_id')):
        raise ValueError('previous labels do not match the frozen HA battery case')
    pairs = {item['id']: pair_key(item['pair']) for item in items}
    if {pair_key(entry['pair']) for entry in label['universe']} != set(pairs.values()):
        raise ValueError('previous label universe does not match the frozen questions')
    answers = [{pair_key(row['pair']): row['present'] for row in review['decisions']}
               for review in label['reviews']]
    if (len(answers) != 2 or answers[0] != answers[1] or set(answers[0]) != set(pairs.values())
            or any(type(value) is not bool for value in answers[0].values())):
        raise ValueError('pair correction requires complete and agreeing previous answers')
    if {key for key, pair in pairs.items() if not answers[0][pair]} != controls:
        raise ValueError('AI control review does not agree with the frozen negative pairs')
    label.update(expected_pairs=[list(pair) for pair in pairs.values() if answers[0][pair]],
        universe=[{'id': key, 'pair': list(pair), 'negative_control': key in controls}
                  for key, pair in pairs.items()], origin='agent_review', human_signoff='pending',
        reviews=[review | {'reviewer_kind': 'ai'} for review in label['reviews']],
        adjudication={'reviewer': None, 'reviewer_kind': None, 'reviewed_at': None, 'decisions': []})
    return label


def workflow_material(item_id, binding, votes, source, root):
    if votes['case'] != binding['id'] or any(votes[slot]['decision'] != 'absent' for slot in ('A', 'B')):
        raise ValueError('workflow control does not agree with the previous review: ' + item_id)
    business = read_json(source_path(binding['sources']['business'], root))
    if item_id == 'W02':
        if not all(business['checks'].get(key) is True for key in ('status_503', 'no_successful_controls')):
            raise ValueError('HA 503 control is missing its independent verification')
        outcome = {'outcome': 'no_successful_http_control', 'http_status': 503}
    else:
        if (business.get('status') != 'post_body_attribution_gap'
                or business.get('proxy_observed_post') is not True or business.get('post_marker_matched') is not True
                or type(business.get('post_flow_attributed')) is not int or business['post_flow_attributed'] != 0):
            raise ValueError('MG4 attribution control is missing the expected proxy or receipt facts')
        outcome = {'outcome': business['status'], **{key: business[key] for key in BROWSER_FIELDS}}
    return {'id': item_id, 'case': binding['id'], 'apk_sha256': binding['apk_sha256'],
            'session_id': binding['session_id'], 'origin': 'agent_review', 'reviewer_kind': 'ai', **source,
            'present': False, 'negative_control': True, 'metrics_eligible': False,
            'human_signoff': 'pending', 'reference_evidence': binding['sources'], 'observations': outcome}


def correct(previous, revised, ai_review, output, root=ROOT):
    root = Path(root).resolve()
    old, old_evidence = frozen_round(previous)
    new, new_evidence = frozen_round(revised)
    validate_revision(old, new, old_evidence, new_evidence, root)
    record = read_json(ai_review)
    if (record['signoff_kind'] != 'ai_adjudicator' or record['conclusion']['status'] != 'not_signed'
            or not record['signer'] or datetime.fromisoformat(record['reviewed_at']).utcoffset() is None):
        raise ValueError('correction requires the original unsigned AI review')
    refs = record['materials']
    reference_identity(list(refs.values()), root)
    if refs['organizer_plan']['sha256'] != digest(previous / 'plan.json') or (
            refs['frozen_evidence_json']['sha256'] != old['evidence_sha256']):
        raise ValueError('AI review does not reference the previous frozen materials')
    controls = {row['id'] for row in record['items'] if row['my_decision'] == {'present': False, 'negative_control': True}}
    if len(controls) != len(record['items']) or {key for key in controls if key.startswith('W')} != {'W02', 'W03'}:
        raise ValueError('AI control record is incomplete or contains duplicate items')
    old_label, = read_json(source_path(refs['labels_draft'], root))['samples']
    pair_items = [item for item in new['items'] if 'pair' in item]
    bindings = {binding['id']: binding for binding in new['cases']}
    questions = {item['id']: item['case'] for item in new['items']}
    votes = {row['id']: row for row in read_json(source_path(refs['workflow_reviews'], root))}
    for binding in new['cases']:
        reference_identity(list(binding['sources'].values()), root)
    label = pair_material(old_label, bindings['ha-battery'], pair_items, controls - {'W02', 'W03'})
    reviewer = {'reviewer': record['signer'], 'reviewed_at': record['reviewed_at']}
    label.update(reviewer_kind='ai', **reviewer, previous_evidence_sha256=old['evidence_sha256'],
                 corrected_evidence_sha256=new['evidence_sha256'])
    workflows = [workflow_material(key, bindings[questions[key]], votes[key], reviewer, root)
                 for key in ('W02', 'W03')]
    output.mkdir(parents=True, exist_ok=False)
    write_json(output / 'labels-reviewed.json', {'samples': [label]})
    write_json(output / 'workflow-labels.json', {'schema_version': 1, 'items': workflows})
    summary = {'status': 'awaiting_review_of_corrected_materials', 'accuracy': 'not_measured',
               'pair_candidates': len(label['universe']), 'expected_pairs': len(label['expected_pairs']),
               'pair_negative_controls': len(controls) - len(workflows), 'workflow_negative_controls': len(workflows),
               'previous_plan': binding_ref(previous / 'plan.json', root),
               'corrected_plan': binding_ref(revised / 'plan.json', root),
               'corrected_evidence': binding_ref(revised / 'evidence.json', root),
               'ai_review': binding_ref(ai_review, root),
               'pair_labels': binding_ref(output / 'labels-reviewed.json', root),
               'workflow_labels': binding_ref(output / 'workflow-labels.json', root)}
    write_json(output / 'review-material.json', summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('previous', 'revised', 'ai-review', 'out'):
        parser.add_argument('--' + option, type=Path, required=True)
    args = parser.parse_args()
    print(correct(args.previous, args.revised, args.ai_review, args.out)['status'])


if __name__ == '__main__':
    main()
