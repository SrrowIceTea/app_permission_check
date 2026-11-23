"""Synthetic B1 workflow checks. The fixture files carry no device acceptance."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4
from zipfile import ZipFile

from core.io_utils import load_jsonl
from vehicle.bench.blind_round import compare
from vehicle.bench.blind_signoff import finalize
from vehicle.bench.label_gate import classify_label
from vehicle.bench.window_calibration import calibrate
from vehicle.bench.window_review import PACKAGE, SOURCE_FILES, prepare
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json, write_json
from vehicle.pipeline.test_support import make_capture, seal_capture


class WindowReviewTests(unittest.TestCase):
    def setUp(self):
        (ROOT / 'output').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'output')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.capture, self.hooks = make_capture(self.root)
        self.rules = ROOT / 'vehicle/rules/rules_library/rules.db'
        self.reference = self.root / 'initial-labels.json'
        self.out = self.root / 'review'
        self.prepare_fixture()

    def prepare_fixture(self):
        rows = load_jsonl(self.capture / 'reads.jsonl')
        template = rows.pop()
        actions, values, flows = [], {}, []
        modes = [('cache_clear', 1000), ('network_enqueue', 3000), ('plain', 45000),
                 ('cache_flush', 46000), ('mismatch', 47000)]
        for mode, ts in modes:
            token = 'synthetic_' + mode
            receipt = self.root / (mode + '-receipt.json')
            fields = {'network_failed': True, 'cached_batches': 1} if mode == 'network_enqueue' else {}
            write_json(receipt, {'mode': mode, 'token': token, 'completed': True, **fields})
            actions.append({'mode': mode, 'token': token, 'sha256': digest(receipt),
                            'start_ms': ts, 'end_ms': ts + 200})
            if mode in ('network_enqueue', 'plain', 'mismatch'):
                rows.append({**template, 'pkg': PACKAGE, 'pid': 201,
                             'evt_id': 10 + 10 * len(values), 'ts': ts - 1000,
                             'host_received_ts': ts + 50, 'stack': 'Fixture.VhalReader.readOne(L:1)'})
                values[mode] = {'propertyId': template['prop_id'], 'property': template['prop_name'],
                                'value': 'CONTROL-DIFFERENT-VALUE' if mode == 'mismatch' else '4',
                                'result': 'ok', 'readAtUtcMs': ts - 1005}
            if mode in ('plain', 'cache_flush', 'mismatch'):
                body = {'scenarioToken': token, 'reads': [values['network_enqueue' if mode == 'cache_flush' else mode]]}
                if mode == 'cache_flush':
                    body['sourceBatchTokens'] = ['synthetic_network_enqueue']
                flows.append({'src': 'proxy', 'evt_id': 1 + len(flows), 'package': PACKAGE, 'uid': 1010123,
                              'session_id': 's1', 'ts': ts + 120, 'path': '/collect', 'method': 'POST',
                              'status_code': 200, 'attribution': 'app_process_hook', 'attribution_ambiguous': False,
                              'request_payload': {'text': json.dumps(body)}})
        for name, records in (('reads', rows), ('flows', flows)):
            (self.capture / (name + '.jsonl')).write_text(
                ''.join(json.dumps(row) + '\n' for row in records), encoding='utf-8')
        manifest = read_json(self.capture / 'session-manifest.json')
        seal_capture(self.capture, {**manifest, 'android_version': '15', 'packages': [PACKAGE]})
        action_file = self.root / 'actions.json'
        write_json(action_file, actions)
        for name in SOURCE_FILES:
            (self.root / name).write_text('synthetic fixture source', encoding='utf-8')
        sources = [action_file, *(self.root / name for name in SOURCE_FILES), *self.root.glob('*-receipt.json')]
        write_json(self.reference, {'sample_class': 'owned_fixture', 'apk_sha256': 'a' * 64, 'session_id': 's1',
                                    'expected_pairs': [['PRIOR_PREDICTIONS_DO_NOT_SHIP', 1, 1]],
                                    'reference_evidence': [{'file': str(path), 'sha256': digest(path)}
                                                           for path in sources]})

    def prepare(self):
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,)):
            return prepare(self.root, self.reference, self.rules, self.out)

    def test_prepare_uses_raw_pairs_and_signs_as_owned_fixture(self):
        plan = self.prepare()
        self.assertEqual(9, len(plan['items']))
        self.assertEqual('subagent', plan['review_mode'])
        positives = {(10, 2), (20, 1)}
        answers, frozen = [], []
        for slot in ('A', 'B'):
            with ZipFile(self.out / f'reviewer-{slot}.zip') as pack:
                frozen.append(pack.read('evidence.json'))
                self.assertNotIn(b'PRIOR_PREDICTIONS_DO_NOT_SHIP', frozen[-1])
                answer = json.loads(pack.read('review.json'))
            answer.update(reviewer=f'Synthetic reviewer {slot}', agent_id=f'synthetic-{slot}',
                          review_session_id=str(uuid4()), reviewed_at='2026-11-21T12:00:00+08:00')
            for row, item in zip(answer['decisions'], plan['items'], strict=True):
                pair = item['pair']
                row.update(decision='present' if (pair[2], pair[4]) in positives else 'absent',
                           reason='synthetic decision')
            path = self.root / f'{slot}.json'
            write_json(path, answer)
            answers.append(path)
        self.assertEqual(frozen[0], frozen[1])

        organizer, compared = self.out / 'organizer-only', self.root / 'compared'
        compare(organizer, *answers, compared)
        form = read_json(compared / 'signoff-request.json')
        form.update(confirmed=True, reviewer='Synthetic adjudicator', reviewer_kind='subagent',
                    agent_id='synthetic-C', review_session_id=str(uuid4()),
                    reviewed_at='2026-11-21T12:00:01+08:00')
        for item in form['controls']:
            pair = item['pair']
            item.update(negative_control=(pair[2], pair[4]) == (30, 3), reason='synthetic control decision')
        signoff = self.root / 'C.json'
        write_json(signoff, form)
        signed = finalize(organizer, *answers, signoff, self.root / 'signed')
        label = read_json(signed)['samples'][0]
        self.assertEqual(('owned_fixture', 'signed', 'not_applicable'),
                         (label['sample_origin'], label['subagent_signoff'], label['human_signoff']))
        self.assertFalse(classify_label(label)['usable_as_gold'])
        with patch('vehicle.pipeline.preflight.HOOK_DIRS', (self.hooks,)):
            replay = calibrate(self.capture, signed, (30000,), pairing='token')
        self.assertEqual('subagent', replay['review_mode'])
        self.assertEqual('signed', replay['subagent_signoff'])

    def test_tampered_or_missing_source_ref_prevents_export(self):
        source = self.root / SOURCE_FILES[0]
        source.write_text('modified fixture source', encoding='utf-8')
        with self.assertRaisesRegex(AuditError, '摘要不一致'):
            self.prepare()
        self.assertFalse(self.out.exists())


if __name__ == '__main__':
    unittest.main()
