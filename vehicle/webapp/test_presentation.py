"""投影层回归：finding_uid 稳定、规则标题中英取值、四档计数与阶段耗时。

合成数据只验证投影行为，不代表任何设备证据。
"""
import json
import unittest

from vehicle.webapp.observation import annotate, observation
from vehicle.webapp.presentation import count_bands, finding_uids, stage_timings
from vehicle.webapp.rule_titles import resolve
from vehicle.webapp.workflow import RULES


def row(**extra):
    base = {'rule_id': 'VSC-R002', 'conclusion_level': 'observed'}
    base.update(extra)
    return base


class FindingUidTest(unittest.TestCase):
    def test_same_input_rerun_keeps_uids(self):
        rows = [row(event_ids=['e2', 'e1']), row(rule_id='VSC-E002', conclusion_level='candidate')]
        self.assertEqual(finding_uids(rows), finding_uids(json.loads(json.dumps(rows))))

    def test_event_and_location_order_do_not_change_uid(self):
        first = row(event_ids=['e1', 'e2'], code_locs=[{'file': 'a.java', 'line': 3},
                                                       {'file': 'b.java', 'line': 9}])
        second = row(event_ids=['e2', 'e1'], code_locs=[{'file': 'b.java', 'line': 9},
                                                        {'file': 'a.java', 'line': 3}])
        self.assertEqual(finding_uids([first]), finding_uids([second]))

    def test_content_change_changes_uid(self):
        base = finding_uids([row()])[0]
        self.assertNotEqual(base, finding_uids([row(rule_id='VSC-R003')])[0])
        self.assertNotEqual(base, finding_uids([row(conclusion_level='candidate')])[0])
        self.assertNotEqual(base, finding_uids([row(event_ids=['e1'])])[0])

    def test_identical_rows_get_stable_distinct_suffixes(self):
        rows = [row(), row(), row(rule_id='VSC-E002')]
        uids = finding_uids(rows)
        self.assertEqual(3, len(set(uids)))
        self.assertTrue(uids[0].endswith('-1'))
        self.assertTrue(uids[1].endswith('-2'))
        self.assertFalse(uids[2].endswith('-1'))
        # 重跑同一输入：序号分配必须指向同一行
        self.assertEqual(uids, finding_uids([row(), row(), row(rule_id='VSC-E002')]))

    def test_index_id_is_not_overwritten(self):
        rows = [row(finding_id='finding-7')]
        finding_uids(rows)
        self.assertEqual('finding-7', rows[0]['finding_id'])


class RuleTitleTest(unittest.TestCase):
    def test_chinese_mapping_wins_and_marks_locale(self):
        resolved, _, _ = resolve(RULES, '15')
        label = resolved['VSC-R002']
        self.assertEqual('读取车辆速度', label['title'])
        self.assertEqual('zh', label['locale'])
        self.assertIn('rule_titles.zh.json', label['source'])

    def test_database_chinese_title_is_kept(self):
        resolved, _, _ = resolve(RULES, '15')
        label = resolved['VSC-GR-location']
        self.assertEqual('zh', label['locale'])
        self.assertIn('rules.db', label['source'])
        self.assertIn('位置', label['title'])

    def test_unmapped_english_title_falls_back(self):
        resolved, _, _ = resolve(RULES, '15')
        for label in resolved.values():
            self.assertTrue(label['title'].strip())
            self.assertIn(label['locale'], ('zh', 'en'))
        self.assertNotIn('VSC-LAB-OWNTRACKS-LOCATION-001', resolved)

    def test_unknown_rule_has_no_title(self):
        resolved, reasons, _ = resolve(RULES, '15')
        self.assertNotIn('VSC-NOT-A-RULE', resolved)
        self.assertNotIn('VSC-NOT-A-RULE', reasons)


class CountAndTimingTest(unittest.TestCase):
    def test_four_bands_always_present(self):
        bands, raw, gaps = count_bands({'findings_total': 11,
                                        'findings_by_conclusion_level': {'observed': 5, 'candidate': 6}})
        self.assertEqual({'correlated': 0, 'observed': 5, 'candidate': 6, 'unjudged': 0}, bands)
        self.assertEqual({'observed': 5, 'candidate': 6}, raw)
        self.assertEqual({}, gaps)

    def test_missing_summary_is_null_not_zero(self):
        bands, raw, gaps = count_bands(None)
        self.assertEqual({'correlated': None, 'observed': None, 'candidate': None, 'unjudged': None}, bands)
        self.assertIsNone(raw)
        self.assertIn('findings_by_conclusion_level', gaps)

    def test_skipped_and_open_stages_have_no_duration(self):
        stages = [{'id': 'static', 'label': '静态'}, {'id': 'capture', 'label': '采集'},
                  {'id': 'audit', 'label': '审计'}]
        rows = [{'stage': 'static', 'status': 'running', 'ts': 10.0},
                {'stage': 'static', 'status': 'done', 'ts': 12.5},
                {'stage': 'capture', 'status': 'skipped', 'ts': 13.0}]
        timings = stage_timings(rows, stages)
        self.assertEqual(2500, timings[0]['duration_ms'])
        self.assertIsNone(timings[1]['duration_ms'])
        self.assertIn('跳过', timings[1]['unavailable_reason'])
        self.assertIsNone(timings[2]['duration_ms'])
        self.assertEqual('pending', timings[2]['status'])


class ObservationProjectionTest(unittest.TestCase):
    """三态投影：只按 general_privacy 与结论行分档，不把注册当读取、不把未观测当安全。"""

    def general(self, **overrides):
        data = {'by_data_type': {'location': {'obtained': 2}, 'microphone': {},
                                 'contacts': {'denied': 1}, 'android_id': {}, 'advertising_id': {}},
                'registrations': {'events': 2, 'by_data_type': {'location': {'listener_registration': 2}}},
                'hook_gaps': [{'where': 'api_unavailable', 'evt_id': 3, 'message':
                               'android.provider.Settings$Secure.getString('
                               '(Landroid/content/ContentResolver;Ljava/lang/String;)'
                               'Ljava/lang/String;: Error: java.lang.ClassNotFoundException'}]}
        data.update(overrides)
        return data

    def test_states_are_distinct_and_never_imply_safety(self):
        rows = [{'data_type': 'location', 'rule_id': 'VSC-GR-location',
                 'observed_basis': {'value_hash_present': 2},
                 'read_evidence': [{'evt_id': 5}, {'evt_id': 9}]}]
        data = observation({'general_privacy': self.general()}, rows)
        items = {item['data_type']: item for item in data['data_types']}
        self.assertEqual('observed', items['location']['state'])
        self.assertEqual(2, items['location']['value_hash_present'])
        self.assertEqual([5, 9], items['location']['evidence_event_ids'])
        self.assertEqual('read_not_obtained', items['contacts']['state'])
        self.assertEqual('no_events_in_session', items['microphone']['reason_code'])
        self.assertEqual('no_events_with_hook_gaps', items['android_id']['reason_code'])
        self.assertEqual([3], items['android_id']['observation_gap_event_ids'])
        self.assertNotIn('observation_gap_event_ids', items['microphone'])
        self.assertIn('未观测不等于未采集', items['microphone']['reason_text'])
        self.assertIn('也不代表安全', items['microphone']['reason_text'])
        self.assertEqual(['microphone', 'android_id', 'advertising_id'], data['not_observed'])
        self.assertEqual(2, data['call_only_events'])

    def test_registration_without_value_does_not_upgrade(self):
        general = self.general(by_data_type={'location': {}, 'microphone': {}, 'contacts': {},
                                             'android_id': {}, 'advertising_id': {}})
        item = {i['data_type']: i for i in observation({'general_privacy': general})['data_types']}['location']
        self.assertEqual('registration_only', item['state'])
        self.assertEqual('call_only_no_value', item['reason_code'])
        self.assertIn('注册了定位订阅，但未取到值，按判据不升级', item['reason_text'])
        self.assertEqual(0, item['read_events'])

    def test_read_not_obtained_reason_code_takes_strongest_state(self):
        """真实产物 org.fossify.contacts 是 call_only=72、empty=6：原因码必须写 empty 而不是占比最大的 call_only。"""
        general = self.general(by_data_type={'location': {}, 'microphone': {},
                                             'contacts': {'call_only': 72, 'empty': 6},
                                             'android_id': {}, 'advertising_id': {}},
                               registrations={'events': 0, 'by_data_type': {}})
        item = {i['data_type']: i for i in observation({'general_privacy': general})['data_types']}['contacts']
        self.assertEqual('read_not_obtained', item['state'])
        self.assertEqual('empty', item['reason_code'])
        self.assertEqual({'call_only': 72, 'empty': 6}, item['read_states'])
        self.assertIn('call_only=72、empty=6', item['reason_text'])
        self.assertIn('不能证明取得数据', item['reason_text'])

    def test_missing_artifact_is_explicit_not_null(self):
        data = observation({'package': 'x.y'})
        self.assertEqual('not_available', data['status'])
        self.assertEqual('no_general_privacy_artifact', data['reason_code'])
        self.assertEqual([], data['data_types'])
        self.assertIn('不能当作安全', data['reason_text'])

    def test_finding_annotation_requires_read_evidence(self):
        rows = [{'conclusion_level': 'observed', 'read_evidence': [{'evt_id': 1}]},
                {'conclusion_level': 'observed'},
                {'conclusion_level': 'candidate'}]
        annotate(rows)
        self.assertEqual(['observed', 'unverified', 'unverified'],
                         [row['observation_state'] for row in rows])
        self.assertEqual('observed_without_read_evidence', rows[1]['observation_reason_code'])
        self.assertEqual(1, rows[0]['read_evidence_count'])
        self.assertNotIn('read_evidence_count', rows[2])


if __name__ == '__main__':
    unittest.main()
