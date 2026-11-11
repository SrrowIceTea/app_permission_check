"""C 周 D2 补充断言：隐私观测四态的最强原因码、registration 透传、失败态 field_gaps 契约。

只补 test_presentation.py 未覆盖的缺口，不重复相同实现。合成数据只验证投影行为，
不代表任何设备证据。authorized testing only.
"""
import unittest

from vehicle.webapp.observation import annotate, observation
from vehicle.webapp.presentation import count_bands


def general(by_data_type=None, registrations=None, hook_gaps=None):
    return {'by_data_type': by_data_type or {}, 'registrations': registrations or {},
            'hook_gaps': hook_gaps or []}


class ReadNotObtainedReasonCodeTest(unittest.TestCase):
    """场景 4：denied/error/unavailable/unknown 各自取最强原因码，而非出现次数最多。"""

    def _state(self, states):
        data = general(by_data_type={'location': states})
        items = {i['data_type']: i for i in observation({'general_privacy': data})['data_types']}
        return items['location']

    def test_denied_is_strongest_even_when_empty_is_more_frequent(self):
        item = self._state({'call_only': 50, 'denied': 2, 'empty': 30})
        self.assertEqual('read_not_obtained', item['state'])
        self.assertEqual('denied', item['reason_code'])
        self.assertEqual({'call_only': 50, 'denied': 2, 'empty': 30}, item['read_states'])

    def test_error_beats_empty(self):
        item = self._state({'empty': 6, 'error': 1})
        self.assertEqual('error', item['reason_code'])

    def test_unavailable_beats_error(self):
        item = self._state({'error': 1, 'unavailable': 3})
        self.assertEqual('unavailable', item['reason_code'])

    def test_unknown_is_weakest_among_read_states(self):
        item = self._state({'unknown': 4})
        self.assertEqual('read_not_obtained', item['state'])
        self.assertEqual('unknown', item['reason_code'])


class RegistrationOnlyTest(unittest.TestCase):
    """场景 3：仅注册不升级，registrations_by_kind 逐字透传，read_events 为 0。"""

    def test_registration_kinds_are_passed_through_and_not_upgraded(self):
        data = general(
            by_data_type={'location': {}},
            registrations={'events': 3,
                           'by_data_type': {'location': {'listener_registration': 2,
                                                         'callback': 1}}})
        items = {i['data_type']: i
                 for i in observation({'general_privacy': data})['data_types']}
        item = items['location']
        self.assertEqual('registration_only', item['state'])
        self.assertEqual('call_only_no_value', item['reason_code'])
        self.assertEqual(0, item['read_events'])
        self.assertEqual({'listener_registration': 2, 'callback': 1},
                         item['registrations_by_kind'])
        self.assertEqual(3, item['call_only_events'])
        self.assertIn('注册了定位订阅，但未取到值，按判据不升级', item['reason_text'])

    def test_registration_only_never_renders_as_observed(self):
        data = general(registrations={'events': 1,
                                      'by_data_type': {'contacts': {'listener_registration': 1}}})
        obs = observation({'general_privacy': data})
        self.assertNotIn('contacts', [i['data_type'] for i in obs['data_types']
                                      if i['state'] == 'observed'])
        self.assertIn('contacts', obs['registration_only'])


class FieldGapsContractTest(unittest.TestCase):
    """场景 6/7：findings_total 为 null 时不进 field_gaps；四档 null 不默认 0。"""

    def test_findings_total_null_does_not_add_field_gaps_key(self):
        # count_bands 是投影层，findings_total 缺失时 field_gaps 只写 findings_by_conclusion_level
        bands, raw, gaps = count_bands(None)
        self.assertEqual({'correlated': None, 'observed': None,
                          'candidate': None, 'unjudged': None}, bands)
        self.assertNotIn('findings_total', gaps)
        self.assertIn('findings_by_conclusion_level', gaps)

    def test_summary_without_bands_keeps_findings_total_as_projected(self):
        # 有 summary 但无分档字典：四档 null，unjudged 也 null（缺 findings_total 无法推算）
        bands, raw, gaps = count_bands({'package': 'x.y'})
        self.assertEqual({'correlated': None, 'observed': None,
                          'candidate': None, 'unjudged': None}, bands)
        self.assertIsNone(raw)
        self.assertIn('findings_by_conclusion_level', gaps)

    def test_inconsistent_summary_does_not_clamp_to_zero(self):
        # findings_total 小于分档之和：unjudged 为 null，不做 max(0, ...) 修正
        bands, raw, gaps = count_bands({'findings_total': 3,
                                        'findings_by_conclusion_level': {'observed': 5}})
        self.assertIsNone(bands['unjudged'])
        self.assertIn('findings_by_conclusion_level.unjudged', gaps)
        self.assertIn('不自洽', gaps['findings_by_conclusion_level.unjudged'])


class FindingAnnotationIsolationTest(unittest.TestCase):
    """场景 2/8：observation_state 只随本行 read_evidence 判定，行间不串。"""

    def test_annotation_does_not_leak_between_rows(self):
        rows = [
            {'conclusion_level': 'observed', 'read_evidence': [{'evt_id': 1}]},
            {'conclusion_level': 'observed'},
            {'conclusion_level': 'candidate'},
            {'conclusion_level': 'correlated', 'observed_basis': {'value_hash_present': 1}},
        ]
        annotate(rows)
        self.assertEqual(['observed', 'unverified', 'unverified', 'correlated'],
                         [r['observation_state'] for r in rows])
        self.assertEqual(1, rows[0]['read_evidence_count'])
        self.assertNotIn('read_evidence_count', rows[1])
        self.assertNotIn('read_evidence_count', rows[2])


if __name__ == '__main__':
    unittest.main()
