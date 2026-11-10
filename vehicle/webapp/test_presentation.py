"""投影层回归：finding_uid 稳定、规则标题中英取值、四档计数与阶段耗时。

合成数据只验证投影行为，不代表任何设备证据。
"""
import json
import unittest

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


if __name__ == '__main__':
    unittest.main()
