"""Coverage derives actual rules and never hides unsupported source paths."""
import tempfile
import unittest
from pathlib import Path
from vehicle.coverage.export import build_coverage, export_coverage
from vehicle.privacy.owntracks_evidence import BODY_RULE, READ_RULE


class CoverageTests(unittest.TestCase):
    def test_each_existing_property_has_real_rules_and_named_gaps(self):
        rows = [r for r in build_coverage()['rows'] if 'property_id' in r]
        self.assertEqual(8, len(rows))
        self.assertTrue(all(r['rule_ids'] and r['uncovered_reasons'] for r in rows))
        self.assertTrue(all(r['hook_coverage']['async_getProperties'] == 'not_hooked' for r in rows))

    def test_null_device_permission_map_not_source_verified(self):
        rows = [r for r in build_coverage()['rows'] if 'property_id' in r]
        self.assertTrue(any(r['permission_mapping_status'] ==
                            'policy_candidate_not_device_permission_mapping' for r in rows))

    def test_shared_sources_connected_but_scope_gaps_remain_explicit(self):
        rows = build_coverage()['rows']
        location = next(r for r in rows if r['data_type'] == '位置/轨迹')
        self.assertIn('VSC-GR-location', location['rule_ids'])
        self.assertEqual('implemented', location['hook_coverage']['status'])
        self.assertTrue(location['uncovered_reasons'])

    def test_other_versions_expand_general_sources_without_copying_vhal(self):
        for version in ('13', '16'):
            rows = build_coverage(version)['rows']
            self.assertFalse(any('property_id' in row for row in rows))
            self.assertEqual({'location', 'microphone', 'contacts', 'android_id', 'advertising_id'},
                             {row['data_type_key'] for row in rows if 'data_type_key' in row})
            self.assertTrue(any(r['hook_coverage']['status'] == 'not_validated_for_version' for r in rows))

    def test_owntracks_experiment_is_not_reported_as_a_general_rule(self):
        rows = build_coverage()['rows']
        owntracks = next(r for r in rows if r['data_type'] == '位置/轨迹（OwnTracks 样本）')
        self.assertEqual([READ_RULE, BODY_RULE], owntracks['rule_ids'])
        self.assertEqual('sample_opt_in', owntracks['hook_coverage']['status'])
        self.assertNotIn(owntracks['data_type'], {r['data_type'] for r in build_coverage('14')['rows']})

    def test_export_keeps_line_cap_and_machine_readable_provenance(self):
        import json
        with tempfile.TemporaryDirectory() as root:
            export_coverage(root)
            text = (Path(root) / 'coverage.json').read_text(encoding='utf-8')
            self.assertLessEqual(len(text.splitlines()), 300)
            data = json.loads(text)
            self.assertTrue(data['rows'][0]['source_refs'] or data['rows'][0]['device_refs'])


if __name__ == '__main__':
    unittest.main()
