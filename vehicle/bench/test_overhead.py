"""Offline guards for paired Hook-overhead arithmetic. 仅用于授权测试。"""
import unittest
from vehicle.bench.overhead_report import cpu_ms, render_markdown, summarize


def stat_text(utime, stime):
    # After the comm field: state is index 0, so utime is index 11 and stime 12.
    tail = ['S'] + [str(i) for i in range(1, 11)] + [str(utime), str(stime), '0', '0']
    return '4242 (fixture app (x)) ' + ' '.join(tail) + '\n'


def run(pair, arm, order, cpu, wall):
    return {'pair': pair, 'arm': arm, 'order': order, 'cpu_ms': cpu, 'wall_ms': wall,
            'actions': 4, 'passed': True}


class OverheadReportTests(unittest.TestCase):
    def test_cpu_ms_counts_utime_and_stime_after_comm_with_spaces(self):
        self.assertEqual((120 + 30) * 10, cpu_ms(stat_text(120, 30)))

    def test_summarize_pairs_and_refuses_accuracy_claims(self):
        runs = [run(0, 'without_hook', 1, 500, 1800), run(0, 'with_hook', 2, 620, 1900),
                run(1, 'with_hook', 1, 540, 1750), run(1, 'without_hook', 2, 480, 1700)]
        report = summarize(runs)
        self.assertEqual(2, report['paired_runs'])
        self.assertEqual(90, report['cpu_delta_ms']['median'])
        self.assertEqual(120, report['cpu_delta_ms']['p95'])
        # 中位增量 90ms / 中位无 Hook 基线 490ms = 18.4%（分母是两轮基线 CPU 的中位数，
        # 不是单轮 500ms）。
        self.assertEqual(18.4, report['cpu_relative_percent'])
        self.assertEqual('not_measured', report['accuracy']['status'])
        self.assertIsNone(report['accuracy'].get('precision'))
        self.assertTrue(any('不能外推' in item for item in report['caveats']))

    def test_unpaired_run_is_skipped_not_counted_as_zero_overhead(self):
        report = summarize([run(0, 'with_hook', 1, 700, 1900),
                            {'pair': 1, 'arm': 'with_hook', 'order': 1,
                             'error': 'TimeoutError: receipt missing', 'passed': False}])
        self.assertEqual(0, report['paired_runs'])
        self.assertEqual([0, 1], report['skipped_pairs'])
        self.assertEqual('TimeoutError: receipt missing', report['failed_runs'][0]['error'])
        self.assertIsNone(report['cpu_delta_ms']['median'])

    def test_markdown_discloses_measurement_scope(self):
        report = summarize([run(0, 'without_hook', 1, 500, 1800),
                            run(0, 'with_hook', 2, 620, 1900)])
        text = render_markdown(report, {'device': 'emulator-5554'}, 1, 4)
        self.assertIn('检测准确率: **未测量**', text)
        self.assertIn('runs.jsonl', text)

    def test_failed_arm_with_valid_timing_is_excluded_from_statistics(self):
        failed = run(0, 'with_hook', 2, 1, 100)
        failed.update(passed=False, hook_errors=1, cleanup=[{'exit_code': 1, 'forced': True}])
        report = summarize([run(0, 'without_hook', 1, 500, 1800), failed,
                            run(1, 'without_hook', 1, 500, 1800), run(1, 'with_hook', 2, 620, 1900)])
        self.assertEqual(1, report['paired_runs'])
        self.assertEqual([0], report['skipped_pairs'])
        self.assertEqual(120, report['cpu_delta_ms']['median'])
        self.assertEqual('run_not_passed', report['failed_runs'][0]['error'])
        self.assertTrue(report['failed_runs'][0]['cleanup'][0]['forced'])


if __name__ == '__main__':
    unittest.main()
