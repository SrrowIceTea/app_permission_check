"""Reachability filtering count regressions."""
import unittest

from mobile.tools.test_reachability import API, API_ROW, _ctx, _graph, reach_report


class ApplyCountsTest(unittest.TestCase):
    """apply() 收窄 findings 后，counts 必须自洽（真实样本踩过：总数 6、分类合计 11）。"""

    ROOT = "com.example.MainActivity.onCreate()V"
    REPO = "com.example.Repo.load()V"

    def _supp(self, specs):
        """specs: [(rule_type, matched_api), ...] → 补扫描的最小 supp 形状。"""
        return {"findings": [{"rule_id": f"MOB-X{i}", "rule_type": rtype,
                              "matched_apis": [api], "mapping_ambiguous": False}
                             for i, (rtype, api) in enumerate(specs)]}

    def test_counts_stay_consistent_after_filtering(self):
        # 一条 App 可达、一条仅库内调用：apply 后前者留下、后者进 downgraded_library。
        lib_api = {**API_ROW, "api_key": "k-lib",
                   "class_name": "androidx.core.content.ContextCompat"}
        graph = _graph({self.ROOT: [self.REPO]}, {self.REPO: [API],
                                                "androidx.helper.Runner.run()V": [API]},
                       [self.ROOT, self.REPO], [self.ROOT],
                       classes=["androidx.helper.Runner"])
        supp = self._supp([("sensitive_read", API_ROW), ("data_egress", lib_api)])
        out = reach_report.apply(supp, _ctx(graph))

        self.assertEqual(len(out["findings"]), 1, "只有 app_reachable 留在 findings")
        self.assertEqual(out["counts"]["findings_total"], 1)
        self.assertEqual(sum(out["counts"]["findings_by_rule_type"].values()),
                         out["counts"]["findings_total"],
                         "按类型分布必须与总数同口径")
        self.assertEqual(out["counts"]["findings_by_rule_type"].get("sensitive_read"), 1)
        self.assertNotIn("data_egress", out["counts"]["findings_by_rule_type"])

    def test_all_filtered_out_yields_empty_distribution(self):
        lib_api = {**API_ROW, "api_key": "k-lib",
                   "class_name": "androidx.core.content.ContextCompat"}
        # hit 键由 API 三元组拼出，必须与 lib_api 一致，否则命中的是别的点。
        lib_hit = ("androidx.core.content.ContextCompat.getLastKnownLocation"
                   "(Ljava/lang/String;)Landroid/location/Location;")
        graph = _graph({}, {lib_hit: [API]}, [], [self.ROOT],
                       classes=["androidx.core.content.ContextCompat"])
        out = reach_report.apply(self._supp([("sensitive_read", lib_api)]), _ctx(graph))
        self.assertEqual(out["counts"]["findings_total"], 0)
        self.assertEqual(out["counts"]["findings_by_rule_type"], {})
        kept = len(out["findings"]) + sum(
            len(out[name]) for name in
            ("downgraded_library", "downgraded_unreachable", "unknown_findings"))
        self.assertEqual(kept, 1, "候选一条不删（app_reachable 存在 findings 里）")


