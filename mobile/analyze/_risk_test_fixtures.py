#!/usr/bin/env python3
"""test_risk_score / test_risk_band 共享的构造 helper。

非 test_ 前缀，不会被 unittest discover 当成测试模块。
"""


def finding(**kw) -> dict:
    base = {
        "rule_id": "r1", "rule_type": "sensitive_read", "data_type": "imei",
        "data_type_zh": "IMEI", "conclusion_level": "observed",
        "severity": "high", "evidence_kind": "read_event",
    }
    base.update(kw)
    return base


def summary(**kw) -> dict:
    base = {
        "package": "com.example", "app_category": "map_navigation",
        "coverage": {"inputs_present": {"reads": True, "flows": True, "consent": True,
                                        "permissions": True, "policy": True},
                     "data_types_coverage_pct": 14.3},
        "gaps": [],
    }
    base.update(kw)
    return base


SENS = {"imei": "sensitive_personal", "installed_apps": "personal",
        "coarse_location": "personal"}