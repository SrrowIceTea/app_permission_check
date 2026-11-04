#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Register the general-privacy rules (VSC-GR-* / VSC-GE-*) in the vehicle library.

2026-11-02: `vehicle/privacy/evaluation.py` emitted these rule IDs while the rule
library had zero matching rows. A finding whose rule ID cannot be looked up is not
traceable, so this module registers six rules per Android version:

    VSC-GR-<type>   sensitive_read / observed
    VSC-GE-<type>   data_egress / correlated, 30s identical-value window

Only android_id and contacts get a GE rule (vehicle/privacy/POLICY.md). The rules
describe Android SDK sources, not VHAL properties, so permission_key columns stay
NULL: the schema's foreign key only accepts permissions already registered for the
version, and neither version's calibration carries the general Android permissions.
The requirement itself is kept verbatim in condition_json.

Provenance stays split (D009):
  * '14' rows cite only the official SDK reference. They were NOT device tested.
  * '15' rows cite the API 35 device observation plus the SDK reference, and never
    an AOSP android-14 commit.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vehicle.privacy.catalog import AAID, AAID_POLICY, AAID_SIGNATURES, HERE, SOURCES, TARGETS, TYPES, contract  # noqa: E402
from vehicle.rules.python.privacy_observation import load_observation, DEFAULT_OBSERVATION
from vehicle.rules.python.aaid_observation import SNAPSHOT as AAID_OBSERVATION, load_snapshot

SOURCE_VERSION = "14"
DEVICE_VERSION = "15"
WINDOW_MS = contract()['egress_window_ms']
EGRESS_TYPES = ("android_id", "contacts")


def specs() -> list[tuple[str, str, bool]]:
    return ([("VSC-GR-" + d, d, False) for d in TYPES]
            + [("VSC-GE-" + d, d, True) for d in EGRESS_TYPES])


def title(dtype: str, egress: bool) -> str:
    name = TYPES[dtype]['name']
    return (f"通用隐私来源：{name}的值出现在外发 JSON（{WINDOW_MS // 1000} 秒窗口）"
            if egress else f"通用隐私来源：{name}的非空读取")


def condition(dtype: str, egress: bool) -> dict:
    base = {'data_type': dtype, 'data_type_name': TYPES[dtype]['name'],
            'required_permissions': TYPES[dtype]['permissions'],
            'permission_op': TYPES[dtype]['permission_op'],
            'api_targets': [f"{t['cls']}.{t['method']}{t['desc']}"
                            for t in TARGETS if t['data_type'] == dtype],
            'scope': 'partial_api_surface'}
    if egress:
        base.update(predicate='same_value_in_outgoing_json', window_ms=WINDOW_MS,
                    identity_scope='same_package_user_uid_session',
                    value_basis='complete_request_json_string_value_hash',
                    requires_read_state='obtained')
    else:
        base.update(predicate='obtained_general_privacy_data',
                    read_outcome='ok', collection_state='obtained')
    return base


def evidence_requirements(egress: bool) -> dict:
    if egress:
        return {'required': ['obtained_read_event', 'complete_outgoing_json_request',
                             'same_package_session_uid_user', 'identical_string_value_hash',
                             'delta_ms_within_window'],
                'not_sufficient': ['time_proximity_only', 'marker_name_only',
                                   'truncated_or_undecoded_payload'],
                'caps': ['attribution_loose_conclusion_candidate'],
                'evidence': ['read_event_id', 'flow_event_id', 'delta_ms', 'value_hash']}
    return {'required': ['read_outcome_ok', 'collection_state_obtained',
                         'non_empty_return_or_evidence_fields'],
            'not_sufficient': ['interface_called_only', 'empty_return',
                               'permission_denied', 'error'],
            'evidence': ['event_ids', 'value_hash', 'uid', 'user_id', 'session_id']}


def source_refs(dtype: str, version: str, provenance: dict) -> list[dict]:
    if dtype == AAID:
        from vehicle.rules.python.privacy_observation import reference
        refs = [{'kind': 'google_play_services_reference', 'url': SOURCES[dtype]},
                {'kind': 'sdk_signature', **reference(HERE / AAID_SIGNATURES)}]
        if version == DEVICE_VERSION and AAID_OBSERVATION.is_file():
            snapshot = load_snapshot()
            refs.append({'kind': 'device_observation', 'observation_snapshot': reference(AAID_OBSERVATION),
                         'device_fingerprint': snapshot['device_fingerprint'],
                         'read_states': sorted(snapshot['cases'])})
        return refs
    sdk = {'kind': 'android_sdk_reference', 'url': SOURCES[dtype],
           'api_levels': contract()['api_levels']}
    if version == SOURCE_VERSION:
        return [{**sdk, 'scope': 'sdk_reference_only_not_device_verified_on_android14'}]
    return [{'kind': 'device_observation',
             'device_api_level': provenance['device_api_level'],
             'device_fingerprint': provenance['device_fingerprint'],
             'observation_snapshot': provenance['snapshot'],
             'captured_from': provenance['captures'],
             'observed': {'data_type': dtype, 'hook_coverage': 'implemented',
                          'read_states': sorted(provenance['observed_states'][dtype]),
                          'state_counts': provenance['observed_states'][dtype]}}, sdk]


def basis_refs(dtype=None) -> list[dict]:
    if dtype == AAID:
        return [{'kind': 'project_policy', 'path': 'vehicle/privacy/' + AAID_POLICY,
                 'sha256': contract()['aaid_policy_sha256']}]
    return [{'kind': 'project_policy', 'path': 'vehicle/privacy/POLICY.md',
             'sha256': contract()['policy_sha256']}]


def insert_privacy_rules(dst: sqlite3.Connection, observation_path=DEFAULT_OBSERVATION) -> dict:
    """Insert the registered privacy rules for '14' and '15'; return per-version counts."""
    provenance = load_observation(observation_path)
    counts = {SOURCE_VERSION: 0, DEVICE_VERSION: 0}
    for version in (SOURCE_VERSION, DEVICE_VERSION):
        payload = []
        for rule_id, dtype, egress in specs():
            payload.append((
                rule_id, version, 1, title(dtype, egress),
                'data_egress' if egress else 'sensitive_read', 'medium',
                None, None, None, 1,
                json.dumps(condition(dtype, egress), ensure_ascii=False, sort_keys=True),
                json.dumps(evidence_requirements(egress), ensure_ascii=False, sort_keys=True),
                WINDOW_MS if egress else None,
                'correlated' if egress else 'observed',
                json.dumps(source_refs(dtype, version, provenance),
                           ensure_ascii=False, sort_keys=True),
                json.dumps(basis_refs(dtype), ensure_ascii=False, sort_keys=True), 1,
                '通用隐私规则登记（项目策略）。求值器见 vehicle/privacy/evaluation.py；'
                + ('设备证据仅覆盖 AAOS 35 四类来源，14 版未做设备验收。'
                   if version == SOURCE_VERSION else
                   '结论上限由规则自身设定，不产出 policy_violation。'),
            ))
        dst.executemany(
            "INSERT INTO risk_rules (rule_id, android_version, rule_revision, title, rule_type,"
            " severity, permission_name, property_key, api_key, evaluator_version,"
            " condition_json, evidence_requirements_json, window_ms, conclusion_level,"
            " source_refs_json, basis_refs_json, enabled, notes)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            payload,
        )
        counts[version] = len(payload)
    return counts
