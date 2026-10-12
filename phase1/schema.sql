-- V-Scanner rules schema v1. Definitions only; no scan events or seed data.
-- Unknown facts use NULL; unknown Android release uses 'UNRESOLVED'.
-- One canonical source snapshot per android_version in each rules.db release.
-- JSON contracts are validated by the future publisher, not SQLite JSON1.
PRAGMA foreign_keys = ON;
BEGIN TRANSACTION;

CREATE TABLE permissions (
    permission_name TEXT NOT NULL,
    android_version TEXT NOT NULL,
    protection_level_raw TEXT,
    protection_level_value INTEGER,
    permission_group TEXT,
    description TEXT,
    definition_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    PRIMARY KEY (permission_name, android_version)
);

CREATE TABLE vhal_properties (
    property_key TEXT NOT NULL,
    android_version TEXT NOT NULL,
    property_name TEXT,
    property_id INTEGER,
    value_type TEXT,
    access_mode TEXT,
    change_mode TEXT,
    area_type TEXT,
    unit TEXT,
    data_category TEXT,
    read_permission_expr_json TEXT,
    write_permission_expr_json TEXT,
    definition_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    PRIMARY KEY (property_key, android_version)
);

CREATE TABLE dangerous_apis (
    api_key TEXT NOT NULL,
    android_version TEXT NOT NULL,
    class_name TEXT,
    method_name TEXT,
    jvm_descriptor TEXT,
    api_role TEXT NOT NULL DEFAULT 'unknown'
        CHECK (api_role IN (
            'unknown', 'read', 'subscribe', 'callback', 'metadata'
        )),
    property_arg_index INTEGER CHECK (property_arg_index >= 0),
    observation_spec_json TEXT,
    permission_expr_json TEXT,
    definition_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes TEXT,
    PRIMARY KEY (api_key, android_version)
);

CREATE TABLE risk_rules (
    rule_id TEXT NOT NULL,
    android_version TEXT NOT NULL,
    rule_revision INTEGER NOT NULL DEFAULT 1 CHECK (rule_revision >= 1),
    title TEXT NOT NULL,
    rule_type TEXT NOT NULL CHECK (rule_type IN (
        'over_permission', 'sensitive_read', 'data_egress'
    )),
    severity TEXT NOT NULL DEFAULT 'unrated' CHECK (severity IN (
        'unrated', 'info', 'low', 'medium', 'high', 'critical'
    )),
    permission_name TEXT,
    property_key TEXT,
    api_key TEXT,
    evaluator_version INTEGER NOT NULL DEFAULT 1
        CHECK (evaluator_version >= 1),
    condition_json TEXT,
    evidence_requirements_json TEXT,
    window_ms INTEGER,
    conclusion_level TEXT NOT NULL DEFAULT 'candidate'
        CHECK (conclusion_level IN (
            'candidate', 'observed', 'correlated', 'policy_violation'
        )),
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    basis_refs_json TEXT NOT NULL DEFAULT '[]',
    enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    notes TEXT,
    PRIMARY KEY (rule_id, android_version),
    FOREIGN KEY (permission_name, android_version)
        REFERENCES permissions (permission_name, android_version),
    FOREIGN KEY (property_key, android_version)
        REFERENCES vhal_properties (property_key, android_version),
    FOREIGN KEY (api_key, android_version)
        REFERENCES dangerous_apis (api_key, android_version),
    CHECK (
        (rule_type = 'data_egress' AND
            window_ms IS NOT NULL AND window_ms > 0)
        OR (rule_type <> 'data_egress' AND window_ms IS NULL)
    ),
    CHECK (
        enabled = 0 OR (
            android_version <> 'UNRESOLVED'
            AND condition_json IS NOT NULL
            AND evidence_requirements_json IS NOT NULL
            AND source_refs_json <> '[]'
            AND basis_refs_json <> '[]'
        )
    )
);

CREATE UNIQUE INDEX index_vhal_properties_property_id_android_version
    ON vhal_properties (property_id, android_version);
CREATE UNIQUE INDEX index_dangerous_apis_signature
    ON dangerous_apis (class_name, method_name, jvm_descriptor, android_version);
CREATE INDEX index_risk_rules_permission_name_android_version
    ON risk_rules (permission_name, android_version);
CREATE INDEX index_risk_rules_property_key_android_version
    ON risk_rules (property_key, android_version);
CREATE INDEX index_risk_rules_api_key_android_version
    ON risk_rules (api_key, android_version);
CREATE INDEX index_risk_rules_android_version_enabled_rule_type
    ON risk_rules (android_version, enabled, rule_type);

PRAGMA user_version = 1;
COMMIT;
