-- V-Scanner Mobile 规则库 schema v2
-- 仅用于授权测试（已获授权的样本与设备）。
--
-- 与车载 phase1/schema.sql (v1) 的关系：
--   * 四张 v1 表（permissions / dangerous_apis / risk_rules）**表名与列名不变**，
--     只做「加列」与「放宽 CHECK 枚举」，使 phase5/phase7 的读取代码不必改动。
--   * v1 的 vhal_properties 在移动语义下没有对应物，由新表 sensitive_data_types 承担。
--   * 新增 app_categories（39 类必要个人信息）与 policy_requirements（隐私政策条款）。
--
-- 约定（沿用 v1）：
--   * 事实行（表 1–3）与规则行（risk_rules）分开；未知事实用 NULL，不编造。
--   * definition_status: source_verified = 从可核对的权威来源抽取（本库 = 本机 android.jar 的
--     javap 输出）；pending = 设备观测或待核对。**设备观测永远不得标 source_verified**。
--   * JSON 列一律 TEXT，默认 '[]'；本条目的发布方负责校验 JSON 契约。
--   * android_version: 本库固定 '36'（事实来源 = SDK platform android-36 的 android.jar，
--     设备 API 35 的观测放在 device_calibration_json 里，不另立版本行）。

PRAGMA foreign_keys = ON;

BEGIN;

-- ---------------------------------------------------------------------------
-- 1) permissions —— 与 v1 逐列一致（移动侧收录隐私相关权限）
-- ---------------------------------------------------------------------------
CREATE TABLE permissions (
    permission_name         TEXT NOT NULL,
    android_version         TEXT NOT NULL,
    protection_level_raw    TEXT,
    protection_level_value  INTEGER,
    permission_group        TEXT,
    description             TEXT,
    definition_status       TEXT NOT NULL DEFAULT 'pending'
                            CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json        TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes                   TEXT,
    PRIMARY KEY (permission_name, android_version)
);

-- ---------------------------------------------------------------------------
-- 2) sensitive_data_types —— 个人信息数据类别（对应 v1 的 vhal_properties 角色）
-- ---------------------------------------------------------------------------
CREATE TABLE sensitive_data_types (
    data_type_key           TEXT NOT NULL,          -- 'imei'
    android_version         TEXT NOT NULL,
    name_zh                 TEXT NOT NULL,
    name_en                 TEXT,
    -- 分级依据 GB/T 35273-2020 第 3.2 条与附录 B.1；children = 14 岁以下儿童个人信息
    sensitivity             TEXT NOT NULL DEFAULT 'personal'
                            CHECK (sensitivity IN ('personal', 'sensitive_personal', 'children')),
    gbt_category            TEXT,                   -- '个人身份信息' / '其他信息' 等
    api_surface             TEXT,                   -- 主要获取途径的类名（人读）
    permission_hint         TEXT,                   -- 典型配套权限（人读）
    definition_status       TEXT NOT NULL DEFAULT 'pending'
                            CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json        TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes                   TEXT,
    PRIMARY KEY (data_type_key, android_version)
);

-- ---------------------------------------------------------------------------
-- 3) dangerous_apis —— 敏感读取 API（v1 同名列 + data_type_key + observation_spec_json）
--    api_key = method_name + jvm_descriptor（**不含类名**，沿用 v1 约定；
--    下游按 (class_name, method_name, jvm_descriptor) 三元组匹配，不单独用 api_key）。
--    一个 API 可能对应多个数据类别（如 ContentResolver.query 按 URI 分派）：
--    data_type_key 只填 1:1 的情形，多对多写进 observation_spec_json.kind='content_uri'。
-- ---------------------------------------------------------------------------
CREATE TABLE dangerous_apis (
    api_key                 TEXT NOT NULL,
    android_version         TEXT NOT NULL,
    class_name              TEXT,
    method_name             TEXT,
    jvm_descriptor          TEXT,
    api_role                TEXT NOT NULL DEFAULT 'unknown'
                            CHECK (api_role IN ('unknown', 'read', 'query', 'observe', 'upload')),
    data_type_key           TEXT,                   -- 1:1 时的数据类别；多对多走 observation_spec_json
    observation_spec_json   TEXT,                   -- 钩子怎么观测本 API（含 content_uri 映射表）
    permission_expr_json    TEXT,
    definition_status       TEXT NOT NULL DEFAULT 'pending'
                            CHECK (definition_status IN ('pending', 'source_verified')),
    source_refs_json        TEXT NOT NULL DEFAULT '[]',
    device_calibration_json TEXT NOT NULL DEFAULT '[]',
    notes                   TEXT,
    PRIMARY KEY (api_key, android_version),
    FOREIGN KEY (data_type_key, android_version)
        REFERENCES sensitive_data_types(data_type_key, android_version)
);

-- ---------------------------------------------------------------------------
-- 4) risk_rules —— v1 同名列；rule_type 枚举扩展；window_ms 仍只允许 data_egress
-- ---------------------------------------------------------------------------
CREATE TABLE risk_rules (
    rule_id                     TEXT NOT NULL,
    android_version             TEXT NOT NULL,
    rule_revision               INTEGER NOT NULL DEFAULT 1 CHECK (rule_revision >= 1),
    title                       TEXT NOT NULL,
    rule_type                   TEXT NOT NULL CHECK (rule_type IN (
                                    -- v1 三类（车载沿用；移动侧继续用前两类 + data_egress）
                                    'over_permission', 'sensitive_read', 'data_egress',
                                    -- v2 移动新增五类
                                    'no_consent_read',       -- 同意前/未授权读取（认定方法三.1）
                                    'over_collection',       -- 超出必要范围收集（认定方法四.1）
                                    'plaintext_transmission',-- 明文/未加密传输（赛题要求二）
                                    'third_party_share',     -- 向第三方提供（认定方法五.1）
                                    'policy_mismatch')),     -- 政策未声明却收集（认定方法二.1）
    severity                    TEXT NOT NULL DEFAULT 'unrated'
                                CHECK (severity IN ('unrated','info','low','medium','high','critical')),
    permission_name             TEXT,
    data_type_key               TEXT,
    api_key                     TEXT,
    evaluator_version           INTEGER NOT NULL DEFAULT 1 CHECK (evaluator_version >= 1),
    condition_json              TEXT,
    evidence_requirements_json  TEXT,
    window_ms                   INTEGER,
    conclusion_level            TEXT NOT NULL DEFAULT 'candidate'
                                CHECK (conclusion_level IN ('candidate','observed','correlated','policy_violation')),
    source_refs_json            TEXT NOT NULL DEFAULT '[]',
    basis_refs_json             TEXT NOT NULL DEFAULT '[]',
    enabled                     INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    notes                       TEXT,
    PRIMARY KEY (rule_id, android_version),
    FOREIGN KEY (permission_name, android_version) REFERENCES permissions(permission_name, android_version),
    FOREIGN KEY (data_type_key, android_version)   REFERENCES sensitive_data_types(data_type_key, android_version),
    FOREIGN KEY (api_key, android_version)         REFERENCES dangerous_apis(api_key, android_version),
    -- window_ms 语义与 v1 相同：只有「读到→发出」这类需要时间窗的规则才带窗口
    CHECK ((rule_type = 'data_egress' AND window_ms IS NOT NULL AND window_ms > 0)
        OR (rule_type <> 'data_egress' AND window_ms IS NULL)),
    -- 启用即须完整溯源（沿用 v1 的守门约束）
    CHECK (enabled = 0 OR (android_version <> 'UNRESOLVED' AND condition_json IS NOT NULL
        AND evidence_requirements_json IS NOT NULL AND source_refs_json <> '[]'
        AND basis_refs_json <> '[]'))
);

-- ---------------------------------------------------------------------------
-- 5) app_categories —— 《常见类型移动互联网应用程序必要个人信息范围规定》
--    国信办秘字〔2021〕14 号 第五条 39 类
-- ---------------------------------------------------------------------------
CREATE TABLE app_categories (
    category_key                TEXT NOT NULL,      -- 'map_navigation'
    android_version             TEXT NOT NULL,
    name_zh                     TEXT NOT NULL,
    basic_function              TEXT NOT NULL,      -- 基本功能服务
    necessary_data_json         TEXT NOT NULL DEFAULT '[]',  -- [{data_type_key, text}]
    no_personal_info_required   INTEGER NOT NULL DEFAULT 0
                                CHECK (no_personal_info_required IN (0,1)),
    ordinal                     INTEGER,            -- 规定原文中的项号（一）…（三十九）
    source_refs_json            TEXT NOT NULL DEFAULT '[]',
    notes                       TEXT,
    PRIMARY KEY (category_key, android_version)
);

-- ---------------------------------------------------------------------------
-- 6) policy_requirements —— 隐私政策必备条款（个保法第 17 条 + 认定方法一、二）
--    check_kind: text_present/text_absent = 可离线字符串检查；ai = 交给 LLM 研判；
--                manual = 需人工。
-- ---------------------------------------------------------------------------
CREATE TABLE policy_requirements (
    req_id              TEXT NOT NULL,              -- 'PP-01'
    android_version     TEXT NOT NULL,
    title               TEXT NOT NULL,
    requirement         TEXT NOT NULL,
    check_kind          TEXT NOT NULL DEFAULT 'manual'
                        CHECK (check_kind IN ('text_present','text_absent','ai','manual')),
    check_spec_json     TEXT,
    severity            TEXT NOT NULL DEFAULT 'unrated'
                        CHECK (severity IN ('unrated','info','low','medium','high','critical')),
    basis_refs_json     TEXT NOT NULL DEFAULT '[]',
    source_refs_json    TEXT NOT NULL DEFAULT '[]',
    enabled             INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0,1)),
    notes               TEXT,
    PRIMARY KEY (req_id, android_version)
);

-- ---------------------------------------------------------------------------
-- 索引（沿用 v1 命名习惯）
-- ---------------------------------------------------------------------------
CREATE UNIQUE INDEX index_dangerous_apis_signature
    ON dangerous_apis (class_name, method_name, jvm_descriptor, android_version);
CREATE INDEX index_risk_rules_data_type_key ON risk_rules (data_type_key, android_version);
CREATE INDEX index_risk_rules_android_version_enabled_rule_type
    ON risk_rules (android_version, enabled, rule_type);
CREATE INDEX index_sensitive_data_types_sensitivity
    ON sensitive_data_types (sensitivity, android_version);

PRAGMA user_version = 2;

COMMIT;
