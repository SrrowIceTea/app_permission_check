package com.vscanner.rules

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index

// Nullable Android facts stay null. JSON is stored as raw text.
// SQL CHECK constraints remain in the prepackaged schema.sql database.

@Entity(
    tableName = "permissions",
    primaryKeys = ["permission_name", "android_version"],
)
data class PermissionEntity(
    @ColumnInfo(name = "permission_name")
    val permissionName: String,
    @ColumnInfo(name = "android_version")
    val androidVersion: String,
    @ColumnInfo(name = "protection_level_raw")
    val protectionLevelRaw: String? = null,
    @ColumnInfo(name = "protection_level_value")
    val protectionLevelValue: Long? = null,
    @ColumnInfo(name = "permission_group")
    val permissionGroup: String? = null,
    @ColumnInfo(name = "description")
    val description: String? = null,
    @ColumnInfo(name = "definition_status", defaultValue = "'pending'")
    val definitionStatus: String = "pending",
    @ColumnInfo(name = "source_refs_json", defaultValue = "'[]'")
    val sourceRefsJson: String = "[]",
    @ColumnInfo(name = "device_calibration_json", defaultValue = "'[]'")
    val deviceCalibrationJson: String = "[]",
    @ColumnInfo(name = "notes")
    val notes: String? = null,
)

@Entity(
    tableName = "vhal_properties",
    primaryKeys = ["property_key", "android_version"],
    indices = [
        Index(
            value = ["property_id", "android_version"],
            name = "index_vhal_properties_property_id_android_version", unique = true,
        ),
    ],
)
data class VhalPropertyEntity(
    @ColumnInfo(name = "property_key")
    val propertyKey: String,
    @ColumnInfo(name = "android_version")
    val androidVersion: String,
    @ColumnInfo(name = "property_name")
    val propertyName: String? = null,
    @ColumnInfo(name = "property_id")
    val propertyId: Long? = null,
    @ColumnInfo(name = "value_type")
    val valueType: String? = null,
    @ColumnInfo(name = "access_mode")
    val accessMode: String? = null,
    @ColumnInfo(name = "change_mode")
    val changeMode: String? = null,
    @ColumnInfo(name = "area_type")
    val areaType: String? = null,
    @ColumnInfo(name = "unit")
    val unit: String? = null,
    @ColumnInfo(name = "data_category")
    val dataCategory: String? = null,
    @ColumnInfo(name = "read_permission_expr_json")
    val readPermissionExprJson: String? = null,
    @ColumnInfo(name = "write_permission_expr_json")
    val writePermissionExprJson: String? = null,
    @ColumnInfo(name = "definition_status", defaultValue = "'pending'")
    val definitionStatus: String = "pending",
    @ColumnInfo(name = "source_refs_json", defaultValue = "'[]'")
    val sourceRefsJson: String = "[]",
    @ColumnInfo(name = "device_calibration_json", defaultValue = "'[]'")
    val deviceCalibrationJson: String = "[]",
    @ColumnInfo(name = "notes")
    val notes: String? = null,
)

@Entity(
    tableName = "dangerous_apis",
    primaryKeys = ["api_key", "android_version"],
    indices = [
        Index(
            value = ["class_name", "method_name", "jvm_descriptor", "android_version"],
            name = "index_dangerous_apis_signature", unique = true,
        ),
    ],
)
data class DangerousApiEntity(
    @ColumnInfo(name = "api_key")
    val apiKey: String,
    @ColumnInfo(name = "android_version")
    val androidVersion: String,
    @ColumnInfo(name = "class_name")
    val className: String? = null,
    @ColumnInfo(name = "method_name")
    val methodName: String? = null,
    @ColumnInfo(name = "jvm_descriptor")
    val jvmDescriptor: String? = null,
    @ColumnInfo(name = "api_role", defaultValue = "'unknown'")
    val apiRole: String = "unknown",
    @ColumnInfo(name = "property_arg_index")
    val propertyArgIndex: Int? = null,
    @ColumnInfo(name = "observation_spec_json")
    val observationSpecJson: String? = null,
    @ColumnInfo(name = "permission_expr_json")
    val permissionExprJson: String? = null,
    @ColumnInfo(name = "definition_status", defaultValue = "'pending'")
    val definitionStatus: String = "pending",
    @ColumnInfo(name = "source_refs_json", defaultValue = "'[]'")
    val sourceRefsJson: String = "[]",
    @ColumnInfo(name = "device_calibration_json", defaultValue = "'[]'")
    val deviceCalibrationJson: String = "[]",
    @ColumnInfo(name = "notes")
    val notes: String? = null,
)

@Entity(
    tableName = "risk_rules",
    primaryKeys = ["rule_id", "android_version"],
    foreignKeys = [
        ForeignKey(
            entity = PermissionEntity::class,
            parentColumns = ["permission_name", "android_version"],
            childColumns = ["permission_name", "android_version"],
            onDelete = ForeignKey.NO_ACTION, onUpdate = ForeignKey.NO_ACTION,
        ),
        ForeignKey(
            entity = VhalPropertyEntity::class,
            parentColumns = ["property_key", "android_version"],
            childColumns = ["property_key", "android_version"],
            onDelete = ForeignKey.NO_ACTION, onUpdate = ForeignKey.NO_ACTION,
        ),
        ForeignKey(
            entity = DangerousApiEntity::class,
            parentColumns = ["api_key", "android_version"],
            childColumns = ["api_key", "android_version"],
            onDelete = ForeignKey.NO_ACTION, onUpdate = ForeignKey.NO_ACTION,
        ),
    ],
    indices = [
        Index(
            value = ["android_version", "enabled", "rule_type"],
            name = "index_risk_rules_android_version_enabled_rule_type", unique = false,
        ),
        Index(
            value = ["api_key", "android_version"],
            name = "index_risk_rules_api_key_android_version", unique = false,
        ),
        Index(
            value = ["permission_name", "android_version"],
            name = "index_risk_rules_permission_name_android_version", unique = false,
        ),
        Index(
            value = ["property_key", "android_version"],
            name = "index_risk_rules_property_key_android_version", unique = false,
        ),
    ],
)
data class RiskRuleEntity(
    @ColumnInfo(name = "rule_id")
    val ruleId: String,
    @ColumnInfo(name = "android_version")
    val androidVersion: String,
    @ColumnInfo(name = "rule_revision", defaultValue = "1")
    val ruleRevision: Int = 1,
    @ColumnInfo(name = "title")
    val title: String,
    @ColumnInfo(name = "rule_type")
    val ruleType: String,
    @ColumnInfo(name = "severity", defaultValue = "'unrated'")
    val severity: String = "unrated",
    @ColumnInfo(name = "permission_name")
    val permissionName: String? = null,
    @ColumnInfo(name = "property_key")
    val propertyKey: String? = null,
    @ColumnInfo(name = "api_key")
    val apiKey: String? = null,
    @ColumnInfo(name = "evaluator_version", defaultValue = "1")
    val evaluatorVersion: Int = 1,
    @ColumnInfo(name = "condition_json")
    val conditionJson: String? = null,
    @ColumnInfo(name = "evidence_requirements_json")
    val evidenceRequirementsJson: String? = null,
    @ColumnInfo(name = "window_ms")
    val windowMs: Long? = null,
    @ColumnInfo(name = "conclusion_level", defaultValue = "'candidate'")
    val conclusionLevel: String = "candidate",
    @ColumnInfo(name = "source_refs_json", defaultValue = "'[]'")
    val sourceRefsJson: String = "[]",
    @ColumnInfo(name = "basis_refs_json", defaultValue = "'[]'")
    val basisRefsJson: String = "[]",
    @ColumnInfo(name = "enabled", defaultValue = "0")
    val enabled: Int = 0,
    @ColumnInfo(name = "notes")
    val notes: String? = null,
)
