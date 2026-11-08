package com.vscanner.rules

import org.json.JSONObject

enum class InstallState {
    FIRST_INSTALL, UPGRADED, UNCHANGED, RECOVERED,
    UPGRADE_FAILED_KEEPING_OLD, FIRST_INSTALL_FAILED, INSTALL_ERROR,
}

fun InstallState.label(): String = when (this) {
    InstallState.FIRST_INSTALL -> "首次安装：已从 APK 复制"
    InstallState.UPGRADED -> "已升级到新库"
    InstallState.UNCHANGED -> "与 APK 内规则库一致，无需重建"
    InstallState.RECOVERED -> "升级中断：已恢复完整规则库"
    InstallState.UPGRADE_FAILED_KEEPING_OLD -> "升级失败：沿用旧库"
    InstallState.FIRST_INSTALL_FAILED -> "首次安装失败：无可用的旧库"
    InstallState.INSTALL_ERROR -> "安装过程异常：停止读取"
}

/** Asset identity is distinct from the live file bytes changed by Room bookkeeping. */
data class InstallReport(
    val state: InstallState,
    val assetSha256: String?,
    val effectiveSha256: String?,
    val activeFileSha256: String?,
    val contentSha256: String?,
    val expectedContentSha256: String?,
    val contentMatch: Boolean,
    val schemaVersion: Int?,
    val previousSha256: String?,
    val reason: String,
    val recovery: String? = null,
    val cause: Throwable? = null,
) {
    val readable: Boolean get() = contentMatch && state !in setOf(
        InstallState.FIRST_INSTALL_FAILED, InstallState.INSTALL_ERROR,
    )

    fun toJson(): JSONObject = JSONObject().apply {
        put("state", state.name)
        put("stateLabel", state.label())
        put("assetSha256", assetSha256 ?: JSONObject.NULL)
        put("effectiveSha256", effectiveSha256 ?: JSONObject.NULL)
        put("activeFileSha256", activeFileSha256 ?: JSONObject.NULL)
        put("contentSha256", contentSha256 ?: JSONObject.NULL)
        put("expectedContentSha256", expectedContentSha256 ?: JSONObject.NULL)
        put("contentMatch", contentMatch)
        put("schemaVersion", schemaVersion ?: JSONObject.NULL)
        put("previousSha256", previousSha256 ?: JSONObject.NULL)
        put("reason", reason)
        put("recovery", recovery ?: JSONObject.NULL)
        put("readable", readable)
        put("errorClass", cause?.javaClass?.name ?: JSONObject.NULL)
    }
}
