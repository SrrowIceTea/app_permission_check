package com.vscanner.rules

import android.content.Context
import org.json.JSONObject
import java.io.File

/** What happened to the on-device copy of the prepackaged rule database. */
enum class InstallState {
    FIRST_INSTALL,
    UPGRADED,
    UNCHANGED,
    UPGRADE_FAILED_KEEPING_OLD,
    FIRST_INSTALL_FAILED,
    INSTALL_ERROR,
}

fun InstallState.label(): String = when (this) {
    InstallState.FIRST_INSTALL -> "首次安装：已从 APK 复制"
    InstallState.UPGRADED -> "已升级到新库"
    InstallState.UNCHANGED -> "与 APK 内规则库一致，无需重建"
    InstallState.UPGRADE_FAILED_KEEPING_OLD -> "升级失败：沿用旧库"
    InstallState.FIRST_INSTALL_FAILED -> "首次安装失败：无可用的旧库"
    InstallState.INSTALL_ERROR -> "安装过程异常"
}

/**
 * How the runtime copy relates to the database packaged in the APK.
 *
 * `effectiveSha256` identifies the rule library that is actually in effect. It is the
 * raw SHA-256 of the bytes installed from the APK, and is kept valid by checking the
 * canonical content digest against the live file. `activeFileSha256` is the digest of
 * the file as it sits on disk right now; it differs after Room's first open because
 * Room adds `room_master_table` / `android_metadata`, which is exactly why the raw
 * asset digest must not be used to decide freshness.
 */
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
) {
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
    }
}

/**
 * Keeps the on-device rule database in step with the one inside the APK.
 *
 * Room's `createFromAsset` copies the asset only while no file exists at the target
 * path. An APK update that changes `rules.db` without changing the Room schema version
 * therefore left the old copy in place and the device silently used rules that were no
 * longer packaged. The decision here is based on the database digest plus its schema
 * version, never on the schema version alone.
 *
 * Upgrade is staged and validated before the live file is touched: the asset is copied
 * aside, its raw digest and canonical rule content are computed, and Room is asked to
 * open it under a throwaway name. Validation failure leaves the previous database in
 * place and is reported as [InstallState.UPGRADE_FAILED_KEEPING_OLD]. Exceptions during
 * file replacement are INSTALL_ERROR; crash-safe replacement is not yet guaranteed.
 */
class RulesDbInstaller(private val context: Context) {

    suspend fun ensureInstalled(
        source: RulesDbSource = RulesDbSource.Asset(),
        databaseName: String = RulesDatabase.DEFAULT_NAME,
    ): InstallReport = try {
        install(source, databaseName)
    } catch (t: Throwable) {
        report(
            databaseName = databaseName,
            state = InstallState.INSTALL_ERROR,
            effectiveSha = runCatching {
                DbMetaStore.read(metaFile(databaseName))?.effectiveSha256
            }.getOrNull(),
            assetSha = null,
            reason = "安装判定异常: ${t.javaClass.simpleName}: ${t.message}",
        )
    }

    private suspend fun install(source: RulesDbSource, databaseName: String): InstallReport {
        val dbFile = context.getDatabasePath(databaseName)
        val metaFile = metaFile(databaseName)
        val backupFile = backupFile(databaseName)
        metaFile.parentFile?.mkdirs()

        val meta = DbMetaStore.read(metaFile)
        val assetSha = runCatching { RulesDbDigest.raw(source.openStream(context)) }.getOrNull()
        val activeContent = if (dbFile.isFile) RulesDbDigest.content(dbFile) else null

        if (assetSha == null) {
            return failure(
                databaseName = databaseName,
                assetSha = null,
                meta = meta,
                reason = "APK 内 rules.db 不可读，无法升级",
            )
        }

        val fresh = meta != null && activeContent != null &&
            meta.algorithmVersion == DbMetaStore.ALGORITHM_VERSION &&
            meta.assetSha256 == assetSha &&
            meta.contentSha256 == activeContent.digest &&
            meta.schemaVersion == activeContent.userVersion
        if (fresh) {
            return report(
                databaseName = databaseName,
                state = InstallState.UNCHANGED,
                assetSha = assetSha,
                effectiveSha = meta.effectiveSha256,
                reason = "已生效的库与 APK 内规则库摘要一致，未重建",
            )
        }

        val staging = File(dbFile.parentFile, "$databaseName.incoming")
        val staged: DbContent = try {
            staging.delete()
            source.openStream(context).use { input ->
                staging.outputStream().use { output -> input.copyTo(output) }
            }
            val stagedSha = RulesDbDigest.raw(staging)
            require(stagedSha == assetSha) { "暂存副本摘要与资产不一致" }
            val stagedContent = requireNotNull(RulesDbDigest.content(staging)) {
                "暂存副本不是完整的规则库（四表缺失或无法打开）"
            }
            validateWithRoom(staging, databaseName)
            stagedContent
        } catch (t: Throwable) {
            staging.delete()
            return failure(
                databaseName = databaseName,
                assetSha = assetSha,
                meta = meta,
                reason = "新库未通过校验: ${t.message}",
            )
        }

        val hadLiveCopy = dbFile.isFile
        if (hadLiveCopy) dbFile.copyTo(backupFile, overwrite = true)
        deleteDatabaseFiles(dbFile)
        if (!staging.renameTo(dbFile)) {
            staging.copyTo(dbFile, overwrite = true)
            staging.delete()
        }

        val installedSha = RulesDbDigest.raw(dbFile)
        val installedContent = RulesDbDigest.content(dbFile)
        if (installedSha != assetSha || installedContent?.digest != staged.digest) {
            dbFile.delete()
            if (backupFile.isFile) backupFile.copyTo(dbFile, overwrite = true)
            return failure(
                databaseName = databaseName,
                assetSha = assetSha,
                meta = meta,
                reason = "切换副本后校验不一致，已回滚旧库",
            )
        }

        DbMetaStore.write(metaFile, DbMeta(assetSha, assetSha, staged.digest, staged.userVersion))
        return report(
            databaseName = databaseName,
            state = if (hadLiveCopy) InstallState.UPGRADED else InstallState.FIRST_INSTALL,
            assetSha = assetSha,
            effectiveSha = assetSha,
            reason = if (hadLiveCopy) {
                "规则库摘要变化：已替换为新库并通过校验"
            } else {
                "首次安装：已从 APK 复制并通过校验"
            },
        )
    }

    /**
     * Opens the staged file through Room under a throwaway name. Schema drift throws,
     * and a zero-byte or truncated file produces no version rows, which is rejected here.
     */
    private suspend fun validateWithRoom(staged: File, databaseName: String) {
        val probeName = "$databaseName.probe"
        context.deleteDatabase(probeName)
        val probe = RulesDatabase.open(context, RulesDbSource.FromFile(staged), probeName)
        try {
            val versions = probe.rules().versions()
            require(versions.isNotEmpty()) { "规则库没有任何版本数据" }
            for (version in versions) probe.rules().counts(version)
        } finally {
            runCatching { probe.close() }
            context.deleteDatabase(probeName)
        }
    }

    /** Keeps the old library when there is one; otherwise reports a failed first install. */
    private fun failure(
        databaseName: String,
        assetSha: String?,
        meta: DbMeta?,
        reason: String,
    ): InstallReport {
        val dbFile = context.getDatabasePath(databaseName)
        val usableOld = if (dbFile.isFile) RulesDbDigest.content(dbFile) else null
        val hasUsableOld = usableOld != null
        val oldSha = meta?.effectiveSha256 ?: if (hasUsableOld) {
            runCatching { RulesDbDigest.raw(dbFile) }.getOrNull()
        } else {
            null
        }
        return report(
            databaseName = databaseName,
            state = if (hasUsableOld) {
                InstallState.UPGRADE_FAILED_KEEPING_OLD
            } else {
                InstallState.FIRST_INSTALL_FAILED
            },
            assetSha = assetSha,
            effectiveSha = oldSha,
            reason = if (hasUsableOld) "$reason；保留旧库并继续使用" else "$reason；没有可用的旧库",
        )
    }

    private fun report(
        databaseName: String,
        state: InstallState,
        assetSha: String?,
        effectiveSha: String?,
        reason: String,
    ): InstallReport {
        val dbFile = context.getDatabasePath(databaseName)
        val backupFile = backupFile(databaseName)
        val meta = DbMetaStore.read(metaFile(databaseName))
        val content = if (dbFile.isFile) RulesDbDigest.content(dbFile) else null
        return InstallReport(
            state = state,
            assetSha256 = assetSha,
            effectiveSha256 = effectiveSha,
            activeFileSha256 = if (dbFile.isFile) RulesDbDigest.raw(dbFile) else null,
            contentSha256 = content?.digest,
            expectedContentSha256 = meta?.contentSha256,
            contentMatch = content != null && content.digest == meta?.contentSha256,
            schemaVersion = content?.userVersion,
            previousSha256 = if (backupFile.isFile) RulesDbDigest.raw(backupFile) else null,
            reason = reason,
        )
    }

    private fun metaFile(databaseName: String) =
        File(context.getDatabasePath(databaseName).parentFile, "$databaseName.meta")

    private fun backupFile(databaseName: String) =
        File(context.getDatabasePath(databaseName).parentFile, "$databaseName.previous")

    private fun deleteDatabaseFiles(dbFile: File) {
        dbFile.delete()
        for (suffix in listOf("-wal", "-shm", "-journal")) {
            File(dbFile.path + suffix).delete()
        }
    }
}
