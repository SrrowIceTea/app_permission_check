package com.vscanner.rules

import android.content.Context
import kotlinx.coroutines.CancellationException
import java.io.IOException

/** Durable intent, same-directory rename, validated backup, and startup reconciliation. */
class RulesDbInstaller internal constructor(
    private val context: Context,
    private val fault: (String) -> Unit = {},
) {
    suspend fun ensureInstalled(
        source: RulesDbSource = RulesDbSource.Asset(),
        databaseName: String = RulesDatabase.DEFAULT_NAME,
    ): InstallReport = withInstalled(source, databaseName) { it }

    /** The application read path keeps this lease until its Room instance is closed. */
    internal suspend fun <T> withInstalled(
        source: RulesDbSource,
        databaseName: String,
        block: suspend (InstallReport) -> T,
    ): T {
        var entered = false
        return try {
            RulesDbLease.use(context, databaseName) {
                entered = true
                block(install(source, databaseName))
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            // Never repeat a caller block that already ran, or inspect files without a lease.
            if (entered) throw error
            block(InstallReport(InstallState.INSTALL_ERROR, null, null, null, null, null,
                false, null, null, "规则库锁不可用，停止读取：${error.message}", cause = error))
        }
    }

    private suspend fun install(source: RulesDbSource, name: String): InstallReport {
        val tx = RulesDbTransaction(context.getDatabasePath(name))
        var assetSha: String? = null
        var recovery: String? = null
        try {
            recovery = tx.recover()
            val meta = DbMetaStore.read(tx.meta)
            assetSha = RulesDbDigest.raw(source.openStream(context))
            if (tx.matches(tx.active, meta) && meta?.assetSha256 == assetSha) {
                return report(tx, InstallState.UNCHANGED, assetSha,
                    "生效库与资产内容一致，无需替换", recovery)
            }
            RulesDbFiles.write(tx.incoming) { output ->
                source.openStream(context).use { input -> input.copyTo(output) }
                fault("STAGING_WRITE")
            }
            check(RulesDbDigest.raw(tx.incoming) == assetSha) { "暂存库摘要与资产不一致" }
            val content = requireNotNull(RulesDbDigest.content(tx.incoming)) { "暂存库不完整或四表无法读取" }
            validateWithRoom(tx.incoming, name)
            fault("STAGED")
            if (tx.active.isFile && meta == null) validateWithRoom(tx.active, name)
            val hadOld = tx.preserveOld() != null
            fault("BACKUP_READY")
            val next = DbMeta(assetSha, assetSha, content.digest, content.userVersion)
            tx.begin(next)
            fault("JOURNALED")
            tx.switch()
            fault("RENAMED")
            check(RulesDbDigest.raw(tx.active) == assetSha) { "切换后的原始摘要不匹配" }
            tx.commit(next)
            fault("META_WRITTEN")
            tx.finish()
            return report(tx, if (hadOld) InstallState.UPGRADED else InstallState.FIRST_INSTALL,
                assetSha, "新库已持久化并通过内容和 schema 校验", recovery)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            val restored = try {
                tx.recover()
            } catch (restoreError: Exception) {
                error.addSuppressed(restoreError)
                return report(tx, InstallState.INSTALL_ERROR, assetSha,
                    "安装与恢复失败：${error.message}；${restoreError.message}；保留现场，停止读取", recovery, error)
            }
            val meta = DbMetaStore.read(tx.meta)
            val valid = tx.matches(tx.active, meta)
            val state = when {
                valid && assetSha != null && meta?.assetSha256 == assetSha -> InstallState.RECOVERED
                valid -> InstallState.UPGRADE_FAILED_KEEPING_OLD
                else -> InstallState.FIRST_INSTALL_FAILED
            }
            return report(tx, state, assetSha,
                "安装未正常完成：${error.message}；" + if (valid) "已核验可用库" else "无可信规则库，停止读取",
                restored ?: recovery, error)
        }
    }

    private suspend fun validateWithRoom(staged: java.io.File, name: String) {
        val probeName = "$name.probe"
        context.deleteDatabase(probeName)
        val probe = RulesDatabase.open(context, RulesDbSource.FromFile(staged), probeName)
        try {
            val versions = probe.rules().versions()
            require(versions.isNotEmpty()) { "规则库没有任何版本数据" }
            for (version in versions) probe.rules().counts(version)
        } finally {
            probe.close()
            context.deleteDatabase(probeName)
        }
    }

    private fun report(
        tx: RulesDbTransaction, state: InstallState, asset: String?, reason: String,
        recovery: String? = null, cause: Throwable? = null,
    ): InstallReport {
        val meta = DbMetaStore.read(tx.meta)
        val content = RulesDbDigest.content(tx.active)
        val valid = tx.matches(tx.active, meta)
        return InstallReport(
            state = state, assetSha256 = asset,
            effectiveSha256 = if (valid) meta?.effectiveSha256 else null,
            activeFileSha256 = runCatching { RulesDbDigest.raw(tx.active) }.getOrNull(),
            contentSha256 = content?.digest, expectedContentSha256 = meta?.contentSha256,
            contentMatch = valid, schemaVersion = content?.userVersion,
            previousSha256 = runCatching { RulesDbDigest.raw(tx.backup) }.getOrNull(),
            reason = reason, recovery = recovery, cause = cause,
        )
    }
}
