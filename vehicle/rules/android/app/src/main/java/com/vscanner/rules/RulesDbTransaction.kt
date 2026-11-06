package com.vscanner.rules

import android.database.sqlite.SQLiteDatabase
import java.io.File
import java.io.IOException

/** Durable intent plus independently validated backup; all callers must hold RulesDbLease. */
internal class RulesDbTransaction(val active: File) {
    val meta = sidecar("meta")
    val backup = sidecar("previous")
    private val backupMeta = sidecar("previous.meta")
    private val journal = sidecar("transaction")
    val incoming = sidecar("incoming")

    private fun sidecar(suffix: String) = File(active.parentFile, "${active.name}.$suffix")

    fun matches(file: File, expected: DbMeta?): Boolean = expected != null &&
        expected.algorithmVersion == DbMetaStore.ALGORITHM_VERSION &&
        RulesDbDigest.content(file)?.let {
            it.digest == expected.contentSha256 && it.userVersion == expected.schemaVersion
        } == true

    fun recover(): String? {
        if (journal.exists()) {
            val next = DbMetaStore.read(journal)
            val old = DbMetaStore.read(backupMeta)
            if (matches(active, next)) {
                DbMetaStore.write(meta, requireNotNull(next))
                RulesDbFiles.remove(journal)
                return "completed_new_library"
            }
            if (matches(active, old)) {
                DbMetaStore.write(meta, requireNotNull(old))
                RulesDbFiles.remove(journal)
                return "retained_old_library"
            }
            if (matches(backup, old)) return restore(requireNotNull(old))
            if (!active.exists() && matches(incoming, next) && RulesDbDigest.raw(incoming) == next?.assetSha256) {
                RulesDbFiles.replace(incoming, active)
                DbMetaStore.write(meta, requireNotNull(next))
                RulesDbFiles.remove(journal)
                return "completed_first_install"
            }
            throw IOException("中断切换没有可验证的当前库或备份；保留现场并停止读取")
        }
        val current = DbMetaStore.read(meta)
        if (matches(active, current)) return null
        if (!meta.exists() && !active.exists()) return null
        // Pre-installer legacy files may be adopted only after validating the new asset.
        if (!meta.exists() && active.isFile) return null
        val old = DbMetaStore.read(backupMeta)
        if (matches(backup, old)) return restore(requireNotNull(old))
        throw IOException("生效库或元数据损坏且无可信备份；保留现场并停止读取")
    }

    private fun restore(old: DbMeta): String {
        // Never remove a potentially recoverable active file before a complete copy exists.
        clearSidecars()
        RulesDbFiles.copy(backup, active)
        check(matches(active, old)) { "备份恢复后内容校验失败" }
        DbMetaStore.write(meta, old)
        RulesDbFiles.remove(journal)
        return "restored_old_backup"
    }

    fun preserveOld(): DbMeta? {
        if (!active.isFile) return null
        // Close/checkpoint historical WAL before copying the base file. No live Room lease may overlap.
        RulesDbSqlite.open(active, writable = true).use { db ->
            db.rawQuery("PRAGMA wal_checkpoint(TRUNCATE)", null).use { c ->
                check(c.moveToFirst() && c.getInt(0) == 0) { "旧库 WAL 仍被占用" }
            }
            db.rawQuery("PRAGMA journal_mode=DELETE", null).use { c ->
                check(c.moveToFirst() && c.getString(0).equals("delete", true)) { "旧库日志模式无法收敛" }
            }
        }
        val content = requireNotNull(RulesDbDigest.content(active)) { "旧库内容无法校验" }
        val raw = RulesDbDigest.raw(active)
        val old = DbMetaStore.read(meta) ?: DbMeta(raw, raw, content.digest, content.userVersion)
        check(matches(active, old)) { "旧库与元数据不匹配，停止替换" }
        RulesDbFiles.copy(active, backup)
        check(matches(backup, old)) { "旧库备份校验失败" }
        DbMetaStore.write(backupMeta, old)
        return old
    }

    fun begin(next: DbMeta) = DbMetaStore.write(journal, next)

    fun switch() {
        clearSidecars()
        RulesDbFiles.replace(incoming, active)
    }

    fun commit(next: DbMeta) {
        check(matches(active, next)) { "切换后内容校验失败" }
        DbMetaStore.write(meta, next)
    }

    fun finish() = RulesDbFiles.remove(journal)

    private fun clearSidecars() {
        for (suffix in listOf("-wal", "-shm", "-journal")) RulesDbFiles.remove(File(active.path + suffix))
    }
}
