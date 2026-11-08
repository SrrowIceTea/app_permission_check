package com.vscanner.rules

import android.database.sqlite.SQLiteDatabase
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.util.Properties

/** Canonical digest of the rule payload, plus the schema version it belongs to. */
internal data class DbContent(val digest: String, val userVersion: Int)

/**
 * Two kinds of digest are needed, for different questions.
 *
 * [raw] answers "which file is this" - it is the SHA-256 of the `rules.db` bytes inside
 * the APK, and is the identity reported as the effective rule library. It cannot be
 * re-computed on the live copy: Room adds `room_master_table` and `android_metadata` on
 * first open, so the on-disk bytes stop matching the asset even though the rules did not
 * change.
 *
 * [content] answers "are the rules still the installed ones" - it hashes a canonical
 * dump of the four rule tables (sorted rows, all columns, plus `PRAGMA user_version`) and
 * ignores Room's bookkeeping tables. This is what decides whether a reinstall is needed.
 */
internal object RulesDbDigest {

    private val utf8 = Charsets.UTF_8
    private val fieldSeparator = byteArrayOf(0x1F)
    private val rowSeparator = byteArrayOf(0x1E)
    private val nullMarker = byteArrayOf(0x00)

    /** Primary-key ordering per table; column order comes from the table definition. */
    private val tables = linkedMapOf(
        "permissions" to "permission_name, android_version",
        "vhal_properties" to "property_key, android_version",
        "dangerous_apis" to "api_key, android_version",
        "risk_rules" to "rule_id, android_version",
    )

    fun raw(stream: InputStream): String {
        val md = MessageDigest.getInstance("SHA-256")
        stream.use {
            val buffer = ByteArray(8192)
            while (true) {
                val read = it.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
            }
        }
        return hex(md.digest())
    }

    fun raw(file: File): String = file.inputStream().use { raw(it) }

    /**
     * Null when the file is not a complete rule database - empty, garbage header, or
     * truncated so that a table is missing. The empty-schema trap makes this the only
     * reliable pre-check: Room would happily build its own empty tables instead.
     */
    fun content(file: File): DbContent? = runCatching {
        RulesDbSqlite.open(file).use { db ->
            db.rawQuery("PRAGMA quick_check", null).use { c ->
                require(c.moveToFirst() && c.getString(0) == "ok") { "SQLite 完整性检查失败" }
            }
            val version = db.rawQuery("PRAGMA user_version", null).use { c ->
                if (c.moveToFirst()) c.getInt(0) else 0
            }
            val md = MessageDigest.getInstance("SHA-256")
            md.update("vscanner-rules-content-v2\n".toByteArray(utf8))
            md.update("user_version=$version\n".toByteArray(utf8))
            for ((table, order) in tables) {
                md.update("table=$table\n".toByteArray(utf8))
                db.rawQuery("SELECT * FROM $table ORDER BY $order", null).use { c ->
                    while (c.moveToNext()) {
                        for (i in 0 until c.columnCount) {
                            val value = c.getString(i)
                            if (value == null) md.update(nullMarker)
                            else md.update(value.toByteArray(utf8))
                            md.update(fieldSeparator)
                        }
                        md.update(rowSeparator)
                    }
                }
            }
            DbContent(hex(md.digest()), version)
        }
    }.getOrNull()

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }
}

/** What was installed, recorded next to the runtime database. */
internal data class DbMeta(
    val assetSha256: String,
    val effectiveSha256: String,
    val contentSha256: String,
    val schemaVersion: Int,
    val algorithmVersion: Int = DbMetaStore.ALGORITHM_VERSION,
)

internal object DbMetaStore {
    const val ALGORITHM_VERSION = 2

    private const val KEY_ASSET = "asset_sha256"
    private const val KEY_EFFECTIVE = "effective_sha256"
    private const val KEY_CONTENT = "content_sha256"
    private const val KEY_SCHEMA = "schema_version"
    private const val KEY_ALGORITHM = "algorithm_version"

    fun read(file: File): DbMeta? = runCatching {
        if (!file.isFile) return null
        val props = Properties()
        file.inputStream().use { props.load(it) }
        DbMeta(
            assetSha256 = requireNotNull(props.getProperty(KEY_ASSET)),
            effectiveSha256 = requireNotNull(props.getProperty(KEY_EFFECTIVE)),
            contentSha256 = requireNotNull(props.getProperty(KEY_CONTENT)),
            schemaVersion = requireNotNull(props.getProperty(KEY_SCHEMA)).toInt(),
            algorithmVersion = requireNotNull(props.getProperty(KEY_ALGORITHM)).toInt(),
        ).also { meta ->
            require(listOf(meta.assetSha256, meta.effectiveSha256, meta.contentSha256).all {
                it.matches(Regex("[a-f0-9]{64}"))
            } && meta.schemaVersion > 0) { "规则库元数据格式无效" }
        }
    }.getOrNull()

    fun write(file: File, data: DbMeta) {
        val props = Properties().apply {
            setProperty(KEY_ASSET, data.assetSha256)
            setProperty(KEY_EFFECTIVE, data.effectiveSha256)
            setProperty(KEY_CONTENT, data.contentSha256)
            setProperty(KEY_SCHEMA, data.schemaVersion.toString())
            setProperty(KEY_ALGORITHM, data.algorithmVersion.toString())
        }
        RulesDbFiles.write(file) { props.store(it, "V-Scanner rules.db install state") }
    }
}
