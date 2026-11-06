package com.vscanner.rules

import android.content.Context
import android.database.sqlite.SQLiteDatabaseCorruptException
import android.database.sqlite.SQLiteException
import android.os.Build
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileNotFoundException
import java.security.MessageDigest

/** The three outcomes the verification page must distinguish. */
enum class DbState { OK, SCHEMA_MISMATCH, MISSING_OR_CORRUPT }

/**
 * Non-negotiable constants describing the rule database this build is supposed to
 * ship. Taken from rules_library/rules.db.summary.json - never adjusted to make a
 * failing check pass.
 *
 * The two versions come from different places and that distinction is load-bearing:
 * "14" is extracted from AOSP android-14.0.0_r1 source; "15" is observed on the API 35
 * test device (146 car permissions read off `pm list permissions -f`, VHAL ids and CPM
 * signatures read off the device's own android.car.jar). Device observations are
 * definition_status=pending and must never be reported as source extractions.
 *
 * enabledRules counts the rules actually approved to produce audit conclusions. It is
 * asserted so that an accidental enable or disable is noticed.
 *
 * All 22 VHAL rules per version enabled after E1 calibration to 30000ms, plus seven
 * registered general-privacy rules (VSC-GR and VSC-GE prefixes): 29 enabled per version.
 * See EGRESS_CALIBRATION.md (2026-09-24 user authorization) and vehicle/privacy/POLICY.md.
 */
object BaselineExpectation {
    const val SHA256 = "4bf51ba0aadb0234aefb80dfc197429347d748c38fb36f567e90c2d928bff824"
    const val SOURCE_TAG = "14=AOSP android-14.0.0_r1 / 15=设备实测 API 35"

    val VERSIONS: Map<String, VersionCounts> = mapOf(
        "14" to VersionCounts(
            permissions = 6,
            vhalProperties = 8,
            dangerousApis = 3,
            // 22 VHAL rules + 5 VSC-GR + 2 VSC-GE general-privacy rules.
            riskRules = 29,
            enabledRules = 29,
        ),
        "15" to VersionCounts(
            permissions = 146,
            vhalProperties = 8,
            dangerousApis = 3,
            // The nine policy drafts are mirrored here. Their basis_refs (POLICY.md) is
            // version-independent project policy and carried over unchanged; their
            // source_refs were replaced with device observations, because the AOSP
            // android-14 citations do not describe this release. DECISIONS D009.
            riskRules = 29,
            enabledRules = 29,
        ),
    )
}

data class VerificationReport(
    val state: DbState,
    val reason: String,
    val counts: Map<String, VersionCounts>,
    val expected: Map<String, VersionCounts>,
    val sha256Actual: String?,
    val sha256Expected: String,
    val sha256Match: Boolean,
    val errorClass: String?,
    val errorMessage: String?,
    /** Class names of the whole cause chain: Room wraps the real error. */
    val causes: List<String>,
    val deviceApiLevel: Int,
    val elapsedMs: Long,
    /** Whether the runtime copy still matches the database packaged in this APK. */
    val install: InstallReport,
) {
    fun toJson(): String {
        val root = JSONObject()
        root.put("state", state.name)
        root.put("stateLabel", state.label())
        root.put("reason", reason)
        root.put("sha256", JSONObject().apply {
            put("actual", sha256Actual ?: JSONObject.NULL)
            put("expected", sha256Expected)
            put("match", sha256Match)
        })
        root.put("install", install.toJson())
        root.put("counts", countsJson(counts))
        root.put("expected", countsJson(expected))
        root.put("deviceApiLevel", deviceApiLevel)
        root.put("sourceTag", BaselineExpectation.SOURCE_TAG)
        root.put("elapsedMs", elapsedMs)
        root.put("error", JSONObject().apply {
            put("class", errorClass ?: JSONObject.NULL)
            put("message", errorMessage ?: JSONObject.NULL)
            put("causes", JSONArray(causes))
        })
        return root.toString(2)
    }

    private fun countsJson(map: Map<String, VersionCounts>) = JSONObject().apply {
        for ((version, c) in map) {
            put(version, JSONObject().apply {
                put("permissions", c.permissions)
                put("vhal_properties", c.vhalProperties)
                put("dangerous_apis", c.dangerousApis)
                put("risk_rules", c.riskRules)
                put("enabled_rules", c.enabledRules)
                put("total", c.total)
            })
        }
    }
}

fun DbState.label(): String = when (this) {
    DbState.OK -> "读取成功"
    DbState.SCHEMA_MISMATCH -> "schema 不匹配"
    DbState.MISSING_OR_CORRUPT -> "数据库缺失或损坏"
}

/**
 * Opens the prepackaged rule database and checks it against [BaselineExpectation].
 *
 * The awkward part is that Room does not report every bad database as an error.
 * A zero-length or wholesale-truncated asset is accepted, an empty schema is
 * created in its place, and every query politely returns nothing. Only comparing
 * the row counts against the expected ones catches that, which is why step 3
 * below exists at all.
 */
class RulesVerifier(private val context: Context) {

    suspend fun verify(
        source: RulesDbSource = RulesDbSource.Asset(),
        databaseName: String = RulesDatabase.DEFAULT_NAME,
    ): VerificationReport {
        val started = System.nanoTime()
        val digest = tryHash(source)
        // Room only copies the asset while the target file is absent, so an APK
        // update that changed rules.db but not the schema version would keep the
        // old copy. The installer decides on the digest, not on the schema version.
        return RulesDbInstaller(context).withInstalled(source, databaseName) { install ->
            if (!install.readable) {
                return@withInstalled failure(install.cause ?: java.io.IOException(install.reason), digest, started, install)
            }
            val db = RulesDatabase.open(context, source, databaseName)
            try {
                // RulesDatabase.open() is lazy. Every copy error and every schema
                // validation error surfaces on the first DAO call below, so the first
                // query - not the open - is the thing that must be guarded.
                val dao = db.rules()
                val present = dao.versions()
                val counts = LinkedHashMap<String, VersionCounts>()
                for (version in (BaselineExpectation.VERSIONS.keys + present).sorted()) {
                    counts[version] = dao.counts(version)
                }
                success(counts, digest, started, install)
            } catch (t: Throwable) {
                failure(t, digest, started, install)
            } finally {
                runCatching { db.close() }
            }
        }
    }

    private fun success(
        counts: Map<String, VersionCounts>,
        digest: String?,
        started: Long,
        install: InstallReport,
    ): VerificationReport {
        val expected = BaselineExpectation.VERSIONS
        val shaMatch = digest == BaselineExpectation.SHA256
        val effectiveMatch = install.effectiveSha256 == BaselineExpectation.SHA256
        val countsMatch = expected.all { (version, exp) -> counts[version] == exp }

        // The empty-schema trap: Room created its own tables from a 0-byte asset,
        // so nothing threw but there is no rule data either.
        val allEmpty = counts.isNotEmpty() && counts.values.all { it.isEmpty }

        val state: DbState
        val reason: String
        when {
            shaMatch && effectiveMatch && countsMatch -> {
                state = DbState.OK
                reason = "预置规则库与基线一致（SHA-256 匹配，四表条数符合预期）"
            }
            allEmpty -> {
                state = DbState.MISSING_OR_CORRUPT
                reason = "四表全部为 0 行：Room 未报错，说明 assets/rules.db 是空文件或被整体截断，" +
                    "Room 用它自建了空 schema。这是唯一能发现该情况的判据。"
            }
            else -> {
                state = DbState.SCHEMA_MISMATCH
                reason = "预置规则库与基线不符：SHA-256 ${if (shaMatch) "匹配" else "不匹配"}，" +
                    "生效库${if (effectiveMatch) "匹配" else "不匹配"}，条数${if (countsMatch) "符合" else "不符合"}预期"
            }
        }

        return VerificationReport(
            state = state,
            reason = reason,
            counts = counts,
            expected = expected,
            sha256Actual = digest,
            sha256Expected = BaselineExpectation.SHA256,
            sha256Match = shaMatch,
            errorClass = null,
            errorMessage = null,
            causes = emptyList(),
            deviceApiLevel = Build.VERSION.SDK_INT,
            elapsedMs = (System.nanoTime() - started) / 1_000_000,
            install = install,
        )
    }

    private fun failure(
        t: Throwable,
        digest: String?,
        started: Long,
        install: InstallReport,
    ): VerificationReport {
        val state = classify(t)
        return VerificationReport(
            state = state,
            reason = defaultReason(state),
            counts = emptyMap(),
            expected = BaselineExpectation.VERSIONS,
            sha256Actual = digest,
            sha256Expected = BaselineExpectation.SHA256,
            sha256Match = digest == BaselineExpectation.SHA256,
            errorClass = t.javaClass.name,
            errorMessage = t.message,
            causes = generateSequence(t) { it.cause }.take(8).map { it.javaClass.name }.toList(),
            deviceApiLevel = Build.VERSION.SDK_INT,
            elapsedMs = (System.nanoTime() - started) / 1_000_000,
            install = install,
        )
    }

    private fun defaultReason(state: DbState) = when (state) {
        DbState.SCHEMA_MISMATCH ->
            "Room 拒绝了预置数据库的 schema。差异见上方异常信息中的 Expected/Found。"
        DbState.MISSING_OR_CORRUPT ->
            "预置数据库无法读取或不是有效的 SQLite 文件。"
        DbState.OK -> ""
    }

    /** Hashes the source the same way Room will read it. Null when unreadable. */
    private fun tryHash(source: RulesDbSource): String? = runCatching {
        val md = MessageDigest.getInstance("SHA-256")
        source.openStream(context).use { stream ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
            }
        }
        md.digest().joinToString("") { "%02x".format(it) }
    }.getOrNull()
}

/**
 * Maps a throwable to one of the three states.
 *
 * Everything is decided on the type of the throwable and on the nested cause
 * chain - never on the wording of a message, apart from Room's own fixed schema
 * strings. Room wraps the real error, so the cause chain is what carries it.
 */
fun classify(t: Throwable): DbState {
    val chain = generateSequence(t) { it.cause }.take(8).toList()

    chain.filterIsInstance<IllegalStateException>().firstOrNull { e ->
        val m = e.message.orEmpty()
        m.contains("Pre-packaged database has an invalid schema") ||
            m.contains("Room cannot verify the data integrity") ||
            m.contains("Migration didn't properly handle")
    }?.let { return DbState.SCHEMA_MISMATCH }

    // Classified by cause type on purpose: Room wraps a missing asset in a
    // deliberately generic RuntimeException("Unable to copy database file.").
    chain.filterIsInstance<FileNotFoundException>().firstOrNull()
        ?.let { return DbState.MISSING_OR_CORRUPT }

    // SQLITE_CORRUPT and SQLITE_NOTADB both surface here.
    chain.filterIsInstance<SQLiteDatabaseCorruptException>().firstOrNull()
        ?.let { return DbState.MISSING_OR_CORRUPT }

    chain.filterIsInstance<SQLiteException>().firstOrNull()
        ?.let { return DbState.MISSING_OR_CORRUPT }

    return DbState.MISSING_OR_CORRUPT
}
