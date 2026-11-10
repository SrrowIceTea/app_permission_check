package com.vscanner.rules

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.MessageDigest

/**
 * Proves on a real device that Room accepts the hand-written schema.sql.
 *
 * Room validates a prepackaged database against its own expected TableInfo the
 * first time it is opened. If schema.sql and RuleEntities.kt had drifted, the
 * first query below would throw - so these assertions ARE the schema contract
 * test, not a restatement of it.
 */
@RunWith(AndroidJUnit4::class)
class RulesSchemaValidationTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private lateinit var db: RulesDatabase

    @Before
    fun setUp() {
        db = RulesDatabase.open(context, RulesDbSource.Asset(), TEST_DB)
    }

    @After
    fun tearDown() {
        runCatching { db.close() }
        context.deleteDatabase(TEST_DB)
    }

    @Test
    fun opensFromAssetAndReturnsBaselineCounts() = runBlocking {
        val counts = db.rules().counts("14")
        assertEquals(10, counts.permissions)
        assertEquals(8, counts.vhalProperties)
        assertEquals(3, counts.dangerousApis)
        assertEquals(29, counts.riskRules)
        assertEquals(50, counts.total)
        // All 29 enabled per version: 6 over_permission + 13 sensitive_read (8 VHAL +
        // 5 VSC-GR) + 10 data_egress (8 VHAL + 2 VSC-GE). Asserted so an accidental
        // enable or disable is caught.
        assertEquals(29, counts.enabledRules)
    }

    @Test
    fun reportsOnlyTheBaselineVersions() = runBlocking {
        assertEquals(listOf("13", "14", "15", "16"), db.rules().versions())
    }

    /**
     * The android-13/16 rows are AOSP source extractions, not device observations. Their
     * egress rules stay disabled because no 30s window calibration exists for these
     * releases, while the other 19 rules follow the android-14 enablement scope.
     */
    @Test
    fun carriesSourceVerifiedAndroid13Rows() = runBlocking {
        val counts = db.rules().counts("13")
        assertEquals(10, counts.permissions)
        assertEquals(8, counts.vhalProperties)
        assertEquals(3, counts.dangerousApis)
        assertEquals(29, counts.riskRules)
        assertEquals(19, counts.enabledRules)
    }

    @Test
    fun carriesSourceVerifiedAndroid16Rows() = runBlocking {
        val counts = db.rules().counts("16")
        assertEquals(10, counts.permissions)
        assertEquals(8, counts.vhalProperties)
        assertEquals(3, counts.dangerousApis)
        assertEquals(29, counts.riskRules)
        assertEquals(19, counts.enabledRules)
    }

    @Test
    fun sourceRulesCarryAospSourceRefsNotDeviceObservations() {
        for (version in listOf("13", "16")) {
            db.openHelper.readableDatabase.query(
                "SELECT rule_id, source_refs_json FROM risk_rules WHERE android_version = ?",
                arrayOf(version),
            ).use { cursor ->
                assertEquals(29, cursor.count)
                while (cursor.moveToNext()) {
                    val ruleId = cursor.getString(0)
                    val sourceRefs = cursor.getString(1)
                    assertFalse(
                        "$ruleId claims device provenance under android-$version: $sourceRefs",
                        sourceRefs.contains("device_observation"),
                    )
                }
            }
        }
    }

    /**
     * The android-15 rows are device observations, not source extractions. They are
     * asserted here so that a future edit cannot quietly drop them or relabel them.
     */
    @Test
    fun carriesDeviceObservedAndroid15Rows() = runBlocking {
        val counts = db.rules().counts("15")
        assertEquals(150, counts.permissions)
        assertEquals(8, counts.vhalProperties)
        assertEquals(3, counts.dangerousApis)
        assertEquals(29, counts.riskRules)
        assertEquals(29, counts.enabledRules)
    }

    @Test
    fun copiedDatabaseKeepsUserVersionOne() {
        // Touching openHelper is what actually opens the copied file.
        val raw = db.openHelper.writableDatabase
        raw.query("PRAGMA user_version").use { cursor ->
            assertTrue(cursor.moveToFirst())
            assertEquals(1, cursor.getInt(0))
        }
    }

    /**
     * The integrity property the whole dual-version split rests on: an android-15 rule
     * must not cite AOSP android-14 sources. Mirrored rules keep their version-independent
     * policy basis but get device-observation provenance. Asserted rather than trusted,
     * because a careless rebuild is exactly how this would silently regress.
     */
    @Test
    fun android15RulesCarryDeviceProvenanceNotAndroid14SourceRefs() {
        db.openHelper.readableDatabase.query(
            "SELECT rule_id, source_refs_json, basis_refs_json FROM risk_rules" +
                " WHERE android_version = '15'"
        ).use { cursor ->
            assertEquals(29, cursor.count)
            while (cursor.moveToNext()) {
                val ruleId = cursor.getString(0)
                val sourceRefs = cursor.getString(1)
                assertFalse(
                    "$ruleId cites an AOSP commit under android-15: $sourceRefs",
                    sourceRefs.contains("\"commit\""),
                )
                assertTrue("$ruleId lacks device provenance", sourceRefs.contains("device_observation"))
                // Policy basis is version-independent and must survive the mirror.
                assertTrue("$ruleId lost its policy basis", cursor.getString(2).contains("POLICY.md"))
            }
        }
    }

    @Test
    fun packagedAssetMatchesGoldenDigest() {
        // Independent of SQLite: catches an asset swapped for a different file
        // that happens to be a valid database.
        val md = MessageDigest.getInstance("SHA-256")
        context.assets.open(RulesDatabase.DEFAULT_ASSET).use { stream ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                md.update(buffer, 0, read)
            }
        }
        val digest = md.digest().joinToString("") { "%02x".format(it) }
        assertEquals(BaselineExpectation.SHA256, digest)
    }

    private companion object {
        const val TEST_DB = "schema-validation-test.db"
    }
}
