package com.vscanner.rules

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * Drives every failure path the verification page claims to distinguish.
 *
 * Each case uses its own database name. Room will not overwrite a copy it has
 * already made at the same version, so sharing a name would let one test's
 * leftovers decide another test's outcome.
 */
@RunWith(AndroidJUnit4::class)
class RulesVerifierStateTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val opened = mutableListOf<String>()

    @After
    fun tearDown() {
        opened.forEach { RulesRecoveryFixtures.clean(context, it) }
        opened.clear()
    }

    private suspend fun verify(source: RulesDbSource, name: String): VerificationReport {
        opened += name
        return RulesVerifier(context).verify(source, name)
    }

    @Test
    fun realAssetPasses() = runBlocking {
        val report = verify(RulesDbSource.Bytes(assetBytes()), "state-real.db")
        assertEquals(DbState.OK, report.state)
        assertTrue(report.sha256Match)
        assertEquals(46, report.counts.getValue("14").total)
    }

    @Test
    fun missingAssetIsReportedAsMissing() = runBlocking {
        val report = verify(RulesDbSource.Missing("rules.db"), "state-missing.db")
        assertEquals(DbState.MISSING_OR_CORRUPT, report.state)
        // Room wraps the real cause, so the chain is what has to be inspected.
        assertTrue(
            "expected FileNotFoundException in ${report.causes}",
            report.causes.any { it.contains("FileNotFoundException") },
        )
    }

    /**
     * Measured on device: bytes with an invalid SQLite header do NOT make SQLite
     * throw. Room builds an empty schema over them exactly as it does for a
     * zero-length asset, so this lands on the count check rather than on an
     * exception - the same trap as [zeroLengthAssetIsCaughtByCountsNotByAnException].
     *
     * The counts query below is what proves it: it selects from all four tables,
     * so it could not have returned zeros if Room had not created them.
     */
    @Test
    fun notADatabaseIsAlsoCaughtByCounts() = runBlocking {
        val report = verify(
            RulesDbSource.Bytes("这不是一个 SQLite 文件 not a database".toByteArray()),
            "state-notadb.db",
        )
        assertEquals(DbState.MISSING_OR_CORRUPT, report.state)
        assertNotNull(report.errorClass)
        assertTrue(report.counts.isEmpty())
        assertFalse(report.install.readable)
    }

    /**
     * The trap this test exists for: a zero-length asset throws nothing at all.
     * Room finds an empty schema, builds its own tables and answers every query
     * with nothing. Only the expected-count comparison catches it.
     */
    @Test
    fun zeroLengthAssetIsCaughtByCountsNotByAnException() = runBlocking {
        val report = verify(RulesDbSource.Bytes(ByteArray(0)), "state-empty.db")
        assertEquals(DbState.MISSING_OR_CORRUPT, report.state)
        assertNotNull(report.errorClass)
        assertTrue(report.counts.isEmpty())
        assertFalse(report.install.readable)
    }

    /**
     * Measured on device: truncating the real asset to 2048 bytes also throws
     * nothing. The valid database is replaced by an empty one and the counts go
     * to zero, exactly as for the two cases above.
     *
     * So every form of "the packaged file is not our schema" measured here -
     * empty, garbage header, truncated - reaches the count check, and none of
     * them raises. The exception branch in [classify] stays as a defence for
     * cases not yet observed, but it is not what catches these.
     */
    @Test
    fun truncatedAssetIsAlsoCaughtByCounts() = runBlocking {
        val report = verify(RulesDbSource.Bytes(assetBytes().copyOf(2048)), "state-truncated.db")
        assertEquals(DbState.MISSING_OR_CORRUPT, report.state)
        assertTrue(report.counts.isEmpty())
        assertFalse(report.install.readable)
    }

    @Test
    fun schemaDriftIsReportedAsSchemaMismatch() = runBlocking {
        val report = verify(RulesDbSource.Bytes(withExtraIndex(assetBytes())), "state-mismatch.db")
        assertEquals(DbState.SCHEMA_MISMATCH, report.state)
        assertTrue(
            "expected Room's schema wording, got: ${report.errorMessage}",
            report.errorMessage.orEmpty().contains("invalid schema") ||
                report.errorMessage.orEmpty().contains("data integrity"),
        )
    }

    private fun assetBytes(): ByteArray =
        context.assets.open(RulesDatabase.DEFAULT_ASSET).use { it.readBytes() }

    /** Adds an index the entities do not declare, which Room's validation rejects. */
    private fun withExtraIndex(bytes: ByteArray): ByteArray {
        val tmp = File(context.cacheDir, "mutated-rules.db")
        tmp.writeBytes(bytes)
        SQLiteDatabase.openDatabase(tmp.absolutePath, null, SQLiteDatabase.OPEN_READWRITE)
            .use { raw -> raw.execSQL("CREATE INDEX extra_idx ON permissions(notes)") }
        return tmp.readBytes().also { tmp.delete() }
    }

}
