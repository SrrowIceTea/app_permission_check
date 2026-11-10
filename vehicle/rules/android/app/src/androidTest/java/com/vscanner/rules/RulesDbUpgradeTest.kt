package com.vscanner.rules

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/**
 * Proves the four upgrade contracts on a device:
 *  - first install equals the packaged database;
 *  - a same-schema content change replaces the old copy;
 *  - a failed upgrade keeps the old library usable;
 *  - a restart keeps the effective library rather than falling back to the old copy.
 */
@RunWith(AndroidJUnit4::class)
class RulesDbUpgradeTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val opened = mutableListOf<String>()

    @After
    fun tearDown() {
        opened.forEach { name ->
            context.deleteDatabase(name)
            sidecar(name, "meta").delete()
            sidecar(name, "previous").delete()
        }
        opened.clear()
    }

    private fun name(): String = "upgrade-test-${opened.size + 1}.db".also { opened += it }

    private suspend fun install(source: RulesDbSource, name: String) =
        RulesDbInstaller(context).ensureInstalled(source, name)

    @Test
    fun firstInstallEffectiveDigestEqualsPackagedDatabase() = runBlocking {
        val report = install(RulesDbSource.Asset(), name())
        assertEquals(InstallState.FIRST_INSTALL, report.state)
        assertEquals(sha256(assetBytes()), report.effectiveSha256)
        assertEquals(report.assetSha256, report.effectiveSha256)
        assertEquals(1, report.schemaVersion)
        assertTrue(report.contentMatch)
    }

    /**
     * The defect: a new APK with different rule content but the same Room schema
     * version used to keep the old copy. The digest - not the schema version - must
     * decide.
     */
    @Test
    fun sameSchemaContentChangeReplacesOldCopy() = runBlocking {
        val dbName = name()
        install(RulesDbSource.Asset(), dbName)
        val modified = withMarker(assetBytes())
        val upgraded = install(RulesDbSource.Bytes(modified), dbName)

        assertEquals(InstallState.UPGRADED, upgraded.state)
        assertEquals(sha256(modified), upgraded.effectiveSha256)
        assertTrue("old copy should be retained as evidence", upgraded.previousSha256 != null)
        assertEquals(MARKER, notes(context.getDatabasePath(dbName)))
        assertTrue(upgraded.contentMatch)
    }

    @Test
    fun failedUpgradeKeepsOldLibraryUsable() = runBlocking {
        val dbName = name()
        val first = install(RulesDbSource.Asset(), dbName)
        val failed = install(RulesDbSource.Bytes(ByteArray(0)), dbName)

        assertEquals(InstallState.UPGRADE_FAILED_KEEPING_OLD, failed.state)
        assertEquals(first.effectiveSha256, failed.effectiveSha256)
        assertEquals(1, failed.schemaVersion)
        assertTrue(failed.contentMatch)
        assertNull(failed.previousSha256)

        // The old library is not merely present, it still loads and returns its rows.
        val report = RulesVerifier(context).verify(RulesDbSource.Asset(), dbName)
        assertEquals(DbState.OK, report.state)
        assertEquals(50, report.counts.getValue("14").total)
        assertEquals(first.effectiveSha256, report.install.effectiveSha256)
    }

    @Test
    fun restartKeepsEffectiveLibrary() = runBlocking {
        val dbName = name()
        val modified = withMarker(assetBytes())
        val first = install(RulesDbSource.Bytes(modified), dbName)
        val again = install(RulesDbSource.Bytes(modified), dbName)

        assertEquals(InstallState.UNCHANGED, again.state)
        assertEquals(first.effectiveSha256, again.effectiveSha256)
        assertEquals(sha256(modified), again.effectiveSha256)
        assertTrue(again.contentMatch)
    }

    private fun sidecar(name: String, suffix: String) =
        File(context.getDatabasePath(name).parentFile, "$name.$suffix")

    private fun assetBytes(): ByteArray =
        context.assets.open(RulesDatabase.DEFAULT_ASSET).use { it.readBytes() }

    /** Same schema, different content: only a text column changes. */
    private fun withMarker(bytes: ByteArray): ByteArray {
        val tmp = File(context.cacheDir, "upgrade-marker-rules.db")
        tmp.writeBytes(bytes)
        SQLiteDatabase.openDatabase(tmp.path, null, SQLiteDatabase.OPEN_READWRITE).use { db ->
            db.execSQL(
                "UPDATE permissions SET notes='$MARKER'" +
                    " WHERE permission_name='android.car.permission.CAR_SPEED'" +
                    " AND android_version='14'"
            )
        }
        return tmp.readBytes().also { tmp.delete() }
    }

    private fun notes(file: File): String? =
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { db ->
            db.rawQuery(
                "SELECT notes FROM permissions" +
                    " WHERE permission_name='android.car.permission.CAR_SPEED'" +
                    " AND android_version='14'",
                null,
            ).use { c -> if (c.moveToFirst()) c.getString(0) else null }
        }

    private fun sha256(bytes: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(bytes)
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val MARKER = "UPGRADE_TEST_MARKER_20261105"
    }
}
