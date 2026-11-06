package com.vscanner.rules

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.content.Context
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.IOException

@RunWith(AndroidJUnit4::class)
class RulesDbRecoveryTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val names = mutableListOf<String>()
    private fun name() = "recovery-unit-${names.size}.db".also {
        RulesRecoveryFixtures.clean(context, it)
        names += it
    }

    @After fun clean() = names.forEach { RulesRecoveryFixtures.clean(context, it) }

    @Test fun writeFailuresAtEveryBoundaryKeepACompleteLibrary() = runBlocking {
        for (point in listOf("STAGING_WRITE", "STAGED", "BACKUP_READY", "JOURNALED", "RENAMED", "META_WRITTEN")) {
            val name = name()
            val first = RulesDbInstaller(context).ensureInstalled(databaseName = name)
            val next = RulesRecoveryFixtures.changed(context)
            val report = RulesDbInstaller(context) { if (it == point) throw IOException("injected:$point") }
                .ensureInstalled(RulesDbSource.Bytes(next), name)
            assertTrue("$point: ${report.reason}", report.readable)
            val actual = RulesRecoveryFixtures.marker(context.getDatabasePath(name))
            if (point in setOf("RENAMED", "META_WRITTEN")) {
                assertEquals(InstallState.RECOVERED, report.state)
                assertEquals(RulesRecoveryFixtures.MARKER, actual)
            } else {
                assertEquals(InstallState.UPGRADE_FAILED_KEEPING_OLD, report.state)
                assertEquals(first.effectiveSha256, report.effectiveSha256)
                assertNotEquals(RulesRecoveryFixtures.MARKER, actual)
            }
            assertNotNull(report.cause)
            val reopened = RulesDbInstaller(context).ensureInstalled(RulesDbSource.Bytes(next), name)
            assertTrue(reopened.readable)
            assertEquals(RulesRecoveryFixtures.MARKER, RulesRecoveryFixtures.marker(context.getDatabasePath(name)))
        }
    }

    @Test fun firstInstallFailureDoesNotLetRoomCreateEmptyTables() = runBlocking {
        val name = name()
        val result = RulesVerifier(context).verify(RulesDbSource.Bytes(ByteArray(0)), name)
        assertFalse(result.install.readable)
        assertEquals(DbState.MISSING_OR_CORRUPT, result.state)
        assertTrue(result.counts.isEmpty())
        assertFalse(context.getDatabasePath(name).exists())
    }

    @Test fun firstInstallWithDurableIntentCanFinishWithoutAnOldCopy() = runBlocking {
        val name = name()
        val report = RulesDbInstaller(context) { if (it == "JOURNALED") throw IOException("first install interrupted") }
            .ensureInstalled(databaseName = name)
        assertTrue(report.readable)
        assertEquals(InstallState.RECOVERED, report.state)
        assertEquals("completed_first_install", report.recovery)
        assertEquals(report.assetSha256, report.effectiveSha256)
        assertEquals(InstallState.UNCHANGED, RulesDbInstaller(context).ensureInstalled(databaseName = name).state)
    }

    @Test fun damagedCurrentCopyRestoresVerifiedBackup() = runBlocking {
        val name = name()
        val old = RulesDbInstaller(context).ensureInstalled(databaseName = name)
        RulesDbInstaller(context).ensureInstalled(RulesDbSource.Bytes(RulesRecoveryFixtures.changed(context)), name)
        context.getDatabasePath(name).writeBytes(ByteArray(12))
        val restored = RulesDbInstaller(context).ensureInstalled(RulesDbSource.Bytes(ByteArray(0)), name)
        assertTrue(restored.readable)
        assertEquals(old.effectiveSha256, restored.effectiveSha256)
        assertEquals("restored_old_backup", restored.recovery)
    }

    @Test fun lossOfCurrentAndBackupStopsWithoutChangingEvidence() = runBlocking {
        val name = name()
        RulesDbInstaller(context).ensureInstalled(databaseName = name)
        context.getDatabasePath(name).writeText("broken evidence")
        val before = context.getDatabasePath(name).readBytes()
        val result = RulesVerifier(context).verify(databaseName = name)
        assertEquals(InstallState.INSTALL_ERROR, result.install.state)
        assertFalse(result.install.readable)
        assertTrue(result.counts.isEmpty())
        assertArrayEquals(before, context.getDatabasePath(name).readBytes())
    }

    @Test fun validHeaderWithCorruptBtreeIsNotDeletedBySqliteErrorHandling() = runBlocking {
        val name = name()
        RulesDbInstaller(context).ensureInstalled(databaseName = name)
        val file = context.getDatabasePath(name)
        val broken = file.readBytes().also { it[100] = 0xFF.toByte() }
        file.writeBytes(broken)
        val report = RulesVerifier(context).verify(databaseName = name)
        assertFalse(report.install.readable)
        assertEquals(InstallState.INSTALL_ERROR, report.install.state)
        assertTrue("corruption detector must preserve the active file", file.exists())
        assertArrayEquals(broken, file.readBytes())
    }

    @Test fun explicitCorruptionCallbackDoesNotDeleteTheFile() = runBlocking {
        val name = name()
        RulesDbInstaller(context).ensureInstalled(databaseName = name)
        val file = context.getDatabasePath(name)
        val before = file.readBytes()
        RulesDbSqlite.open(file).use { RulesDbSqlite.corruptionHandler.onCorruption(it) }
        assertArrayEquals(before, file.readBytes())
    }

    @Test fun unavailableLockReturnsStructuredFailureWithoutOpeningRoom() = runBlocking {
        val name = name()
        assertTrue(java.io.File(context.getDatabasePath(name).path + ".lock").mkdir())
        val report = RulesVerifier(context).verify(databaseName = name)
        assertEquals(InstallState.INSTALL_ERROR, report.install.state)
        assertFalse(report.install.readable)
        assertTrue(report.counts.isEmpty())
        assertNotNull(report.errorClass)
        assertFalse(context.getDatabasePath(name).exists())
    }

    @Test fun concurrentInstallersSerializeAndAgreeOnOneLibrary() = runBlocking {
        val name = name()
        val results = (1..8).map {
            async(Dispatchers.Default) { RulesDbInstaller(context).ensureInstalled(databaseName = name) }
        }.awaitAll()
        assertEquals(1, results.count { it.state == InstallState.FIRST_INSTALL })
        assertEquals(7, results.count { it.state == InstallState.UNCHANGED })
        assertTrue(results.all { it.readable })
        assertEquals(1, results.map { it.effectiveSha256 }.toSet().size)
    }

    @Test fun readerLeaseBlocksAnUpgradeUntilRoomCloses() = runBlocking {
        val name = name()
        RulesDbInstaller(context).ensureInstalled(databaseName = name)
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val read = async(Dispatchers.Default) {
            RulesDbInstaller(context).withInstalled(RulesDbSource.Asset(), name) {
                val db = RulesDatabase.open(context, databaseName = name)
                try {
                    db.rules().versions()
                    entered.complete(Unit)
                    release.await()
                    db.rules().counts("14")
                } finally { db.close() }
            }
        }
        entered.await()
        val upgrade = async(Dispatchers.Default) {
            RulesDbInstaller(context).ensureInstalled(RulesDbSource.Bytes(RulesRecoveryFixtures.changed(context)), name)
        }
        delay(250)
        assertFalse(upgrade.isCompleted)
        release.complete(Unit)
        read.await()
        assertEquals(InstallState.UPGRADED, upgrade.await().state)
    }
}
