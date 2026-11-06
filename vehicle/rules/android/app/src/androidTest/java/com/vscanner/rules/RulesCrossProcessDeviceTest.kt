package com.vscanner.rules

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/** Host-only driver; the competing work is done in two separate debug Service processes. */
class RulesCrossProcessDeviceTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val name = "lease-crossprocess.db"

    @Before fun hostOnly() = assumeTrue(InstrumentationRegistry.getArguments().getString("host_driver") == "true")

    @Test fun seed() = runBlocking {
        RulesRecoveryFixtures.clean(context, name)
        val report = RulesDbInstaller(context).ensureInstalled(databaseName = name)
        assertTrue(report.readable)
        File(context.filesDir, "lease-crossprocess-next.db").writeBytes(RulesRecoveryFixtures.changed(context))
        File(context.filesDir, "lease-crossprocess-before.json").writeText(report.toJson().toString(2))
    }

    @Test fun inspect() = runBlocking {
        val file = context.getDatabasePath(name)
        RulesDbLease.use(context, name) {
            val tx = RulesDbTransaction(file)
            val meta = requireNotNull(DbMetaStore.read(tx.meta))
            val content = requireNotNull(RulesDbDigest.content(file))
            val next = RulesDbDigest.raw(File(context.filesDir, "lease-crossprocess-next.db"))
            assertTrue(tx.matches(file, meta))
            assertEquals(next, meta.effectiveSha256)
            assertEquals(RulesRecoveryFixtures.MARKER, RulesRecoveryFixtures.marker(file))
            val result = JSONObject().put("effectiveSha256", meta.effectiveSha256)
                .put("contentSha256", content.digest).put("expectedContentSha256", meta.contentSha256)
                .put("schemaVersion", content.userVersion).put("activeFileSha256", RulesDbDigest.raw(file))
            File(context.filesDir, "lease-crossprocess-final.json").writeText(result.toString(2))
        }
    }
}
