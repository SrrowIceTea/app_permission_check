package com.vscanner.rules

import android.content.Context
import android.os.Process
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.File

/** Host orchestration invokes one method at a time, including real process death/reboot. */
class RulesDbRecoveryDeviceTest {
    private val context: Context = ApplicationProvider.getApplicationContext()
    private val args get() = InstrumentationRegistry.getArguments()
    private val name = "recovery-device.db"

    @Before fun hostOnly() = assumeTrue(args.getString("host_driver") == "true")

    private fun save(file: String, value: JSONObject) = File(context.filesDir, file).writeText(value.toString(2))

    @Test fun reset() = runBlocking {
        for (file in listOf("recovery-fault.json", "recovery-after.json")) File(context.filesDir, file).delete()
        RulesRecoveryFixtures.clean(context, name)
        val old = RulesDbInstaller(context).ensureInstalled(databaseName = name)
        assertTrue(old.readable)
        File(context.filesDir, "recovery-next.db").writeBytes(RulesRecoveryFixtures.changed(context))
        save("recovery-before.json", old.toJson())
    }

    @Test fun interrupt() = runBlocking {
        val point = requireNotNull(args.getString("fault_point"))
        val action = requireNotNull(args.getString("fault_action"))
        RulesDbInstaller(context) { reached ->
            if (reached == point) {
                save("recovery-fault.json", JSONObject().put("point", point).put("action", action)
                    .put("pid", Process.myPid()).put("boot_id", File("/proc/sys/kernel/random/boot_id").readText().trim()))
                if (action == "kill") Process.killProcess(Process.myPid())
                else if (action == "pause") while (true) Thread.sleep(1000)
                else error("unsupported fault action")
            }
        }.ensureInstalled(RulesDbSource.FromFile(File(context.filesDir, "recovery-next.db")), name)
        fail("fault point was not reached")
    }

    @Test fun reopen() = runBlocking {
        // No source upgrade: observe the state recovered from the interrupted transaction itself.
        val tx = RulesDbTransaction(context.getDatabasePath(name))
        val recovered = RulesDbLease.use(context, name) { tx.recover() }
        val meta = requireNotNull(DbMetaStore.read(tx.meta))
        assertTrue(tx.matches(tx.active, meta))
        val marker = RulesRecoveryFixtures.marker(tx.active)
        val next = RulesDbDigest.raw(File(context.filesDir, "recovery-next.db"))
        val before = JSONObject(File(context.filesDir, "recovery-before.json").readText())
        assertTrue(meta.effectiveSha256 in setOf(next, before.getString("effectiveSha256")))
        val content = requireNotNull(RulesDbDigest.content(tx.active))
        save("recovery-after.json", JSONObject().put("effectiveSha256", meta.effectiveSha256)
            .put("activeFileSha256", RulesDbDigest.raw(tx.active)).put("contentSha256", content.digest)
            .put("expectedContentSha256", meta.contentSha256).put("contentMatch", content.digest == meta.contentSha256)
            .put("schemaVersion", content.userVersion).put("readable", true).put("startup_recovery", recovered)
            .put("marker", marker).put("pid", Process.myPid())
            .put("boot_id", File("/proc/sys/kernel/random/boot_id").readText().trim()))
    }

    @Test fun clean() {
        RulesRecoveryFixtures.clean(context, name)
    }
}
