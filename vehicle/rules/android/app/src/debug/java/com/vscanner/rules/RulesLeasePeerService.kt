package com.vscanner.rules

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import java.io.File

/** Debug-only, privileged diagnostic entry. 仅用于授权测试（自有规则库夹具）。 */
open class RulesLeasePeerService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val databaseName = "lease-crossprocess.db"

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val run = intent?.getStringExtra("run")
        val actor = intent?.getStringExtra("actor")
        val mode = intent?.getStringExtra("mode")
        if (run == null || !run.matches(Regex("[a-f0-9]{16}")) || actor !in setOf("A", "B", "C")
            || mode !in setOf("hold", "install")) {
            Log.e("VScannerRules", "Invalid cross-process diagnostic command")
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val folder = File(filesDir, "lease-crossprocess/$run").apply { mkdirs() }
        scope.launch {
            try {
                emit(folder, actor!!, "started")
                withTimeout(45000) {
                    emit(folder, actor, "attempting")
                    if (mode == "hold") hold(folder, actor)
                    else install(folder, actor, intent.getBooleanExtra("pause_inside", false))
                }
            } catch (error: Exception) {
                emit(folder, actor!!, "failed", JSONObject().put("error_class", error.javaClass.name)
                    .put("error", error.message))
            } finally {
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    private suspend fun awaitFile(file: File) {
        while (!file.isFile) delay(50)
    }

    private fun emit(folder: File, actor: String, phase: String, extra: JSONObject = JSONObject()) {
        val value = JSONObject(extra.toString()).put("actor", actor).put("phase", phase)
            .put("pid", Process.myPid()).put("uid", Process.myUid())
            .put("user_id", Process.myUid() / 100000).put("elapsed_ns", SystemClock.elapsedRealtimeNanos())
            .put("boot_id", File("/proc/sys/kernel/random/boot_id").readText().trim())
            .put("database_path", getDatabasePath(databaseName).canonicalPath)
            .put("process_name", File("/proc/self/cmdline").readText().trimEnd('\u0000'))
        RulesDbFiles.write(File(folder, "$actor-$phase.json")) { it.write(value.toString(2).toByteArray()) }
    }

    private suspend fun hold(folder: File, actor: String) {
        RulesDbLease.use(this, databaseName) {
            val before = requireNotNull(RulesDbDigest.content(getDatabasePath(databaseName)))
            val db = RulesDatabase.open(this, databaseName = databaseName)
            try {
                require(db.rules().versions().isNotEmpty())
                emit(folder, actor, "acquired", JSONObject().put("content_before", before.digest))
                awaitFile(File(folder, "release-$actor"))
                require(db.rules().counts("14").total > 0)
                val after = requireNotNull(RulesDbDigest.content(getDatabasePath(databaseName)))
                require(after == before) { "规则库在读取租约内发生改变" }
                emit(folder, actor, "read_checked", JSONObject().put("content_after", after.digest))
            } finally {
                db.close()
            }
            // Timestamp while still holding the lock; next peer may acquire immediately after return.
            emit(folder, actor, "leaving")
        }
        emit(folder, actor, "done")
    }

    private suspend fun install(folder: File, actor: String, pause: Boolean) {
        val source = RulesDbSource.FromFile(File(filesDir, "lease-crossprocess-next.db"))
        val result = RulesDbInstaller(this) { phase ->
            if (phase == "STAGING_WRITE") {
                emit(folder, actor, "install_entered")
                if (pause) {
                    val until = SystemClock.elapsedRealtime() + 40000
                    while (!File(folder, "continue-$actor").isFile) {
                        check(SystemClock.elapsedRealtime() < until) { "Host did not release diagnostic pause" }
                        Thread.sleep(50)
                    }
                }
            }
        }.ensureInstalled(source, databaseName)
        require(result.readable && result.state in setOf(InstallState.UPGRADED, InstallState.UNCHANGED)) { result.reason }
        emit(folder, actor, "done", JSONObject().put("install", result.toJson()))
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }
}

class RulesLeasePeerA : RulesLeasePeerService()
class RulesLeasePeerB : RulesLeasePeerService()
