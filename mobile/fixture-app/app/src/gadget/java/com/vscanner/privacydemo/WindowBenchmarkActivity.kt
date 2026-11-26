package com.vscanner.privacydemo

// 仅用于授权测试。This test-only activity sends the emulator's scoped ID to a fixed local receiver.
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.util.Log
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest

class WindowBenchmarkActivity : Activity() {
    private var token: String? = null
    private val cached = mutableMapOf<String, String>()
    private lateinit var queue: ScenarioQueue

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(TextView(this).apply { text = "移动读取与外发对照" })
        queue = ScenarioQueue(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val run = intent.getStringExtra("benchmark_run") ?: return
        if (!run.matches(Regex("[a-f0-9]{32}")) || (token != null && token != run)) return
        token = run
        val step = intent.getStringExtra("benchmark_step") ?: return
        try {
            when (step) {
                "read-a", "read-b" -> read(run, step.last().toString(), "foreground")
                "send-a" -> backgroundSend(run, "a", "foreground", false)
                // 后台只读：读取发生在具名后台线程，标记 origin=background。
                "bg-read-a", "bg-read-b" -> {
                    val batch = step.last().toString()
                    background(run, "bg-read") { read(run, batch, "background") }
                }
                // 后台即时发送：不经 adb reverse 绕路，走设备回环。
                "bg-send-a" -> backgroundSend(run, "a", "background", false)
                // 断网发送：强制走 10.0.2.2（不经 adb reverse），断网时应失败并入队。
                "bg-offline-send-a" -> backgroundSend(run, "a", "background", true)
                // 恢复联网后补传：把队列里的批次逐条送回本地回环。
                "bg-flush-a" -> background(run, "bg-flush") { flush(run) }
                "bg-queue-clear" -> queue.clearFor(run)
            }
        } catch (error: Exception) {
            record(run, "error", step, "type", error.javaClass.simpleName)
        }
    }

    private fun background(run: String, name: String, action: () -> Unit) {
        Thread({
            try { action() }
            catch (error: Exception) { record(run, "error", name, "type", error.javaClass.simpleName) }
        }, "owned-$name").start()
    }

    private fun backgroundSend(run: String, batch: String, origin: String, offline: Boolean) {
        background(run, if (offline) "bg-offline-send" else "bg-send") {
            val value = cached.getValue(batch)
            if (offline) {
                // 断网路径先入队；POST 失败保留队列，成功则移除。
                val pending = queue.enqueue(run, batch, value, System.currentTimeMillis())
                record(run, "enqueue", batch, "cached_batches", pending, "origin", origin)
                try {
                    send(run, batch, value, origin, "10.0.2.2")
                    queue.clearFor(run)
                } catch (error: Exception) {
                    record(run, "offline_failed", batch, "type", error.javaClass.simpleName,
                        "cached_batches", queue.size(), "origin", origin)
                }
            } else {
                send(run, batch, value, origin, "127.0.0.1")
            }
        }
    }

    private fun read(run: String, batch: String, origin: String) {
        check(batch !in cached)
        val start = System.currentTimeMillis()
        val value = requireNotNull(Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID))
        check(value.matches(Regex("[0-9a-fA-F]{16}")))
        cached[batch] = value
        val digest = sha256(value.toByteArray())
        // 旧字段 run/batch/value_sha256 原样保留；新增 origin/thread 供后台观测。
        val marker = JSONObject().put("run", run).put("batch", batch).put("value_sha256", digest)
            .put("origin", origin).put("thread", Thread.currentThread().name)
        Log.i("VScanWindowObserve", marker.toString())
        record(run, "read", batch, "start_ms", start, "end_ms", System.currentTimeMillis(),
            "value_sha256", digest, "origin", origin, "thread", Thread.currentThread().name)
    }

    private fun send(run: String, batch: String, value: String, origin: String, host: String) {
        val tokens = if (host == "127.0.0.1" && queue.size() > 0) queue.sourceBatchTokens(run) else JSONArray()
        val bodyObject = JSONObject().put("run", run).put("source_batch", batch).put("android_id", value)
            .put("origin", origin).put("thread", Thread.currentThread().name)
        if (tokens.length() > 0) bodyObject.put("source_batch_tokens", tokens)
        val body = bodyObject.toString().toByteArray(Charsets.UTF_8)
        val connection = URL("http://$host:18960/collect").openConnection(Proxy.NO_PROXY) as HttpURLConnection
        try {
            connection.requestMethod = "POST"
            connection.connectTimeout = 5000
            connection.readTimeout = 5000
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Connection", "close")
            connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            check(status == 200)
            val receipt = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
            val responseSha = receipt.getString("sha256")
            check(responseSha == sha256(body))
            record(run, "send", batch, "http_status", status, "body_sha256", responseSha,
                "origin", origin, "thread", Thread.currentThread().name,
                "source_batch_tokens", if (tokens.length() > 0) tokens else JSONArray())
        } finally { connection.disconnect() }
    }

    private fun flush(run: String) {
        val pending = queue.pending(run)
        record(run, "flush_start", "a", "cached_batches", pending.size, "origin", "background")
        for (row in pending) {
            val batch = row.optString("source_batch")
            val value = row.optString("android_id")
            val tokens = queue.sourceBatchTokens(run)
            val bodyObject = JSONObject().put("run", run).put("source_batch", batch).put("android_id", value)
                .put("origin", "background").put("thread", Thread.currentThread().name)
                .put("source_batch_tokens", tokens).put("created_ms", row.optLong("created_ms"))
            val body = bodyObject.toString().toByteArray(Charsets.UTF_8)
            val connection = URL("http://127.0.0.1:18960/collect").openConnection(Proxy.NO_PROXY) as HttpURLConnection
            try {
                connection.requestMethod = "POST"
                connection.connectTimeout = 5000
                connection.readTimeout = 5000
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body) }
                val status = connection.responseCode
                check(status == 200)
                val receipt = JSONObject(connection.inputStream.bufferedReader().use { it.readText() })
                check(receipt.getString("sha256") == sha256(body))
                record(run, "flush_send", batch, "http_status", status,
                    "body_sha256", receipt.getString("sha256"),
                    "source_batch_tokens", tokens, "origin", "background",
                    "thread", Thread.currentThread().name)
            } finally { connection.disconnect() }
        }
        queue.clearFor(run)
        record(run, "flush_done", "a", "origin", "background", "thread", Thread.currentThread().name)
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun record(run: String, event: String, batch: String, vararg fields: Any) {
        val row = JSONObject().put("run", run).put("event", event).put("batch", batch).put("pid", Process.myPid())
        for (index in fields.indices step 2) row.put(fields[index] as String, fields[index + 1])
        Log.i("VScanWindow", row.toString())
    }
}
