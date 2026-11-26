package com.vscanner.privacydemo

// 仅用于授权测试。This test-only activity sends the emulator's scoped ID to a fixed local receiver.
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.util.Log
import android.widget.TextView
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest

class WindowBenchmarkActivity : Activity() {
    private var token: String? = null
    private val cached = mutableMapOf<String, String>()

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(TextView(this).apply { text = "移动读取与外发对照" })
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val run = intent.getStringExtra("benchmark_run") ?: return
        if (!run.matches(Regex("[a-f0-9]{32}")) || (token != null && token != run)) return
        token = run
        val step = intent.getStringExtra("benchmark_step") ?: return
        try {
            when (step) {
                "read-a", "read-b" -> read(run, step.last().toString())
                "send-a" -> {
                    val value = cached.getValue("a")
                    Thread({
                        try { send(run, value) }
                        catch (error: Exception) { record(run, "error", "a", "type", error.javaClass.simpleName) }
                    }, "owned-window-send").start()
                }
            }
        } catch (error: Exception) {
            record(run, "error", step, "type", error.javaClass.simpleName)
        }
    }

    private fun read(run: String, batch: String) {
        check(batch !in cached)
        val start = System.currentTimeMillis()
        val value = requireNotNull(Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID))
        check(value.matches(Regex("[0-9a-fA-F]{16}")))
        cached[batch] = value
        val digest = sha256(value.toByteArray())
        val marker = JSONObject().put("run", run).put("batch", batch).put("value_sha256", digest)
        Log.i("VScanWindowObserve", marker.toString())
        record(run, "read", batch, "start_ms", start, "end_ms", System.currentTimeMillis(), "value_sha256", digest)
    }

    private fun send(run: String, value: String) {
        val body = JSONObject().put("run", run).put("source_batch", "a").put("android_id", value)
            .toString().toByteArray(Charsets.UTF_8)
        val connection = URL("http://127.0.0.1:18960/collect").openConnection(Proxy.NO_PROXY) as HttpURLConnection
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
            record(run, "send", "a", "http_status", status, "body_sha256", responseSha)
        } finally { connection.disconnect() }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun record(run: String, event: String, batch: String, vararg fields: Any) {
        val row = JSONObject().put("run", run).put("event", event).put("batch", batch).put("pid", Process.myPid())
        for (index in fields.indices step 2) row.put(fields[index] as String, fields[index + 1])
        Log.i("VScanWindow", row.toString())
    }
}
