package com.vscanner.targetapp

// Authorized tests on owned devices/APKs only. Test actor, not an observation Hook.
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import kotlin.concurrent.thread

class AuditScenarioReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val mode = intent.getStringExtra("mode") ?: return
        val token = intent.getStringExtra("token") ?: return
        if (!token.matches(Regex("[a-zA-Z0-9_-]{1,80}"))) return
        if (mode !in setOf("read_only", "plain", "mismatch", "derived", "delayed")) return
        val endpoint = intent.getStringExtra("endpoint") ?: "http://127.0.0.1:8888/collect"
        val uri = runCatching { URI(endpoint) }.getOrNull() ?: return
        if (uri.scheme != "http" || uri.host != "127.0.0.1" || uri.port != 8888 ||
            uri.path != "/collect" || uri.rawQuery != null || uri.userInfo != null) return
        val pending = goAsync()
        thread(name = "vsc-scenario") {
            val result = JSONObject().put("mode", mode).put("token", token)
            try {
                EventLog.init(context.applicationContext)
                val reads = VhalReader(context.applicationContext).readAll()
                result.put("reads", reads.size)
                val payload = JSONObject(EgressSender.buildPayload(reads))
                val records = payload.getJSONArray("reads")
                for (i in 0 until records.length()) {
                    val item = records.getJSONObject(i)
                    if (item.optString("result") != "ok" || !item.has("value")) continue
                    val raw = item.getString("value")
                    when (mode) {
                        "mismatch" -> item.put("value", "CONTROL-DIFFERENT-VALUE")
                        "derived" -> item.put("value", MessageDigest.getInstance("SHA-256")
                            .digest(raw.toByteArray(Charsets.UTF_8)).joinToString("") { "%02x".format(it) })
                    }
                }
                payload.put("scenarioToken", token)
                if (mode == "delayed") Thread.sleep(2500)
                if (mode != "read_only") {
                    val connection = uri.toURL().openConnection() as HttpURLConnection
                    try {
                        connection.connectTimeout = 5000
                        connection.readTimeout = 5000
                        connection.requestMethod = "POST"
                        connection.doOutput = true
                        connection.setRequestProperty("Content-Type", "application/json")
                        connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                        result.put("http_status", connection.responseCode)
                        connection.inputStream.use { it.readBytes() }
                    } finally { connection.disconnect() }
                }
                result.put("completed", true)
            } catch (error: Throwable) {
                result.put("completed", false).put("error", "${error.javaClass.name}: ${error.message}")
            } finally {
                context.openFileOutput("audit-scenario-$token.json", Context.MODE_PRIVATE)
                    .use { it.write(result.toString().toByteArray(Charsets.UTF_8)) }
                pending.finish()
            }
        }
    }
}
