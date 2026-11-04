package com.vscanner.targetapp

// Authorized tests on owned devices/APKs only. Test actor, not an observation Hook.
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.Proxy
import java.net.InetSocketAddress
import java.io.IOException
import java.security.MessageDigest
import kotlin.concurrent.thread

class AuditScenarioReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val mode = intent.getStringExtra("mode") ?: return
        val token = intent.getStringExtra("token") ?: return
        if (!token.matches(Regex("[a-zA-Z0-9_-]{1,80}"))) return
        if (mode !in setOf("read_only", "plain", "mismatch", "derived", "delayed",
                "grant_consent", "revoke_consent", "cache_collect", "cache_flush", "cache_clear",
                "consent_respected", "consent_ignored", "network_enqueue")) return
        val endpoint = intent.getStringExtra("endpoint") ?: "http://127.0.0.1:8888/collect"
        val uri = runCatching { URI(endpoint) }.getOrNull() ?: return
        // 10.0.2.2 is the emulator's host-loopback alias; no external endpoint is accepted.
        if (uri.scheme != "http" || uri.host !in setOf("127.0.0.1", "10.0.2.2") || uri.port !in setOf(8888, 8890) ||
            uri.path != "/collect" || uri.rawQuery != null || uri.userInfo != null) return
        val pending = goAsync()
        thread(name = "vsc-scenario") {
            val result = JSONObject().put("mode", mode).put("token", token)
            try {
                EventLog.init(context.applicationContext)
                val state = AuditScenarioState(context.applicationContext)
                when (mode) {
                    "grant_consent" -> state.setConsent("granted")
                    "revoke_consent" -> state.setConsent("revoked")
                    "cache_clear" -> state.clearCache()
                }
                result.put("consent", state.consent())
                if (mode in setOf("grant_consent", "revoke_consent", "cache_clear")) {
                    result.put("completed", true)
                    return@thread
                }
                if (mode == "consent_respected" && state.consent() != "granted") {
                    result.put("suppressed_by_fixture_consent", true).put("completed", true)
                    return@thread
                }
                val payload = if (mode == "cache_flush") {
                    state.cachedPayload() ?: run {
                        result.put("cache_empty", true).put("completed", true)
                        return@thread
                    }
                } else {
                    val reads = VhalReader(context.applicationContext).readAll()
                    result.put("reads", reads.size)
                    JSONObject(EgressSender.buildPayload(reads))
                }
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
                if (mode == "cache_collect") {
                    result.put("cached_batches", state.enqueue(payload))
                } else if (mode != "read_only") {
                    if (mode == "network_enqueue") result.put("cached_batches", state.enqueue(payload))
                    // A direct emulator-host connection is required to test a real
                    // Wi-Fi outage; an ADB-reversed system proxy would bypass it.
                    val connection = (if (uri.host == "10.0.2.2")
                        uri.toURL().openConnection(Proxy.NO_PROXY)
                        else if (uri.port == 8890)
                        uri.toURL().openConnection(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 8888)))
                        else uri.toURL().openConnection()) as HttpURLConnection
                    try {
                        connection.connectTimeout = 5000
                        connection.readTimeout = 5000
                        connection.requestMethod = "POST"
                        connection.doOutput = true
                        connection.setRequestProperty("Content-Type", "application/json")
                        connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                        result.put("http_status", connection.responseCode)
                        connection.inputStream.use { it.readBytes() }
                        if (mode == "cache_flush") state.clearCache()
                    } catch (error: IOException) {
                        if (mode != "network_enqueue") throw error
                        result.put("network_failed", true).put("network_error_class", error.javaClass.name)
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
