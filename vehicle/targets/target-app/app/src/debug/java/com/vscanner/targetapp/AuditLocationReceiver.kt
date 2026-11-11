package com.vscanner.targetapp

// 仅用于授权测试。Self-owned debug Actor; observers never rewrite API results.
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.location.LocationListener
import android.location.LocationManager
import android.os.Looper
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class AuditLocationReceiver : BroadcastReceiver() {
    @Suppress("MissingPermission")
    override fun onReceive(context: Context, intent: Intent) {
        val mode = intent.getStringExtra("mode") ?: return
        val token = intent.getStringExtra("token") ?: return
        if (mode !in setOf("pair", "mismatch", "single", "repeat")) return
        if (!token.matches(Regex("[a-zA-Z0-9_-]{1,80}"))) return
        val pending = goAsync()
        thread(name = "vsc-location-control") {
            val result = JSONObject().put("mode", mode).put("token", token)
            val manager = context.getSystemService(LocationManager::class.java)
            val ready = CountDownLatch(1)
            val listener = LocationListener { ready.countDown() }
            try {
                manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0f,
                    listener, Looper.getMainLooper())
                if (!ready.await(8, TimeUnit.SECONDS)) error("synthetic GPS update not received")
                val fix = manager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                    ?: error("no actual Location returned")
                if (mode == "repeat") {
                    val again = manager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
                        ?: error("second actual Location missing")
                    if (again.latitude != fix.latitude || again.longitude != fix.longitude)
                        error("GPS changed between repeated reads")
                }
                val latitude = fix.latitude
                val longitude = fix.longitude
                val value = when (mode) {
                    "pair", "repeat" -> String.format(Locale.US, "%.6f,%.6f", latitude, longitude)
                    "mismatch" -> String.format(Locale.US, "%.6f,%.6f", latitude + 1, longitude + 1)
                    else -> String.format(Locale.US, "%.6f", latitude)
                }
                val body = JSONObject().put("location", value).put("fixture_token", token)
                val connection = URL("http://127.0.0.1:8890/collect").openConnection(
                    Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 8888))) as HttpURLConnection
                try {
                    connection.connectTimeout = 3000
                    connection.readTimeout = 3000
                    connection.requestMethod = "POST"
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
                    result.put("http_status", connection.responseCode)
                    connection.inputStream.close()
                } finally { connection.disconnect() }
                result.put("returned_pair", String.format(Locale.US, "%.6f,%.6f", latitude, longitude))
                result.put("sent_value", value).put("completed", true)
            } catch (error: Exception) {
                result.put("completed", false).put("error_class", error.javaClass.name)
                    .put("error_message", error.message)
            } finally {
                manager.removeUpdates(listener)
                java.io.File(context.filesDir, "location-$token.json").writeText(result.toString())
                pending.finish()
            }
        }
    }
}
