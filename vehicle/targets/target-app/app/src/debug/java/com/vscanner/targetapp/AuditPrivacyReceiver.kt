package com.vscanner.targetapp

// 仅用于授权测试。Owned debug Actor; uploads only to fixed host-loopback fixture.
import android.content.BroadcastReceiver
import android.content.ContentProviderOperation
import android.content.Context
import android.content.Intent
import android.location.LocationListener
import android.location.LocationManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.os.Looper
import android.provider.ContactsContract
import android.provider.Settings
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

class AuditPrivacyReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val mode = intent.getStringExtra("mode") ?: return
        val token = intent.getStringExtra("token") ?: return
        if (!token.matches(Regex("[a-zA-Z0-9_-]{1,80}"))) return
        if (mode !in setOf("positive", "query_only", "wrong_key", "mismatch", "denied")) return
        val pending = goAsync()
        thread(name = "vsc-general-privacy") {
            val result = JSONObject().put("mode", mode)
            try {
                when (mode) {
                    "query_only" -> context.contentResolver.query(ContactsContract.Contacts.CONTENT_URI,
                        arrayOf(ContactsContract.Contacts._ID), null, null, null)?.use { }
                    "wrong_key" -> Settings.Secure.getString(context.contentResolver, "vscanner_owned_unmapped_key")
                    "denied" -> {
                        result.put("location", attempt { location(context, false) })
                        result.put("contacts", attempt { readContacts(context, false) })
                    }
                    else -> {
                        val id = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                        val payload = JSONObject().put("android_id",
                            if (mode == "mismatch") "CONTROL_DIFFERENT_ANDROID_ID" else id)
                        if (mode == "positive") {
                            result.put("location", attempt { location(context, true) })
                            result.put("microphone", attempt { recordAudio() })
                            payload.put("contact", readContacts(context, true))
                        }
                        val connection = URL("http://127.0.0.1:8890/collect").openConnection(
                            Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", 8888))) as HttpURLConnection
                        try {
                            connection.connectTimeout = 3000
                            connection.readTimeout = 3000
                            connection.requestMethod = "POST"
                            connection.doOutput = true
                            connection.setRequestProperty("Content-Type", "application/json")
                            connection.outputStream.use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
                            result.put("http_status", connection.responseCode)
                            connection.inputStream.close()
                        } finally { connection.disconnect() }
                    }
                }
                result.put("completed", true)
            } catch (e: Exception) { result.put("error_class", e.javaClass.name) }
            finally {
                java.io.File(context.filesDir, "privacy-$token.json").writeText(result.toString())
                pending.finish()
            }
        }
    }

    private fun attempt(block: () -> Any?): JSONObject = try {
        JSONObject().put("returned", block()).put("outcome", "ok")
    } catch (e: Exception) { JSONObject().put("outcome", "error").put("exception", e.javaClass.name) }

    @Suppress("MissingPermission")
    private fun location(context: Context, warm: Boolean): Boolean {
        val manager = context.getSystemService(LocationManager::class.java)
        if (warm) {
            val latch = CountDownLatch(1)
            val listener = LocationListener { latch.countDown() }
            manager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0f, listener, Looper.getMainLooper())
            try { latch.await(8, TimeUnit.SECONDS) } finally { manager.removeUpdates(listener) }
        }
        return manager.getLastKnownLocation(LocationManager.GPS_PROVIDER) != null
    }

    @Suppress("MissingPermission")
    private fun recordAudio(): Int {
        val minimum = AudioRecord.getMinBufferSize(16000, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        val recorder = AudioRecord(MediaRecorder.AudioSource.MIC, 16000, AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT, maxOf(4096, minimum))
        try {
            recorder.startRecording()
            val samples = ByteArray(320)
            repeat(10) {
                Thread.sleep(100)
                val count = recorder.read(samples, 0, samples.size, AudioRecord.READ_NON_BLOCKING)
                if (count > 0) return count
            }
            return 0
        } finally {
            if (recorder.recordingState == AudioRecord.RECORDSTATE_RECORDING) recorder.stop()
            recorder.release()
        }
    }

    private fun readContacts(context: Context, create: Boolean): String? {
        val resolver = context.contentResolver
        var raw: android.net.Uri? = null
        try {
            if (create) {
                val ops = arrayListOf(ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null).build(),
                    ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                        .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                        .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                        .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, "VScanner Owned Fixture Contact").build())
                raw = resolver.applyBatch(ContactsContract.AUTHORITY, ops)[0].uri
            }
            val rawId = raw?.lastPathSegment
            return resolver.query(ContactsContract.Data.CONTENT_URI,
                arrayOf(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME),
                if (rawId == null) "_id=-1" else "raw_contact_id=?", rawId?.let { arrayOf(it) }, null)?.use {
                if (it.moveToFirst()) it.getString(0) else null
            }
        } finally { raw?.let { resolver.delete(it, null, null) } }
    }
}
