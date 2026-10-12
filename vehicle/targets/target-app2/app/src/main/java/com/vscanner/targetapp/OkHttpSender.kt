package com.vscanner.targetapp2

// 仅用于授权测试（自有设备与自有 APK）。错误 pin 是可重复的负向对照。
import okhttp3.CertificatePinner
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.URI
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

object OkHttpSender {
    fun send(endpoint: String, reads: List<ReadResult>, done: (String) -> Unit) {
        thread(name = "vsc-okhttp") {
            var client: OkHttpClient? = null
            val result = runCatching {
                require(URI(endpoint).scheme == "https") { "OkHttp pinning 夹具必须使用 HTTPS" }
                val host = requireNotNull(URI(endpoint).host)
                val pinner = CertificatePinner.Builder()
                    .add(host, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").build()
                client = OkHttpClient.Builder().certificatePinner(pinner)
                    .callTimeout(10, TimeUnit.SECONDS).build()
                val request = Request.Builder().url(endpoint)
                    .post(EgressSender.buildPayload(reads).toRequestBody("application/json".toMediaType()))
                    .build()
                client!!.newCall(request).execute().use { response ->
                    "OKHTTP_RESPONSE ${response.code}: ${response.body?.string()?.take(200)}"
                }
            }.getOrElse { "OKHTTP_ERROR ${it.javaClass.name}: ${it.message}" }
            EventLog.log(result)
            client?.connectionPool?.evictAll()
            client?.dispatcher?.executorService?.shutdown()
            done(result)
        }
    }
}
