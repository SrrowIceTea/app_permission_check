package com.vscanner.targetapp

// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// 行为 3：数据外泄。把行为 2 读取到的结果 POST 为 JSON。
//   - 3a HTTP 明文变体：usesCleartextTraffic=true（清单里明示），供抓包直接观察。
//   - 3b HTTPS 变体：走系统默认信任链、无证书固定、无自签校验收紧 —— 特意保持“最平凡”的
//     TLS 客户端，让 Phase 4 的 CA 注入 / 绕过演练有真实靶点。Mitmproxy CA 未装为系统 CA 时
//     预期得到 SSLHandshakeException，日志会如实记录（这是有效结果，不是缺陷）。
// 每次请求的 URL、方法、响应码、响应体摘要、异常类名+消息全部落日志。

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import kotlin.concurrent.thread

object EgressSender {

    private const val TIMEOUT_MS = 10_000
    const val USER_AGENT = "VSCTarget/1.0 (authorized test fixture)"

    /** 异步发送；结果通过 onDone 回传摘要文本（调用方负责切回 UI 线程）。 */
    fun send(endpoint: String, reads: List<ReadResult>, onDone: (String) -> Unit) {
        thread(name = "vsc-egress") {
            onDone(doSend(endpoint, reads))
        }
    }

    private fun doSend(endpoint: String, reads: List<ReadResult>): String {
        EventLog.log("== 数据外泄开始: POST $endpoint（${reads.size} 条读取结果）==")
        var conn: HttpURLConnection? = null
        return try {
            val payload = buildPayload(reads)
            EventLog.log("外泄 payload: $payload")
            val url = URL(endpoint)
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("User-Agent", USER_AGENT)
            }
            conn.outputStream.use { it.write(payload.toByteArray(StandardCharsets.UTF_8)) }
            val code = conn.responseCode
            val body = readBody(conn).take(200)
            EventLog.log("外泄响应: HTTP $code body=$body")
            "HTTP $code: $body"
        } catch (e: Throwable) {
            // 异常类名全量记录：网络不通 / TLS 握手失败 / 超时 必须可区分
            EventLog.log("外泄失败: ${e.javaClass.name}: ${e.message}")
            "${e.javaClass.name}: ${e.message}"
        } finally {
            runCatching { conn?.disconnect() }
            EventLog.log("== 数据外泄结束 ==")
        }
    }

    private fun readBody(conn: HttpURLConnection): String {
        val stream = runCatching { conn.inputStream }.getOrElse { conn.errorStream }
        if (stream == null) return ""
        return stream.bufferedReader().use { it.readText() }
    }

    /** 载荷含：属性名、数值 ID、类型、所需权限、结果三态、值/异常、读取时间戳。 */
    fun buildPayload(reads: List<ReadResult>): String {
        val root = JSONObject().apply {
            put("event", "vhal_reads_egress")
            put("package", "com.vscanner.targetapp")
            put("app", "VSCTarget test fixture")
            put("note", "authorized test on owned device and owned APK only")
            put("sentAtUtcMs", System.currentTimeMillis())
        }
        val arr = JSONArray()
        reads.forEach { r ->
            arr.put(JSONObject().apply {
                put("property", r.property)
                put("propertyId", r.propertyId)
                put("valueType", r.valueType)
                put("requiredPermission", r.requiredPermission)
                put("result", r.result)
                r.value?.let { put("value", it) }
                r.errorClass?.let { put("errorClass", it) }
                r.errorMessage?.let { put("errorMessage", it) }
                put("readAtUtcMs", r.readAtUtcMs)
            })
        }
        root.put("reads", arr)
        return root.toString()
    }
}
