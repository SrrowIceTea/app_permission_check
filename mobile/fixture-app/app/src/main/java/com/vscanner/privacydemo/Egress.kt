package com.vscanner.privacydemo

// 仅用于授权测试（自有设备与自有 APK）。
//
// 外发组件。用平台自带的 HttpURLConnection，**不引 okhttp** ——
// 目的不是测证书固定（车载侧夹具已覆盖），而是产生两种可对比的传输：
//   HTTP  → 明文，命中「明文/未加密传输」检测项
//   HTTPS → 加密，作为对照（同样的数据、不同的保护）
//
// 载荷里带 device_id 与 android_id，且这两个值都**先经 PrivacyReader 读过**，
// 因此工具侧可以把读取事件的值哈希与报文令牌对上，形成值级匹配。

import android.annotation.SuppressLint
import android.content.Context
import android.provider.Settings
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object Egress {

    /** 读取 AndroidID：这是 Settings.Secure.getString 的 hook 目标。 */
    @SuppressLint("HardwareIds")
    fun androidId(ctx: Context): String =
        Settings.Secure.getString(ctx.contentResolver, Settings.Secure.ANDROID_ID) ?: "null"

    /** 构造外发载荷。字段名刻意用真实 App 常见的键名，让打标的关键词规则有对象。 */
    fun payload(ctx: Context, deviceId: String, location: String): String {
        val json = JSONObject()
        json.put("device_id", deviceId)
        json.put("android_id", androidId(ctx))
        json.put("location", location)
        json.put("model", android.os.Build.MODEL)
        json.put("ts", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US).format(Date()))
        return json.toString()
    }

    /** POST JSON。返回可读的结果摘要；失败如实回传，不吞异常。 */
    fun post(urlStr: String, body: String): String {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(urlStr)
            conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 8000
                readTimeout = 8000
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val bytes = (conn.inputStream ?: conn.errorStream)?.use { it.readBytes() }?.size ?: 0
            "HTTP $code，响应 $bytes 字节，请求 ${body.toByteArray(Charsets.UTF_8).size} 字节"
        } catch (e: Exception) {
            "外发失败：${e.javaClass.simpleName}: ${e.message}"
        } finally {
            conn?.disconnect()
        }
    }
}
