// 仅用于授权测试（自有设备与自有 APK）。
//
// 这个入口专用于 hook_native_ssl 的设备端正控：在进程内 127.0.0.1 起一个最小 TLS
// 服务端，再用 SSLSocket 握手 + 一次 ping/pong 读写。它不携带业务数据、不联网、
// 不做证书固定，也不是外泄场景，不要把它当成业务路径复用。
package com.vscanner.targetapp

import android.content.Context
import android.util.Log
import java.net.InetAddress
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

object SslLoopbackProbe {
    private const val TAG = "VSCTarget"
    private const val STORE = "loopback-tls.p12"
    private const val PASS = "vscan-fixture"

    fun run(context: Context): String {
        val keyStore = KeyStore.getInstance("PKCS12")
        context.assets.open(STORE).use { keyStore.load(it, PASS.toCharArray()) }
        val kmf = KeyManagerFactory.getInstance("PKIX")
        kmf.init(keyStore, PASS.toCharArray())
        val serverContext = SSLContext.getInstance("TLS")
        serverContext.init(kmf.keyManagers, null, null)

        val trustStore = KeyStore.getInstance("PKCS12")
        trustStore.load(null, null)
        trustStore.setCertificateEntry("loop", keyStore.getCertificate(keyStore.aliases().nextElement()))
        val tmf = TrustManagerFactory.getInstance("PKIX")
        tmf.init(trustStore)
        val clientContext = SSLContext.getInstance("TLS")
        clientContext.init(null, tmf.trustManagers, null)

        val server = serverContext.serverSocketFactory
            .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))
        val port = server.localPort
        val serverError = arrayOfNulls<String>(1)
        val serverThread = Thread {
            try {
                server.accept().use { raw ->
                    val socket = raw as SSLSocket
                    socket.soTimeout = 5000
                    socket.startHandshake()
                    val buf = ByteArray(32)
                    val n = socket.inputStream.read(buf)
                    socket.outputStream.write("pong".toByteArray())
                    socket.outputStream.flush()
                    if (n <= 0) serverError[0] = "empty request"
                }
            } catch (e: Exception) {
                serverError[0] = "${e.javaClass.simpleName}: ${e.message}"
            }
        }
        serverThread.start()
        return try {
            val message = clientContext.socketFactory.createSocket("127.0.0.1", port).use { raw ->
                val socket = raw as SSLSocket
                socket.soTimeout = 5000
                socket.startHandshake()
                socket.outputStream.write("ping-ssl-loopback".toByteArray())
                socket.outputStream.flush()
                val reply = ByteArray(8)
                val n = socket.inputStream.read(reply)
                "TLS 回环完成 reply=${String(reply, 0, maxOf(n, 0))}"
            }
            if (serverError[0] != null) throw IllegalStateException("server: ${serverError[0]}")
            Log.i(TAG, message)
            message
        } finally {
            server.close()
            serverThread.join(3000)
        }
    }
}
