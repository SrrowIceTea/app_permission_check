package com.vscanner.privacydemo

// 仅用于授权测试。This test-only activity sends the emulator's scoped ID to a fixed local receiver.
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Process
import android.provider.Settings
import android.util.Log
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

class WindowBenchmarkActivity : Activity() {
    private var token: String? = null
    // 读取在主线程与具名后台线程之间传递，必须用并发容器；普通 HashMap 无跨线程可见性保证。
    private val cached = ConcurrentHashMap<String, String>()
    private val workers = CopyOnWriteArrayList<Thread>()
    private lateinit var queue: ScenarioQueue

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        setContentView(TextView(this).apply { text = "移动读取与外发对照" })
        queue = ScenarioQueue(this)
        // 冷启动也要执行 step：Activity 被重建时 am start 不会再走 onNewIntent，
        // 若这里忽略 step，编排只能等到超时才暴露。
        handle(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
    }

    override fun onDestroy() {
        workers.forEach { it.interrupt() }
        super.onDestroy()
    }

    private fun handle(intent: Intent?) {
        val run = intent?.getStringExtra("benchmark_run") ?: return
        if (!run.matches(Regex("[a-f0-9]{32}")) || (token != null && token != run)) return
        token = run
        val step = intent.getStringExtra("benchmark_step") ?: return
        try {
            when {
                step == "read-a" || step == "read-b" -> read(run, step.last().toString(), "foreground")
                // 前台发送保持旧契约：body 只有 run/source_batch/android_id，线程名也与旧版一致。
                step == "send-a" -> background(run, "window-send") {
                    sendLegacy(run, "a", cached.getValue("a"))
                }
                // 后台只读：读取发生在具名后台线程，标记 origin=background。
                step == "bg-read-a" || step == "bg-read-b" ->
                    background(run, "bg-read") { read(run, step.last().toString(), "background") }
                // 后台即时发送：走 adb reverse 回环，代理仍能归因。
                step == "bg-send-a" -> background(run, "bg-send") {
                    send(run, "a", cached.getValue("a"), "background", "127.0.0.1")
                }
                // 断网发送：强制走 10.0.2.2（不经 adb reverse），断网时必须失败并入队。
                step == "bg-offline-send-a" -> offlineSend(run, "a", "background")
                // 可达性探针：只做 TCP 连接，不产生 HTTP 回执，用于证明断网区间真实生效。
                step.startsWith("bg-probe") -> background(run, "bg-probe") {
                    probe(run, step.removePrefix("bg-probe-"))
                }
                // 恢复联网后补传：连同真实网络路径送回，成功即证明网络已恢复。
                step == "bg-flush-a" -> background(run, "bg-flush") { flush(run) }
                step == "bg-queue-clear" -> queue.clear()
            }
        } catch (error: Exception) {
            record(run, "error", step, "type", error.javaClass.simpleName)
        }
    }

    private fun background(run: String, name: String, action: () -> Unit) {
        // 线程名带步骤标识，native observer 依赖它证明读取确实发生在后台。
        val thread = Thread({
            try { action() }
            catch (error: Exception) { record(run, "error", name, "type", error.javaClass.simpleName) }
        }, "owned-$name")
        workers.add(thread)
        thread.start()
    }

    private fun offlineSend(run: String, batch: String, origin: String) {
        background(run, "bg-offline-send") {
            val value = cached.getValue(batch)
            val created = System.currentTimeMillis()
            val pending = queue.enqueue(run, batch, value, created)
            record(run, "enqueue", batch, "cached_batches", pending, "origin", origin)
            try {
                send(run, batch, value, origin, "10.0.2.2")
                queue.remove(run, batch, created)
            } catch (error: Exception) {
                record(run, "offline_failed", batch, "type", error.javaClass.simpleName,
                    "cached_batches", queue.pendingCount(run), "origin", origin)
            }
        }
    }

    private fun read(run: String, batch: String, origin: String) {
        val start = System.currentTimeMillis()
        val value = requireNotNull(Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID))
        check(value.matches(Regex("[0-9a-fA-F]{16}")))
        check(cached.putIfAbsent(batch, value) == null)
        val digest = sha256(value.toByteArray())
        // 旧字段 run/batch/value_sha256 原样保留；新增 origin/thread 供后台观测。
        val marker = JSONObject().put("run", run).put("batch", batch).put("value_sha256", digest)
            .put("origin", origin).put("thread", Thread.currentThread().name)
        Log.i("VScanWindowObserve", marker.toString())
        record(run, "read", batch, "start_ms", start, "end_ms", System.currentTimeMillis(),
            "value_sha256", digest, "origin", origin, "thread", Thread.currentThread().name)
    }

    /** 旧契约：三字段 body，字节格式与 13f225c 完全一致。 */
    private fun sendLegacy(run: String, batch: String, value: String) {
        val body = JSONObject().put("run", run).put("source_batch", batch).put("android_id", value)
            .toString().toByteArray(Charsets.UTF_8)
        val (status, responseSha) = post("127.0.0.1", body)
        check(responseSha == sha256(body))
        record(run, "send", batch, "http_status", status, "body_sha256", responseSha)
    }

    private fun send(run: String, batch: String, value: String, origin: String, host: String) {
        val body = payload(run, batch, value, origin)
        val (status, responseSha) = post(host, body)
        check(responseSha == sha256(body))
        record(run, "send", batch, "http_status", status, "body_sha256", responseSha,
            "origin", origin, "thread", Thread.currentThread().name)
    }

    private fun flush(run: String) {
        val pending = queue.pending(run)
        record(run, "flush_start", "a", "cached_batches", pending.size, "origin", "background")
        for (row in pending) {
            val batch = row.optString("source_batch")
            val created = row.optLong("created_ms")
            val tokens = queue.sourceBatchTokens(run)
            val body = payload(run, batch, row.optString("android_id"), "background", tokens, created)
            val (status, responseSha) = post("10.0.2.2", body)
            check(responseSha == sha256(body))
            record(run, "flush_send", batch, "http_status", status, "body_sha256", responseSha,
                "source_batch_tokens", tokens, "origin", "background", "thread", Thread.currentThread().name)
            // 逐行确认后再删，避免把快照之后新入队的行一起清掉。
            queue.remove(run, batch, created)
        }
        record(run, "flush_done", "a", "origin", "background", "thread", Thread.currentThread().name)
    }

    private fun payload(run: String, batch: String, value: String, origin: String,
                        tokens: JSONArray? = null, createdMs: Long? = null): ByteArray {
        val body = JSONObject().put("run", run).put("source_batch", batch).put("android_id", value)
            .put("origin", origin).put("thread", Thread.currentThread().name)
        if (tokens != null && tokens.length() > 0) body.put("source_batch_tokens", tokens)
        if (createdMs != null) body.put("created_ms", createdMs)
        return body.toString().toByteArray(Charsets.UTF_8)
    }

    private fun post(host: String, body: ByteArray): Pair<Int, String> {
        val connection = URL("http://$host:18960/collect").openConnection(Proxy.NO_PROXY) as HttpURLConnection
        return try {
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
            status to receipt.getString("sha256")
        } finally { connection.disconnect() }
    }

    /** 只建 TCP 连接即关闭：可达性证据，不产生 /collect 回执。 */
    private fun probe(run: String, stage: String) {
        val socket = Socket()
        try {
            socket.connect(InetSocketAddress("10.0.2.2", 18960), 2000)
            record(run, "probe", "net", "stage", stage, "reachable", true, "origin", "background")
        } catch (error: Exception) {
            record(run, "probe", "net", "stage", stage, "reachable", false,
                "type", error.javaClass.simpleName, "origin", "background")
        } finally {
            try { socket.close() } catch (_: Exception) { }
        }
    }

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun record(run: String, event: String, batch: String, vararg fields: Any) {
        require(fields.size % 2 == 0)
        val row = JSONObject().put("run", run).put("event", event).put("batch", batch)
            .put("pid", Process.myPid()).put("ts", System.currentTimeMillis())
        for (index in fields.indices step 2) row.put(fields[index] as String, fields[index + 1])
        Log.i("VScanWindow", row.toString())
    }
}
