// 仅用于授权测试（自有设备与自有 APK）。后台断网补传的持久化队列。
// 观察/审计钩子从不改写本队列；它只由夹具自身的测试动作写入。
// 所有写操作在单进程内串行化：入队、按行删除、全清来自多个后台线程，
// SharedPreferences 的读-改-写不是原子操作，必须自行加锁。
package com.vscanner.privacydemo

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class ScenarioQueue(context: Context) {
    private val store = context.getSharedPreferences("vscan-owned-window-state", Context.MODE_PRIVATE)
    private val lock = Any()

    /** 损坏的存档按空队列处理，避免把解析异常抛给主线程。 */
    private fun read(): JSONArray = try {
        JSONArray(store.getString("queue", "[]"))
    } catch (error: Exception) {
        JSONArray()
    }

    private fun write(queue: JSONArray) {
        check(store.edit().putString("queue", queue.toString()).commit())
    }

    /** 全清：跨会话的残留行不能留到下一轮，否则 cached_batches 会被算成脏值。 */
    fun clear() = synchronized(lock) { write(JSONArray()) }

    /** 入队并返回**当前 run** 的待发条数（不是全局条数）。 */
    fun enqueue(run: String, batch: String, value: String, createdMs: Long): Int = synchronized(lock) {
        val queue = read()
        queue.put(JSONObject()
            .put("run", run)
            .put("source_batch", batch)
            .put("android_id", value)
            .put("created_ms", createdMs))
        write(queue)
        countLocked(run)
    }

    fun size(): Int = synchronized(lock) { read().length() }

    fun pending(run: String): List<JSONObject> = synchronized(lock) { pendingLocked(run) }

    fun pendingCount(run: String): Int = synchronized(lock) { countLocked(run) }

    fun sourceBatchTokens(run: String): JSONArray {
        val tokens = JSONArray()
        for (row in pending(run)) tokens.put(row.optString("source_batch"))
        return tokens
    }

    /** 只删除已确认发送成功的那一行，快照之外新入队的行必须保留。 */
    fun remove(run: String, batch: String, createdMs: Long) = synchronized(lock) {
        val queue = read()
        val kept = JSONArray()
        for (index in 0 until queue.length()) {
            val row = queue.optJSONObject(index) ?: continue
            val same = row.optString("run") == run && row.optString("source_batch") == batch &&
                row.optLong("created_ms") == createdMs
            if (!same) kept.put(row)
        }
        write(kept)
    }

    private fun pendingLocked(run: String): List<JSONObject> {
        val queue = read()
        return (0 until queue.length()).mapNotNull { index ->
            queue.optJSONObject(index)?.takeIf { it.optString("run") == run }
        }
    }

    private fun countLocked(run: String): Int = pendingLocked(run).size
}
