// 仅用于授权测试（自有设备与自有 APK）。后台断网补传的持久化队列。
// 观察/审计钩子从不改写本队列；它只由夹具自身的测试动作写入。
package com.vscanner.privacydemo

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class ScenarioQueue(context: Context) {
    private val store = context.getSharedPreferences("vscan-owned-window-state", Context.MODE_PRIVATE)

    fun clear() { check(store.edit().remove("queue").commit()) }

    fun enqueue(run: String, batch: String, value: String, createdMs: Long): Int {
        val queue = JSONArray(store.getString("queue", "[]"))
        queue.put(JSONObject()
            .put("run", run)
            .put("source_batch", batch)
            .put("android_id", value)
            .put("created_ms", createdMs))
        check(store.edit().putString("queue", queue.toString()).commit())
        return queue.length()
    }

    fun size(): Int = JSONArray(store.getString("queue", "[]")).length()

    fun pending(run: String): List<JSONObject> {
        val queue = JSONArray(store.getString("queue", "[]"))
        val result = mutableListOf<JSONObject>()
        for (index in 0 until queue.length()) {
            val row = queue.getJSONObject(index)
            if (row.optString("run") == run) result.add(row)
        }
        return result
    }

    fun sourceBatchTokens(run: String): JSONArray {
        val tokens = JSONArray()
        for (row in pending(run)) tokens.put(row.optString("source_batch"))
        return tokens
    }

    fun clearFor(run: String) {
        val queue = JSONArray(store.getString("queue", "[]"))
        val kept = JSONArray()
        for (index in 0 until queue.length()) {
            val row = queue.getJSONObject(index)
            if (row.optString("run") != run) kept.put(row)
        }
        check(store.edit().putString("queue", kept.toString()).commit())
    }
}
