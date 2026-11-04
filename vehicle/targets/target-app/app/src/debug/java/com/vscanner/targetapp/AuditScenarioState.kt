package com.vscanner.targetapp

// 仅用于授权测试。Debug-only test actor; observation Hooks never change consent/data.
import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

class AuditScenarioState(context: Context) {
    private val store = context.getSharedPreferences("vscan-owned-audit-state", Context.MODE_PRIVATE)

    fun consent(): String = store.getString("consent", "unknown") ?: "unknown"

    fun setConsent(value: String) {
        check(value in setOf("granted", "revoked"))
        check(store.edit().putString("consent", value).commit())
    }

    fun clearCache() { check(store.edit().remove("queue").commit()) }

    fun enqueue(payload: JSONObject): Int {
        val queue = JSONArray(store.getString("queue", "[]"))
        queue.put(payload)
        check(store.edit().putString("queue", queue.toString()).commit())
        return queue.length()
    }

    fun cachedPayload(): JSONObject? {
        val queue = JSONArray(store.getString("queue", "[]"))
        if (queue.length() == 0) return null
        val reads = JSONArray()
        val batchTokens = JSONArray()
        for (i in 0 until queue.length()) {
            val batch = queue.getJSONObject(i)
            val token = batch.optString("scenarioToken")
            if (token.isNotEmpty()) batchTokens.put(token)
            val items = batch.getJSONArray("reads")
            for (j in 0 until items.length()) reads.put(items.getJSONObject(j))
        }
        return JSONObject().put("reads", reads).put("cachedBatches", queue.length())
            .put("sourceBatchTokens", batchTokens)
    }
}
