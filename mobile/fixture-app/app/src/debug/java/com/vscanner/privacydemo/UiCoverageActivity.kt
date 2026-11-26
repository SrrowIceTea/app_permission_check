package com.vscanner.privacydemo

// 仅用于授权测试。记录自有夹具的页面和实际动作结果。
import android.app.Activity
import android.os.Bundle
import android.provider.Settings
import android.util.Log
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject

class UiCoverageActivity : Activity() {
    private lateinit var run: String
    private var sequence = 0

    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        run = intent.getStringExtra("coverage_run").orEmpty()
        if (!run.matches(Regex("[a-f0-9]{32}"))) {
            finish()
            return
        }
        val layout = show("home", R.id.coverage_home, "隐私检测入口")
        button(layout, R.id.coverage_open_read, "打开设备标识") {
            record("effect", "open_read", "home", "navigation")
            showRead()
        }
    }

    private fun showRead() {
        val layout = show("read", R.id.coverage_read, "设备标识")
        button(layout, R.id.coverage_read_id, "读取 Android ID") {
            val value = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
            val obtained = value?.matches(Regex("[0-9a-fA-F]{16}")) == true
            record("effect", "read_id", "read", if (obtained) "obtained" else "unavailable")
            if (obtained) {
                layout.removeView(findViewById<Button>(R.id.coverage_read_id))
                button(layout, R.id.coverage_open_settings, "打开隐私偏好") {
                    record("effect", "open_settings", "read", "navigation")
                    showSettings()
                }
            }
        }
    }

    private fun showSettings() {
        val layout = show("settings", R.id.coverage_settings, "隐私偏好")
        button(layout, R.id.coverage_save, "保存隐私偏好") {
            val preferences = getSharedPreferences("coverage", MODE_PRIVATE)
            val saved = preferences.edit().putString("last_run", run).commit() &&
                preferences.getString("last_run", null) == run
            record("effect", "save", "settings", if (saved) "persisted" else "failed")
        }
    }

    private fun show(page: String, rootId: Int, title: String): LinearLayout {
        val layout = LinearLayout(this).apply {
            id = rootId
            orientation = LinearLayout.VERTICAL
            val top = (96 * resources.displayMetrics.density).toInt()
            setPadding(24, top, 24, 24)
            addView(TextView(this@UiCoverageActivity).apply { text = title; textSize = 26f })
        }
        setContentView(layout)
        record("page", page, page, "rendered")
        return layout
    }

    private fun button(parent: LinearLayout, viewId: Int, title: String, click: () -> Unit) {
        parent.addView(Button(this).apply {
            id = viewId
            text = title
            setOnClickListener { click() }
        })
    }

    private fun record(kind: String, name: String, page: String, result: String) {
        val entry = JSONObject().put("run", run).put("kind", kind).put("name", name).put("page", page)
            .put("result", result).put("seq", ++sequence).put("ts", System.currentTimeMillis())
        Log.i("VScanUiCoverage", entry.toString())
    }
}
