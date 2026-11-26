package com.vscanner.targetapp

// 仅用于授权测试。Only this fixture build exposes the three coverage activities.
import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

abstract class CoverageActivity : Activity() {
    private lateinit var panel: LinearLayout

    protected fun showPage(title: String) {
        panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val padding = (24 * resources.displayMetrics.density).toInt()
            setPadding(padding, padding, padding, padding)
        }
        label(title).textSize = 24f
        setContentView(panel)
    }

    protected fun label(value: String): TextView = TextView(this).apply {
        text = value
        panel.addView(this)
    }

    protected fun button(id: Int, label: String, action: () -> Unit) {
        panel.addView(Button(this).apply {
            this.id = id
            text = label
            setOnClickListener { action() }
        })
    }
}

class CoverageMenuActivity : CoverageActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showPage("车载数据观察")
        button(R.id.btnG1OpenRead, "打开读取页") {
            startActivity(Intent(this, CoverageReadActivity::class.java))
        }
    }
}

class CoverageReadActivity : CoverageActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showPage("VHAL 读取")
        val summary = label("等待读取")
        button(R.id.btnG1Read, "读取 VHAL") {
            Thread({
                val reads = VhalReader(applicationContext).readAll()
                runOnUiThread { summary.text = "成功读取 ${reads.count { it.result == "ok" }} 项" }
            }, "vscan-g1-read").start()
        }
        button(R.id.btnG1OpenSubscription, "打开订阅页") {
            startActivity(Intent(this, CoverageSubscriptionActivity::class.java))
        }
    }
}

class CoverageSubscriptionActivity : CoverageActivity() {
    private var subscription: SubscriptionReader? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showPage("VHAL 订阅")
        val summary = label("等待订阅")
        val reader = SubscriptionReader(applicationContext) { result ->
            runOnUiThread {
                summary.text = if (result.result == "ok") "已收到档位回调" else "档位回调不可用"
            }
        }
        subscription = reader
        button(R.id.btnG1Subscribe, "订阅档位 10 秒") { reader.start() }
    }

    override fun onStop() {
        subscription?.stop()
        super.onStop()
    }
}
