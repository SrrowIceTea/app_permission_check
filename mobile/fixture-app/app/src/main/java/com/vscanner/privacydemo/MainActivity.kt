package com.vscanner.privacydemo

// 仅用于授权测试（自有设备与自有 APK）。
//
// 靶子 App 主界面。每个按钮的写法有两条硬约定：
//   1) **第一条日志必须是 EventLog.Markers 里的标记行** —— 主机侧触发器
//      （mobile/tools/trigger.py）就是靠它判断"按钮真的点到了"。
//      少了它，点击落空与动作执行成功在主机侧看起来一样。
//   2) 动作结果如实回显，包括 SecurityException —— 被拒与成功必须可区分。

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.view.View
import android.webkit.WebView
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast

class MainActivity : Activity() {

    private lateinit var tvLog: TextView
    private lateinit var etEndpoint: EditText

    private val permForDemo = arrayOf(
        Manifest.permission.READ_PHONE_STATE,
        Manifest.permission.READ_CONTACTS,
        Manifest.permission.ACCESS_FINE_LOCATION
        // 刻意**不**请求 READ_SMS：它已在清单里声明但从不申请，
        // 这样「声明了却没用」与「读了却被拒」两种形态都能被观测到。
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        tvLog = findViewById(R.id.tvLog)
        etEndpoint = findViewById(R.id.etEndpoint)

        wire(R.id.btnDeviceId, EventLog.Markers.READ_DEVICE_ID) {
            "${PrivacyReader.deviceId(this)}  ${PrivacyReader.phoneNumber(this)}"
        }
        wire(R.id.btnLocation, EventLog.Markers.READ_LOCATION) {
            PrivacyReader.location(this)
        }
        wire(R.id.btnContacts, EventLog.Markers.READ_CONTACTS) {
            PrivacyReader.contacts(this)
        }
        wire(R.id.btnApps, EventLog.Markers.READ_APPS) {
            PrivacyReader.installedApps(this)
        }
        wire(R.id.btnClipboard, EventLog.Markers.READ_CLIPBOARD) {
            PrivacyReader.clipboard(this)
        }
        wire(R.id.btnSms, EventLog.Markers.READ_SMS) {
            PrivacyReader.sms(this)
        }
        wire(R.id.btnPerm, EventLog.Markers.REQUEST_PERMS) {
            requestPermissions(permForDemo, REQ_CODE)
            PrivacyReader.checkPermission(this, Manifest.permission.READ_PHONE_STATE)
        }
        // 外发必须走**后台线程**：主线程做网络会抛 NetworkOnMainThreadException，
        // 结果是"按钮点到了、日志也打了、但一个字节都没发出去"——
        // 触发器只验标记行，这种失败它会判成通过（实测踩过）。
        wireAsync(R.id.btnEgressHttp, EventLog.Markers.EGRESS_HTTP) {
            val body = Egress.payload(this, PrivacyReader.deviceId(this),
                                      PrivacyReader.location(this))
            Egress.post(httpEndpoint(), body)
        }
        wireAsync(R.id.btnEgressHttps, EventLog.Markers.EGRESS_HTTPS) {
            val body = Egress.payload(this, PrivacyReader.deviceId(this),
                                      PrivacyReader.location(this))
            Egress.post(httpsEndpoint(), body)
        }
        findViewById<Button>(R.id.btnPolicy).setOnClickListener {
            EventLog.log(EventLog.Markers.SHOW_POLICY)
            showPolicy()
        }

        EventLog.log("隐私演示 App 启动（自有 APK，授权测试）")
        render()
    }

    /** 统一包装：先打标记、再执行、再回显；异常不吞。 */
    private fun wire(id: Int, marker: String, action: () -> String) {
        findViewById<Button>(id).setOnClickListener {
            EventLog.log(marker)
            val result = try {
                action()
            } catch (e: Exception) {
                "异常：${e.javaClass.simpleName}: ${e.message}"
            }
            EventLog.log("结果：$result")
            render()
        }
    }

    /** 后台线程版本：动作可能阻塞（网络 I/O），标记载 UI 线程上打，结果回到 UI 线程记录。 */
    private fun wireAsync(id: Int, marker: String, action: () -> String) {
        findViewById<Button>(id).setOnClickListener {
            EventLog.log(marker)
            render()
            Thread {
                val result = try {
                    action()
                } catch (e: Exception) {
                    "异常：${e.javaClass.simpleName}: ${e.message}"
                }
                runOnUiThread {
                    EventLog.log("结果：$result")
                    render()
                }
            }.start()
        }
    }

    private fun render() {
        tvLog.text = EventLog.snapshot().joinToString("\n")
    }

    private fun httpEndpoint(): String =
        etEndpoint.text.toString().trim().ifEmpty { DEFAULT_HTTP }

    private fun httpsEndpoint(): String =
        etEndpoint.text.toString().trim()
            .replaceFirst("http://", "https://")
            .ifEmpty { DEFAULT_HTTPS }

    /** 应用内展示隐私政策：走 WebView.loadUrl —— 工具的 POLICY_VIEW 观测点。
     *
     * 弹窗 8 秒后自动关闭：它是**测试夹具**，弹窗会盖住整个界面，
     * 自动化触发后续按钮时会被挡住（实测：第一次跑，btnPolicy 之后 11 个按钮全部
     * "界面上找不到控件"）。留一个必须人工点掉的全屏弹窗会让自动化卡死在这种
     * 看起来像"控件 id 写错了"的地方。 */
    private fun showPolicy() {
        val web = WebView(this)
        web.loadUrl("file:///android_asset/privacy-policy.html")
        val dialog = AlertDialog.Builder(this)
            .setTitle("隐私政策")
            .setView(web)
            .setPositiveButton("关闭", null)
            .create()
        dialog.show()
        android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(
            { if (dialog.isShowing) dialog.dismiss() }, 8000)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>,
                                            grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_CODE) {
            // 逐条如实记录：部分授权必须能被工具区分出来。
            val detail = permissions.mapIndexed { i, p ->
                val ok = grantResults.getOrNull(i) == 0
                "${p.substringAfterLast('.')}=${if (ok) "GRANTED" else "DENIED"}"
            }.joinToString(", ")
            EventLog.log("权限结果：$detail")
            Toast.makeText(this, detail, Toast.LENGTH_LONG).show()
            render()
        }
    }

    companion object {
        private const val REQ_CODE = 100

        /** 默认指向宿主机 mock 接收端（模拟器里 10.0.2.2 = 宿主机回环）。 */
        private const val DEFAULT_HTTP = "http://10.0.2.2:8888/collect"
        private const val DEFAULT_HTTPS = "https://10.0.2.2:8888/collect"
    }
}
