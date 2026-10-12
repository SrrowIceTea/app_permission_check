package com.vscanner.privacydemo

// 仅用于授权测试（自有设备与自有 APK）。
//
// 统一事件出口：所有行为都只经这一个类落日志，便于把工具侧的事件
// 与设备侧的动作对齐。logcat 标签固定为 VSPrivacyDemo ——
// 主机侧触发器（tools/trigger.py）就是按这个标签的成功标记行判断"按钮真的点到了"。
//
// 为什么不用 UI 文本判断成功：TextView 的可见文本随滚动区域变化，
// 而 logcat 行是确定的（vehicle/targets/D 记录的结论）。

import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object EventLog {

    const val TAG = "VSPrivacyDemo"

    private const val MAX_LINES = 300

    private val lines = ArrayDeque<String>()
    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    fun log(message: String) {
        val stamped = fmt.format(Date()) + "  " + message
        Log.i(TAG, message)          // 主机侧读这一行
        synchronized(lines) {
            lines.addLast(stamped)
            while (lines.size > MAX_LINES) lines.removeFirst()
        }
    }

    fun snapshot(): List<String> = synchronized(lines) { lines.toList() }

    /** 每行按钮处理的**第一条**日志必须与主机侧的标记一致，否则按钮点击无法判定成败。 */
    object Markers {
        const val READ_DEVICE_ID = "按下按钮：读取设备标识"
        const val READ_LOCATION = "按下按钮：读取位置"
        const val READ_CONTACTS = "按下按钮：读取通讯录"
        const val READ_APPS = "按下按钮：读取应用列表"
        const val READ_CLIPBOARD = "按下按钮：读取剪贴板"
        const val READ_SMS = "按下按钮：读取短信"
        const val REQUEST_PERMS = "按下按钮：请求运行时权限"
        const val EGRESS_HTTP = "按下按钮：明文 HTTP 外发"
        const val EGRESS_HTTPS = "按下按钮：HTTPS 外发"
        const val SHOW_POLICY = "按下按钮：展示隐私政策"
    }
}
