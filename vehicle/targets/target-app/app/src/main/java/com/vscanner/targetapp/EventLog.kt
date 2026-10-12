package com.vscanner.targetapp

// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// 统一事件出口：所有行为（权限、VHAL 读取、网络外泄）都只经这一个类落日志，
// 便于审计工具在一条链路上对齐时间与结果。
//   - logcat：标签 VSCTarget
//   - 内存面板：MainActivity 的 tvLog
//   - 文件：/data/data/<pkg>/files/vscanner_events.log（需 adb root）
//           与 <外部存储>/Android/data/<pkg>/files/vscanner_events.log（无需 root）

import android.content.Context
import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

object EventLog {

    const val TAG = "VSCTarget"
    const val FILE_NAME = "vscanner_events.log"

    private const val MAX_LINES = 500

    private val lines = ArrayDeque<String>()
    private val sinkFiles = mutableListOf<File>()
    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    /** 必须在任何 log() 之前调用一次。 */
    fun init(ctx: Context) {
        val candidates = mutableListOf<File>()
        candidates += File(ctx.filesDir, FILE_NAME)
        ctx.getExternalFilesDir(null)?.let { candidates += File(it, FILE_NAME) }
        sinkFiles += candidates.filter { it.parentFile?.isDirectory == true }
        sinkFiles.forEach {
            try {
                if (!it.exists()) it.createNewFile()
            } catch (e: Exception) {
                Log.w(TAG, "日志文件不可写: $it (${e.message})")
            }
        }
    }

    @Synchronized
    fun log(msg: String) {
        val stamp = fmt.format(Date())
        lines.addLast("$stamp  $msg")
        while (lines.size > MAX_LINES) lines.removeFirst()
        Log.i(TAG, msg)
        val line = "$stamp  $msg\n"
        sinkFiles.forEach {
            try {
                it.appendText(line)
            } catch (_: Exception) {
                // 文件写失败不阻断面板与 logcat
            }
        }
    }

    @Synchronized
    fun snapshot(): String = lines.joinToString("\n")
}
