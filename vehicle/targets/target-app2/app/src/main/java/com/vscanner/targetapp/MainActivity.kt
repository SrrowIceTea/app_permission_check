package com.vscanner.targetapp2

// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// 靶子 App 主界面：三个按钮对应三种可独立触发的行为，与审计规则一一对应：
//   1. btnPerm   —— 过度索权：dump 清单中声明的 android.car.permission.*，
//                    对 dangerous 级（CAR_SPEED / CAR_ENERGY）发起运行时申请并记录结果。
//                    纯静态+权限态行为，不读 VHAL、不发网络。
//   2. btnRead   —— 敏感读取：经 VhalReader 读 8 个 VHAL 属性（行为见 VhalReader.kt）。
//   3. btnEgress* —— 数据外泄：把最近一次读取缓存 POST 为 JSON（HTTP 明文 / HTTPS 两个变体）。
//                    缓存为空时只记警告不发送，保证三个行为严格可分。

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread

class MainActivity : Activity() {

    // 6 条 android.car.permission.* 全部取自 vehicle/rules/baseline_android14/rules.db permissions 表
    private val carPermissionNames = listOf(
        VhalProps.PERM_CAR_IDENTIFICATION,      // signature|privileged
        VhalProps.PERM_CAR_SPEED,               // dangerous
        VhalProps.PERM_CAR_ENERGY,              // dangerous
        VhalProps.PERM_CAR_MILEAGE,             // signature|privileged
        VhalProps.PERM_CAR_ENGINE_DETAILED,     // signature|privileged
        VhalProps.PERM_CAR_POWERTRAIN           // normal
    )

    // 只有 dangerous 级能走运行时申请；signature|privileged 申请必然被拒（不申请，只记录状态）
    private val runtimeRequestable = listOf(
        VhalProps.PERM_CAR_SPEED,
        VhalProps.PERM_CAR_ENERGY
    )

    private var subscription: SubscriptionReader? = null
    @Volatile private var lastReads: List<ReadResult> = emptyList()

    private lateinit var tvLog: TextView
    private lateinit var scrollLog: ScrollView
    private lateinit var etHttpEndpoint: EditText
    private lateinit var etHttpsEndpoint: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        EventLog.init(applicationContext)
        tvLog = findViewById(R.id.tvLog)
        scrollLog = findViewById(R.id.scrollLog)
        etHttpEndpoint = findViewById(R.id.etHttpEndpoint)
        etHttpsEndpoint = findViewById(R.id.etHttpsEndpoint)

        findViewById<Button>(R.id.btnPerm).setOnClickListener { demoPermissions() }
        findViewById<Button>(R.id.btnRead).setOnClickListener { doRead() }
        findViewById<Button>(R.id.btnEgressHttp).setOnClickListener {
            doEgress(etHttpEndpoint.text.toString())
        }
        findViewById<Button>(R.id.btnEgressHttps).setOnClickListener {
            doEgress(etHttpsEndpoint.text.toString())
        }

        findViewById<Button>(R.id.btnOkHttp).setOnClickListener {
            EventLog.log("用户按下 OkHttp 按钮")
            if (lastReads.isEmpty()) EventLog.log("WARN: 先读取 VHAL")
            else OkHttpSender.send(etHttpsEndpoint.text.toString(), lastReads) {
                runOnUiThread { refreshPanel() }
            }
        }
        subscription = SubscriptionReader(applicationContext) { value ->
            lastReads = listOf(value)
            runOnUiThread { refreshPanel() }
        }
        findViewById<Button>(R.id.btnSubscribe).setOnClickListener {
            EventLog.log("用户按下订阅按钮")
            subscription?.start()
        }

        EventLog.log("Activity 启动: package=$packageName uid=${applicationInfo.uid}")
        EventLog.log("事件文件: ${filesDir}/${EventLog.FILE_NAME} 与 getExternalFilesDir 同名文件")
        refreshPanel()
    }

    // ---------------- 行为 1：过度索权演示 ----------------

    private fun demoPermissions() {
        EventLog.log("== 行为 1 开始：索权演示 ==")
        try {
            val pi = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            val requested = pi.requestedPermissions ?: emptyArray()
            EventLog.log("清单声明权限共 ${requested.size} 条：")
            requested.forEach { name ->
                EventLog.log("  声明 [$name]")
            }
            // 授予状态一律用公开 API checkSelfPermission 判断，
            // 不解析 requestedPermissionsFlags 的隐藏位（其常量非公开 API，规则一禁止使用）。
            carPermissionNames.forEach { name ->
                val ok = checkSelfPermission(name) == PackageManager.PERMISSION_GRANTED
                EventLog.log("  checkSelfPermission($name) = ${if (ok) "GRANTED" else "DENIED"}")
            }
            EventLog.log("发起运行时申请: $runtimeRequestable")
            EventLog.log("  （signature|privileged 的 3 条不申请：普通应用永远无法获得，声明即静态信号）")
            requestPermissions(runtimeRequestable.toTypedArray(), REQ_CODE_CAR_PERMS)
        } catch (t: Throwable) {
            EventLog.log("行为 1 出错: ${t.javaClass.name}: ${t.message}")
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQ_CODE_CAR_PERMS) return
        permissions.forEachIndexed { i, name ->
            val g = if (i < grantResults.size) {
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) "GRANTED" else "DENIED"
            } else "NO_RESULT"
            EventLog.log("运行时申请结果 [$name] = $g")
        }
        EventLog.log("== 行为 1 结束 ==")
        runOnUiThread { refreshPanel() }
    }

    // ---------------- 行为 2：敏感读取 ----------------

    private fun doRead() {
        EventLog.log("用户按下按钮 2（读取 VHAL）")
        thread(name = "vsc-read") {
            val results = VhalReader(applicationContext).readAll()
            lastReads = results
            runOnUiThread { refreshPanel() }
        }
    }

    // ---------------- 行为 3：数据外泄 ----------------

    private fun doEgress(endpoint: String) {
        EventLog.log("用户按下外泄按钮，端点=$endpoint")
        if (lastReads.isEmpty()) {
            EventLog.log("WARN: 读取缓存为空 —— 先按「2. 读取 VHAL」再外泄（两个行为保持可分）")
            refreshPanel()
            return
        }
        EgressSender.send(endpoint, lastReads) { summary ->
            EventLog.log("外泄摘要: $summary")
            runOnUiThread { refreshPanel() }
        }
    }

    // ---------------- 日志面板 ----------------

    private fun refreshPanel() {
        tvLog.text = EventLog.snapshot()
        scrollLog.post { scrollLog.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    override fun onDestroy() {
        subscription?.stop()
        super.onDestroy()
    }

    companion object {
        private const val REQ_CODE_CAR_PERMS = 42
    }
}
