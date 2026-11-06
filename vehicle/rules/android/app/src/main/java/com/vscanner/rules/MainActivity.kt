package com.vscanner.rules

import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.vscanner.rules.databinding.ActivityMainBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Phase 1 verification page.
 *
 * Loads the rule database packaged in assets/ through Room and reports whether it
 * is the expected baseline. It does not audit anything yet; its job is to prove
 * the rule library survives the trip into a real APK on a real device.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        lifecycleScope.launch {
            val report = withContext(Dispatchers.IO) {
                RulesVerifier(applicationContext).verify()
            }
            val exported = withContext(Dispatchers.IO) { export(report) }
            render(report, exported)
        }
    }

    /** Writes the report where `adb pull` can reach it, and to internal storage. */
    private fun export(report: VerificationReport): List<File> {
        val json = report.toJson()
        val targets = listOfNotNull(
            getExternalFilesDir(null)?.resolve(FILE_NAME),
            File(filesDir, FILE_NAME),
        )
        val written = mutableListOf<File>()
        for (target in targets) {
            runCatching {
                target.parentFile?.mkdirs()
                target.writeText(json)
                written += target
            }.onFailure { Log.w(TAG, "导出失败: ${target.absolutePath}", it) }
        }
        Log.i(TAG, "verification state=${report.state.name}")
        return written
    }

    private fun render(report: VerificationReport, exported: List<File>) {
        binding.resultText.text = buildString {
            appendLine("状态: ${report.state.label()}")
            appendLine("原因: ${report.reason}")
            appendLine()
            appendLine("设备 API: ${report.deviceApiLevel} (Android ${report.deviceApiLevel - 20})")
            appendLine("规则库基线: ${BaselineExpectation.SOURCE_TAG}")
            appendLine("规则库版本: ${report.expected.keys.joinToString(", ")}")
            appendLine(versionGapNote(report))
            appendLine()
            appendLine("SHA-256: ${if (report.sha256Match) "匹配" else "不匹配"}")
            appendLine("  期望 ${report.sha256Expected}")
            appendLine("  实际 ${report.sha256Actual ?: "(读取失败)"}")
            appendLine()
            appendLine("安装状态: ${report.install.state.label()}")
            appendLine("  ${report.install.reason}")
            appendLine("  生效规则库 SHA-256: ${report.install.effectiveSha256 ?: "(未知)"}")
            appendLine("  APK 内 rules.db: ${report.install.assetSha256 ?: "(读取失败)"}")
            appendLine("  运行时文件 SHA-256: ${report.install.activeFileSha256 ?: "(缺失)"}")
            appendLine("    注: Room 首次打开会追加 room_master_table/android_metadata，" +
                "原始文件摘要变化不代表规则变化")
            appendLine("  生效内容摘要: ${report.install.contentSha256 ?: "(无法读取)"}" +
                (if (report.install.contentMatch) " ✓ 与安装记录一致" else " ✗ 与安装记录不一致"))
            report.install.previousSha256?.let { appendLine("  升级前库文件 SHA-256: $it") }
            appendLine()

            for ((version, exp) in report.expected) {
                val got = report.counts[version]
                appendLine("── android_version = $version ──")
                appendLine("  期望  权限 ${exp.permissions} / 属性 ${exp.vhalProperties} / " +
                    "API ${exp.dangerousApis} / 规则 ${exp.riskRules}   合计 ${exp.total}")
                if (got == null) {
                    appendLine("  实际  读取失败")
                } else {
                    appendLine("  实际  权限 ${got.permissions} / 属性 ${got.vhalProperties} / " +
                        "API ${got.dangerousApis} / 规则 ${got.riskRules}   合计 ${got.total}")
                    appendLine("  启用规则 ${got.enabledRules} / ${got.riskRules}" +
                        "（含 data_egress；项目实测窗口 30000ms，非法律阈值）")
                    appendLine("  ${if (got == exp) "✓ 符合预期" else "✗ 与预期不符"}")
                }
                appendLine()
            }

            val extra = report.counts.keys - report.expected.keys
            if (extra.isNotEmpty()) {
                appendLine("数据库中另有未预期的 android_version: ${extra.joinToString(", ")}")
                appendLine()
            }

            report.errorClass?.let {
                appendLine("异常: $it")
                appendLine("  ${report.errorMessage}")
                appendLine()
            }

            appendLine("耗时: ${report.elapsedMs} ms")
            if (exported.isEmpty()) {
                appendLine("导出: 失败，见 logcat ($TAG)")
            } else {
                exported.forEach { appendLine("导出: ${it.absolutePath}") }
            }
        }
    }

    /**
     * The rule library is keyed by AOSP source version and the device is what it
     * is; the two do not have to agree. Saying so out loud is the point.
     */
    private fun versionGapNote(report: VerificationReport): String {
        val deviceVersion = (Build.VERSION.SDK_INT - 20).toString()
        val hasRulesForDevice = report.counts[deviceVersion]?.isEmpty == false
        return if (hasRulesForDevice) {
            "版本匹配: 设备 Android $deviceVersion 有对应规则集"
        } else {
            "版本差异: 设备为 Android $deviceVersion，但当前规则库只有 " +
                "${report.expected.keys.joinToString(", ")}；本次结论仅作【需实测校准】参考"
        }
    }

    private companion object {
        const val TAG = "VScanner"
        const val FILE_NAME = "verification.json"
    }
}
