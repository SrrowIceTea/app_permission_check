# 外部评估核对与落地记录（2026-10-13）

仅用于授权测试（已获授权的样本与设备）。

本文档记录：① 对另一份外部评估报告的**逐条事实核对**；② 核对后实际落地的改动；
③ 核对中发现的、评估报告**没有提到**的问题；④ 有意不采纳 / 延期的项及理由。
决策细节见 `DECISIONS.md`（M021–M025）。

## 结论摘要

报告的**事实层整体可靠**——所有可数的数字（24/14/3/37/39/193/30000ms）逐项复核后都成立，
没有发现夸大或臆测。它的判断（"有规则无抓手"是核心缺口、加壳检测是低成本高价值）
也站得住。核对的增量价值在于：**发现了两处比报告所述更深的问题**（第 3 节），
并把报告里"应该做"的建议真正落成了可回归的代码。

## 一、事实层核对（逐条）

| # | 评估断言 | 核对方法 | 结论 |
| --- | --- | --- | --- |
| 1 | `sensitive_data_types` 定义 24 个数据类别 | 数 seed 与 DB | ✅ 准确（24） |
| 2 | `api_targets` 只**直接**覆盖 14 个 | 对 `data_type_key` 去重 | ✅ 准确（13 条显式 + `android_id` 走 `string_key_arg` map = 14） |
| 3 | 3 个类别完全没有对应 API：`advertising_id` / `ip_address` / `notification_content` | 24 − 21 = 3，逐项确认 | ✅ 准确 |
| 4 | 其余 7 类靠 `ContentResolver.query` 的 URI 分派与 `LocationManager` 的 provider 分派间接覆盖，不算缺口 | 读 `observation_spec_json` | ✅ 准确（`content_uri` 5 类 + `provider_arg` 2 类） |
| 5 | 整类高敏 API 完全没收录（摄像头/麦克风/录屏/无障碍/生物识别/短信发送/写入类/电话状态/剪贴板监听/健康数据） | 逐项 grep 种子表 | ✅ 准确——一条都没有 |
| 6 | 移动端 `window_ms=30000` 未校准（`window_calibrated: false`） | 读 `rules_mobile.summary.json` | ✅ 准确 |
| 7 | 37 条 seed 权限 `protectionLevel` 未断言 | 数 seed=37；DB `definition_status` 全 `pending` | ✅ 准确（但问题更深，见第 3 节） |
| 8 | `over_collection` 靠 `--app-category` 手工声明，39 类已有但无法自动推断 | 读规则 `condition.requires_app_category` | ✅ 准确 |
| 9 | `README.md:17` 写"33 个敏感 API"，与实际的 30 目标/47 签名对不上 | 数 seed 目标=30、`api_facts.jsonl`=47 行 | ✅ 准确（口径混乱属实） |
| 10 | 193 条规则 / 8 种类型 | DB 计数 + `rules_by_type` 逐类对账 | ✅ 准确（8 类计数全对） |
| 11 | `sensor_data` 只启了 3 类规则 | 读 seed `enable` | ✅ 准确 |
| 12 | 回归"11 组 + 移动 16 项" | 数 `run_regressions.py` 与 `run_mobile_checks.py` | ✅ 准确 |

> 一处口径澄清：第 2 条的"14"指的是**1:1 直连**类别；若把 spec 分派算上，改造前
> 实际可观测的是 21 类。报告自己在括号里也这么说，两处并不矛盾。

## 二、本轮已落地的优化

| 项 | 文件 | 对应评估建议 |
| --- | --- | --- |
| **覆盖守护**：每个数据类别要么有 API 抓手、要么显式声明 `uncovered_by_design`（+理由），构建期断言；反向也查（声明缺口却查到抓手 = 声明过期） | `seed/sensitive_data_types.json`、`build_mobile_rules.py`、`test_rules.py` | "把靠人工核对的三类缺口变成机器守护" |
| **补 API 抓手**：`ip_address` 补 `NetworkInterface.getInetAddresses`；新增 4 类高敏数据类别 — `camera_capture`(CameraManager.openCamera / Camera.open)、`microphone_capture`(AudioRecord.startRecording)、`screen_capture`(MediaProjectionManager.getMediaProjection)、`biometric_data`(BiometricPrompt / FingerprintManager.authenticate) | `seed/api_targets.json`、`seed/sensitive_data_types.json` | P0/P1 批次（全部 `javap -s` 实证，`api_missing.json` 仍为 0） |
| **规则覆盖矩阵报告**：数据类别 × 规则类型矩阵、每类 API 抓手数、空白格理由、空转规则单独列出；退出码 1 = 存在未声明的空转类别，已并入离线回归 | `tools/rule_coverage_report.py`、`output/mobile-rule-coverage/` | "缺一份哪些数据类别 × 哪些规则类型是空的可视化报告" |
| **APK 加固特征探测**：只需标准库；命中公开加固厂商特征（libjiagu / libshella / libDexHelper …）即在证据包 `gaps` 写入"结论受限" | `tools/apk_packer_probe.py`、`ai/evidence_bundle.py`(`--apk`)、`device_run*.py` | "APKiD 加固检测进报告，加壳样本如实标注受限" |
| **修通权限 protectionLevel 标定链路** | `build_mobile_rules.py`、`calibration/README.md` | "protectionLevel 实测校准"的前置（链路本身过去是断的） |

改后计数：规则 193 → **223**、数据类别 24 → **28**、权限 37 → **40**、实证签名 47 → **58**、
离线回归 16 → **19** 项。**既有规则 ID（MOB-P001… / R… / E…）全部不变**——新类别与新权限
一律追加在种子表末尾，序号只增不改。

## 三、核对中发现、评估报告没说到的问题

1. **权限标定链路是一条死路（比"未断言"更严重）。**
   `build_mobile_rules.py` 的 permissions INSERT 列清单里**根本没有**
   `protection_level_raw` / `protection_level_value`。所以哪怕按报告建议把实测文件放进
   `calibration/`，值也永远落不进库——`over_permission` 缺"保护级别"这一维不是"待实测"，
   而是**接了也白接**。已修（M025），并加了回归用例锁住它。

2. **`provider_arg` 的抽取一直是漏的。**
   `LocationManager` 的 spec 里 `map` 是 **dict**（`{"gps": "precise_location", …}`），
   而旧代码（含 `test_rules.py` 的旧 orphan 检查）只认 **list**。结果
   `precise_location` / `coarse_location` 在"可观测类别"集合里**长期缺席**，
   旧的反向检查从未覆盖它们。已抽出 `spec_data_types()` 统一处理两种形态。

3. **报告引用的复用对象不对。**
   报告说"车载已有成熟路径（`calibrate_permissions.py`），移动端可复用同一套"——
   实测该脚本只**比对权限名**，源码注释写着 `No protection levels inferred`。
   真正抽取保护级别的是 `vehicle/rules/python/extract_device_calibration.py`
   （平台无关，`--prefix` 换一下就能用于 `android.permission.`）。已在 `calibration/README.md` 纠正。

## 四、有意不采纳 / 延期（含理由）

| 项 | 处置 | 理由 |
| --- | --- | --- |
| 写入类 API（`ContentResolver.insert/update/delete`、`MediaStore.insert`、`SmsManager.sendTextMessage`） | **本轮有意不做** | 语义是"数据改动/发送"而非"采集"。塞进现有 8 种谓词，会把写操作误判成"读取收集"——正是本工程最忌的静默错判。要覆盖须先新增 write/send 类谓词与 `api_role` 枚举值，属规则语义层改动。 |
| `AccessibilityService` / `NotificationListenerService` | 声明为**设计缺口** | 二者都是 App 继承并**覆写**的服务类，SDK 侧没有调用点；钩基类不会被覆写实现命中（症状：钩子 ARMED 但永不触发）。正确处理需运行期枚举子类挂钩，属独立钩子策略。 |
| `MediaRecorder.start()` | **有意不钩** | 一个 API 同时覆盖录音与录像，`start()` 时无法判定音/视频源，强归一类会做错归因。 |
| HealthConnect | 不覆盖 | 不在 android.jar（属独立 apk 依赖），`javap` 抽不到。 |
| AppShark 静态污点分析 | 延期 | 它产出的是**线索**而非结论，接入前须先定清"线索如何进报告"且**不得**污染 `code_locs`（AGENTS.md 硬约束：静态证据不写进 code_locs）。JDK 21 兼容性也需实测。 |
| PrivacySentry 式 ASM 编译期插桩 | 延期 | 需要对 `fixture-app` 改构建（Gradle plugin + ASM）。fixture 是设备端端到端验收的锚点，改其构建会牵动设备验收链路，本轮不动。 |
| AppScan 的 so 敏感函数扫描清单 | 延期 | native 静态属 `core/static` 的边界，且要与车载产品线协同命名与规则前缀，不宜在移动侧单独立一套。 |
| REA / Ghidra、Hegui3.0 / droid-privacy（Xposed） | **不引入** | 采纳报告自己的判断：前者只在人工调查环节用、不入流水线；后者技术栈与 Frida 不同源。 |
| `window_ms` 校准 | 待设备 | 必须跑移动夹具实测"读取→外发"间隔分布，离线做不了。步骤已写在 `DECISIONS.md` 待办。 |
| 权限 `protectionLevel` 实测 | 待设备 | 链路已修通、产出步骤已写进 `calibration/README.md`；**无实测数据前不得编造级别**。 |
| 合并 `run_mobile_checks.py` 与 `run_regressions.py` | **不合并** | 两者职责不同（根回归覆盖车载 + 内核 + parity + workbench；移动回归覆盖移动全链）。合并会削弱"移动侧可脱离车载独立跑"的能力，风险大于收益。已在 `mobile/README.md` 里让两者互相可见。 |

## 五、复现

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"

# 规则库：抽取 → 构建（含覆盖守护）
cd mobile/rules
"$PY" extract_android_apis.py            # → build/api_facts.jsonl（58 条，missing=0）
"$PY" build_mobile_rules.py --force      # → rules_mobile.db（223 条规则）
cd ../hooks && "$PY" gen_targets.py && node build.mjs && cd ../..

# 覆盖矩阵（退出码 1 = 有未声明的空转规则）
"$PY" mobile/tools/rule_coverage_report.py --out-dir output/mobile-rule-coverage

# 全部离线回归
"$PY" mobile/tools/run_mobile_checks.py  # 19 项，看 verification.json
"$PY" tools/run_regressions.py           # 11 组（含 parity / hook-bundles）
```

判据一律看 **`verification.json`**，不能只看目录存在（失败运行同样保留）。
