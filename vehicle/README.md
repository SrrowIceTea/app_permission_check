# 车载 App 隐私数据评估

仅用于授权测试（自有设备与已授权 APK）。当前面向普通第三方安装的车载 App，以 AAOS 35 为动态基线。
研究来源、方法取舍与验收条件见 [研究计划](../docs/VEHICLE_RESEARCH_PLAN.md)。
版本与量产车型实例见 [COMPATIBILITY.md](COMPATIBILITY.md)，不是所有品牌通用的兼容承诺。
覆盖链见 [coverage/generated/COVERAGE.md](coverage/generated/COVERAGE.md)，场景见 [scenarios/CATALOG.md](scenarios/CATALOG.md)。
本轮实现、实际验收与未完成项见 [P0_P1_DELIVERY.md](P0_P1_DELIVERY.md)。
AAOS 35 三个应用家族的业务复验、隔离服务与 agent 初评见 [P1_P2_RESULTS.md](lab/P1_P2_RESULTS.md)。

## 已接入的能力

- 共享 `core/static`：清单与 DEX 静态事实、车载规则匹配，候选不当作采集事实。
- 车辆主动读取与订阅回调；成功、拒绝、不可用、错误分别记录。
- 属性绑定的原值、base64/hex/URL 编码及 md5/sha1/sha256 派生值匹配。
- 出站归因保留 UID/userId；延迟重试同样刷新完整身份；跨用户冲突不关联。
- 单个 `hook_vehicle_all` agent 共用 Java runtime，避免多个 bridge 并发卸载的 JNI 崩溃。
- 场景执行记录、按 API 分组的主机观察频率、实验性复核排序。
- 共用 `core/ai/llm_client.py`，车载 AI 证据封装与输出门控独立；移动端旧导入兼容。
- `pipeline/audit.py` 将静态核对、关联、场景、AI 和 PDF 编排到一个入口。

## 本机运行

车载 Web 工作台已接入：`./vehicle.ps1 web`，访问车载 v2 工作台 `http://127.0.0.1:8773/v2/`。
复用移动端界面布局，车载规则与流水线独立；支持静态分析、采集重放和已安装授权 App 的新采集。
入口、前提及边界见 [frontend/README.md](frontend/README.md)。

依赖：Python 3.12+、`pip install -r requirements.txt`、Android SDK、JDK 21、Gradle 8.13。
统一由根 `environment.ps1` 选择 Python（显式覆盖 > 现有 .venv > 本机实际解释器），不要求虚拟环境预先存在。
设置 `VSCAN_SDK`、`VSCAN_ADB`、
`VSCAN_SERIAL`（如 `emulator-5554`），把 SDK platform-tools 加到 PATH。
Frida 17.18.0 server 在自有 AAOS 中监听回环 `127.0.0.1:27043`，ADB 转发同端口。
签名和属性常量以 `rules/device_calibration/` 与对应 SDK 实证为准。

```powershell
./vehicle.ps1 prepare --install-deps  # 依赖齐全时不会联网；按锁文件安装且跳过安装脚本
./vehicle.ps1 profiles
./vehicle.ps1 coverage
./vehicle.ps1 scenarios --suite all  # 已启动自有 AAOS/Frida 且夹具 APK 构建后，单设备串行验收
./vehicle.ps1 overhead --pairs 6 --actions 4  # 有/无 Hook 配对开销，产物含 report.md
. ./environment.ps1

# 自有测试 APK：在 vehicle/targets/target-app 使用 Gradle :app:assembleDebug。
# 必须用真实 JDK 根覆盖旧 gradle.properties 的 org.gradle.java.home。
# 代理故障时只对本次命令覆盖代理，不修改用户全局 Gradle 配置。

# 测试必须串行，不能并发争用设备前台、8888 端口或 ADB reverse。
& $VScanPython tools/device_acceptance.py
& $VScanPython tools/vehicle_scenario_acceptance.py
& $VScanPython tools/vehicle_context_acceptance.py
& $VScanPython tools/vehicle_user_acceptance.py
& $VScanPython tools/run_regressions.py --mobile
& $VScanPython tools/check_mobile_branch.py
```

每次执行创建全新 `output/` 会话，失败也保留。`output/latest-vehicle-scenarios.txt`、
`latest-vehicle-users.txt` 和 `latest-device.txt` 指向当前结果。
用户测试创建临时用户，切回原用户并删除临时用户；不验证旧用户私人缓存的残留。
新的场景夹具 receiver 仅存在于自有 debug APK，端点只允许 `127.0.0.1:8888/collect`
与模拟器宿主回环别名 `10.0.2.2:8888/collect`；后者用于绕开 ADB 代理回环的断网验收。

## 从采集证据生成审计

```powershell
./vehicle.ps1 audit `
  --capture output/本轮会话/plain --out output/新的审计目录 `
  --package com.vscanner.targetapp `
  --scenarios output/本轮会话/plain/scenarios.json `
  --apk vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk
```

指定 APK 时，必须与采集当时 `session-manifest.json` 中装机哈希一致。
所有审计都先检查采集健康、会话、白名单、API、规则及实际使用 Hook 摘要；失败只写失败状态及阶段日志。
新版采集同时绑定原始输入摘要，旧会话缺输入摘要/普通安装身份时明确列出限制。
已有三家授权样本可用 `benchmark --suite vehicle/bench/aaos35-suite.json` 重放。
对封存的 API 35 自有夹具采集，`coverage --vhal-capture <采集目录> --out <输出目录>` 会按属性导出运行时事件与覆盖缺口。
固定 YAABSA 样本在 AAOS 35 user 10 的隔离 ABS 测试中可用 `capture --scope general --preserve-system-proxy --abs-send`，
审计重放已封存的写入与回环正文证据。设备端需有既有 `tcpdump`，详见 [第三方验收登记](lab/THIRD_PARTY_ACCEPTANCE.md)。
AAOS 35 指定 HA Automotive 样本可用 `--scope general --preserve-system-proxy --ha-webhook`
观察隔离服务的电量 HTTP 正文，复验入口及字段范围见 [HA 电量请求正文验收](lab/HA_WEBHOOK_VALIDATION.md)。
`summary.json` 只在全部请求阶段成功后提交；健康但无 VHAL 读取会明确输出有限的无观测结果，不代表无隐私风险。
省略 APK 显式标 `static_analysis: skipped`，不得把另一版本源码当成当前动态证据。
生成 `findings.jsonl`、`summary.json`、阶段日志、可选静态结果和 `vehicle-audit.pdf`。
`--no-pdf` 可以只分析，`--android-version` 选择实测版本对应的车载规则库。

AI 可复制 `vehicle/ai/config.example.json` 为 **不入库** 的 `config.local.json`。
加 `--ai-config vehicle/ai/config.local.json` 才联网；默认明确 skipped，不冒充已运行。
请求只带规则/属性类别/匹配类型/计数/场景，不发送原值、完整载荷、UID 或调用栈。
会保留每次调用与校验失败，格式错误最多纠正一次；不得改变工具结论或严重度。
未经允许，不应把真实用户的隐私数据发送到外部模型。

## 普通第三方样本

```powershell
./vehicle.ps1 samples --out output/my-samples
# 在自有 AAOS 的正确用户下普通安装/启动已授权 APK 后，显式指定包名；不自动提权或授予权限。
./vehicle.ps1 capture --package 实际包名 --user 10 --seconds 60 --out output/my-capture
./vehicle.ps1 audit --capture output/my-capture --package 实际包名 --out output/my-audit --apk 实际APK路径
./vehicle.ps1 benchmark --manifest output/my-samples/manifest.json --out output/my-benchmark
```

详见 [bench/README.md](bench/README.md)。捕获会暂设系统代理并恢复原值；严格模式启用目标匹配，
拒绝将全部未知流量兜底给唯一白名单包，无法归因的正文不保留。URL/OkHttp 请求目标是候选而非已发送事实。
白名单外应用、WebView 子进程、忽略系统代理的流量仍可能形成缺口，不作全协议保证。
`--policy 元数据JSON` 可加入与本轮 APK 绑定的本地政策、字符位置引用和业务用途复核。

## 边界

场景：只读不发、正常上传、同名不同值、SHA-256 派生上传、延迟上传、后台、拒绝权限；
另有订阅/OkHttp/HTTPS 基线与真实用户切换隔离。测试脚本同时核对正常退出与原 PID 存活。
新增自有 debug 同意 UI/撤回、持久缓存批传/清理、跨用户缓存隔离、模拟停车/行驶和断网重传验收。
并发多用户显示、独立 App 真实同意界面、真实车辆/休眠电源状态、厂商私有接口、座舱音视频、
跨 App ICC 污点分析和真实车辆未完成验证，不能用已有测试替代。
属性绑定 JSON 之外的二进制协议/嵌套自定义编码可能漏检；相等内容不证明因果传播。
历史缺原值/正文的属性名证据仍保留，但明确 `value_match: false`。
复核关注分是透明的初始工程权重，未校准；不报告准确率或法规合规概率。
政策正文抽取已提升到 core/policy，mobile 保留兼容导入；车载独立处理 APK 绑定、协议分离和引用。
未提供政策或抽取失败时仍不得推测披露内容；所有必要性判断保留人工复核。
