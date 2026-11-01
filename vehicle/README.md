# 车载 App 隐私数据评估

仅用于授权测试（自有设备与自有 APK）。本次改造以 AAOS 35 为设备基线。
研究来源、方法取舍与验收条件见 [研究计划](../docs/VEHICLE_RESEARCH_PLAN.md)。

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

依赖：Python 3.12+、`pip install -r requirements.txt`、Android SDK、JDK 21、Gradle 8.13。
项目专用 Python 为 `.venv/Scripts/python.exe`。设置 `VSCAN_SDK`、`VSCAN_ADB`、
`VSCAN_SERIAL`（如 `emulator-5554`），把 SDK platform-tools 加到 PATH。
Frida 17.18.0 server 在自有 AAOS 中监听回环 `127.0.0.1:27043`，ADB 转发同端口。
签名和属性常量以 `rules/device_calibration/` 与对应 SDK 实证为准。

```powershell
# 构建观察脚本；只需 bridge 依赖，避免执行 Node 原生绑定安装脚本。
Set-Location vehicle/hooks
npm ci --ignore-scripts
Set-Location ../..
.venv/Scripts/python.exe core/frida_host/build.py --platform vehicle
.venv/Scripts/python.exe core/frida_host/build.py --platform shared

# 自有测试 APK：在 vehicle/targets/target-app 使用 Gradle :app:assembleDebug。
# 必须用真实 JDK 根覆盖旧 gradle.properties 的 org.gradle.java.home。
# 代理故障时只对本次命令覆盖代理，不修改用户全局 Gradle 配置。

# 测试必须串行，不能并发争用设备前台、8888 端口或 ADB reverse。
.venv/Scripts/python.exe tools/device_acceptance.py
.venv/Scripts/python.exe tools/vehicle_scenario_acceptance.py
.venv/Scripts/python.exe tools/vehicle_user_acceptance.py
.venv/Scripts/python.exe tools/run_regressions.py --mobile
.venv/Scripts/python.exe tools/check_mobile_branch.py
```

每次执行创建全新 `output/` 会话，失败也保留。`output/latest-vehicle-scenarios.txt`、
`latest-vehicle-users.txt` 和 `latest-device.txt` 指向当前结果。
用户测试创建临时用户，切回原用户并删除临时用户；不验证旧用户私人缓存的残留。
新的场景夹具 receiver 仅存在于自有 debug APK，端点只允许 `127.0.0.1:8888/collect`。

## 从采集证据生成审计

```powershell
.venv/Scripts/python.exe vehicle/pipeline/audit.py `
  --capture output/本轮会话/plain --out output/新的审计目录 `
  --package com.vscanner.targetapp `
  --scenarios output/本轮会话/plain/scenarios.json `
  --apk vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk
```

指定 APK 时，必须与采集当时 `session-manifest.json` 中装机哈希一致。
省略 APK 显式标 `static_analysis: skipped`，不得把另一版本源码当成当前动态证据。
生成 `findings.jsonl`、`summary.json`、阶段日志、可选静态结果和 `vehicle-audit.pdf`。
`--no-pdf` 可以只分析，`--android-version` 选择实测版本对应的车载规则库。

AI 可复制 `vehicle/ai/config.example.json` 为 **不入库** 的 `config.local.json`。
加 `--ai-config vehicle/ai/config.local.json` 才联网；默认明确 skipped，不冒充已运行。
请求只带规则/属性类别/匹配类型/计数/场景，不发送原值、完整载荷、UID 或调用栈。
会保留每次调用与校验失败，格式错误最多纠正一次；不得改变工具结论或严重度。
未经允许，不应把真实用户的隐私数据发送到外部模型。

## 边界

场景：只读不发、正常上传、同名不同值、SHA-256 派生上传、延迟上传、后台、拒绝权限；
另有订阅/OkHttp/HTTPS 基线与真实用户切换隔离。测试脚本同时核对正常退出与原 PID 存活。
并发多用户显示、真实同意界面、模拟行驶状态、厂商私有接口、座舱音视频、
跨 App ICC 污点分析和真实车辆未完成验证，不能用已有测试替代。
属性绑定 JSON 之外的二进制协议/嵌套自定义编码可能漏检；相等内容不证明因果传播。
历史缺原值/正文的属性名证据仍保留，但明确 `value_match: false`。
复核关注分是透明的初始工程权重，未校准；不报告准确率或法规合规概率。
政策解析框架可继续从 mobile 迁移；当前车载 AI 未提供政策原文时不得猜测披露内容。
