# 移动端 Android ID 关联窗口基准

仅用于授权测试。使用自有 `com.vscanner.privacydemo` Gadget 构建、非 root 手机模拟器及本机回环接收端。原始请求与 ID 留在本机 `output/`。

| 场景 | 独立参考 |
| --- | --- |
| 只读 | 一次真实读取，接收端和代理均无请求。 |
| 即时发送 | 读取 A 后上传 A，间隔小于 5 秒。 |
| 延迟发送 | 缓存 A，等待后发送 A，间隔在 30 至 60 秒之间。 |
| 同值跨批 | 缓存旧读取 A，等待后再次获得同值 B，随即只发送 A。B 与该请求为负控。 |

每个场景使用独立会话。夹具实际调用 `Settings.Secure.getString`，随后发出只含本轮令牌、批次和值摘要的读取标记。Gadget 在 `liblog` 观察自有夹具的指定标记。重放按 PID、会话、批次、摘要和时间范围绑定观测事件与夹具动作日志。独立接收端验证单次会话令牌、来源批次和原始正文摘要，再与代理请求及 HTTP 回执逐项核对。 [AOSP 原生日志入口](https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r1/core/jni/android_util_Log.cpp)

移动关联器使用单包排除法并维持候选等级。该对照测量时间窗和值匹配的行为。生产读取 Hook 的设备兼容性、独立应用的网络归因和窗口表现待另行验证。`rules.db` 与观测脚本复制到本轮目录，重放用 `--window-override-ms` 计算 5、10、30、60、120 秒，生产规则继续使用 30 秒。

## 2026-11-26 设备实测

Android 16（API 36）手机模拟器上完成四个独立会话。三条发送均取得 HTTP 200 正文回执。两次离线重放报告 SHA-256 完全一致。 [验收摘要](../../output/mobile-window-20261126/verification.json) · [逐配对重放](../../output/mobile-window-20261126/replay/verification.json)

| 场景 | 读取至请求 | 5 秒 | 10 秒 | 30 秒 | 60 秒 | 120 秒 |
| --- | --- | --- | --- | --- | --- | --- |
| 只读 | 无请求 | 无候选 | 无候选 | 无候选 | 无候选 | 无候选 |
| 即时发送 | A 168 ms | 命中 | 命中 | 命中 | 命中 | 命中 |
| 延迟发送 | A 36,165 ms | 漏配 | 漏配 | 漏配 | 命中 | 命中 |
| 同值跨批 | A 36,216 ms · B 97 ms | 漏 A、误配 B | 漏 A、误配 B | 漏 A、误配 B | 命中 A、误配 B | 命中 A、误配 B |

扩大窗口能收入本轮延迟正例，同值跨批误配在所有窗口都出现。发送来源以独立回执记录的批次为准。

## 复跑

在项目根解析本机环境。使用已就绪、已授权的专用手机模拟器与已按宿主 Frida 版本准备的自有 Gadget APK。Gadget 准备流程见 [自有 APK 构建](../fixture-app/README.md)。

```powershell
. .\environment.ps1
node mobile/hooks/build.mjs hook_window_benchmark
.\mobile\fixture-app\gradlew.bat -p mobile/fixture-app :app:assembleGadget --offline
$apk = 'mobile/fixture-app/app/build/outputs/apk/gadget/app-gadget.apk'
$run = 'output/mobile-window-rerun'
.\tools\python313.ps1 -m mobile.lab.window_benchmark_capture --serial emulator-5566 --apk $apk --out $run
.\tools\python313.ps1 -m mobile.lab.window_benchmark --source $run --out "$run/replay"
```

每轮的 `suite.json` 指向四个独立采集目录，`replay/verification.json` 记录每档命中的参考正例、漏配、同值跨批误配及参考范围外候选。采集失败保留日志和原始记录，复跑使用新目录。
