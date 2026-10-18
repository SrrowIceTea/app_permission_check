# 原始 APK 兼容环境与 SDK 限定采集

仅用于授权测试。2026-10-18 的五款受阻原包，改用独立 Android 11/API30
Google APIs x86_64 模拟器 `VScanner_Compat_API30` / `emulator-5564`，不替换 APK，
不重签名，不改返回值，不安装 CA。原 API36 的 15 款报告不被此次结果覆盖。

## 本轮真实结果

| 原始应用 | 无 Hook 对照 | SDK 限定真实采集 | 读取 / 明文 HTTP流 | 结果目录（output/domestic-compat-api30-20261018/ 下） |
| --- | --- | --- | --- | --- |
| QQ音乐 | 原包安装、进程存活 | 通过，spawn | 0 / 0 | capture-scoped/cn-qqmusic |
| 天猫 | 原包安装、进程存活 | 通过，spawn | 0 / 0 | capture-scoped/cn-tmall |
| 魔珠 Pop Lines | 系统旧版权限 Review 点 Continue 后进程存活 | 通过，late attach | 7 / 0 | poplines-legacy-late-attach |
| 人民网+ | 32 / 64 位均在无 Hook 时退出 | 受阻 | unknown | launch-baseline/cn-peopleplus、abi32-baseline/cn-peopleplus |
| 迅雷 | 32 / 64 位均在无 Hook 时退出 | 受阻 | unknown | launch-baseline/cn-xunlei、abi32-baseline/cn-xunlei |

三款采集的 `verification.json` 均检查原 APK 摘要、原进程存活、脚本无错误、所选全部 Hook
健康、证据可解析、测试安装清理。QQ音乐和天猫只运行有限启动场景，未点同意/登录/购买。
0 次读取或 0 条可解析 HTTP **不代表没有收集或没有风险**。魔珠的启动及系统 Review 操作
发生在 late attach 之前；这部分行为不在 Hook 观察窗口内，不能据此判定同意前收集。

同环境正控为 `fixture-scoped-endpointfix/verification.json`：11 条真实隐私读取、1 条已归因
HTTP 200 流，八项检查全部通过。初始未完成运行、端点填写失败和 spawn 受权限 Review
阻塞的运行原样保留，不覆盖为成功。

## SDK 适配不是放宽失败门控

- 官方 API30 Google APIs 镜像 revision16 实际支持
  `x86_64,x86,arm64-v8a,armeabi-v7a,armeabi`；API36 镜像没有 ARM32。
- `--android-jar` 显式提供与实际设备 API 相同的 SDK。`sdk_hook_scope.py` 使用现有相同 seed
  重新执行官方 `android.jar` 的 `javap -public -s`，以类/方法/描述符精确三元组与原监视表取交集。
  提取错误直接拒绝；运行时失败仍使采集失败，不按 API 数字硬编码豁免。
- API30 精确交集为 privacy **54/58**、consent **6/8**。4 个不支持的 privacy 重载为
  `getInstalledApplications(ApplicationInfoFlags)`、`getInstalledPackages(PackageInfoFlags)`，以及
  `requestLocationUpdates(String,LocationRequest,PendingIntent)`、
  `requestLocationUpdates(String,LocationRequest,Executor,LocationListener)`。
  consent 缺少新版含额外 int 参数的 `requestPermissions` / `onRequestPermissionsResult` 重载。
- 每轮 `compiled-hooks/sdk-hook-scope.json` 保存原规则版本 **36**、实际签名 API **30**、
  Jar SHA256、选中和不支持的完整描述符。没有改写全局 API36 targets 或合规规则数据库。
  此次 API30 采集没有伪装为 API36 正式规则分析，也没有新增正式 AI 合规报告。

## 两款剩余阻断的实际原因

- 人民网+：加固层加载 `libDexHelper-x86.so`，64 位报 `EM_X86_64 instead of EM_AARCH64`，
  强制同原包 ARM32 后报 `EM_386 instead of EM_ARM`。这是本机 Native Bridge 兼容阻断，
  不是降低 Hook 门控可以解决的问题。
- 迅雷：同原包 ARM32 和 ARM64 的无 Hook 对照均报 Secneo
  `No implementation found for boolean com.secneo.apkwrapper.H.is(int)`。
  后续需要可实际运行这些原包的原生 ARM 环境或应用方测试构建；不能以另一版本 APK 替换当前工件。

## 复跑

先启动独立 API30 模拟器、确认 root 和匹配版本 Frida Server，显式转发该设备 27043。
在仓库根目录使用已装项目依赖的 Python：

```powershell
python -m mobile.lab.core_capture --apk APP.apk --package PACKAGE `
  --out output/NEW-UNUSED-DIRECTORY --serial emulator-5564 `
  --scenario launch-only --android-jar E:/Android-CompatSDK/platforms/android-11/android.jar --authorize
```

`--install-abi armeabi-v7a` 仅传递 Android 安装器的 ABI 选择参数，仍校验原 APK 哈希。
魔珠限定场景为 `--scenario legacy-review --startup-mode attach`，只对已验证的该包、720×1280
画面与前景系统 Review Activity 接受已记录的 Continue，不使用 uiautomator 连接游戏 Canvas。

官方镜像、平台 Jar 的原始仓库 XML、下载 URL、官方校验值与实际 Javap 事实见
`output/root-compat-runtime-20261018/`。同目录保留 API30 UI 自动化服务 Watchdog 原始日志；
launch-only 明确绕开该辅助 UI 服务，不绕开应用/Hook/证据健康检查。
42 项定向离线契约测试通过（合成单元测试不冒充真实 APK 运行证据）。
