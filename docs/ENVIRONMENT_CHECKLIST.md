# V-Scanner 运行依赖与环境清单

更新于 2026-11-23。命令按 Windows PowerShell 编写，从仓库根目录执行。动态采集仅用于自有设备与自有 APK。

## 1. 按使用场景准备

| 要做的事 | 需要准备 |
| --- | --- |
| 打开车载工作台 | Windows、PowerShell、Python 3.13、项目 Python 依赖、浏览器 |
| 上传 APK 做车载静态分析 | 加 JDK、JADX、Android SDK Build-Tools。全程可在电脑上完成 |
| 在工作台新建车载采集 | 加 ADB、AAOS 35 模拟器、匹配的 frida-server、车载 Hook 构建产物、装在 user 10 的自有 APK |
| 从源码编译自有夹具或 Room 规则 App | 加 SDK Platform 36、Build-Tools 36.0.0，由各 Android 工程的 Gradle Wrapper 安装和解析构建依赖 |
| 跑移动一键审计 | 加手机 AVD、移动 Hook 构建产物、自有移动 APK。移动批采另需对应 ABI 的 frida-server |
| 跑离线回归或重建 Hook | 安装 Python 依赖、Node.js 24 和 npm。本地回环端口要能绑定。重建 Hook 需要 npm 缓存或依赖下载权限 |

## 2. 宿主机与通用工具

- [ ] **Windows x64、PowerShell 5.1 或兼容版本**。`.bat` 是双击入口，`.ps1` 是命令行入口。需要启动模拟器的机器应有硬件虚拟化和可用的 Windows 加速后端。本机实测使用 WHPX。
- [ ] **Git 与完整仓库**。用于取版本，以及核对 Hook 构建对应的源码状态。仓库自带两条产品线的规则库和前端资源。SQLite 由 Python 提供。
- [ ] **Python 3.13 x64 + pip**。本机实测 3.13.9。统一用 `tools/python313.ps1`，选择顺序是 `VSCAN_PYTHON`、项目 `.venv`、`%LOCALAPPDATA%\Programs\Python\Python313\python.exe`。本机裸 `python` 指向 WindowsApps 的 3.15。
- [ ] **JDK 21**。本机为 Temurin 21.0.12.1，位置 `D:\Android\JDK`。用于运行 JADX、从源码编译 APK 和提取 SDK 签名。项目目前采用 JDK 21，APK 工程的 JVM target 是 17。完整构建使用这个组合，避免切换到 JBR 25。
- [ ] **Android SDK Platform-Tools**。提供 `adb.exe`。本机 SDK 在 `%LOCALAPPDATA%\Android\Sdk`，ADB 为 37.0.1。接设备或跑动态流程时准备它。
- [ ] **Android SDK Build-Tools 36.0.0**。Room 工程固定该版本。静态工作台可选用已安装的较新版本，本机解析到 36.1.0。`aapt2` 读取 APK 包名、版本和权限，`dexdump` 用于 DEX 证据核对，签名相关工具用于自有 APK 构建。新机可用 Android Studio 的 SDK Manager 或 SDK Command-line Tools 安装组件。
- [ ] **JADX 发行版**。本机已解析到 1.5.6。`VSCAN_JADX` 指向含 `lib/jadx-*-all.jar` 的目录，静态工作台可用 JADX 自带 JRE，或使用配置好的 Java。
- [ ] **浏览器**。普通前端直接打开即可。车载和移动前端均为纯 HTML、CSS 和 JavaScript。

### Python 依赖

直接安装 [requirements.txt](../requirements.txt)。以下版本取自该文件。

| 包 | 版本 | 用途 |
| --- | --- | --- |
| `frida` | `17.18.0` | 宿主驱动与 Hook 编译器 |
| `frida-tools` | `14.10.4` | Frida 命令行工具。设备端 server 版本跟 `frida` 对齐 |
| `mitmproxy` | `12.2.3` | 本地流量代理和采集，包含 `mitmdump` |
| `cryptography` | `48.0.0` | 证书和采集相关校验 |
| `reportlab` | `5.0.1` | PDF 报告 |
| `Pillow` | `12.1.0` | 报告图片与截图处理，导入名为 `PIL` |
| `pypdf` | `6.19.0` | PDF 读取和验收 |
| `jsonschema` | `4.26.0` | 移动报告 SARIF schema 校验 |
| `maxminddb` | `3.2.0` | 按需读取本地 IP 地理位置 `.mmdb`，常规回归前置检查不强制导入 |

```powershell
$Python313 = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'
& $Python313 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
. .\environment.ps1
```

如果 Python 装在其他位置，将 `$Python313` 改为对应的 3.13 可执行文件路径。项目启动时如需指定解释器，可设 `VSCAN_PYTHON`。

### 路径覆盖项

先设置覆盖项，再加载 [environment.ps1](../environment.ps1)。

| 变量 | 内容 |
| --- | --- |
| `VSCAN_PYTHON` | Python 3.13 `python.exe` 的完整路径 |
| `VSCAN_SDK` | Android SDK 根目录，启动脚本据此设置 `ANDROID_HOME` 和 `ANDROID_SDK_ROOT` |
| `VSCAN_JDK` | JDK 根目录，启动脚本据此设置 `JAVA_HOME` |
| `VSCAN_JADX` | JADX 根目录，其下包含 `lib/jadx-*-all.jar` |
| `VSCAN_ADB` | 可选，显式指定 `adb.exe`。普通安装由 SDK 路径解析 |
| `ANDROID_AVD_HOME` | AVD 配置所在目录。车载准备脚本启动项目 AVD 时会设置自己的 AVD 目录 |

## 3. 车载 AAOS 动态测试

- [ ] **Android Emulator**。安装 SDK 中的 Emulator 组件。本机版本 37.2.12.0，是宿主模拟器程序版本。
- [ ] **AAOS 35 镜像与 AVD**。项目主线验证环境为 Android 15 / API 35、`userdebug`、`automotive`、`emulator_car64_x86_64`。AVD 名为 `VScanner_AAOS_35_P1`，目标 `android-35-ext15`，默认 ADB serial 为 `emulator-5554`。车辆应用运行在 **user 10**。跨版本能力见 [AAOS 兼容性说明](../vehicle/COMPATIBILITY.md)。
- [ ] **匹配的设备端 frida-server**。本机车载用 Android `x86_64` 的 `17.18.0`。将解压后的文件放到 `output/vehicle-device-setup/frida-server`。默认准备脚本在自有 `userdebug` 设备上使用 `adb root` 并部署 server。设备回环监听为 `127.0.0.1:27043`，驱动处理 ADB 转发。当前夹具走 attach。
- [ ] **自有测试 APK**。首次走默认流程使用 `com.vscanner.targetapp` 的 debug APK，路径为 `vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk`。备好设备后，工作台上传同一份 APK，动态入口核对已装包摘要并要求目标应用运行中。
- [ ] **车载及共享 Hook**。需要 `vehicle/hooks/dist/` 和 `core/frida_host/dist/` 中的 bundle 和配套 SHA-256 构建清单。Node.js 24 与 npm 用于按锁文件安装 Java bridge `7.0.13`。项目的 Python Frida Compiler 完成打包。
- [ ] **设备网络和本机回环**。需要网络的场景须确认 AVD 已连 Wi-Fi。车载动态默认需要宿主 `127.0.0.1:8888` 可用。共用同一 AVD 时按样本串行，独立保留每次会话和失败日志。

复制团队准备的环境时保留以下结构。`output/` 下的大文件和编译后的 APK、Hook bundle 都要单独准备，普通 Git 检出不包含它们。

```text
output/vehicle-device-setup/
├── avd/VScanner_AAOS_35_P1.ini
├── avd/VScanner_AAOS_35_P1.avd/config.ini
├── image/x86_64/                   # AAOS 35 系统镜像及配套文件
└── frida-server                    # Android x86_64 17.18.0 解压后的二进制
```

迁机时将 AVD `.ini` 的 `path` 和 `.avd/config.ini` 的 `image.sysdir.1` 指向新机器上的实际目录。本机车载镜像保存在上述项目目录，手机 AVD 另存。**运行设备用 API 35，以下编译工具链用 SDK 36。**

### 自有 APK 编译与首次启动

- 安装 SDK Platform `android-36`，车载工程需要 `platforms/android-36/optional/android.car.jar`。本机另装有 `android-37.0`，项目构建仍固定 `compileSdk = 36`。
- Gradle Wrapper 固定 **8.13**，Android Gradle Plugin 固定 **8.11.1**，Kotlin 固定 **2.2.0**。车载规则 App 另用 **KSP 2.2.0-2.0.2** 与 **Room 2.8.5**。首次构建需要能访问项目 Gradle/Maven 配置中指定的仓库，或事先提供缓存。本项目配置了阿里云镜像。
- 工程路径含中文等非 ASCII 字符时，现有 `gradle.properties` 已带 `android.overridePathCheck=true`。

```powershell
. .\environment.ps1
Push-Location .\vehicle\targets\target-app
try { .\gradlew.bat :app:assembleDebug } finally { Pop-Location }
if ($LASTEXITCODE -ne 0) { throw '夹具 APK 编译失败' }
.\vehicle.ps1 prepare --install-deps
if ($LASTEXITCODE -ne 0) { throw '车载 Hook 构建失败' }
.\prepare-vehicle-device.ps1
.\start-vehicle.bat -NoAi
```

已有指定 AAOS 正在运行时，准备脚本可传 `-NoEmulator`。仅开工作台或做静态分析时直接运行最后一行。动态采集前先确认准备脚本通过，再打开 `http://127.0.0.1:8773/`。车载 Hook 构建输出见 `output/vehicle-prepare-*/verification.json`。

## 4. 移动端补充项

- [ ] **独立手机 AVD**。本机示例 `VScan_Phone` 在 `D:\AVD`，为 x86_64 手机镜像。传统 root 动态采集路线用支持 `adb root` 的测试镜像，移动测试的 Android 用户以所选手机 AVD 或流程参数为准。共用默认 serial 时，一次只开需要的模拟器。
- [ ] **移动的自有 APK、Hook 和服务端二进制**。夹具工程在 `mobile/fixture-app/`，移动 Hook 位于 `mobile/hooks/`。常用跑批及夹具自检从 `output/_frida/frida-server` 查找设备端二进制，与宿主 Frida 版本及设备 ABI 匹配。
- [ ] **样本目录**。手机 APK 放 `apk/mobile/`，车载 APK 放 `apk/vehicle/`。移动 F-Droid-60 是附加数据集，项目约定路径 `D:/数据集/数据集/F-Droid-60`，本机未挂载。它只在对应跑批时需要。

```powershell
. .\environment.ps1
.\tools\python313.ps1 mobile/hooks/gen_targets.py
if ($LASTEXITCODE -ne 0) { throw '移动 Hook 监视表生成失败' }
Push-Location .\mobile\hooks
try {
    npm ci --ignore-scripts
    if ($LASTEXITCODE -ne 0) { throw '移动 Hook 依赖安装失败' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw '移动 Hook 构建失败' }
} finally { Pop-Location }
.\start-all.ps1 -Only frontend,pipeline
```

移动静态工作台可按需单独用 `./tools/python313.ps1 mobile/workbench/server.py --port 8772` 启动。跑批与设备准备入口见 [移动跑批手册](AGENT_TEST_SUITE_RUNBOOK_20261019.md) 和 [移动一键审计说明](../mobile/pipeline/README.md)。

## 5. 端口与按需依赖

| 端口 | 用途 |
| --- | --- |
| `8773` | 车载审计工作台，同一进程提供前端和后端 |
| `8770` | 独立车载静态 APK 工作台，默认 `start-all` 会启动它 |
| `8771` / `8090` | 移动一键审计后端 / 零构建前端，前端入口 `/app.html` |
| `8772` | 单独启动的旧移动静态工作台 |
| `27043` | 默认 Frida server 回环端口。自有 Gadget 路线默认使用 `27044` |
| `8888` / `8890` | 常用动态代理 / 部分自有夹具实验的独立 HTTP 接收端 |

| 需要的能力 | 额外准备 |
| --- | --- |
| AI 辅助复核 | 可访问的模型服务、模型名和 Key。使用车载或移动 `ai/config.example.json` 生成各自的 `config.local.json`，或在相应入口使用 `VSCAN_LLM_BASE_URL`、`VSCAN_LLM_MODEL`、`VSCAN_LLM_API_KEY`。车载启动器以 `vehicle/ai/config.local.json` 为自动启用条件。密钥保存在本机 |
| pcap 重组与额外流量证据 | 自有测试设备上的 `tcpdump` 及相应采集权限、宿主 Wireshark 的 `tshark.exe`。可设 `VSCAN_TSHARK`，或使用 `output/_tools/wireshark/tshark.exe`。本机手册验证过 4.6.9。常规车载代理采集不依赖它 |
| 中文 PDF 渲染 | ReportLab 优先使用 Windows 已安装的中文字体，如黑体、等线或微软雅黑，缺少时回退到 `STSong-Light` |
| 自有源码的 Frida Gadget 路线 | 与宿主 Frida 同版本、与 APK ABI 一致的 Android Gadget 库，自有源码及签名和安装权限。选这条路线时阅读对应夹具的说明 |
| 专项 APK 封装或版本核验 | 仅相关实验需要。仓库移动封装工具声明 Apktool `3.0.3`、JDK `keytool` 和 SDK `zipalign`、`apksigner`，见 [工具定义](../mobile/repack/toolchain.py) |
| 端点估计与外部策略数据 | 可选的离线 `.mmdb`、既有 RDAP/位置缓存、授权获取的应用隐私政策。在线查询需要网络。IP 位置按估计展示 |
| 特定车载 App 的业务验收 | 只在相应场景中准备隔离的 Home Assistant 或 Audiobookshelf 等测试服务，见 [车载专项验收](../vehicle/lab/P1_P2_RESULTS.md) |
| CI、代码检查与浏览器验收 | [requirements-dev.txt](../requirements-dev.txt) 固定 `ruff==0.8.4`，GitHub Actions 和 Jenkins 使用 Python 3.13 与 Node.js 24。车载浏览器验收脚本启动本机 Chrome，普通使用可选其他现代浏览器 |

## 6. 环境验收顺序

1. 用固定 Python 入口执行离线回归。依赖可用且测试通过时退出 `0`，测试失败为 `1`，前置依赖缺失为 `3`。依赖是否可用以当次检查为准。
2. 静态工作台上传一份自有 APK，确认 `aapt2`、JADX、DEX 核验工具能解析，并取得静态结果。
3. 车载动态先备好自有夹具，再进入工作台发起新采集。确认导出的 `verification.json` 健康检查通过，且报告、规则版本与原始记录属于同一会话。

```powershell
.\tools\python313.ps1 tools/run_regressions.py
# 开发移动端时追加两条
.\tools\python313.ps1 mobile/tools/run_mobile_checks.py
.\tools\python313.ps1 tools/check_mobile_branch.py
```

清单核对时，本机的依赖前置检查通过，Python 3.13.9、宿主 Frida 17.18.0、JDK 21、ADB、Emulator、JADX、SDK 36 的 `android.car.jar`、`aapt2`、`dexdump` 均可定位。AAOS AVD、镜像、设备端二进制和默认 debug APK 文件在位。三条回归入口及设备故障处理见 [回归手册](REGRESSION_CI.md)、[车载前端入口](../vehicle/frontend/README.md) 和 [项目全局约定](../AGENTS.md)。
