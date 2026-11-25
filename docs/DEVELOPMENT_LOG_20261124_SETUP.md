# V-Scanner 开发日志分卷

## 2026-11-24 · 本机从零搭起车载动态审计环境（Node/JDK/SDK/镜像/AVD/frida）

- 范围：环境与工具链。业务代码无改动，唯一代码改动是 `start-all.ps1` 的参数引号修复（见「坑 2」）。
- 前提纠正：`AGENTS.md` 环境表记的是原开发机（`%LOCALAPPDATA%\Android\Sdk`、`D:\Android\JDK`）。本机（HW）实际已有
  `VSCAN_SDK`/`ANDROID_SDK_ROOT` = `D:\app project\AndroidSdk`（platform-tools、emulator、system-images、jdk-21、avd 都在），
  JADX 在 `D:\app project\Jadx\jadx-gui-1.5.3-with-jre-win`。**按文档默认路径探测会误判成"什么都没有"**。
- 实际补齐：
  - Node.js 24.22.3 + npm 11.19.1 → `D:\tools\node`，写入用户 PATH（2026-11-23 `prepare` 卡在 `npm_missing` 就是缺它）
  - Temurin JDK 21.0.13.1 → `D:\Android\JDK`（`environment.ps1` 的回退位）
  - `build-tools;35.0.0`（AGP 8.11.1 实际用 35，先报过一次 `Install Build-Tools 35 failed`）、`build-tools;36.0.0`、
    `platforms;android-36`（含 `optional/android.car.jar`），后两者用 robocopy 补进 `D:\app project\AndroidSdk`
  - Gradle 8.13：`gradle-wrapper.properties` 的 `networkTimeout=10000` 下阿里云镜像会 SSL decode 中断，改为手工下载 zip 放进
    `~/.gradle/wrapper/dists/gradle-8.13-bin/bynj8867joaln2pdnozgpow3q/` 并写 `.ok`。
    **缓存目录名是 distributionUrl 的 MD5 再转 base36，不是 hex**（先按 hex 放了一份，gradlew 不认）
  - `output/vehicle-device-setup/avd/VScanner_AAOS_35_P1.ini` 的 `path` 指向本机已配好的
    `D:\app project\AndroidSdk\avd\VScanner_AAOS_35_P1.avd`（1408×792、6G data），避免复制数 GB 的 userdata
  - `output/vehicle-device-setup/frida-server`：17.18.0 x86_64，`.xz` 用 `lzma` 解压，与 `.venv` 的 frida 17.18.0 对齐
- 三个坑：
  1. `prepare-vehicle-device.ps1:188` 的 `adb push` 进度走 stderr，在 `ErrorActionPreference='Stop'` 下被当终止错误，
     脚本在推完 frida-server 后中断（文件到位但没 chmod/启动）。**没改这个脚本**，手工补 `chmod 755` + 启动 + 装 APK，再复跑脚本全绿。
  2. `start-all.ps1:314` 用 `Start-Process -ArgumentList $svc.Args`，PowerShell 对数组只用空格拼接、不加引号，
     `--workdir D:\app project\...\output\vehicle-web` 被拆成两个参数 → `error: unrecognized arguments: project\...`。
     已修：先把含空格的参数补引号再拼成单行，再传给 `-ArgumentList`。
  3. 模拟器用 `Start-Process` 启动会被执行会话回收；本次改用 WMI `Win32_Process.Create` 启动的 `emulator-5554` 存活了下来，
     后续 `prepare-vehicle-device.ps1` 直接复用它（`[ok] 已在线，不再启动模拟器`）。
- 验证：
  - `emulator-5554`：API 35、当前用户 10、`adbd 已是 root`、AAOS 特征齐全
  - `pidof frida-server` = 8768；`pm path --user 10 com.vscanner.targetapp` 有值且应用已拉起
  - `http://127.0.0.1:8773/api/config` 200（`platform: vehicle`、`api: 35`）；`/` 200（16071 B）；`/v2/` 200（12822 B）；`/api/pipeline` 200
- 未提交的产物：`vehicle.ps1 prepare` 重建后 `core/frida_host/dist/*.sha256.json` 会变（`platform: vehicle→shared`，
  源哈希也变）。这两个 json **已还原**：本机 `core.autocrlf=true`，工作区是 CRLF 而 git 里是 LF，
  哈希绑定换行符、属环境相关抖动，入库只会让换机后不一致。`.bundle.js` 本身被 `.gitignore` 排除，不受影响。
- 收尾（同日补做，用户确认后执行）：
  - `AGENTS.md` 环境表按本机实况重写：Python 用项目 `.venv` 3.14.10、主 SDK 是 `D:\app project\AndroidSdk`
    （`%LOCALAPPDATA%` 那份注明是补装副本）、AVD 实体在 `AndroidSdk\avd` 而 `output/.../*.ini` 只是指针、
    本机 `dl.google.com` 可通、AGP 8.11.1 实际要 build-tools 35、Node 在 `D:\tools\node`、
    frida-server 版本须等于 `.venv`（17.18.0）。
  - `prepare-vehicle-device.ps1` 的 `Ensure-Frida`：`adb push` 改为临时放宽 `ErrorActionPreference` 并用 `2>&1`
    合并 stderr，最后按 `$LASTEXITCODE` 判成败。实测：`killall frida-server` + `rm` 清掉设备端文件后复跑，
    push 不再中断，一路走到 `[ok] frida-server 已启动（pid 10944）`，`/data/local/tmp/frida-server` 权限 `-rwxr-xr-x`，脚本退出码 0。
