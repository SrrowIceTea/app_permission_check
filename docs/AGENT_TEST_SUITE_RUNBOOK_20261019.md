# 移动端测试集跑批手册（给 agent 用）

> 仅用于授权测试（自有设备 + 已授权的公开第三方样本）。
> 本文是 2026-10-19 实跑 3 个 F-Droid 样本后整理的操作手册，命令都在本机验证过。
> 面向对象是**下一个接手跑批的 agent**，所以每一步都写可执行命令、明确判据，
> 以及"看到什么就必须停下来改口径"。

---

## 0. 一句话路径

```
定义 4 个变量 → 起模拟器(2 个必做口令) → 静态批 → 动态批(含夹具自检) → 按判据读结果
```

全程不碰 AI 阶段（`--skip-ai`）。需要 AI 研判请走 `mobile/pipeline/server.py` 的正控配置，
不属于本文范围。

> 在 **AAOS 车载模拟器**上跑单样本，或流水线走不通要改手动 attach 时，先读 §10
> （多显示器 / 驾驶限制 / GPU / 系统 CA / TLS 绕过反噬 / 报告口径 / 触发路径）。

---

## 1. 开工前：定义变量 + 五项检查

**每个新 shell 都要重跑这一段**（后文所有命令都依赖 `$PY` / `$ADB`）：

```bash
cd "$USERPROFILE/Desktop/vscanner-phase1-seeds(3)/vscanner-phase1-seeds(1)"   # 原开发机路径（本机实测不存在）；本机请 cd 到仓库根 D:/AAA/mobile-app-permission-check

export PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"
# 本机实测（2026-11-10）：下面三行按当前机器写；原开发机是 D:/Anroid/{SDK,JDK,Jadx}。
# 换机只改这三行，别去改 core/sdk_paths.py 的 LEGACY 兜底表。
export VSCAN_SDK="$(cygpath -m "$LOCALAPPDATA")/Android/Sdk"
export VSCAN_JDK="D:/Android/JDK"
export ADB="$VSCAN_SDK/platform-tools/adb.exe"
export MSYS_NO_PATHCONV=1                 # 见 §2.3，不加会把 /sdcard 路径改坏
# export VSCAN_JADX="..."                 # 未核实：本机 D:\ 下未找到 jadx；指到含 lib/jadx-*-all.jar 的那层
export ANDROID_SDK_ROOT="$VSCAN_SDK"
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

| 项 | 检查 | 不合格的后果 / 处理 |
|---|---|---|
| **Python 必须选对** | `"$PY" -c "import frida,mitmproxy,cryptography,jsonschema,reportlab,pypdf;print('ok')"` | 裸 `python` 是 WindowsApps 的 3.15，**没有 frida / mitmproxy / cryptography / jsonschema / pypdf**，动态阶段会在 `import frida` 处失败。只用 `$PY`（或 `tools/python313.ps1`） |
| SDK / JDK | `ls "$VSCAN_SDK/platform-tools/adb.exe" "$VSCAN_JDK"` | 走 `core/sdk_paths.py` 的 `VSCAN_SDK`/`VSCAN_JDK` 覆盖位，别改 LEGACY 候选表 |
| jadx | `ls "$VSCAN_JADX"/lib/jadx-*-all.jar` | 指到含 `lib/jadx-*-all.jar` 的那层（**不是 `bin/`**），否则静态 `MissingTool` |
| frida-server | `ls output/_frida/frida-server` | 批次默认读这个路径（`output/_frida/` 本机尚不存在，批次会建）。没有就从仓库 `output/vehicle-device-setup/frida-server` 复制（原开发机路径 `D:/Anroid/frida-server`）；**版本必须等于宿主 `frida.__version__`**（本次均 17.18.0） |
| 测试集 | `ls "D:/数据集/数据集/F-Droid-60"/*.apk \| wc -l` | 应为 60。**用户说的"D:/测试集"不存在**，真实位置是 `D:/数据集/数据集/F-Droid-60`。先 `ls` 再动手，别照抄用户给的路径。**2026-11-11 本机实测该目录不存在**：`batch_thirdparty.py` 现在用 `core/env_guard.diagnose_apk_dir()` 分开报「目录不存在 / 目录在但没 APK / `--only` 全过滤」，不会再把路径错显示成「没有 .apk」 |

---

## 2. 起模拟器（两个必做动作，少一个必失败）

### 2.1 启动

```bash
"$VSCAN_SDK/emulator/emulator.exe" -avd VScan_Phone \   # VScan_Phone 在 ANDROID_AVD_HOME=D:\AVD 下（本机实测）
  -no-window -no-audio -no-boot-anim -no-snapshot-load \
  -writable-system -gpu swiftshader_indirect
```

后台跑，轮询 `"$ADB" shell getprop sys.boot_completed` 直到返回 `1`（冷启动 2–3 分钟）。

**不要用 PowerShell 的 `Start-Process` 起**：本机环境变量同时存在 `HTTPS_PROXY` 和
`https_proxy`，PowerShell 转字典时直接抛
`字典中的关键字:“HTTPS_PROXY”所添加的关键字:“https_proxy”`。用 bash 后台启动。

> **`-gpu swiftshader_indirect` 只适用于手机 AVD `VScan_Phone`，不要照抄到 AAOS 车载模拟器。**
> 2026-11-10 在 `VScanner_AAOS_35_P1` 上实测：软件渲染下应用周期性
> `SIGABRT`（`Failed to create context, error = EGL_NOT_INITIALIZED`），
> 详见 §10.4。车载 AVD 的启动参数、AVD 位置与 user 10 的差异见 §10.1。

### 2.2 必做一：连 Wi-Fi

`VScan_Phone` 冷启动后 `wlan0` 是 **DOWN**，`ip route` 为空，`ping 10.0.2.2` 报
`Network is unreachable`。静态阶段不受影响，**动态阶段的前置检查会全线失败**。

```bash
"$ADB" shell "svc wifi enable"
"$ADB" shell "cmd wifi connect-network AndroidWifi open"
sleep 10
"$ADB" shell "ip -br addr show wlan0"      # 期望 UP + 10.0.2.x（本次 10.0.2.16）
"$ADB" shell "ping -c 1 -W 3 10.0.2.2"     # 期望 0% packet loss
```

只开 `svc wifi enable` 不够——`cmd wifi status` 会显示 enabled 但 `Wifi is not connected`，
必须显式 `connect-network`。

### 2.3 必做二：压制系统错误弹窗

冷启动 + swiftshader 软件渲染经常弹 **`System UI isn't responding`**。
弹窗会盖住应用界面，夹具自检直接报
`界面上找不到控件 btnDeviceId（应用在跑，pid=xxxx）`——**看着像夹具坏了，其实是弹窗挡的**。

```bash
"$ADB" shell "settings put global hide_error_dialogs 1"
"$ADB" shell "settings put global window_animation_scale 0"
"$ADB" shell "settings put global transition_animation_scale 0"
"$ADB" shell "settings put global animator_duration_scale 0"
```

已经弹出来的要手动点掉（`hide_error_dialogs` 只防后续）：

```bash
"$ADB" shell uiautomator dump /sdcard/ui.xml
"$ADB" shell cat /sdcard/ui.xml > D:/vscanner-tp/ui.xml
# 从 ui.xml 里取 text="Wait" 节点的 bounds 中心点，然后：
"$ADB" shell input tap <x> <y>
```

> **必须 `MSYS_NO_PATHCONV=1`**（§1 已导出）。否则 `/sdcard/ui.xml` 被 MSYS 改写成
> `D:/Workbuddy/resources/vendor/PortableGit/sdcard/ui.xml`：`uiautomator dump` 报成功，
> `cat` 报文件不存在——典型静默错位，会让人误判成"设备没 dump 出来"。

验收：`"$ADB" shell "dumpsys window | grep mCurrentFocus"` 应回到被测应用，
不再是 `Application Not Responding: com.android.systemui`。

### 2.4 root

动态脚本自己会 `adb root`，提前确认更省事：`"$ADB" root` 后 `"$ADB" shell id` 应为 `uid=0(root)`。
`-writable-system` 只是备用，本轮没有装系统 CA（第三方应用的 TLS 解密率因此有限，见 §5）。

### 2.5 单设备约束

`thirdparty_env.device_guard()` 检测到**多台设备且未设 `ANDROID_SERIAL`** 时直接退出。
别同时开 Android Studio 的模拟器（`Medium_Phone` 等），也别同时开手机 AVD `VScan_Phone`
与车载 AVD `VScanner_AAOS_35_P1`（两者都是 `emulator-5554` 起，冲突后裸 adb 命令全部
`more than one device/emulator`，失败形态是**静默空结果**（pidof 空 → 写成"原因未记录"）。
真要两台：`export ANDROID_SERIAL=emulator-5554`。

---

## 3. 阶段一：静态（不碰设备，可并行）

```bash
"$PY" -B mobile/tools/batch_thirdparty.py \
  --apk-dir "D:/数据集/数据集/F-Droid-60" \
  --only <pkg1> <pkg2> <pkg3> \
  --static-only --static-workers 2 \
  --out "D:/vscanner-tp/<批次名>-static"
```

要点：

- **`--out` 必须落在短路径**（`D:/vscanner-tp/...`）。工程根路径本身 67 字符且含非 ASCII，
  jadx 解出的 Kotlin 类名单个见过 105 字符，两者相加越过 Windows MAX_PATH 260 →
  `path.stat()` 抛 `FileNotFoundError`（jadx 写得进、Python 读不出）。
  不给 `--out` 时脚本自己落到 `D:/vscanner-tp/tp-<MMDDHHMM>` 并在 `output/` 下建 junction。
- `--static-workers 2`：3 个小包实测 4 分 21 秒。大包批次降到 1（每个 jadx 进程峰值内存不受控）。
- `--only` 收多个包名，空格分隔，**不带 `.apk`**。

通过判据：

```json
{"status": "ok", "samples": 3, "succeeded": 3, "failed": []}
```

产物在 `<静态批次目录>/_static/<NN-短名>/static-manifest.json`，关键字段：
`static.rules_evaluated`（应为 223）、`static.findings_by_rule_type`、
`static.facts_counts`、`decompile.status`。

`unhandled_rule_types` 里出现 `no_consent_read` / `over_collection` / `plaintext_transmission` /
`policy_mismatch` / `third_party_share` 是**正常的**——这些要运行时证据，静态判不了，不是规则坏了。

---

## 4. 阶段二：动态（单设备串行）

```bash
"$PY" -B mobile/tools/batch_thirdparty.py \
  --apk-dir "D:/数据集/数据集/F-Droid-60" \
  --only <pkg1> <pkg2> <pkg3> \
  --skip-ai --seconds 100 \
  --out "D:/vscanner-tp/<批次名>-dyn"
# 静态产物已按包名建好 junction 时，再追加一行：
#   --static-reuse "D:/vscanner-tp/_reuse"
```

要点：

- **`--static-reuse` 按完整包名寻址**（`<root>/<包名>/static-manifest.json`），
  而静态批次目录是 `NN-短名`。直接指 `_static` **不会命中，也不报错**——
  日志照样打印 `[static] 3 个样本`，等于白跑一遍 jadx（本次实测踩了，多花约 2.5 分钟）。
  两种正确做法：

  ```bash
  # A. 不传 --static-reuse：接受重跑静态，最省事、不会错
  # B. 建按包名寻址的目录联接，让复用真的命中（PowerShell）：
  #    New-Item -ItemType Junction -Path D:\vscanner-tp\_reuse\com.domivega.gps_car `
  #             -Target D:\vscanner-tp\<批次名>-static\_static\01-domivega-gps_car
  ```

  先验证再跑（返回路径=命中，返回 `None`=没命中）：

  ```bash
  "$PY" -c "import sys;sys.path.insert(0,'mobile/tools');import batch_static as bs,pathlib;\
  print(bs.reuse_hit(pathlib.Path('D:/vscanner-tp/_reuse'),'<包名>'))"
  ```

- **系统 CA 默认会装，别关**。`verification.system_ca` 失败时，HTTPS 全部在客户端
  证书校验处断开（mitmproxy 日志：`client does not trust the proxy's certificate`），
  addon 拿不到完整 flow → `flows.jsonl` 必空，pcap 里只剩未解密的 TLS 帧。
  这正是"流量只到 URL 层"的直接原因。实装修复后同一份 openmensa 从 **0 条 flow**
  变成 **14 条**（`/api/v2/canteens?page=1..N`，HTTP 200）。
  装的是 conscrypt APEX 那份（Android 14+），需要模拟器 `-writable-system`；
  对照实验可用 `--no-system-ca` 关掉，但那时所有"无外发"结论都不成立。
- **流量归因有两种，看 `attribution` 字段再下笔。** `app_process_hook` 才是时间归因；
  `single_package_fallback` 是"非系统探测的流量只能来自唯一被测包"的**排除法**，
  没有时间对齐，相关结论一律封顶 `candidate`。报告里不许把它写成"按时间归因"。
  另外：单包前提只在**测试机没有第二个真实应用**时成立，模拟器里预装的 Chrome 等不算
  被测包，但结论里要声明这个前提。
- **不要加 `--skip-fixture-selftest`**。批前夹具自检是唯一能区分"采不到"与"应用没收集"的机制；
  跳过会把采集链路故障写成"该应用清白"，而且事实会被记进 `batch-summary.json`。
  只有明确知道 A1 未修、要做对照实验时才跳，并在结论里声明。
- 动态**必须串行**：8888 单端口、全局 `http_proxy`、单前台应用、固定 pcap 路径，
  并发两个包归因必然 ambiguous。
- `--seconds 100` 是采集窗口（默认 150）。单包实际 4–5 分钟（安装 + 窗口 + 清理 + PDF）。
- `--spawn-hook` 让钩子在应用第一条指令前就位，减少启动期漏采，但已知更容易打死应用。
  **默认不开**；只在明确需要启动期流量且能接受崩溃率时用。
- 需要准确的"必要个人信息范围"就逐包传类目（见 §6 末尾）。

三层判据，缺一不可：

1. `batch-summary.json`：`status == "ok"` 且 `succeeded == samples`。
2. 每个样本 `verification.json`：`passed == true` 且 `failed` 为空（共 26 项检查）。
3. 每个样本 `out/summary.json` 存在、`findings_total > 0`，`out/mobile-report.pdf` 有页数。

**`passed == true` 不等于结论可信**——见下一节。

---

## 5. 判据第二层：什么时候必须降级表述

`verification.json` 只看"流程走完"，不看"观测是否完整"。以下四个信号任一为真，
**结论必须降级，不能吞**：

| 信号 | 位置 | 含义 | 结论里必须怎么写 |
|---|---|---|---|
| `.covered == false` | `session/conns.summary.json` | 目标进程在窗口内死过，pid 覆盖有缺口（`coverage_basis` 给原因） | "窗口内 N 轮无进程覆盖，读取数为**下界**，不是全量" |
| `fatal_lines` 非空 / `hooked_pid_alive == false` | `app-death.json` | 被挂钩进程崩溃（本轮 SIGSEGV / SIGABRT） | "采集窗口内崩溃，崩溃前证据有效，崩溃后为盲区" |
| `.policy.available == false` | `out/summary.json` | 没有匹配的应用政策 | 看 `.policy.status`：`store_missing` = 政策库目录没准备/被清理；`not_found` = 库在但没这个包。两种都写"政策一致性维度**不可判定**"，**不能写"合规"或"违规"** |
| `.policy_consent_state == "unknown"` | `out/summary.json` | 同意链里没有可用于判定的接受信号 | 看 `.consent_observation`：`observed` = 有 PERM_RESULT/POLICY_VIEW；`requested_only` = 只发起了权限请求、没看到结果（**用户是否选择不可判定**）；`not_observed` = 钩子装了但窗口内没有任何同意事件（**规则不适用 ≠ 通过**）；`no_consent_channel` = consent 文件缺失/为空（采集链路问题） |

两条最容易越界的边界：

- `flows.jsonl` 缺失或为空时，`gaps` 会写"无网络流证据（**不等于没有外发**）"。
  本轮三个样本 `session/flows.sqlite` 的 `events` 表 0 行，唯一抓到应用出站的是
  openmensa 的一条 `EGRESS_URL`（hook 层），**不是 pcap 归因**。不能据此说"没有外发"。
- `http_messages.jsonl` 里的 `www.googleapis.com` / `connectivitycheck.gstatic.com` /
  `android.clients.google.com` 是**模拟器系统连通性探测**，不是被测应用流量。
  把它们写进"应用外发域名"是硬错误。

---

## 6. 结果怎么读（文件 → 字段 → 能得出什么）

```
D:/vscanner-tp/<批次>/
├── batch-summary.json          # 批次判据；每样本一条 rec（含 static_reused_from）
├── fixture-selftest.log        # 夹具自检过程
├── _static/_logs/              # 静态日志
└── 01-<短名>/
    ├── verification.json       # 26 项流程检查（含 system_ca）
    ├── ca-install.json         # 系统 CA 安装明细（/system + APEX + zygote 命名空间）
    ├── policy-source.json      # 本轮用的是 APK 内政策 / 显式库 / 默认库
    ├── app-death.json          # 崩溃真身；hooked_pid_alive 才定义有效窗口
    ├── hook-all.log            # 钩子装载与事件计数
    ├── session/
    │   ├── reads.jsonl         # 只有 ev=PRIVACY_READ 才是读取
    │   ├── egress.jsonl        # 只有 ev=EGRESS_URL 才是应用自身 URL
    │   ├── tls.jsonl           # PINNING_ARMED / PINNING_BYPASS 等
    │   └── conns.summary.json  # covered / endpoints / 覆盖缺口
    └── out/
        ├── findings.jsonl      # 逐条结论（rule_type / title / severity / note）
        ├── summary.json        # findings_by_rule_type / coverage / gaps / caveat
        └── mobile-report.pdf   # 9–13 页
```

读 `reads.jsonl` 的两个坑：

1. 第一行是装载头 `{script, pkg, uid, watch_apis, apis:[...]}`，**`ev` 为空**。
   按 `ev == "PRIVACY_READ"` 过滤才是真实读取；不过滤会把"1 条读取"数成"8 条"。
   ```bash
   "$PY" -c "
   import json
   rows=[json.loads(l) for l in open(r'<样本>/session/reads.jsonl',encoding='utf-8') if l.strip()]
   print([r.get('api') for r in rows if r.get('ev')=='PRIVACY_READ'])"
   ```
2. `gaps` 出现「返回值证据为 call_only：仅记录调用，不能证明取得数据」时，该条只能算
   "调用了 API"，不能写"取到了数据"。

`findings_by_rule_type` 的语义：

| 类型 | 含义 | 边界 |
|---|---|---|
| `over_permission` | 清单声明了某权限，**需必要性复核** | 工具不判是否超范围 |
| `over_collection` | 实测数据类型不在该类目必要范围内 | 依赖 `--app-category`，类目错则结论错 |
| `sensitive_read` | 运行时实际调用了敏感 API | 最强的一条，仍受 `call_only` 限制 |

`summary.json` 的 `caveat` 写死了"本工具不产出 policy_violation"——报告里不许把 findings 说成"违规"。

### 类目（最容易把结论带偏的一项）

不给 `--category` 时全部按默认 `utility`。而 `utility`（实用工具类）在规则库里
`no_personal_info_required = 1`——必要个人信息范围是**空集**，于是任何一次敏感读取都会命中
`data_type_not_in_necessary_scope`。本轮 gps_car 那条"WiFi 标识超出必要范围"的
`over_collection` 就是这个前提下出的。

类目键**不是自由文本**，必须取自 `mobile/rules/rules_mobile.db` 的
`app_categories.category_key`（39 条，按《常见类型移动互联网应用程序必要个人信息范围规定》录入）：

```bash
"$PY" -c "import sqlite3;c=sqlite3.connect('mobile/rules/rules_mobile.db');\
print([r[0] for r in c.execute('select category_key from app_categories order by rowid')])"
```

常用键：`map_navigation`（地图导航）、`photo_beauty`（拍摄美化）、`fitness`、
`online_video`、`news`、`education`、`utility`。

```bash
--category com.domivega.gps_car=map_navigation \
--category com.lukeneedham.videodiary=photo_beauty
```

不确定就**留默认并在结论里声明"按实用工具类判定"**，别随便塞近义键——库里没有的键会让类目变成
`known: false`，`over_collection` 直接不出结论（比给错结论好，但也要写清楚）。

---

## 7. 故障处置表

| 症状 | 根因 | 动作 |
|---|---|---|
| 自检 `fixture_selftest_failed`：`按钮没点到（trigger 失败）`，`dialog.xml` 是 `System UI isn't responding` | 系统 ANR 弹窗盖屏 | §2.3：`hide_error_dialogs` + dump 找 `Wait` 点位点击，再重跑 |
| 自检 `frida_server` 项 `missing_local_binary` | `output/_frida/frida-server` 不存在 | 从仓库 `output/vehicle-device-setup/frida-server` 复制（原开发机是 `D:/Anroid/frida-server`），核对与宿主 `frida.__version__` 一致 |
| `network_up` 失败 / `ping 10.0.2.2` 不可达 | `wlan0` DOWN、未关联 SSID | §2.2 `cmd wifi connect-network AndroidWifi open` |
| 启动即 `[fatal] 检测到多台设备` | 多模拟器 + 无 `ANDROID_SERIAL` | 关掉多余模拟器，或显式 export |
| `MissingTool: 下没有 lib/jadx-*-all.jar` | `VSCAN_JADX` 指到了 `bin/` 或空目录 | 指到含 `lib/jadx-gui-1.5.3-all.jar` 的那层 |
| `UnicodeDecodeError` / `result.stderr is None` | 子进程 GBK 字节 + `PYTHONUTF8=1` | 保证 `PYTHONIOENCODING=utf-8`；脚本内已有 `errors="replace"`，别另写调用 |
| `path.stat() FileNotFoundError`（jadx 阶段） | MAX_PATH 260 越界 | 批次 `--out` 换到 `D:/vscanner-tp/<短名>` |
| 传了 `--static-reuse` 但日志仍打印 `[static] N 个样本` | 复用按包名寻址，`_static` 是 `NN-短名`，没命中 | §4：不传，或建包名 junction，用 `reuse_hit` 验 |
| 样本 `device_failed`、`run.log` 停在 `app_started` | 启动后被系统杀 / 无 launcher | 看 `main-activity.log`；`no_launcher_activity` 的插件包静态结论仍有效 |
| `covered: false` | 挂钩进程崩溃（A1） | **不是流程失败**，按 §5 降级表述，不要靠重试掩盖 |
| `flows.jsonl` 缺失，但 pcap 有几万字节 | CA 没装上 / 没生效（HTTPS 握手被客户端拒绝） | 看 `verification.system_ca`；确认模拟器 `-writable-system`，重跑会重装。只有 `--no-system-ca` 时才允许"flows 为空" |
| `policy.status = store_missing` | `output/local-policy-library-20261018` 被清理（10-19） | 用 `prepare_local_policies.py --manifest <APK清单> --store <目录>` 重建；**不要**因此写"该应用没有政策" |
| 应用每 18–26s 被 `SIGABRT`，`cause` 含 `EGL_NOT_INITIALIZED` | 车载 AVD 上软件渲染创建 EGL 上下文失败 | §10.4：先换 `-gpu host`；仍复现则手动启动稳定后再 attach，并按 §5 降级 |
| `input tap` 返回成功但界面不动 | 点到了 display 0（多显示器）或 UXR 驾驶限制吞触摸 | §10.2 先确认 display 并用 `--display`；§10.3 关 UXR + 车速归零 |
| `system_ca` 失败且 `adb remount` 被 verity 拒 | 系统分区只读，装不进系统 CA | §10.5：改用 Java/native 明文 hook，并在结论里声明跨进程/native 不覆盖 |
| 手动 attach 后零事件 | bundle 白名单仍是 `com.vscanner.privacydemo` | §10.7：先 `bundle_config.configure(body,[PKG])` 再 attach |
| 开启 TLS 绕过即崩溃（okhttp `CertificateChainCleaner` NPE） | 绕过返回空证书链 | §10.6：直连真实站点时改用 no-pinning bundle |

重跑原则：**换个新的 `--out` 批次目录**。同目录续跑用 `--resume`（只跳过
"verification passed + PDF 已生成"的样本），但目录里已有 `_static/` 也会被复用——
怀疑静态产物损坏或改过 `--static-workers` 时，直接开新目录。

---

## 8. 禁止事项（红线）

1. **不要用裸 `python`**——托管版没有 frida/mitmproxy。
2. **不要跳过夹具自检**，除非显式声明"本轮无法区分采不到与没收集"。
3. **不要把 `http_messages.jsonl` 里的 Google 域名算成应用外发。**
4. **不要在 `policy.available == false` 时给合规结论。**
5. **不要把 `passed: true` 当成"数据收集完整"**，必须同时看 `covered` 与 `app-death`。
6. **不要并发跑动态**，跑批时不要另起第二台模拟器。
7. **不要覆盖已有批次目录。**
8. **不要照抄用户给的路径**，先 `ls` 验证。
9. **不要把手动 attach 的结果写成流水线窗口结论**（§10.7），也不要把
   `dumpsys location` 的 `WorkSource` 当成 hook 级归因（§10.8）。

---

## 9. 预算（3 个 3–4 MB 样本实测）

| 阶段 | 耗时 | 备注 |
|---|---|---|
| 模拟器冷启动到 boot_completed | 2–3 分钟 | swiftshader 更慢，首次可能 4 分钟 |
| 静态（2 路并行） | 4 分 21 秒 | jadx 是主要开销 |
| 夹具自检 | 35 秒 | 失败重试另算 |
| 动态（串行） | 14 分 16 秒 | 单包 4–5 分钟。**含一次没命中的静态重跑**（约 2.5 分钟）；复用真命中后约 11–12 分钟 |
| **合计** | **约 20 分钟** | 不含排障 |

60 包估算：静态 1–2 小时（2–3 路），动态 4–5 小时（串行、`--seconds 100`）。

---

## 10. AAOS 车载模拟器：单样本动态采集（2026-11-10 实测补充）

### 10.0 先重建钩子产物，再做任何设备动作（硬闸）

`vehicle/hooks/dist/` 被 gitignore，设备执行的代码与工作区源码之间**不能靠人记着同步**。
2026-11-10 实测过反面案例：设备跑 11-06 的 bundle、源码已是 11-10，当时没有任何检查会发现。
现在任何走设备采集的车载入口都会在起设备前比对产物清单，落后即拒绝开跑。

```powershell
# 唯一支持的重建命令（写 dist/*.bundle.js + 同名 .sha256.json 清单）
.\tools\python313.ps1 core\frida_host\build.py --platform vehicle
```

- 只改了一两个钩子也要跑**整条命令**（`--only` 只用于排查，不是发布口径）。
- 清单记录：bundle sha256、构建时间、参与源码的逐文件 sha256 + 组合指纹、构建时 dirty 标记。
- 三档：一致且源码干净 → 放行；一致但 dirty → 告警放行并写 dirty 标记；**产物落后 → 拒绝**。
- 证据里能查到本轮的 bundle sha256：`verification.json` / `session-manifest.json` /
  `summary.json` 的 `hook_bundle`，PDF 报告头部「钩子产物」行。
- 已知缺口：`mobile/hooks/dist`（`build.mjs` 构建）不产清单，不在本闸范围。

> 场景：在 AAOS（`VScanner_AAOS_35_P1`，API 35，user 10）上对单个第三方 APK 做动态采集，
> 尤其是**流水线走不通、需要手动 attach** 的情况。本轮样本 Breezy Weather 6.2.2
> （`org.breezyweather`）与 Organic Maps web（`app.organicmaps.web`），产物与两份
> `REPORT.md` 在 `output/thirdparty-dynamic-20261110/`。命令沿用 §1 的 `$ADB`。

### 10.1 与手机 AVD 的差异

| 项 | 手机 `VScan_Phone`（§2.1） | 车载 `VScanner_AAOS_35_P1` |
| --- | --- | --- |
| AVD 位置 | `ANDROID_AVD_HOME=D:\AVD` | `output/vehicle-device-setup/avd`（必须显式设 `ANDROID_AVD_HOME`） |
| 启动参数 | `-no-snapshot-load` | `-no-snapshot -no-boot-anim`，端口 5554 |
| GPU | `-gpu swiftshader_indirect` | **不要用**，见 10.4 |
| 用户 | 主用户 | 应用跑在 **user 10** |

`adb shell cmd package list packages -U` 会给出两个 uid
（本轮 `package:org.breezyweather uid:10260,1010260`），**业务 uid 取后一个**；
数据目录 `u10_a260` / `u10_a261` 与之一一对应。

### 10.2 多显示器：`input tap` 默认打 display 0

现象：`adb shell input tap x y` 返回成功、界面完全不动——**不是点击没生效，是打到了另一块屏**。
AAOS 默认有中控（display 0）、仪表、副驾等多块屏；`input` 不指定时只投 display 0。

确认应用在哪块屏：
```bash
"$ADB" shell dumpsys display | grep -E "DisplayDeviceInfo|mDisplayId"
"$ADB" shell dumpsys window displays | grep -E "mCurrentFocus|mDisplayId"
"$ADB" shell dumpsys activity activities | grep -E "mResumedActivity"
```
指定屏点击 / 截图（API 30+，语法先用 `"$ADB" shell input --help` 核对）：
```bash
"$ADB" shell input --display <id> tap <x> <y>
"$ADB" shell screencap -p -d <id> /sdcard/d<id>.png
```
坐标取 `uiautomator dump` 的 `bounds` 中心点；`uiautomator dump` 只覆盖当前活动屏。

> 坦白说明：本轮**没有触发**这个故障（应用与点击目标都在 display 0），所以这里没有
> 失败原文。可复现的相关现象是：同一次 `screencap` 在多显示器下会给出警告，
> 且 `exec-out>` 重定向会把 PNG 写坏（见 §10.9 的替代写法）。
> 下轮一旦"tap 成功但界面不动"，先按上面三条命令确认 display，再怀疑 10.3。

### 10.3 驾驶限制（UXR）吞触摸

现象：界面能看到车速（本轮显示 63 km/h）时，tap / swipe 全部无效果，`input` 不报错。
根因：CarUxRestrictions 在车速非零时限制触摸交互。

采集前（本轮实测命令）：
```bash
"$ADB" shell cmd car_service enable-uxr false
"$ADB" shell cmd car_service inject-vhal-event PERF_VEHICLE_SPEED 0
"$ADB" shell dumpsys car_service | grep -i -E "uxr|restriction"   # 复核已关闭
```
采集结束**必须还原**（本轮收尾已执行）：
```bash
"$ADB" shell cmd car_service enable-uxr true
```
证据：`breezy/manual-session/trigger-actions.log` 的 7 次动作（Add current location /
Save / 下拉刷新）都在解除限制后完成，随后 hook 采到 2 条 `requestLocationUpdates`。

### 10.4 GPU 与周期性 `EGL_NOT_INITIALIZED`

现象：应用每约 18–26 秒被 `SIGABRT` 打死，`verification.json` 的
`coverage.detail[*].death.cause` 为
```
Failed to create context, error = EGL_NOT_INITIALIZED
```
`fatal_lines` 里是 `Fatal signal 6 (SIGABRT)`。原样见
`output/thirdparty-dynamic-20261110/breezy/verification.json` 与
`_attempt1-breezy-egl-crash/`（`-gpu swiftshader_indirect` 那次）。

辨识特征 = **周期性崩溃 + RenderThread/EGL 报错**；偶发一次按 §5 的崩溃口径处理即可。

处理顺序：
1. `-gpu swiftshader_indirect` → `-gpu host` 重试；
2. 仍复现时判定为镜像/应用渲染路径问题，**不要继续怀疑 hook**：本轮改为"先手动启动应用，
   确认稳定 >10 分钟后再 attach"，应用不再崩；
3. 崩溃段不计入有效窗口（本轮 `coverage.truncated=true`、`observed_s=59.4/180`），
   结论按 §5 写"崩溃前有效、崩溃后盲区"。

### 10.5 系统 CA 装不进：verity / 只读 `/system`

`verification.json` 里 `system_ca` 的失败原文：
```
ModuleNotFoundError: No module named 'transparent'
```
（本轮是调用路径的 `sys.path` 指错；绕过它直接调
`mobile/traffic/transparent.install_system_ca()` 后，`adb remount` 仍因 dm-verity /
只读系统分区被拒。**该步原始输出本轮没落盘**——下轮请重定向进样本目录再判定，
不要凭"装过了"下结论。）

替代与局限（`-writable-system` 见 §2.4，第三方 TLS 解密边界见 §5；这里只补车载侧）：
- 可用：Java 层绕过（`ssl_pinning_tp.js`）或 native 明文 hook
  （`hook_native_ssl.js` / `hook_native_crypto.js`）。本轮 Organic Maps 靠后者拿到
  272 条 `SSL_WRITE_PLAINTEXT` + 15633 条 `SSL_READ_PLAINTEXT`。
- 不覆盖：**跨进程**（GMS / 系统服务）和 native 自有 TLS 栈。
  所以"没有 flows"不能写成"没有外发"。
- 不要为了装 CA 去关 verity 或改系统镜像。

### 10.6 TLS 绕过的反噬：空链 → OkHttp NPE

现象：开启绕过后再下载，Organic Maps 立即崩溃，logcat 指向
`AndroidCertificateChainCleaner.clean()` 的 `NullPointerException`。
（本轮终端观察；成文记录见 `output/thirdparty-dynamic-20261110/organicmaps/REPORT.md` §1。）
根因：`ssl_pinning_tp.js` 放宽校验后返回**空证书链**，okhttp 不接受。

正确做法：
- 目标直连真实站点、不需要抓明文时，**不要开绕过**。本轮改用
  `hook_all_nopinning.bundle.js`（920336 B，SHA256
  `B9AE02F8E28CD6B4B3C52D3DEE525C609E1CE2EBCD90F8940E20E18BC52A5479`，
  去掉 `ssl_pinning_tp.js` 的 import 与 `tlsMain()` 调用）后应用稳定、下载完成。
- 必须抓包时，先确认目标 okhttp 版本能处理空链；否则优先系统 CA 或 native 明文 hook。
- **该缺陷已在修**；修好前按上面两条执行，别把"开绕过就崩"当成样本行为。

### 10.7 流水线窗口 vs 手动 attach（报告口径）

| 项 | 流水线窗口 | 手动 attach |
| --- | --- | --- |
| 谁启动应用 | 流水线 `am start` | 人工/脚本先启动，`dev.attach(pkg)` |
| 窗口边界 | `app_started` → `--seconds` | attach → 人工停止 |
| 能否声明"窗口内全量" | 可以（受 §5 降级约束） | **不可以** |
| 报告必须写 | 覆盖率、`truncated`、`app-death` | "手动受控会话，非流水线窗口；不做窗口覆盖率声明" |

本轮两条流水线都没走通（Breezy `ui_taps_made=完成 0 次点击` 且 `coverage.truncated=true`；
Organic Maps 被 TLS 绕过 NPE 打断），因此两份报告都标明手动会话，
**没有把手动结果冒充流水线窗口**。

手动 attach 的前置校验（缺一项就不许写 observed）：
1. **bundle 新鲜**：`Get-FileHash mobile/hooks/dist/hook_all.bundle.js`，
   mtime 晚于所有参与打包的源码。本轮 `SHA256 85CD809A...D95BBA8`，938229 B，
   2026-11-09 23:54:12 > 最新源码 11-02。
2. **白名单**：`core.frida_host.bundle_config.configure(body, [PKG], watch_limit=58)`。
   不配置时 bundle 内白名单是 `com.vscanner.privacydemo`，所有 hook 报 `not in whitelist`，
   表现为**零事件**（本轮踩过）。
3. **`hook_armed`**：`summary.json` 的 `hook_armed_count > 0` 且事件数 > 0；本轮 14 条。
4. **附加探针不要裸 `create_script`**：Frida 17 已移除全局 `Java`，
   本轮报 `ReferenceError: 'Java' is not defined`（见
   `organicmaps/manual-session/supp-events.jsonl`），必须经 bundle 编译注入。

### 10.8 怎么让样本真的读定位（触发路径）

| 样本 | 触发步骤 | 实测证据 |
| --- | --- | --- |
| Breezy 6.2.2 | 走完引导 → Add current location → 在 Weather sources 对话框**选源并 Save** → 下拉刷新 | `trigger-actions.log` 7 次动作；随后 2 条 `requestLocationUpdates`（fused，`coarse_location`）+ 6 条传感器 |
| Organic Maps web | 进地图 → 点 **MyPosition**；只下载离线地图不会触发定位 | `trigger-actions.log` 两次 MyPosition；同秒 `dumpsys location` 出现 `WorkSource{1010261 app.organicmaps.web}` 的 `HIGH_ACCURACY` 注册 |

**Organic Maps 的覆盖缺口必须写进结论**：应用经 GMS fused provider 跨进程取位置，
且 `LocationManager.getCurrentLocation`（API 30+）**不在 watch 集**，所以 hook 层只采到
1 条传感器读取、`LocationManager` 读取为 0。系统层能证明它发起了高精度请求，
但**归不到某条 `MOB-*` 运行时 API**，只能写"系统层 observed + hook 未覆盖"，
既不能写"未读取"，也不能把 `WorkSource` 当 hook 归因。随手留证：
```bash
"$ADB" shell dumpsys location | grep -E "WorkSource|last location|registration" \
  > "$OUT/<样本>/manual-session/location-system-trace.txt"
```

### 10.9 车载截图与进程收尾（本轮踩到的小坑）

- `adb exec-out screencap -p > x.png` 在 PowerShell 下会把二进制写坏
  （重定向按文本处理）。改用：
  ```bash
  "$ADB" shell screencap -p /sdcard/x.png && "$ADB" pull /sdcard/x.png .
  ```
- 收尾顺序（本轮已验证）：`am force-stop` 两个包 → `pm revoke` 定位权限 →
  `pm uninstall` → `cmd car_service enable-uxr true` → 停 frida-server →
  `adb forward --remove-all` → `adb emu kill` → `adb devices` 应为空；
  再确认无残留 `qemu-system-x86_64` / `emulator` 进程。

### 10.10 证书固定（pinning）判据：2026-11-10 修订

> 适用：带证书固定的样本（NSC `<pin-set>` 或应用自绘 TrustManager）。
> 本轮样本 Proton Mail 3.0.17（`ch.protonmail.android`）。
> **依据文档**（都可回溯）：
> `output/memhook-evidence-20261110/POS-CONTROL-SYSTEM-CA.md`（正控）、
> `output/memhook-evidence-20261110/NEG-C-SYSTEM-CA.md`（负控-c，系统 CA 二分）、
> `output/memhook-evidence-20261110/NEG-B-READONLY.md` 与 `NEG-RESULT.md`（负控 b/a）；
> 原判据出处 `output/memhook-pinning-samples-20261110/DEVICE-VALIDATION-PLAN.md` §6.2 / §7.3 / §8。

#### 10.10.1 旧判据（保留原文，不要删）

`DEVICE-VALIDATION-PLAN.md` §6.2 原文——「必须看到的证据（三条同时成立才算负控通过）」：

| # | 证据 | 采集位置 | 通过示例 |
| --- | --- | --- | --- |
| N1 | TLS 已到达拦截端点（收到 ClientHello / 证书已发出） | mitmproxy 事件日志 | `client connect` + `TLS handshake failed` / `server TLS handshake failed` |
| N2 | 应用侧明确 pin 失败 | logcat | `SSLHandshakeException`，`Caused by: java.security.cert.CertificateException: Pin verification failed` |
| N3 | 未产生任何 HTTP 请求 | mitmproxy flow 列表 | `mail-api.proton.me` 只有 TLS 事件，**0 条 flow** |

正控侧 §7.3 里被修订的那一条原文（P1，其余三条本轮未改）：

| # | 证据 | 采集位置 | 通过示例 |
| --- | --- | --- | --- |
| P1 | bypass 已挂载 | JSONL | `PINNING_ARMED` 事件，且含 `SSLContext.init` 类手法 |

#### 10.10.2 2026-11-10 修订（为什么改）

上面这套判据是围着**可调试夹具**设计的：N2 直接要求应用侧 `Pin verification failed` 原文，
P1 直接要求出现 `SSLContext.init` 类手法。2026-11-10 在真实第三方样本上实测，两条都落空：

- **N2 对 release 构建结构性不可满足**：本轮 logcat 6,084 行 / 752,924 B，
  `grep -c 'Pin verification failed'` = **0**。release 包不输出应用侧网络异常，
  加长窗口也拿不到；负控-c 与正控两轮都卡在同一点，第三层因此在真实样本上**永远无法判定**。
- **P1 绑定手法会把已成立的绕过判成失败**：该域名的握手闸根本不在 `SSLContext.init`
  注入的 `TrustManagerImpl` 上（本轮 `hookTrustManagerImpl` / `hookSslContextInit`
  均 **0 命中**），而在 `android.security.net.config.NetworkSecurityTrustManager.checkPins`。
  按 P1 原文，一次**已经绕过成功**的正控会被判成 `POS_HOOK_MISS`。

以下六条自 2026-11-10 起执行；旧判据原文保留在此供回溯，不作废历史结论。

#### 10.10.3 修订一：N2 等价物（三件证据必须同时具备）

`Pin verification failed` 原文不可得时，用下面**三项合取**替代 N2，缺一项不能结案：

1. **CA 可信基线**：把 mitmproxy CA 装成系统 CA 后，用**不 pin 的旁路**证明设备侧 TLS 栈
   真的认了这张 CA——默认信任库与 **APEX 信任库**（`--capath /apex/com.android.conscrypt/cacerts`）
   两条路径都必须通过（负控-c §3：两条路径均 `HTTP 200`、正文 `vscan-baseline-ok`）。
   只验一条不够，应用真正读的是 APEX 那份。
2. **同进程同秒差分**：**同一信任库**下，同一秒内他域握手成功、目标域失败。
   本轮 11:23:39：同进程 `api.protonmail.ch` 成功并发出
   `POST /core/v4/reports/sentry/api/41/envelope/`，同一秒 `mail-api.proton.me` 失败。
   这一条把信任锚从嫌疑里摘出去，比 alert 类型可靠得多。
3. **失败形态记录**：TLS alert 具体码（本轮 `certificate_unknown(46)`）原样落盘，
   并记录**是否出现新的失败形态**（形态变了，说明钩子生效但方向不对）。
   `certificate_unknown(46)` 在"pin 失败"与"信任锚失败"下**同形**，只能用于排除/发现新形态，
   **不能单独用作归因**。

**原文可得时仍以原文为准**：可调试构建、有自有源码、或能开应用侧日志时，优先补 N2 原文，
等价物只作退路。等价物最多支撑到"失败在信任锚之外"，**不能**写成
"已证明是 pin，而不是别的自定义校验"。

#### 10.10.4 修订二：P1 不绑定手法

P1 改为：**`PINNING_ARMED` 事件 + 命中记录（哪条接缝、哪个 host）**，不要求出现
`SSLContext.init` 类手法。命中记录要能指到日志里的具体行，例如本轮 `SEAM_SKIP` 中
`okhttp.CertificatePinner` 那条带 `"host":"mail-api.proton.me"`。

#### 10.10.5 修订三：新增必填字段「接缝归属」

判据新增一个必填字段：**实际生效的接缝**。可选值至少包含：

- `android.security.net.config.NetworkSecurityTrustManager.checkPins`（NSC 声明式 pin）
- `okhttp3.CertificatePinner.check$okhttp`（握手之后的请求闸）
- `com.android.org.conscrypt.TrustManagerImpl`（`hookTrustManagerImpl`）
- `SSLContext.init` 注入 TrustManager（`hookSslContextInit`）
- 其它：写类名 + 方法名，并说明怎么确认的

**接缝不是单选。** 本轮 Proton 是**两道分立的闸**：握手闸 `checkPins`（不绕 → 客户端
alert 46，握手失败）+ 请求闸 `CertificatePinner.check$okhttp`（握手通了但 pin 不符 →
OkHttp 直接关连接、不发请求）。只写"绕过了"而不写走哪条接缝，**不算结案**；
握手通了却判不出为什么通，同样只能写"不能结案"。

#### 10.10.6 修订四：`server_connect = 0` 仍是硬指标

抓解密流量时上游连接数必须为 **0**（`--set connection_strategy=lazy`，请求由本地 addon
就地应答），并且**原样贴出计数与地址列表**：

```text
ON7 fail_total=26 est_total=9  mailapi_fail=0 mailapi_est=1 mailapi_req=1 server_connect=0 []
```

`[]` 是地址列表原文，空即没有建任何上游连接。不贴计数就无法区分"解密成功"和
"其实放行了真实上游"，也无法证明 lazy 生效。

#### 10.10.7 修订五：关钩子对照必须紧邻正控前后各一次

正控最容易出的假阳是"其实本来就能通"。**同一设备、同一会话配置**下，正控前与正控后
各跑一次**关钩子**对照，两次都必须失败（本轮 C1′ / C2′ 各 6 次失败、0 次成功、0 条请求）。
两次都失败而正控成功，才排得掉"本来就能通"。

#### 10.10.8 修订六（新增）：禁止"只挂一条接缝就判成功"

**明确禁止**：只要握手成功就判 `POS_BYPASS_OK`。本轮两条实测教训：

| 轮次 | 挂载范围 | `mail-api` 握手 | HTTP 请求 |
| --- | --- | --- | --- |
| ON3 | 只挂 `checkPins` | 成功 6 次 | **0 条** |
| ON5 | 多接缝 | 成功 1 次（另 1 次在途失败） | 2 条 |

ON3 说明**握手通 ≠ 采到流量**（请求被第二道闸掐掉）；ON5 说明武装时刻之前已在途的握手
仍会失败，不能把窗口内第一次失败当成"钩子无效"。判据必须同时满足"握手成功 **且** 有解密后
请求"，并写清两道闸各由哪条接缝放行。

#### 10.10.9 结论码口径（沿用 §8，不新增码）

本轮正控结论码 `POS_BYPASS_OK`（按本节修订后的判据）。同时必须写明：按
`DEVICE-VALIDATION-PLAN.md` §7.3 **P1 原文**（要求 `SSLContext.init` 类手法）**不满足**，
如实标注"不宣称满足原文 P1"。不得为凑码表新增结论码。

---

## 11. 附：修复前基线（**只作历史对照，别当回归基准**）

> 下表是 **2026-10-19 19:17 之前**（系统 CA 修复前）的结果：三个样本 `flows.jsonl` 为空、
> `consent_observation` 字段还不存在。修复后同一份 openmensa 单样本重跑
> （`D:/vscanner-tp/ds3-ca-test`）得到：`system_ca=passed`、`flows.jsonl` 14 条
> （`/api/v2/canteens?page=1..N`，200，归因 `single_package_fallback`）、
> `consent_observation=not_observed`。回归基准请以修复后的批次为准。

> 修复后的端到端复核结论、证据链与仍开放项，原文见归档说明
> [archive/MANIFEST.md](../archive/MANIFEST.md)（`FIX_VERIFICATION_20261019.md` 已不随工作区分发）。
> 其中修复后重新生成的报告是 `D:/vscanner-tp/regen-openmensa-1019/out/mobile-report-v2.pdf`
> （14 页，含"单包排除法/封顶 candidate"披露）；19:40 与 19:54 那两份 PDF 是修复前产物，
> 不能当证据引用。

批次：`D:/vscanner-tp/ds3-static-1019`（静态）、`D:/vscanner-tp/ds3-dyn-1019`（动态）

| 包 | targetSdk | 静态 findings | 运行时读取 | 应用出站 | 总 findings | PDF |
|---|---|---:|---:|---|---:|---:|
| com.domivega.gps_car 2.1 | 36 | 13 | 1（`WifiInfo.getSSID`） | 无 | 15 | 13 页 |
| com.lukeneedham.videodiary 1.0.8 | 35 | 3 | 1（`openCamera`，call_only） | 无 | 3 | 9 页 |
| de.uni_potsdam.hpi.openmensa 2.2.0 | 36 | 8 | 0 | `https://openmensa.org/`（HTTP 200 ×2） | 8 | 12 页 |

三个样本 `verification.passed` 全为 `true`，但 `conns.covered` **全为 `false`**
（`pid_lost_rounds_est` 100–200），`policy.available` 全为 `false`。
下一轮这些数字变了，先怀疑环境或钩子版本，别直接当成样本行为变化。

### 10.11 回环目标（`127.0.0.1` / `adb reverse`）是双盲区（2026-11-15 实测）

给第三方样本搭"自有服务端 + 回执"时，**不要让被测应用访问回环地址**：

- WebView 对 `127.0.0.1` 直连会绕过系统代理（mitmproxy 一条 flow 都拿不到）；
- Chromium 网络栈不走 `libcore.io.Linux.connect`，钩子也看不到；
- 结果：回执端有 2 条 GET、工具侧 flows=0 / 外发=0，只看 flows 会写成"没有外发"。

**但 pcap 抓得到**（`tcpdump -i any` 含 lo）：装上 tshark 后，`127.0.0.1:18899` 的
4 条请求行与页面正文都能还原。所以回环不是"全盲"，是"代理+钩子盲、pcap 可解"——
判阴性之前必须先看 `pcap_http.py` 的解码结果。

改用宿主局域网 IP（如 `http://10.18.80.25:18900/...`）后，同一动作立刻产生 4 条 flow。
但注意：单包窗口下这些 flow 的归因是 `single_package_fallback`（排除法，无 uid/时间差），
summary 会多出 `flows_by_attribution` / `flows_identity_verified` 两个字段，
引用时按 candidate 处理，别写成"按时间归因"。

另：受控窗口（`--max-rounds 0`）用 `--action-log` 登记外部动作，见 `mobile/tools/log_action.py`；
不登记的话 `business_action_made` 会判红——这是**有意**的，别为了变绿去补假动作。

tshark 不用装系统版：把 Wireshark MSI 用 `msiexec /a <msi> /qn TARGETDIR=<dir>` 解到
`output/_tools/wireshark`（不注册、不装 Npcap），`find_tshark()` 会优先命中这个项目路径。
本机实测 4.6.9 可直接跑 `tshark -r x.pcap`。

换机时把已安装的 `tshark.exe` 或组织提供的便携版本配置成 `VSCAN_TSHARK`，开始前运行
`& $env:VSCAN_TSHARK --version` 核对。设备验收开头记录 `tshark_available`；缺少解码器时
仍保存 pcap 供复解。部分 TLS 无法解密时，`http_messages_extracted` 记录是否解出 HTTP，
具体 TLS 缺口看 `http-stats.json`。CI 的离线回归不覆盖新设备 pcap。

单次运行使用新 `--out`，失败目录原样保留。跑批重试在样本目录下创建 `try-*`。
零观测需要人工复核时，可提供 `--confirm-no-activity <JSON>`，包含 `package`、`reviewer`、
`basis`。两类钩子就绪、目标进程存活且窗口未截断时，复核后的零观测为降级结果，
仍保留失败判据与复核摘要。第三方采集保持设备的 QUIC 行为，代理中未确认归属的流只留计数。

自有回环明文 HTTP 复验传 `--fixture-http-port <设备端口>`。该模式仅抓回环接口上的指定
TCP 端口，并用 tshark 按 HTTP 解码。用请求路径与独立服务端回执交叉核对。
设备端 pcap 每轮拥有独立文件名。常规第三方抓包排除 Frida 控制端口。
