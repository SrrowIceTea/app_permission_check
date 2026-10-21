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

---

## 1. 开工前：定义变量 + 五项检查

**每个新 shell 都要重跑这一段**（后文所有命令都依赖 `$PY` / `$ADB`）：

```bash
cd "$USERPROFILE/Desktop/vscanner-phase1-seeds(3)/vscanner-phase1-seeds(1)"

export PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"
export ADB="D:/Anroid/SDK/platform-tools/adb.exe"
export MSYS_NO_PATHCONV=1                 # 见 §2.3，不加会把 /sdcard 路径改坏
export VSCAN_SDK="D:/Anroid/SDK"
export VSCAN_JDK="D:/Anroid/JDK"
export VSCAN_JADX="D:/Anroid/Jadx/jadx-gui-1.5.3-with-jre-win"
export ANDROID_SDK_ROOT="D:/Anroid/SDK"
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
```

| 项 | 检查 | 不合格的后果 / 处理 |
|---|---|---|
| **Python 必须选对** | `"$PY" -c "import frida,mitmproxy,reportlab,pypdf;print('ok')"` | 裸 `python` 是 WorkBuddy 托管版，**没有 frida / mitmproxy**，动态阶段会在 `import frida` 处失败。只用 `$PY` |
| SDK / JDK | `ls "$VSCAN_SDK/platform-tools/adb.exe" "$VSCAN_JDK"` | 走 `core/sdk_paths.py` 的 `VSCAN_SDK`/`VSCAN_JDK` 覆盖位，别改 LEGACY 候选表 |
| jadx | `ls "$VSCAN_JADX"/lib/jadx-*-all.jar` | 指到含 `lib/jadx-*-all.jar` 的那层（**不是 `bin/`**），否则静态 `MissingTool` |
| frida-server | `ls output/_frida/frida-server` | 批次默认读这个路径。没有就从 `D:/Anroid/frida-server` 复制；**版本必须等于宿主 `frida.__version__`**（本次均 17.18.0） |
| 测试集 | `ls "D:/数据集/数据集/F-Droid-60"/*.apk \| wc -l` | 应为 60。**用户说的"D:/测试集"不存在**，真实位置是 `D:/数据集/数据集/F-Droid-60`。先 `ls` 再动手，别照抄用户给的路径 |

---

## 2. 起模拟器（两个必做动作，少一个必失败）

### 2.1 启动

```bash
"D:/Anroid/SDK/emulator/emulator.exe" -avd VScan_Phone \
  -no-window -no-audio -no-boot-anim -no-snapshot-load \
  -writable-system -gpu swiftshader_indirect
```

后台跑，轮询 `"$ADB" shell getprop sys.boot_completed` 直到返回 `1`（冷启动 2–3 分钟）。

**不要用 PowerShell 的 `Start-Process` 起**：本机环境变量同时存在 `HTTPS_PROXY` 和
`https_proxy`，PowerShell 转字典时直接抛
`字典中的关键字:“HTTPS_PROXY”所添加的关键字:“https_proxy”`。用 bash 后台启动。

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
别同时开 Android Studio 的模拟器（`Medium_Phone` 等），否则裸 adb 命令全部
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
| 自检 `frida_server` 项 `missing_local_binary` | `output/_frida/frida-server` 不存在 | 从 `D:/Anroid/frida-server` 复制，核对与宿主 `frida.__version__` 一致 |
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

## 10. 附：修复前基线（**只作历史对照，别当回归基准**）

> 下表是 **2026-10-19 19:17 之前**（系统 CA 修复前）的结果：三个样本 `flows.jsonl` 为空、
> `consent_observation` 字段还不存在。修复后同一份 openmensa 单样本重跑
> （`D:/vscanner-tp/ds3-ca-test`）得到：`system_ca=passed`、`flows.jsonl` 14 条
> （`/api/v2/canteens?page=1..N`，200，归因 `single_package_fallback`）、
> `consent_observation=not_observed`。回归基准请以修复后的批次为准。

> 修复后的端到端复核结论、证据链与仍开放项，见
> [文档归档前版本](archive/FIX_VERIFICATION_20261019.md)。
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
