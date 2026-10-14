# 五个移动端样本的实机实测报告

日期：2026-10-13 · 设备：`VScan_Phone`（Android 16 / API 37 / x86_64 / **16 KB 页**）· 模拟器 `emulator-5554`

> **授权与范围声明**：本轮样本全部为**公开发布的开源应用**（F-Droid 生态），从各自
> GitHub Releases 官方直链下载，仅在本机自有模拟器上做**合规自查性质的**隐私行为观测。
> 不含任何针对第三方的攻击、绕过或数据窃取；不记录任何用户数据原文（钩子只存值哈希
> 与 6 字符预览，见 DECISIONS M005）。

---

## 1 选样标准（自定，记录在此以便复现）

四条同时满足：

1. **开源 + 可核验来源**：能拿到 GitHub Releases 直链与 SHA-256，便于日后复跑同一二进制。
2. **targetSdk ≥ 35**：低于这个值会因平台兼容性豁免干扰隐私行为判定（Android 16 上的
   低 targetSdk 应用很多行为走兼容路径）。
3. **声明了敏感权限**：否则静态维度没有 `over_permission` 可判，"跑通"会退化成"跑空"。
4. **强制 16 KB 页对齐**：本模拟器是 16 KB 页镜像，未对齐的 APK 会因加载失败而表现为
   "应用起不来"，与真实缺陷混淆。

## 2 样本

| # | 应用 | 包名 | 版本 | targetSdk | 大小 | 来源 |
|---|---|---|---|---|---|---|
| 1 | Fossify Camera | `org.fossify.camera` | 1.5.0 (11) | 36 | 9.8 MB | GitHub Releases |
| 2 | Fossify Voice Recorder | `org.fossify.voicerecorder` | 1.7.3 (20) | 36 | 7.0 MB | GitHub Releases |
| 3 | KeePassDX | `com.kunzisoft.keepass.libre` | 4.5.5 (45500) | 36 | 16.0 MB | GitHub Releases |
| 4 | Breezy Weather | `org.breezyweather` | 6.2.2 (60202) | 36 | 15.0 MB | GitHub Releases |
| 5 | F-Droid | `org.fdroid.fdroid` | 1.18.0 (1018050) | **28** | 12.1 MB | GitHub Releases |

每个 APK 旁有 `<包名>.provenance.json`（下载 URL、SHA-256/MD5、字节数、identity）
与 `<包名>.download.log`，可直接复跑。注意 F-Droid 的 targetSdk 是 28，
**不满足选样标准 2**——它是被有意留下的：作为"低 targetSdk 对照组"，用来观察
兼容路径是否影响判定（结论见 §5）。

## 3 跑通情况

判据定义在每轮的 `verification.json`，**本报告只是汇总，不替代逐样本判据**。

| 判据 | Camera | VoiceRec | KeePassDX | Breezy | F-Droid |
|---|---|---|---|---|---|
| provenance / static 拷贝 | ✓ | ✓ | ✓ | ✓ | ✓ |
| frida-server | ✓ | ✓ | ✓ | ✓ | ✓ |
| network_up（设备侧实测 TCP） | ✓ | ✓ | ✓ | ✓ | ✓ |
| install | ✓ | ✓ | ✓ | ✓ | ✓ |
| geo_injected | ✓ | ✓ | ✓ | ✓ | ✓ |
| conn_probe_started | ✓ | ✓ | ✓ | ✓ | ✓ |
| **app_started** | ✓ | ✓ | ✓ | ✓ | ✓（见 §6.1） |
| ui_taps_made | ✓ | ✓ | ✓ | **✗** | ✓ |
| **app_alive_at_window_end** | **✗** | ✓ | **✗** | **✗** | ✓ |
| hook_privacy_armed (58/58) | ✓ | ✓ | ✓ | ✓ | ✓ |
| hook_consent_armed | ✓ | ✓ | ✓ | ✓ | ✓ |
| requested_permissions_nonempty | ✓ | ✓ | ✓ | ✓ | ✓ |
| policy_from_apk（optional） | ✗ | ✗ | ✗ | ✗ | ✗ |
| correlate / bundle / report | ✓ | ✓ | ✓ | ✓ | ✓ |
| **综合** | **通过** | **通过** | 失败(`ai_review`) | 失败(`ui_taps_made`) | **通过** |

结论产出与报告：

| 应用 | 结论条数 | 类型分布 | PDF 报告 |
|---|---|---|---|
| Fossify Camera | 7 | 全部 `over_permission` | 103 KB |
| Fossify Voice Recorder | 5 | 全部 `over_permission` | 98 KB |
| KeePassDX | 6 | 全部 `over_permission` | 101 KB |
| Breezy Weather | 12 | 全部 `over_permission` | 102 KB |
| F-Droid | 14 | 全部 `over_permission` | 93 KB |

**五个样本、44 条结论，100% 来自静态维度；运行时维度产出为零。** 这是本报告的核心发现，
根因见 §5。

## 4 功能实现度核对（逐环节）

| 环节 | 状态 | 说明 |
|---|---|---|
| 样本获取 + SHA-256 + provenance | ✅ 完整 | 代理环境下多轮重试成功；`urllib` 失败时自动降级 `curl` |
| 16 KB 页对齐预检 | ✅ | 5/5 通过 |
| aapt2 静态身份提取 | ✅ | 但 launchable-activity 不可信，见 §6.1 |
| jadx 反编译 | ⚠️ 有损 | F-Droid 有 **31 个类反编译失败**（写入 `code_loc_note`，不静默） |
| 权限申请清单 | ✅ | 25 条（F-Droid）/ 各样本非空 |
| 规则匹配（静态） | ✅ | `over_permission` 全样本生效 |
| **设备端敏感读取钩子** | ❌ **不可用** | `armed 58/58` 但**零事件**；插桩会打死应用，见 §5 |
| 同意时序钩子 | ❌ 同因 | 只产出 START/ARMED |
| 出网钩子（Java 层） | ⚠️ 部分 | 8 个钩子挂上；`libcore.io.Posix` 在 API 37 上不存在（死目标） |
| mitmproxy 强制抓包 | ✅ 链路通 | 但**目标应用零流量**；GMS 域名 502（宿主到 Google 不通，环境所致） |
| UI 自动化 | ⚠️ 浅 | 只探索首屏，~10-12 次点击；不驱动应用进入"会读数据"的状态 |
| 死亡取证（tombstone） | ✅ 有效 | 本轮靠它定性，见 §5 |
| 关联引擎 | ✅ 跑通 | 无运行时事件可关联，退化为静态关联 |
| 证据包 + gaps | ✅ | 缺口如实写入 |
| AI 三阶段研判 | ⚠️ | KeePassDX 那轮 `ai_review` 失败；修复后重跑通过（见 §6.4） |
| PDF 报告 | ✅ | 5/5 生成 |

## 5 根因：钩子链"挂载成功但捕获为零"（P0）

### 5.1 阳性对照怎么做的

样本不可信（可能真的没触发），所以用**项目自带的夹具**做阳性对照：
`mobile/fixture-app/`（`com.vscanner.privacydemo`）有 10 个按钮，覆盖设备标识 / 位置 /
通讯录 / 应用列表 / 剪贴板 / 短信 / 明文外发 / HTTPS 外发 / 权限 / 政策。

`python mobile/tools/device_run.py --seconds 120` 走完整链路。结果：

- **12 个按钮全部命中** logcat 标记，且带真实结果：`line1=+15551234567`、
  `gps=39.908998,116.397`、`installed_apps=270`、三个运行时权限 GRANTED。
  这些动作**必然**调用被监视 API。
- `reads.jsonl` **仍然只有 2 行**（START + ARMED），零事件。
- 钩子日志：`armed 58/58 apis; failed=0` → 紧接着
  `!! pid 28892 在第 17s 消失——钩子已随之失效`。

### 5.2 最小化实验（只挂钩子，不启代理、不走编排）

| 步骤 | 结果 |
|---|---|
| 起夹具 | pid = 32755 |
| 挂 `hook_privacy` | `armed 58/58 apis; failed=0` |
| 按 `btnDeviceId`（按前 pid=32755） | **按后 pid 为空 → 进程当场消失** |
| 按 `btnApps` | 命中标记，但 pid 已是 780（`trigger.py` 内部 `am start` 拉起的新进程）→ 钩子是孤儿 |

从 dropbox 取回的现场（`data_app_native_crash@…`，设备时间 16:02:30）：

```
Process: com.vscanner.privacydemo    PID: 28892   ← 正是被钩子 attach 的那个
signal 6 (SIGABRT), code -1 (SI_QUEUE)
Abort message: '02000000-0e000000 rw-p 00000000 00:00 0   [anon:dalvik-main space]'
2 total frames:  #00 abort+189 (libc)   #01 <anonymous:7bde68aa4000>
Process uptime: 37s
```

### 5.3 对照实验（同夹具、同按钮、不挂钩子）

pid 1599 **全程稳定**，4 个按钮逐个通过，再等 30 秒仍存活，crash 缓冲 0 行。

### 5.4 结论

**插桩是唯一变量。`hook_privacy` 的 58 个钩子会在第一次被监视 API 被调用附近把应用打死
（SIGABRT），且崩前的事件一条也发不出来。**

这条结论同时解释了三件事，且三条互相印证：

1. 夹具（我们自己最简单的 app）与 **Fossify Camera 崩法同型**（SIGABRT + abort message
   是一条内存映射行 + 2 帧栈）→ 不是第三方样本的问题；
2. KeePassDX / Breezy / Camera 在窗口内死亡，而**唯一存活的 F-Droid 恰好就是零读取的那个**
   → "存活"与"没触碰被监视 API"强相关；
3. 五个样本 44 条结论全部是静态的 `over_permission` → 运行时维度在源头就没有输入。

判据层面的设计缺口：`hook_privacy_armed` 只看"58/58 挂上"，而 **`armed` ≠ 能捕到**。
这正是 M016「钩子必须自证挂载成功」没覆盖到的下一层。

## 6 优化点清单（按投入产出排序）

### P0-1 · 修 `hook_privacy` 打死应用
分档定位崩点：先只挂 1~3 个 API（`Settings$Secure.getString`、
`TelephonyManager.getLine1Number`）确认机制本身可用，再按 8 / 16 / 32 递增。
候选方向：改用 `Interceptor.attach` 在 native 层拦 libc；或挂载前先
`Java.deoptimizeBootImage()`；或对高流量类（`java.net.*` / `android.provider.*`）改采样。
**在此之前，所有"零读取"结论都不可信。**

### P0-2 · 把夹具阳性对照内建进链路
`device_run.py` 已有夹具链路，但它是独立入口。把它作为 `batch_thirdparty.py` 的
**前置自检**：跑批前自动跑一次夹具，**读数为零即拒绝出批**，并把结论写进批次摘要。
这样"采集链路故障"再也不可能被写成一堆"该应用未收集"。

### P1-1 · 崩溃自愈 + 分段采集
崩溃是非确定的（同配置同 UI 序列一死一活），不能靠调 ART 参数规避
（已实测 `dalvik.vm.usejit=false` + 框架重启**无效**：zygote 与 app 进程仍带
`Jit thread pool`）。做法是把窗口切成 N 段（如 30s/段），每段重新拉起应用并重挂钩子，
数据跨段累加。判据：高死亡率样本即使中途崩 1~2 次，`reads.jsonl` 仍应有崩前的真实事件。

### P1-2 · UI 自动化太浅
当前只探索首屏（约 10-12 次点击），从未把应用驱动到"会读数据"的状态
（KeePassDX 停在数据库选择页、Breezy 停在欢迎页）。Breezy 那轮 `ui_taps_made`
直接判失败。需要按类目做**意图化的探索脚本**（如"添加一个地点"、"打开相机预览"），
而不是通用点击。

### P1-3 · 夹具 `showPolicy` 的 dialog 生命周期
编排按 BACK 提前关掉政策弹窗后，夹具的 8 秒定时器再到时会 `Dialog.dismiss()`
一个已 detach 的 view → `IllegalArgumentException`。夹具侧应先判 `isShowing`。

### P2-1 · `addon_mobile.py` 与钩子的启动顺序
插件启动时 `egress.jsonl` / `egress_tp.jsonl` 必然还不存在（钩子在其后才起），
于是"本轮所有流都是 unresolved"。要么把插件推迟到钩子 ARMED 之后再起，要么让插件
容忍源文件后到。

### P2-2 · 清理死钩子目标
`hook_egress_tp.js` 的 `libcore.io.Posix.connect` 两个重载在 API 37 上
`ClassNotFoundException`（已记 `HOOK_MISS`，非致命）。留作已知死目标或删除，
避免每次跑都产生噪声。

### P2-3 · 出网归因的能力边界要写进 gaps
目前只有 Java 层 `connect()` 抓手。纯 native 出网（NDK socket、cronet）没有观测手段
→ 应显式写进 `gaps`，而不是让 `flows.jsonl` 静默为空。

## 7 本轮顺带修掉的平台缺陷（已实证）

1. **启动 Activity 以设备侧为准**（`device_run_thirdparty.py`）。
   F-Droid 的 manifest 有两个 LAUNCHER，aapt2 取到的是伪装的
   `org.fdroid.fdroid.panic.CalculatorActivity`，而该类已被 R8 裁掉 →
   `am start` 报 "Activity class does not exist"（结果码 -92）。
   改用 `cmd package resolve-activity --brief -c android.intent.category.LAUNCHER`，
   两个来源都写进 `main-activity.log`。**F-Droid 重跑后判据全过**，日志为：
   `from_batch=…CalculatorActivity / from_device=.views.main.MainActivity / used=.views.main.MainActivity`。
2. **多设备静默失真**：裸 `adb` 在双模拟器下返回空串，"查不到进程"被写成"进程已死"。
   加 `device_guard()` 启动前拦截 + `serial` 改用 `get-serialno`（M027）。
3. **死亡取证重写**：旧实现按时间戳分块会把**同毫秒的邻居进程崩溃**误归属给目标应用
   （实测 UWB HAL 与 Breezy 同毫秒）。改为"崩溃标记行必须自己点名目标"（M028）。
4. **AI 校验器补整体缺失检查**：模型静默省略 `items`/`recommendations`/`uncertainties`
   时原先零警告通过；现在给出 warning（M030 相关）。
5. **子进程 `PYTHONUNBUFFERED=1`**：`taskkill /F` 收树时未落盘的 stdout 会整块丢失，
   表现为日志 0 字节（M026）。

## 8 复现与证据位置

```bash
export ANDROID_SERIAL=emulator-5554
python mobile/tools/start_emulator.py            # 强制抓包模式 + 系统 CA + 压 UWB HAL
python mobile/tools/batch_thirdparty.py --out D:/vscanner-tp/tp-final \
    --only org.fdroid.fdroid org.fossify.voicerecorder \
    --category org.fdroid.fdroid=app_store --category org.fossify.voicerecorder=utility
python mobile/tools/device_run.py --seconds 120   # 夹具阳性对照（§5.1）
python mobile/tools/run_mobile_checks.py          # 离线回归，21 项
```

| 证据 | 位置 |
|---|---|
| 各样本判据 | `D:/vscanner-tp/tp-final/<序号>-<名>/verification.json` |
| 夹具崩溃现场（tombstone 原文） | `output/dropbox/data_app_native_crash@1791907351120.txt` |
| KeePassDX 主线程取指崩溃 tombstone | `output/tombstone-kp/tombstone_49` |
| 判据矩阵汇总脚本输入 | 上述 `verification.json` 全集 |
| 决策记录 | `mobile/DECISIONS.md` M029（插桩竞态）、M030（本报告对应结论） |
