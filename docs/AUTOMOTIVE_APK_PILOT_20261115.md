# 车载 APK 第二轮试点：3 个驾驶场景样本与 6 项新缺陷（2026-11-15）

> 一句话：从 F-Droid 镜像取了 3 个**纯 Java、可在 AAOS 35 安装**的驾驶场景应用（OBD 诊断、
> GPS 速度计 ×2），跑通 4 个受控窗口。业务侧第一次拿到**可计算的界面回执**（注入 7.72 m/s → 显示 27），
> 同时暴露 6 个新缺陷：3 个已修并复验，2 个是能力边界，1 个在本环境无解。

仅用于授权测试（自有 AAOS 模拟器 / F-Droid 公开授权样本）。本文只写本轮真实观测。

---

## 0. 结论

| 样本 | 业务路径 | 回执 | 工具侧 | 判定 |
| --- | --- | --- | --- | --- |
| Blue Square Speedometer 1.2.1 | 启动 → 选 gps → 注入速度 | **UI 文本 `Speed=27`**（另有高度 58 m、精度 5.0 m） | 4 条 `requestLocationUpdates`（observe/empty）、flows 0、pcap **0 条应用报文** | 业务成立；读取只到"订阅"，未到"取值" |
| Roam 1.2.0 | 启动 → 注入速度 | **截图 36 / 53 km/h**（画布，无文本节点） | 21 条事件**全为装载类**、0 条读取 | 业务可见、读取不可见：启动期调用漏采 |
| AndrOBD V2.7.10 | 启动 → 选 ECU → DEMO 页 | 无（业务未完成） | 无完整窗口 | 安装/启动成立，业务路径未走完 |
| （对照）Roam + `--spawn-hook` | 同上 | 同上 | 0 条读取 | spawn 超时，回退 attach 后仍漏采 |

四条要点：

1. **开源生态里的"车载 APK"基本都不是 AAOS 原生**：3 个样本都用 `aapt2` 查过，**没有一个声明
   `android.hardware.type.automotive`**；它们是"驾驶场景的手机应用"。这对结论适用范围很关键。
2. **`http_messages_extracted` 之前是假绿**：Blue 窗口里 2 条报文全是工具自己的 `/ws` 控制通道；
   Roam 两个窗口的报文分别来自系统 `connectivitycheck`、`www.google.com` 和 **OwnTracks**——
   被测应用一条都没有。判据只看"pcap 里有几条 HTTP"，没有应用归因。
3. **启动期是读取侧的系统性盲区**：Roam 的 dex 里只有一条 `requestLocationUpdates`，就在启动时调用；
   UI 确实按注入速度显示 36/53 km/h，钩子 0 条读取。`--spawn-hook` 本想覆盖这一段，但在本环境
   `frida` spawn 直接超时（`TimedOutError`），回退 attach 后依旧漏。
4. **回调式数据只记录"注册"，不记录"取值"**：Blue 的 4 条读取 `api_role=observe`、
   `collection_state=empty`，所以 MOB-R006（精确定位读取）不会触发——报告里只有 2 条
   `over_permission` 候选，没有 observed。这不是漏判，是语义边界，但必须写清楚。

---

## 1. 样本与准入

来源：清华镜像 `mirrors.tuna.tsinghua.edu.cn/fdroid/repo/`，三个 APK 的 SHA-256 与仓库索引
`index-v1.json` 逐条一致（`sha256sum` 实测）。

| 项 | Blue Square Speedometer | Roam | AndrOBD |
| --- | --- | --- | --- |
| 包名 | `net.nhiroki.bluesquarespeedometer` | `com.nic.roam` | `com.fr3ts0n.ecu.gui.androbd` |
| 版本 | 1.2.1（vc 15） | 1.2.0（vc 7） | V2.7.10（vc 20710） |
| 大小 | 839,612 B | 65,140 B | 2,411,076 B |
| SHA-256 | `f7e9f944…a25b4` | `7bf434e1…50af5` | `71d3cecd…2d67e` |
| min / target SDK | 23 / 37 | 26 / 36 | 17 / 36 |
| 声明权限 | 精确定位、粗略定位 | 精确定位、粗略定位 | 16 项：蓝牙扫描/连接、INTERNET、前台服务（连接设备）、悬浮窗、通知… |
| automotive 声明 | **无** | **无** | **无** |
| 原生库 | 无（纯 Java） | 无 | 无 |
| 账号前提 | 无 | 无 | 无（但需 OBD 适配器才有真实数据） |

`aapt2 dump badging` 的 `uses-feature` 只有 `faketouch` / `location` / `bluetooth`，
没有 `android.hardware.type.automotive`，也没有 `CarAppService` 相关组件。

---

## 2. 方法与设备

- 设备：`emulator-5554`，AAOS 15 / API 35，`x86_64`，`automotive`，user 10，1408×792；关 UXR。
- 采集：`mobile/tools/device_run_thirdparty.py`，`--max-rounds 0 --no-system-ca --skip-ai`，
  窗口 90 s / 90 s / 90 s / 75 s，钩子 attach（最后一轮额外试了 `--spawn-hook`）。
- 业务动作注入（全部外部、全部登记）：
  - UI 点击走 `input tap`（坐标取自 `uiautomator dump` 的 `bounds`）；
  - 速度注入走模拟器控制台 `adb emu geo fix <lon> <lat> <alt> <sats> <velocity>`，
    设备侧 `dumpsys location` 可核对 `vel=`；
  - 每条动作用 `mobile/tools/log_action.py` 记 `ts_ms/action/detail`。
- 回执：本轮没有服务端可对，回执是**界面状态**——文本节点（Blue）或截图（Roam）。
  输入（注入速度）与输出（显示速度）可独立计算，比上一轮的"自建 HTTP 回执"更硬。

---

## 3. 逐样本结果

### 3.1 Blue Square Speedometer —— 唯一一条完整闭环

| 指标 | 值 |
| --- | --- |
| 窗口 | 90.0 s / 90 s，未截断，0 次死亡 |
| 业务动作 | 2 条（`select_provider` → `inject_speed`），`business_action_made=0` |
| 界面回执 | `Speed=27`、`MSL Altitude=58`、`GPS Accuracy=5.0 m`；注入速度 7.72 m/s（≈27.8 km/h） |
| 读取事件 | 4 条 `PRIVACY_READ`，全部 `LocationManager.requestLocationUpdates(...LocationRequest, Executor, LocationListener)`，`api_role=observe`、`collection_state=empty`、`non_empty=false` |
| 结论 | 2 条，均 `over_permission`（MOB-P003/P004，candidate） |
| flows / egress | 0 / 0 |
| pcap 报文 | 解码出 2 条，**全是 `GET http://127.0.0.1/ws`（101 Switching Protocols）**——工具自己的钩子控制通道 |

复验（改完过滤后重解同一份 pcap）：**0 条报文**，`control_channel_dropped=2`。

判定：业务闭环成立（输入→计算→显示），但工具侧只证明"应用注册了定位监听"，
没有证明"应用拿到了定位值"。4 条读取全是订阅，MOB-R006 因此不触发。

### 3.2 Roam —— 业务看得见，读取看不见

第一轮（attach，未加容差）：

| 指标 | 值 |
| --- | --- |
| 窗口 | 90.1 s，未截断 |
| 业务动作 | `inject_speed` 记在 **13:36:50.286**，窗口 **13:36:51.611** 才开始 → 早 1.3 s，被整条丢弃 |
| 界面回执 | 截图 **36**（注入 10.29 m/s ≈ 37.0 km/h）；最终轮 **53**（注入 15.43 m/s ≈ 55.6 km/h）——差值随速度变大，不是单纯取整，像有一阶平滑，未深究 |
| 读取事件 | **21 条，全部装载类**（START/ARMED/NATIVE_MIGRATED/SKIPPED_JAVA/RESCAN），0 条观测 |
| 判据 | `passed=false`，failed=`business_action_made`、`runtime_events_captured` |

为什么看不到读取：`dexdump` 显示 Roam 只调用
`Landroid/location/LocationManager;->requestLocationUpdates:(Ljava/lang/String;JFLandroid/location/LocationListener;)V`
——**这个重载在钩子白名单里**（`targets.generated.js` 第 72 条）。它是启动期（`onCreate`）注册的，
而工具是"先 `am start`、再挂钩"的 attach 模式，调用发生在钩子就位之前。

第三轮（修完容差后再跑）：`business_action_made=0`（"窗口内 1 条动作：inject_speed"），
`runtime_events_captured` 仍为 1（21 条装载事件），并新增一条
`startup_calls_covered`（optional）="attach 模式：启动期调用可能早于挂钩"。

### 3.3 Roam + `--spawn-hook` —— 本环境没有这条兜底路径

```
frida.TimedOutError: unexpectedly timed out while waiting for app to launch
```

spawn 失败后工具回退到 attach（`attached pid 23485`），继续采集，读取仍是 0 条。
随后在解码阶段整轮崩溃（见 N4）。也就是说：**想覆盖启动期，当前环境没有可用开关**。

### 3.4 AndrOBD —— 装得上、起得来，业务没走完

- `adb install -r -g` 成功，`MainActivity` 起得来；首次启动弹「Select ECU address …」，选
  `0x7E8 — ECM (11-bit CAN)` 后进入主界面，顶部有 `DEMO` 标记。
- 主界面内容区一直停在带 logo 的 DEMO 页，没有出现仪表数据；logcat 只有
  `com.fr3ts0n.prot: Set ECU address: 0x7e8`，没有后续。
- 点击工具栏图标后，应用内 WebView 打开 `https://www.mojeek.com/`，被 mitmproxy 拦下并弹出
  "SSL Certificate Error / The certificate authority is not trusted"。
- 结论：**业务路径未成立**。这个样本没有 OBD 适配器就没有数据源；本轮不计入成功场景，
  但保留它的价值在于：它声明了蓝牙扫描/连接、前台服务、悬浮窗等 16 项权限，是下一轮"权限面"
  测试的好样本。

---

## 4. 本轮暴露的缺陷（6 项，3 项已修）

| ID | 级别 | 现象 | 证据 | 状态 |
| --- | --- | --- | --- | --- |
| N1 | 高 | **控制通道被当成应用报文**：pcap 解码把钩子宿主的 `GET /ws`（101）计入 `http_messages_extracted`。Blue 的应用侧零流量，判据却"通过"（2 条报文） | `run-blue/http_messages.jsonl`（2 条全是 `/ws`）、重解后 `control_channel_dropped=2`、`messages=0` | **已修**：`pcap_http.decode()` 末尾按 loopback + `/ws` 精确剔除整条 TCP 流；业务回环（`127.0.0.1:18899/pilot/...`）不受影响 |
| N2 | 高 | **动作早 1.3 s 被整条丢弃**：没有"窗口开启"信号，测试者看到进程起来就动手，`business_action_made` 判成"没做业务" | `run-roam/coverage.json` t0=13:36:51.611 vs `actions-roam.jsonl` 13:36:50.286 | **已修**：`--action-grace-ms`（默认 5000）+ `before_window_within_grace` 单列 + `out/window-open.json` 标记窗口起点；单测 2 例覆盖 |
| N3 | 高 | **`--spawn-hook` 在本环境不可用**：frida spawn 超时，回退 attach；启动期读取无法覆盖 | `run-roam-spawn/hook-all.log` 的 `TimedOutError` | **未修**（环境/版本问题）；已加 `startup_calls_covered` 判据，让每次 attach 跑都显式提示这个盲区 |
| N4 | 高 | **解码阶段异常会带走整轮**：`keylog_from_events` 抛 `NameError: json` 后进程直接退出，pcap 和 reads 都在，却没有 correlate 和报告 | `run-roam-spawn.log` traceback（13:43:5x） | **已修**：`_stage_decode` 把 keylog/decode 包进 try，失败降级为 `stats.ok=false` 并写缺口，后续阶段照常跑 |
| N5 | 高 | **pcap 没有应用归因**：`http_messages_extracted` 统计的是"设备上所有 HTTP"。Roam 窗口 8 条 = 系统 `connectivitycheck`×2 + `www.google.com:443` CONNECT + **OwnTracks `POST /owntracks/...`（502）**；最终轮 2 条全是 OwnTracks。被测应用 0 条 | `run-roam/http_messages.jsonl`、`run-roam-final/http_messages.jsonl` | **已修**（[FIXES_20261115_ROUND2.md](FIXES_20261115_ROUND2.md) §1）：根因是 uid 未按多用户换算（10276 vs 1010276），`conn_probe` 一直 0 行；修后按端口归属，Blue **0/7 判红**、Proton **4/28 通过** |
| N6 | 中 | **回调式取值不产生 observed**：`requestLocationUpdates` 记为 `observe/empty`，位置值经系统回调返回，钩子看不到；MOB-R006 因此不触发 | `run-blue/session/reads.jsonl` 4 条 `PRIVACY_READ` + `findings.jsonl` 仅 2 条 candidate | **已修**（[FIXES_20261115_ROUND2.md](FIXES_20261115_ROUND2.md) §2）：规则库新增 `Location.getLatitude/getLongitude/getSpeed/getAccuracy` 四个取值点；Blue 读取 4 → **52**，结论出现 **MOB-R006 observed** |


> 2026-11-15 晚补记：N5/N6 已在 [FIXES_20261115_ROUND2.md](FIXES_20261115_ROUND2.md) 修复并实测；
> N3 仍是环境限制（frida spawn 超时），只加了 `startup_calls_covered` 判据让它可见。

另有两项环境/运维问题，不计入缺陷编号但影响复现：

- **残留代理与 mitm**：13:31 观察到设备 `http_proxy=10.0.2.2:8888` 且 8888 仍有 mitmproxy 监听
  （至少在一次失败/中断轮次之后）。正常结束的轮次会还原，但中断路径没保证。
- **OwnTracks 常驻**：这台模拟器上 OwnTracks 一直在跑并向 `10.18.80.25:18145` 重试（502），
  每个窗口都会混进它的流量。做单包结论前应先停掉无关应用。
- **政策库缺失**：`output/local-policy-library-20261018` 不存在，`policy_from_apk` 恒失败，
  与样本无关（上一轮已记录，本轮 Blue 同样命中）。

---

## 5. 仍然没解决的（本轮新增/改写）

| # | 未决项 | 本轮事实 | 出路 |
| --- | --- | --- | --- |
| S1 | **启动期读取盲区** | Roam 唯一的 `requestLocationUpdates` 就在 onCreate；attach 漏，spawn 超时 | 换 frida 版本/注入方式（gadget、zygote），或在应用 `attachBaseContext` 之前用 ptrace 级注入；短期内只能标"启动期未覆盖" |
| S2 | **pcap 无应用归因** | Roam 窗口 8 条报文全部来自系统/其他应用 | 用 `conns.jsonl` 的 uid+时间做二次归属，或按被测 uid 建 iptables owner 规则单独抓 |
| S3 | **回调式取值** | Blue 4 条 observe/empty，无 observed 结论 | 扩钩子到 `LocationListener.onLocationChanged`、传感器回调等投递点 |
| S4 | **AAOS 原生样本缺失** | 3 个样本都不声明 automotive；F-Droid 上没有 AAOS 原生应用 | 需要 OEM/车厂提供的 priv-app 或 AOSP Car 示例应用；这类包还涉及平台签名与 sharedUserId |
| S5 | **证书固定/CA** | AndrOBD 的 WebView 一开就撞证书错误 | 沿用上一轮结论：可写 system 装 CA，或 native 明文钩子 |
| S6 | **准确率** | 6 条结论（Blue 2、Roam 2、Roam-final 2）无参考标签 | 需要人工标注 + 重复轮次；现在只能报"判据通过/未通过" |

上一轮遗留的 split APK、OEM 特权包、多用户并发、长稳，本轮**依旧未触碰**。

---

## 6. 验证

| 项 | 结果 |
| --- | --- |
| 新增单测 | `test_device_tools` **14/14**（新增 2 例：容差内保留、容差 0 严格） |
| 编译 | `py_compile` 通过：`device_run_thirdparty.py`、`_run3`、`_run4`、`_armed`、`_helpers`、`pcap_http`、`pcap_tshark` |
| 实跑复验 | N1：Blue pcap 重解 2 → 0（`control_channel_dropped=2`）；N2：最终轮 `business_action_made=0`（窗口内 1 条）；N3：`startup_calls_covered` 按预期判 1 并给出说明 |
| 全量回归 | **63/63** 通过：`output/mobile-regression-20261115-134829-tx67vld6/` |

---

## 7. 证据索引

```
output/auto-apks-20261115/
├── com.fr3ts0n.ecu.gui.androbd_20710.apk   # 2,411,076 B
├── com.nic.roam_7.apk                       # 65,140 B
├── net.nhiroki.bluesquarespeedometer_15.apk # 839,612 B
├── index-v1.json                            # F-Droid 仓库索引（73 MB，核对 sha256 用）
├── run-blue/                                # 90 s，passed；receipt 见 session + UI 文本
├── run-roam/                                # 90 s，failed（动作早 1.3 s + 0 读取）
├── run-roam-final/                          # 75 s，failed（仅 runtime_events；动作已判过）
├── run-roam-spawn/                          # spawn 超时 + 解码崩溃现场
├── actions-blue.jsonl / actions-roam*.jsonl # 动作登记
└── roam-01.png / roam-vel-01.png / blue-01.png / androbd-01.png
```

复现（以 Blue 为例）：

```bash
export ANDROID_SERIAL=emulator-5554
adb -s emulator-5554 shell cmd car_service enable-uxr false
"$LOCALAPPDATA/Programs/Python/Python313/python.exe" mobile/tools/device_run_thirdparty.py \
  --apk net.nhiroki.bluesquarespeedometer_15.apk \
  --package net.nhiroki.bluesquarespeedometer \
  --main-activity net.nhiroki.bluesquarespeedometer.MainActivity \
  --out output/auto-apks-20261115/run-blue --seconds 90 --max-rounds 0 --no-system-ca --skip-ai \
  --action-log output/auto-apks-20261115/actions-blue.jsonl

# 看到 out/window-open.json 之后再动手（或在 5 s 容差内）
adb -s emulator-5554 shell "input tap 704 487"        # 选 gps
adb -s emulator-5554 emu geo fix 116.397 39.909 50 8 15
# 回执：uiautomator dump 里 Speed=27
```

---

## 8. 下一轮建议（按依赖）

1. **先停无关应用再采**（OwnTracks），否则每个窗口的报文都掺别人的流量（S2 的最低成本缓解）。
2. **pcap 归因**：用 `conns.jsonl` 的 uid + 时间做二次归属，给 `http_messages_extracted` 加
   "归属到被测包几条"的口径（S2）。
3. **启动期注入**：先确认 frida spawn 超时是不是版本问题；不行就试 gadget/zygote（S1）。
4. **回调投递点**：补 `LocationListener.onLocationChanged` 一类钩子（S3）。
5. AndrOBD 单独开一轮"权限面"测试（16 项权限、蓝牙扫描），业务路径需要 OBD 模拟器。
6. AAOS 原生样本（S4）只能等 OEM/系统侧提供，别在 F-Droid 上找。
