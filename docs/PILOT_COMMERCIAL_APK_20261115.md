# 授权真实 APK 首批试点：逐场景验证与覆盖缺口（2026-11-15）

仅用于授权测试（自有 AAOS 模拟器 / 公开授权样本）。本文只写本轮真实观测，
未跑的场景标"未测"，不把"没看到"写成"没发生"。

> 本轮的任务级总结（含全部未决项、交付物清单、操作纪律）见
> [TASK_SUMMARY_PILOT_20261115.md](TASK_SUMMARY_PILOT_20261115.md)；
> 本文侧重逐场景证据与缺陷细节。

## 0. 结论

| 场景 | 样本 | 业务动作 | 独立回执 | 工具侧证据 | 判定 |
| --- | --- | --- | --- | --- | --- |
| A1 | Privacy Browser 3.20.1 | 打开固定 URL（回环 `127.0.0.1`） | **2 条**（窗口内） | flows **0**、钩子 0；**pcap 解出 4 条请求**（`/pilot/pilot-a2-0023`、`a3`、两次 favicon） | 业务与证据均成立；代理/钩子看不见，pcap 看得见 |
| A2 | 同上，改走局域网 IP | 打开固定 URL（`10.18.80.25`） | **2 条**（窗口内） | flows **4**，归因 `single_package_fallback` | 业务与证据均成立，归因强度低 |
| B | Proton Mail 3.0.17 | 启动到登录页（无账号） | **0 条** | 22 次 `getSSID`、3 个后端域名、37 条连接 | **阻断**：无授权测试账号 + MITM 打断 HTTPS |

三句话：

1. **同一条业务路径，目标地址决定"谁"看得见**：回环地址下代理与钩子都盲，但 pcap 抓到了
   4 条请求（A1）；换成局域网 IP 后代理立刻拿到 4 条 flow（A2）。这不是采样抖动，是通道结构。
2. **能看见 ≠ 能归因**：A2 的 4 条 flow 全部标 `single_package_fallback`，
   `attribution_delta_ms`/`user_id` 均为空——结论对，证据链不成立。
3. **账号型商用样本当前不可跑**：不是"测不出来"，是两重前置没满足（账号 + CA）。

> **修正（2026-11-15 12:55）**：初版把 A1 判成"证据缺失"，原因是当时没装 tshark、pcap 解不开。
> 用便携版 tshark 4.6.9 复核后：A1 的 4 条请求（含 `/pilot/pilot-a2-0023`）与页面正文都能还原。
> 差别不是"抓没抓到"，而是"解不解得开"——这条更正同时改写了 §3.1、§4（P1-03/P2-01）与 §5。

## 1. 样本与准入登记

| 项 | 场景 A | 场景 B |
| --- | --- | --- |
| 包名 | `com.stoutner.privacybrowser.standard` | `ch.protonmail.android` |
| 版本 | 3.20.1（versionCode 81） | 3.0.17 |
| SHA-256 | `209e0670cb44a959dd628737eaa5b8df05bfb605e4706de49ea2b72684cf72e3` | `54a6a5e42e33088b68fda0a7cd9f3345ce039546b379b26ea5b225171bbb22a3` |
| 来源 | F-Droid 镜像（TUNA）`.../com.stoutner.privacybrowser.standard_81.apk` | GitHub Release `ProtonMail-3.0.17.apk` |
| ABI | 无原生库（纯 Java） | 含 x86_64（可跑） |
| min / target SDK | 26 / 36 | 23 / 35 |
| 权限（清单） | INTERNET、INSTALL_SHORTCUT | 19 项（含 READ_CONTACTS、READ_MEDIA_*） |
| 账号前提 | **无**（浏览器基础路径不需要账号） | **需要 Proton 测试账号——本轮没有** |
| 业务路径 | 打开 `http://<sink>/pilot/<nonce>` 并渲染 | 启动 → 登录页（无法继续） |
| 回执来源 | 自有回执端 `mobile/lab/pilot_receipt_sink.py`（JSONL，含 UA/路径/时间） | 无 |

两台样本都是**单 APK、`adb install` 直接成功**，装在 AAOS 35 / user 10 上，
没有 split APK、没有 OEM 特权包——这两类兼容性缺口本轮**未被触碰**，结论不外推。

## 2. 方法

- 设备：`emulator-5554`，AAOS 15/API 35，`ro.build.characteristics=automotive`，user 10，
  1408x792；关 UXR（`cmd car_service enable-uxr false` + 车速 0）。
- 采集：`mobile/tools/device_run_thirdparty.py`（钩子 + mitmproxy + pcap + 关联 + 报告），
  窗口 110s / 100s / 90s，`--max-rounds 0`（不自动点击），
  业务动作在钩子 `ARMED` 之后由外部 `am start -a android.intent.action.VIEW` 注入，
  每场景做**两次**（不同 nonce）以验证可重复性。
- 回执端：独立进程，GET/POST 各记一行 JSONL（方法、路径、UA、Referer、时间、正文摘要），
  写盘即 fsync。
- 判据：回执时间必须落在窗口内（`coverage.json` 的 `started_at`/`ended_at`），
  窗口外的预试回执单独列出，不计入业务证据。

## 3. 逐场景结果

### 3.1 A1 —— 回环地址：代理与钩子看不见，pcap 看得见

| 指标 | 值 | 说明 |
| --- | --- | --- |
| 窗口 | 110.0s / 110s，未截断，0 次死亡 | `scenario-a/coverage.json` |
| 回执（窗口内） | `/pilot/pilot-a2-0023`、`/pilot/pilot-a3-0023` | UA `PrivacyBrowser/1.0`，见 `sink-a/receipts.jsonl` |
| 页面渲染 | `uiautomator` 读到 `pilot-a-0023` / `served_at` / 路径 | 应用确实渲染了回执页 |
| flows | **0** | `mitm.log` 无 `18899` 任何记录 |
| 钩子外发 | 5 条 `EGRESS_CONNECT`，全部 `2001:4860:4860::8888:443` | 与业务目标无关 |
| 读取 | 21 条事件，**0 条观测**（全是 START/ARMED/SKIPPED_JAVA/RESCAN） | 浏览器本身不读隐私 API |
| **pcap 复核** | **4 条请求**：`GET /pilot/pilot-a2-0023`、`/favicon.ico`、`/pilot/pilot-a3-0023`、`/favicon.ico`；响应正文含 `<h1 id=token>` | `tshark-redecode/scenario-a.messages.jsonl`（36 条报文 / 19 请求 / 6 正文） |

结论：WebView 对 `127.0.0.1` 直连（`adb reverse`）**绕过系统代理**，Chromium 网络栈又不走
`libcore.io.Linux.connect`——代理与钩子两条通道都看不见。**但设备侧 tcpdump 抓到了**
（`tcpdump -i any` 含 lo），pcap 里能还原完整请求行与页面正文。

所以准确说法是：**"代理+钩子盲，pcap 可见"**，不是"没有外发"。初版写成"零证据"，
真实原因是当时缺 tshark、pcap 解不开（P2-01）——这条更正把 A1 的判定从"证据缺失"
改成"证据在第三通道"。只读 `flows=0` 仍会得出相反结论，报告的降级口径不变。

### 3.2 A2 —— 局域网地址：业务成立，flow 成立，归因是兜底

| 指标 | 值 | 说明 |
| --- | --- | --- |
| 窗口 | 100.0s / 100s，未截断 | `scenario-a-lan/coverage.json` |
| 回执（窗口内） | `/pilot/pilot-b1-0023`、`/pilot/pilot-b2-0023` | 同一 keep-alive 连接，端口 49900 |
| flows | **4**（2 × 页面 + 2 × favicon），`status 200` | `mitm.log` 第 21–32 行 |
| 归因 | 4/4 `attribution_source=single_package_fallback`，`delta_ms=null`，`user_id=null` | `session/flows.sqlite` |
| 读取 | 0 条真实读取 | 同上 |

把目标从 `127.0.0.1` 换成宿主局域网 IP 后，代理立刻看到请求并"归属"到被测包。
但归属依据是**白名单里只有这一个包**，不是 uid/socket/进程身份核对。

本轮 B 场景窗口（00:38:41–00:40:11）里同时出现了**另一个应用**的流量
（`POST http://10.18.80.25:18145/owntracks/e7b425...`，OwnTracks 遗留配置）。
同一个 `single_package_fallback` 在多包环境下会把别人的流量记到被测包头上——
这不是假设，是这台设备上的常态。

### 3.3 B —— Proton Mail：能装、能起、能读，但业务无法完成

| 指标 | 值 |
| --- | --- |
| 窗口 | 90.0s / 90s，应用存活到窗口结束，0 崩溃 |
| 读取 | **22 条 `PRIVACY_READ`，全部 `WifiInfo.getSSID()`**（值 `<unknown ssid>`） |
| 外发意图 | `EGRESS_URL` 3 条：`mail-api.proton.me` / `api.protonmail.ch` / `firebaseinstallations.googleapis.com` |
| 连接 | 37 条 `EGRESS_CONNECT` |
| flows | **0**：`Client TLS handshake failed ... does not trust the proxy's certificate`（proton 两域名各多次） |
| 结论条目 | 18 条：16 `over_permission`、1 `over_collection`（`wifi_ssid_bssid`）、1 `sensitive_read`（`MOB-R017`，观测级） |
| 独立回执 | **0**：无账号，登录页都过不去 |

阻断原因是两条叠加，缺一不可解：

1. **没有授权测试账号**（业务路径走不完，拿不到回执）；
2. 本轮为规避 AAOS 只读 `/system` 用了 `--no-system-ca`，代理一拦，
   应用的 HTTPS **全部握手失败**——即使有账号，登录也必然失败。
   也就是说"开代理 + 不装 CA"这种配置**不能用于账号型业务试点**。

## 4. 运行中暴露的缺陷

| ID | 级别 | 现象 | 证据 | 状态 |
| --- | --- | --- | --- | --- |
| P0-01 | 阻断 | 脚本方式启动即在 install 前崩溃：`KeyError: 'device_run_thirdparty'`（`run1.py` 第 89 行把值写到 `sys.modules["device_run_thirdparty"]`，直接执行时模块名是 `__main__`；且该副本从未被读取，真正用的是 `ctx.prev_proxy`） | 首轮 `scenario-a-run.log`（**已被同路径重跑覆盖，见 §7 说明**）；修法：删掉死代码 | **已修** |
| P1-01 | 高 | 受控窗口必然判红：`--max-rounds 0` 时 `ui_taps_made` 恒失败（"完成 0 次点击"），三个场景全部 `passed=false`，但窗口内确实完成了外部注入的业务动作 | 三份 `verification.json` 的 `failed` 均为 `ui_taps_made` | **已修**：新增 `--action-log` + `business_action_made`（`mobile/tools/log_action.py`） |
| P1-02 | 高 | `runtime_events_captured` 把钩子装载/迁移事件算作"真实事件"：A1 只有 21 条 START/ARMED/SKIPPED_JAVA/RESCAN，仍判通过并记"15 条 START/ARMED 之外的真实事件"；`inputs.reads=21` 同源 | `scenario-a/verification.json`、`out/summary.json` | **已修**：只认观测事件（含 egress），装载事件不再计数 |
| P1-03 | 高 | 回环目标双盲：WebView 对 `127.0.0.1` 绕过代理，Chromium 不走 `libcore.connect` → 回执 2 条、flows 0、钩子 0 | `sink-a/receipts.jsonl` vs `scenario-a/session/*.jsonl` | **部分**：代理/钩子确实到不了回环，但 pcap 能解出请求与正文（§3.1 修正）；§10.11 已补这条 |
| P1-04 | 高 | 归因兜底被当成"已归属"：4/4 flow 是 `single_package_fallback`，无 uid、无 user、无时间差；同窗口内有其他包的流量 | `scenario-a-lan/session/flows.sqlite`、`scenario-b/mitm.log` | **已修**：summary 增 `flows_by_attribution` / `flows_identity_verified`，混合场景也记缺口 |
| P2-01 | 中 | `tshark` 缺失 → 三份 pcap（1.1–1.3 MB）解出 **0 条报文**，只有一条 optional 失败；"完整报文链路"实际未生效 | 三份 `http-stats.json` | **已解决**：便携 tshark 4.6.9 解到 `output/_tools/wireshark`，`find_tshark()` 优先命中；三份 pcap 复解 36 / 20 / 51 条报文 |
| P2-02 | 中 | `summary.json` 的 `android_version` 取自规则库默认值 **36**，设备是 API **35**；字段名容易被读成"设备版本" | 三份 `out/summary.json` vs `getprop ro.build.version.sdk` | **已修**：新增 `device_api`（设备）与 `android_version_source: rules_db` |
| P2-03 | 低 | 入口解析误报：`main-activity.log` 记 `cross_package: true`，实际 `com.stoutner.privacybrowser.activities.*` 与包名 `.standard` 不同命名空间，属正常 | `scenario-a/main-activity.log` | **已修**：改按命名空间判定，`cross_package` 不再误报 |
| P2-04 | 中 | 浏览器前台时 `screencap` 两次都只截到桌面/taskbar（`uiautomator` 同时能读到页面文本）；`screencap -d 0` 报 `Status: -2`（`-d` 要 SurfaceFlinger token 而不是显示序号）；`adb exec-out > x.png` 写出非 PNG | `browser-vis.png`、`screen-a-01.png`、`protonauth-screen.png` | **已修（工具层）**：新增 `mobile/tools/device_screencap.py`；WebView 截不到内容仍属镜像限制，需如实标注 |

### 4.1 修复记录与回归（2026-11-15 01:20–01:40）

| 缺陷 | 改动 | 验证 |
| --- | --- | --- |
| P1-01 | `device_run_thirdparty.py` 增 `--action-log`；`run3` 据窗口内登记数判 `business_action_made`，`ui_taps_made` 降为 optional；新增 `mobile/tools/log_action.py` | 受控窗口重跑（`output/pilot-20261115-0023/fixcheck/run`）：`business_action_made=0`（"窗口内 1 条动作：open_url"），`failed=[]`，`passed=true` |
| P1-02 | `helpers.LIFECYCLE_EVENTS` + `observation_events()`；`run5` 同时统计 `egress.jsonl` | 同一轮：`runtime_events_captured=0`，note"观测事件 4 条"；若只有装载事件则判 1 |
| P1-04 | `correlate_mobile` 增 `flows_by_attribution` / `flows_identity_verified`；兜底归因**混合场景也记缺口** | 本轮 summary：`{single_package_fallback: 2}`、`identity_verified=0`，缺口写"本轮 2 条网络流全部为单包排除法归因" |
| P2-02 | 新增 `--device-api`；summary 增 `device_api` 与 `android_version_source` | 本轮：`android_version=36 / source=rules_db / device_api=35` |
| P2-03 | `activity_namespace_matches()` 按命名空间判定 | 本轮 `main-activity.log` 的 `cross_package` 由 `true` 变 `false` |
| P2-04 | 新增 `mobile/tools/device_screencap.py`（token 解析 + `-d` + pull + PNG 校验 + 元数据 sidecar） | 实机：`via=display_token`、`is_png=true`、40236 B；同盘 `shot-d0.png.json` 记录显示名 |
| P2-01 | 便携 tshark 4.6.9：MSI `/a` 管理安装解出（不注册系统、不装 Npcap）→ `output/_tools/wireshark`；`find_tshark()` 项目路径优先 | 三份 pcap 复解 **36 / 20 / 51** 条报文；A1 解出 4 条 `/pilot/*` 请求与页面正文；修复轮 pcap 24 条 |
| 测试 | 新增 `mobile/tools/test_device_tools.py`（10 例），并入 `device_tools` 组 | 单测 10/10；`test_analyze*` 40/40；全量移动回归 63/63（拆分前后各一轮） |

P1-03 不是代码缺陷（代理/钩子都到不了回环），已在跑批手册 §10.11 写成操作约束。

另：B 场景 APK 内无政策，`summary.policy` 为 `null`，`apk_sha256`/`version_code` 一并在
summary 丢失（`bundle.json` 里仍在）——"判定可追溯"只在 bundle 层成立，汇总层不成立。

## 5. 覆盖缺口（本轮实测口径）

| 缺口 | 本轮事实 | 影响 |
| --- | --- | --- |
| WebView / Chromium 网络栈 | 钩子看不到；代理只在非回环目标时可见；**pcap 可见（含 lo）** | 读取侧仍缺，流量侧要靠 pcap 兜底 |
| 回环目标（`127.0.0.1` / `adb reverse`） | 代理被绕过、钩子也看不到；**pcap 能还原请求与正文** | 不能只凭 flows 判"没外发"；验收需同时给 pcap 解码结果 |
| CA / TLS 解密 | AAOS 只读 `/system`，未装 CA；所有 HTTPS 握手失败 | 账号型业务在"开代理"配置下不可完成 |
| 归因身份 | 单包兜底，无 uid/socket | 多包同窗口（本机常态）会记错账 |
| pcap 报文还原 | 已装便携 tshark；明文可读，TLS 仍有 16/5/23 帧未解（无 CA/keylog） | 明文流量可给正文；HTTPS 仍只能给元数据 |
| 证书固定 | B 样本有 pinning 实现（历史结论），本轮未开 bypass | 未验证 |
| split APK / OEM 特权包 | **未触碰** | 兼容性缺口保持原状 |
| 多用户并发 / 多 App 并发 | 未设计 | 未测 |
| 账号型业务回执 | 无账号 | 未测 |

## 6. 下一轮（按依赖排序）

1. ~~装 tshark~~ **已做**：便携 4.6.9 已就位，A1/A2/B 三份 pcap 复解成功。下一步是让`http_messages_extracted` 在流水线里自动通过，并给 TLS 补 keylog 覆盖（现在 16/5/23 帧未解）。
2. **修 P1-01/P1-02**：给入口加"外部动作"登记（动作时间线文件），
   并让 `runtime_events_captured` 只认 `PRIVACY_READ`/`EGRESS_*` 这类观测事件。
3. **账号到位后再跑 B**：同时解决 CA（`-writable-system` 或 native 明文钩子），
   否则登录必然失败；回执取 Proton API 侧的邮件列表/发件记录。
4. **多包同窗口归因实验**：在 A2 的窗口里同时让 OwnTracks 发一条，
   检验 `single_package_fallback` 到底会不会记错账（预期会）。
5. split APK / OEM 特权包单独开一轮，别和业务试点混在一起。

## 7. 证据索引

```
output/pilot-20261115-0023/
├── pilot-summary.json          # 机读汇总（回执已按窗口过滤）
├── sink-a/receipts.jsonl       # A1 回执（含 1 条窗口外预试）
├── sink-b/receipts.jsonl       # A2 回执（含 1 条窗口外自查）
├── scenario-a/                 # A1：verification.json / out/summary.json / session/*.jsonl
├── scenario-a-lan/             # A2：同上
├── scenario-b/                 # B：同上
├── tshark-redecode/            # 用便携 tshark 复解的报文（*.messages.jsonl / *.stats.json）
├── browser-vis.png             # 浏览器前台截图（截到桌面）
└── protonauth-screen.png       # 对照组：Proton Auth 截图正常

离线回归：`mobile/tools/run_mobile_checks.py` **63/63 通过**，修复轮两跑：
`output/mobile-regression-20261115-013702-nbahlshm/`（拆分前）、
`output/mobile-regression-20261115-115411-i9s1_phi/`（拆分后）。
```

复现（单场景）：

```bash
export ANDROID_SERIAL=emulator-5554
adb -s emulator-5554 shell cmd car_service enable-uxr false
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"
"$PY" mobile/lab/pilot_receipt_sink.py --out <out>/sink --port 18900 --bind 0.0.0.0 --token <token>
"$PY" mobile/tools/device_run_thirdparty.py \
  --apk <apk> --package <pkg> --main-activity <activity> \
  --out <out> --seconds 100 --max-rounds 0 --no-system-ca --skip-ai
# 钩子 ARMED 后，在窗口内注入业务动作：
adb -s emulator-5554 shell "am start -n <pkg>/<activity> -a android.intent.action.VIEW -d http://<host>:18900/pilot/<nonce>"
```

**过程教训**：首轮的 P0 崩溃日志被同路径重跑覆盖了。以后每次重跑必须换目录
（`scenario-a-attempt1/`），失败现场要单独保留——这次只能引用终端原文。
