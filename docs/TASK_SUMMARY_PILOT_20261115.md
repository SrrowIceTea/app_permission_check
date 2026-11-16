# 授权商用 APK 首批试点：任务总结与未决项（2026-11-15）

> 一句话：本轮用 2 个单 APK 跑了 3 个采集窗口，验证了"业务动作 → 独立回执 → 运行时证据"这条链
> 在什么条件下成立、在什么条件下断掉；运行中暴露 9 个缺陷，处置了 8 个（其中 1 项是环境依赖，已就地解决）。
> 剩下 **7 项能力边界 + 3 项外部前置 + 6 项完全未触碰的范围 + 6 项遗留待办**，本文逐条列清楚，
> 不打包成"后续优化"。

仅用于授权测试（自有 AAOS 模拟器 / 公开授权样本）。本文只写本轮真实观测，
未跑的场景标"未测"，不把"没看到"写成"没发生"。

## 交接修复复验

- D1 已复验。Privacy Browser 3.20.1 在 AAOS 35 / user 10 的最终轮解出 4 条请求和 4 条响应。两条窗口内业务回执均与捕获到的路径和响应正文一致。首个修复窗口的 pcap 经最终解码器复解为 0 条，排除了 Frida 控制握手造成的通过。
- D2、D3、D5 已修。Proton 离线重放在政策缺失时仍保留 APK 摘要和 versionCode。显式零观测复核保留原判据、确认依据与降级状态，经离线回归验证。同目录重试会拒绝覆盖，批次重试另建子目录。
- D4 已加适用性提示，API 35 规则校准仍待完成。D6 已进环境准备和验收预检，本机通过 tshark 4.6.9 校验。换机与 CI 仍由环境提供可用安装。
- 最终轮验证见 `output/pilot-repair-20261115-135141/run/verification.json`。跨通道回执对照见 `output/pilot-repair-complete-fixture/receipt-check.json`。Proton 账号型业务仍待授权测试账号和服务端回执。多包同窗口实机归因、split APK 和 OEM 特权包待测。改动和回归记录见 [开发日志](DEVELOPMENT_LOG.md#2026-11-15--真实-apk-试点交接修复)。

---

## 0. 一页速览

| 项 | 结果 |
| --- | --- |
| 目标 | 用已授权、能在 AAOS 35 普通安装的单 APK，各挑一条可重复业务路径，核对运行时证据与独立业务回执 |
| 实际样本 | Privacy Browser 3.20.1（无需账号）、Proton Mail 3.0.17（账号型） |
| 采集窗口 | 110s / 100s / 90s，三窗口均未截断、0 次应用死亡 |
| 业务回执 | A1 2 条、A2 2 条、B **0 条** |
| 工具侧证据 | A1 flows 0（pcap 4 条请求）、A2 flows 4（全兜底归因）、B 22 次 `getSSID` + 37 条连接 |
| 暴露缺陷 | 9 项（P0 1、P1 4、P2 4）：**8 项已处置**，1 项（回环双盲）降级为操作约束 |
| 回归 | 全量移动端 **63/63**，三轮；新增单测 10 例；`test_analyze*` 40/40 |
| 结论强度 | 场景 A 到"网络行为级"；场景 B 未成立（阻断）；准确率**不能**报 |

**最重要的一条认知变化**：本轮先判"回环目标下证据缺失"，复核后改判为"代理+钩子盲、pcap 可解"。
差别不在抓没抓到，而在当时没装 tshark、解不开。这条更正连带改了报告 5 个小节——
**"没看到"和"看不见"必须分开写**，这是本轮最贵的教训。

---

## 1. 任务目标与边界

原定任务是"测授权商用 APK 的真实场景"，具体要求：
用 1–2 个已授权、能在 AAOS 35 普通安装的单 APK，每个挑一条可重复的业务路径，
用测试账号实际操作，再核对运行时证据和独立业务回执。

明确的边界（本轮**没有**越界外推）：

- 只做单 APK；split APK、OEM 特权包不碰；
- 只做单包单窗口；不做多 App / 多用户并发；
- 不做准确率评估（需要独立参考标签 + 重复轮次）；
- 商用样本必须"有明确授权"，授权不确定的不跑。

---

## 2. 实际做了什么

| 阶段 | 动作 | 产出 |
| --- | --- | --- |
| 1. 准入登记 | 从 F-Droid 镜像 / GitHub Release 取 2 个单 APK，登记包名、版本、SHA-256、ABI、权限、账号前提 | `docs/PILOT_COMMERCIAL_APK_20261115.md` §1 |
| 2. 设备准备 | AAOS 15/API 35、`automotive`、user 10、关 UXR、车速 0；`adb install` 直接成功 | `verification.json` 的 `install` / `geo_injected` |
| 3. 采集 | 钩子（Frida）+ mitmproxy + pcap + 关联 + 报告；`--max-rounds 0`，业务动作在钩子 `ARMED` 后由外部注入，每场景做两次（不同 nonce） | 3 份 `session/`、`capture.pcap`、`out/` |
| 4. 回执核对 | 自建回执端（JSONL，含方法/路径/UA/时间，写盘 fsync）；回执时间必须落在窗口内，窗口外单列 | `sink-a/`、`sink-b/`、`pilot-summary.json` |
| 5. 缺陷修复 | 处置 8 项，新增 6 个文件（`log_action` / `device_screencap` / `summary_sections` / `flow_attribution` / `pilot_receipt_sink` / `test_device_tools`）+ 10 例单测；实机复验一轮 | `output/pilot-20261115-0023/fixcheck/` |
| 6. pcap 复核 | 便携 tshark 4.6.9 解出四份 pcap，**推翻**了 A1 的初判 | `tshark-redecode/` |

---

## 3. 场景结果

| 场景 | 样本 | 业务动作 | 独立回执 | 工具侧证据 | 判定 |
| --- | --- | --- | --- | --- | --- |
| A1 | Privacy Browser 3.20.1（vc 81） | 打开固定 URL（回环 `127.0.0.1:18899`） | **2 条**（窗口内） | flows **0**、钩子 0 观测；**pcap 4 条 `/pilot/*` 请求 + 页面正文** | 业务与证据均成立；代理/钩子盲，pcap 可见 |
| A2 | 同上，改走局域网 `10.18.80.25:18900` | 同一动作 | **2 条** | flows **4**（status 200），归因 4/4 `single_package_fallback` | 业务与证据成立，归因强度低 |
| B | Proton Mail 3.0.17 | 启动到登录页（无账号） | **0 条** | 22 次 `getSSID`、3 个后端域名、37 条连接、0 条 flow | **阻断**：无账号 + MITM 打断 HTTPS |

三条结论：

1. **同一条业务路径，目标地址决定"谁"看得见**：回环下代理与钩子都盲，但 pcap 抓到 4 条请求；
   换成局域网 IP 后代理立刻拿到 4 条 flow。这不是采样抖动，是通道结构。
2. **能看见 ≠ 能归因**：A2 的 4 条 flow 全部 `single_package_fallback`，`delta_ms`/`user_id` 为空；
   而 B 窗口里混进了 OwnTracks 的遗留流量——多包环境下这套兜底会记错账。
3. **账号型商用样本当前不可跑**：不是"测不出来"，是两重前置没满足（账号 + CA），缺一不可解。

---

## 4. 运行中暴露的 9 个缺陷与处置

| ID | 级别 | 现象 | 状态 |
| --- | --- | --- | --- |
| P0-01 | 阻断 | 脚本方式启动即在 install 前崩溃：`KeyError: 'device_run_thirdparty'`（写了从未被读取的 `sys.modules` 副本，真正用的是 `ctx.prev_proxy`） | **已修** |
| P1-01 | 高 | 受控窗口必然判红：`--max-rounds 0` 时 `ui_taps_made` 恒失败，三个场景全部 `passed=false`，但业务动作确实做了 | **已修**：新增 `--action-log` + `business_action_made`，`ui_taps_made` 降为 optional |
| P1-02 | 高 | `runtime_events_captured` 把装载/迁移事件当观测：A1 只有 21 条 START/ARMED/SKIPPED_JAVA/RESCAN，仍判通过 | **已修**：只认读取/外发/同意，`egress.jsonl` 计入观测 |
| P1-03 | 高 | 回环目标双盲：WebView 绕过代理，Chromium 不走 `libcore.connect` | **部分**：确属通道边界；pcap 可解，已写成跑批手册 §10.11 操作约束 |
| P1-04 | 高 | 归因兜底被当成"已归属"：4/4 flow 无 uid/无 user/无时间差 | **已修**：summary 增 `flows_by_attribution` / `flows_identity_verified`，混合场景也记缺口 |
| P2-01 | 中 | `tshark` 缺失 → 三份 pcap（1.1–1.3 MB）解出 0 条报文，"完整报文链路"未生效 | **已解决**：便携 4.6.9 解到 `output/_tools/wireshark`，`find_tshark()` 项目路径优先 |
| P2-02 | 中 | `android_version` 取规则库默认 36，设备是 35，字段名易读成"设备版本" | **已修**：新增 `device_api` + `android_version_source` |
| P2-03 | 低 | 入口误报 `cross_package: true`（实际同命名空间） | **已修**：改按命名空间判定 |
| P2-04 | 中 | 截图不可用：`screencap -d 0` 报 `Status: -2`（要 SurfaceFlinger token），`exec-out > png` 写出非 PNG，浏览器前台只截到桌面 | **已修（工具层）**：新增 `device_screencap.py`；WebView 截不到内容仍属镜像限制 |

实机复验（`fixcheck/run`）：`passed=true`、`failed=[]`、`business_action_made=0`（"窗口内 1 条动作"）、
`runtime_events_captured=0`（观测 4 条）、`cross_package=false`、`device_api=35`、
`flows_by_attribution={single_package_fallback:2}`、`flows_identity_verified=0`。

---

## 5. 仍然没解决的

分四类。前三类是**短期改代码也解决不了**的，第四类是这轮没做完的。

### 5.1 能力边界：换个写法也绕不过去

| # | 未决项 | 本轮事实 | 影响与出路 |
| --- | --- | --- | --- |
| A1 | **WebView / Chromium 读取侧全盲** | A1 21 条钩子事件里 **0 条观测**；Chromium 网络栈不走 `libcore.io.Linux.connect` | 浏览器类、内嵌 WebView 的 App，"读取了什么"没有证据，只能由流量反推。出路是换插桩点（Chromium 层）或明确标注"读取侧未覆盖" |
| A2 | **回环目标只剩 pcap 一条通道** | `127.0.0.1` 下代理被绕过、钩子看不到；pcap 明文可解 | 不能只凭 `flows=0` 判"没外发"；验收必须同时交 pcap 解码结果 |
| A3 | **TLS 正文读不到** | 无 CA（AAOS `/system` 只读，走 `--no-system-ca`）、无 keylog；四份 pcap 未解应用数据帧 **16 / 5 / 0 / 17** | HTTPS 只能给域名、连接数、时间；B 场景 37 条连接只有 3 条带 URL。要么可写 system 装 CA，要么改用 native 明文钩子 |
| A4 | **归因没有身份** | 4/4 flow 是 `single_package_fallback`，无 uid、无 socket、无时间差 | 多包同窗口（本机常态）会记错账，相关结论只能封顶 candidate |
| A5 | **证书固定未验证** | B 样本有 pinning 实现，本轮未开 bypass | 即使账号 + CA 到位，也不保证 B 能跑通；需单独验证 pinning 绕过 |
| A6 | **WebView 截图留证不可靠** | 工具层已修（token/PNG 校验/sidecar），但镜像层截不到 WebView 内容（`uiautomator` 能读到文本） | 只能给结构树 + 回执，给不了"肉眼可见"的页面截图；需换真机或换截图通道 |
| A7 | **回执强度只到"网络行为级"** | A1/A2 的"独立回执"来自**我们自己搭的 HTTP 服务** | 能证明"应用发起了这个请求并渲染了页面"，**不能**证明业务语义成功（如"登录成功""邮件已发"）。真正的业务回执需要第三方系统侧记录 |

### 5.2 外部前置缺失：不是代码问题，需要账号与权限

| # | 未决项 | 现状 | 需要什么 |
| --- | --- | --- | --- |
| B1 | **没有 Proton 测试账号** | B 停在登录页，3 次 `EGRESS_URL` 全是登录前置请求，回执 0 条 | 在 Proton 后台建授权测试账号，并明确授权范围 |
| B2 | **没有可用的 CA 方案** | `--no-system-ca` 下所有 HTTPS 握手失败（`does not trust the proxy's certificate`） | 二选一：`-writable-system` 起可写分区装 CA；或改 native 明文钩子，不依赖 CA |
| B3 | **没有服务端侧独立回执源** | 目前唯一回执是自己写的 sink | 拿到 Proton API 侧记录（邮件列表/发件箱时间戳），否则仍是"自证" |

### 5.3 一次都没碰的范围（报告里按"未测"标注，不外推）

| # | 未覆盖 | 说明 |
| --- | --- | --- |
| C1 | **split APK** | AAB 拆分 / 多 APK / OBB，安装兼容性完全未测 |
| C2 | **OEM 特权包** | priv-app、平台签名、`sharedUserId`；这类包权限模型与普通应用不同，结论不可套用 |
| C3 | **多 App / 多用户并发** | 本轮是单包单窗口；多包同窗口只观察到"会混流"，没做受控实验 |
| C4 | **准确率** | 18 条结论无独立 ground truth，无重复轮次 → **不能报准确率/召回** |
| C5 | **对抗样本** | 反调试、反 hook、pinning 绕过、环境检测，均未做 |
| C6 | **长稳与场景态** | 最长 110s；后台、息屏、驾驶态、长时间运行均未测 |

### 5.4 遗留待办：可修，但这轮没做完

| # | 待办 | 现状 | 下一步 |
| --- | --- | --- | --- |
| D1 | **`http_messages_extracted` 没在新窗口复跑** | 工具层已验证：`find_tshark()` 命中 `output/_tools/wireshark/tshark.exe`，四份 pcap 全部 `ok=true`（36/20/51/24 条报文）；但流水线内该判据最后一次记录仍是失败（01:37，tshark 装之前） | 下一轮跑一个窗口确认该判据转绿，别只信工具层 |
| D2 | **汇总层丢样本身份** | B 场景 APK 内无政策 → `summary.policy=null` → `apk_sha256`/`version_code` 一并在 summary 丢失（`bundle.json` 里还有） | 从 bundle / SAMPLE_MANIFEST 回填到 summary，保证"汇总层可追溯" |
| D3 | **`runtime_events_captured` 对"真的什么都没做"仍判红** | 这是有意的防误判（避免把"没捕到"写成"没收集"），但没有"人工确认后放行"的通道 | 加一个显式的 `--confirm-no-activity` 通道，附确认人与依据，别让判据变成噪声 |
| D4 | **规则库 36 vs 设备 35 的实质问题没解决** | 字段拆开了（`android_version=36 / device_api=35`），但"API 35 上套 36 的规则"是否成立、有无 35 专属差异，未核 | 逐条核对 API 35 与 36 的权限/行为差异，必要时按 API 分库 |
| D5 | **首轮 P0 崩溃现场被覆盖** | 同路径重跑覆盖了原始日志，只能引终端原文 | 以后每次重跑换目录（`scenario-a-attempt1/`），失败现场单独保留 |
| D6 | **便携 tshark 未进部署流程** | 270 MB 在 `output/_tools/wireshark`（gitignore 内），换机器 / CI 需重装 | 写进环境准备脚本，或改为 CI 镜像预置 |

---

## 6. 验证状态

| 项 | 结果 | 证据 |
| --- | --- | --- |
| 实机复验（受控窗口） | `passed=true`、`failed=[]`；optional 失败 2 项：`system_ca`（`--no-system-ca`，设计如此）、`http_messages_extracted`（tshark 装之前的记录） | `fixcheck/run/verification.json` |
| pcap 解码 | 四份 `ok=true`：36 / 20 / 51 / 24 条报文；A1 解出 4 条 `/pilot/*` 与页面正文 | `tshark-redecode/*.stats.json` |
| 新增单测 | `test_device_tools.py` **10/10** | 显示 token、动作窗口过滤、观测事件、命名空间 |
| 关联引擎 | `test_analyze*` **40/40** | 拆分 `summary_sections.py` / `flow_attribution.py` 后输出逐字段比对一致 |
| 全量移动回归 | **63/63**，三轮 | `mobile-regression-20261115-013702-nbahlshm/`（拆分前）、`...-115411-i9s1_phi/`（拆分后）、`...-125542-i34h8scb/` |
| `correlate_mobile.py` 体量 | 316 → **295 行**（回到 300 行硬线内） | 聚合段与归因段拆出 |

---

## 7. 交付物

**代码**

| 文件 | 类型 | 说明 |
| --- | --- | --- |
| `mobile/tools/device_run_thirdparty.py` | 改 | 新增 `--action-log` |
| `mobile/tools/device_run_thirdparty_helpers.py` | 改 | `LIFECYCLE_EVENTS` / `observation_events()` / `load_action_log()` / `activity_namespace_matches()` / `device_api()` |
| `mobile/tools/device_run_thirdparty_run1.py` | 改 | 修 P0；入口判定改命名空间 |
| `mobile/tools/device_run_thirdparty_run3.py` | 改 | `business_action_made` 判据 |
| `mobile/tools/device_run_thirdparty_run5.py` | 改 | 观测事件口径；传 `--device-api` |
| `mobile/tools/pcap_http.py` | 改 | `find_tshark()` 项目路径优先 |
| `mobile/tools/run_mobile_checks.py` | 改 | `device_tools` 组（组数不变） |
| `mobile/analyze/correlate_mobile.py` | 改 | `device_api` / `flows_by_attribution` / `flows_identity_verified`；拆到 295 行 |
| `mobile/tools/log_action.py` | 新 | 外部动作登记 |
| `mobile/tools/device_screencap.py` | 新 | token 解析 + `-d` 截图 + PNG 校验 + sidecar |
| `mobile/tools/test_device_tools.py` | 新 | 10 例单测 |
| `mobile/analyze/summary_sections.py` | 新 | 汇总聚合段 |
| `mobile/analyze/flow_attribution.py` | 新 | 归因分布与缺口 |
| `mobile/lab/pilot_receipt_sink.py` | 新 | 独立回执端（JSONL + fsync） |

**文档**

- `docs/PILOT_COMMERCIAL_APK_20261115.md` —— 逐场景验证报告（含缺陷表、覆盖缺口、证据索引）
- `docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md` §10.11 —— 回环盲区与 `--action-log` 操作约束、便携 tshark
- `docs/DEVELOPMENT_LOG.md` —— 四轮开发日志（试点 / 缺陷修复 / tshark 落地与结论复核 / 本文登记）
- 本文 —— 任务总结与未决项

**证据**

`output/pilot-20261115-0023/`：`pilot-summary.json`（机读汇总）、`sink-a`/`sink-b`（回执）、
`scenario-a` / `scenario-a-lan` / `scenario-b`（窗口产物）、`fixcheck/`（修复复验）、
`tshark-redecode/`（报文解码）。

---

## 8. 首批试点交接时的下一轮安排（最新状态见本文开头）

1. **复跑一个窗口**确认 `http_messages_extracted` 转绿（D1）——现在只是工具层验证，判据本身没复跑。
2. **补 summary 层样本身份**（D2），让"判定可追溯"在汇总层也成立。
3. **账号 + CA 到位后补 B**（B1/B2/B3）：账号与 CA 必须同时解决，否则登录必然失败；
   回执取 Proton API 侧记录，别再只用自己的 sink。
4. **多包同窗口归因实验**：在 A2 窗口里同时让 OwnTracks 发一条，验证 `single_package_fallback`
   到底怎么记错账（预期会）——这是把 A4 从"推断"变成"实测"的最小实验。
5. **split APK / OEM 特权包**单独开一轮，别和业务试点混。
6. **API 35 vs 36 规则差异**核对（D4），否则 18 条结论的规则适用性说不清。

---

## 9. 操作纪律（本轮踩过的坑，写下来防复发）

1. **失败现场不能覆盖**：首轮 P0 日志被同路径重跑冲掉，只能引终端原文。重跑换目录。
2. **别用回环地址做"工具能看见"的证据**：`127.0.0.1` + `adb reverse` 是代理与钩子的双盲区；
   判阴性前必须先看 pcap 解码结果。
3. **别为让判据变绿去补假动作**：`business_action_made` 判红说明窗口里真没登记动作，
   该补的是登记，不是造数据。
4. **"没看到"≠"没发生"**：`flows=0` 只说明这条通道没记录；要下"没有外发"的结论，
   得三条通道（钩子 / 代理 / pcap）都给出否定证据。
5. **装东西不必动系统**：Wireshark MSI 用 `msiexec /a` 管理安装即可解出 `tshark`，
   不注册、不装 Npcap、不需要管理员。
6. **字段名要照实抄**：`verification.json` 里没有 `status`，只有 `passed`。前几轮报告写成
   `status=passed/failed` 属笔误，本文与试点报告已回改为 `passed=true/false`——
   这类小偏差在校对时会被当成"结论不一致"，宁可改字，不要留模糊。

---

## 10. 复现（单场景）

```bash
export ANDROID_SERIAL=emulator-5554
adb -s emulator-5554 shell cmd car_service enable-uxr false
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"

"$PY" mobile/lab/pilot_receipt_sink.py --out <out>/sink --port 18900 --bind 0.0.0.0 --token <token>
"$PY" mobile/tools/device_run_thirdparty.py \
  --apk <apk> --package <pkg> --main-activity <activity> \
  --out <out> --seconds 100 --max-rounds 0 --no-system-ca --skip-ai \
  --action-log <out>/actions.jsonl

# 钩子 ARMED 后，在窗口内注入业务动作并登记（两步都要做，少一步判据会红）
adb -s emulator-5554 shell "am start -n <pkg>/<activity> -a android.intent.action.VIEW -d http://<host>:18900/pilot/<nonce>"
"$PY" mobile/tools/log_action.py --log <out>/actions.jsonl --action open_url \
  --detail "http://<host>:18900/pilot/<nonce>" --source adb

# 收尾必须看 pcap 解码，别只看 flows
"$PY" mobile/tools/pcap_http.py --pcap <out>/capture.pcap --out <out>/msgs.jsonl \
  --bodies-dir <out>/bodies --session <out>/session --stats <out>/http-stats.json
```
