# V-Scanner 开发日志

从 2026-11-15 起记录每次开发。按日期追加，同日多轮写明任务。开始时登记范围，收尾时记录改动、验证、证据和待办。达到 300 行时将旧记录转入按日期命名的分卷，并在这里保留索引。验收记录只引用可复核、无测试凭据的产物。

## 2026-11-15 · 第三轮行协议取证与 BLE 交接

- 复核 gpsdRelay pcap 和回执时间，修复连接采样窗口、跨包行重组和监听方外发归属。验证 BLE 扫描调用和结果边界。
- 历史轮次的 128 条独立回执中有 101 条在审计窗口内，与 pcap 的 101 条逐条匹配。其余 27 条在窗口后收到。连接采样器从准备阶段起算并先于约定窗口结束，尾段缺 UID 快照。
- 连接采样延长准备预算，按窗口收尾。校验 tcpdump 与连接采样器是否运行到窗口末，并修复采样器正常总结路径缺 `datetime` 导入。TCP 行重组使用方向与序列号，处理乱序、重复和跨段 UTF-8，丢弃缺段或不完整边界，保留诊断。跨段长 JSON 通过真实 pcap 的 tshark 回归。
- 监听端归属。单凭端口保留为候选，确认归属需要 UID/inode 的双侧快照，或同一完整 TCP 流的可靠快照锚点与已见 SYN。历史重放 101/101 行均获得可靠归属，直接快照 54 行、同流锚点 47 行。
- 外发判定。完整、校验和正确、含有效定位字段的已归属出站 NMEA 进入 `MOB-E006`，与同设备时钟下的成功坐标 getter 按原规则窗口关联。规则保留 `correlated / shape_tag`，证据引用带 UID、inode、包号和 pcap 摘要。继续用移动规则 36，设备 API 35 的适用性缺口保留。
- gpsdRelay 实机。已验安装 APK 与 F-Droid 样本 SHA-256 一致。44 秒窗口、无截断、无死亡。159 条回执中的 132 条在窗口内，pcap 132 条在内容和顺序上全部一致。UID 归属 132/132，直接快照 130 行、同流锚点 2 行，候选 0 行。44 行有效定位参与规则，PDF 和 findings 均出现 `MOB-E006`。产物见 `output/round5-gpsd-20261115-212558/`。
- BLE 实机。自有夹具用测试 UUID 调用 Android BLE 扫描，`startScan` 和 `stopScan` 均取得 `observe / call_only / ok`，窗口完整。未收到测试广播，TpmsMonitor 实际传感器回调仍待验证。产物见 `output/round5-ble-20261115-212717/`。已清理临时 APK、回执转发和代理。
- ELM327 测试夹具把固定应答与 TCP 收发拆成两个文件，保留命令入口、转速测试值和 ISO-TP 头部行为。行协议专项 19/19、工程守卫 13/13，夹具入口和指定转速应答通过。
- 全量验证。`tools/run_regressions.py --mobile` 退出码 0，仓库 23/23，内含移动侧 63/63。首次在沙箱内运行时回环连接及临时文件替换被拦截，改用本机环境后通过，结果见 `output/round5-verified-regression-20261115/verification.json` 和 `mobile/verification.json`。

## 2026-11-15 · HTTP/3 与启动期盲区可行性验证

- HTTP/3。自有离线 QUIC 客户端和服务端通过真实 TLS 1.3 握手并交换 HTTP/3 DATA。tshark 使用这次会话的测试密钥还原请求 30 字节、响应 31 字节，两段 SHA-256 均与独立端点记录一致。无密钥对照解出 0 帧正文。验证记录见 `output/round4-http3-feasibility-20261115/verification.json`。这轮只验证解码和密钥前提。
- 短连接。AAOS 实测有 `CONFIG_BPF_SYSCALL`、`CONFIG_BPF_EVENTS`、`CONFIG_INET_DIAG_DESTROY` 和 `raw_syscalls` 目录。尚未验证当前 SELinux 策略下能否运行目标 UID 过滤的采集程序，也未验证短连接样本的覆盖与丢事件率。
- 启动期。临时 bundle 把 socket 与 TLS 元数据提前到第一阶段。Roam 两组钩子均就绪后，首个 PID 约 1 秒退出，证据见 `output/round4-roam-early-20261115/run.log`。
- 隔离对照。只提前 socket 时，Roam 原 PID 存活至 14 秒窗口末，TLS 模块比 socket 晚 4090 ms 就绪。只提前 TLS 时，Roam 约 1 秒退出，RenderThread 报 `EGL_NOT_INITIALIZED`。证据见 `output/round4-roam-isolation-20261115/verification.json` 和 `tls-crash.log`。这轮使用临时验证 bundle，正式流水线接入待完成。

## 2026-11-15 · R1–R6 后续修复

- 范围为 AAOS 授权样本的 spawn 后稳定性、TCP/UDP 归属、短连接漏采与端口复用、移动 bundle 构建和高频定位事件量。
- R1。无脚本、空脚本与普通启动在同一 Roam APK 上均存活 10 秒。旧全量脚本恢复后崩在 RenderThread，错误为 `EGL_NOT_INITIALIZED`。移动 spawn 先装隐私读取钩子，4 秒后启用其余模块。Roam 新方案连续两轮在原 spawn PID 上各完成 32 秒、0 次死亡，能看到启动期定位订阅。证据在 `output/round3-roam-20261115-191315/` 和 `output/round3-roam-20261115-191857/`。启动后的前 4 秒中，其他钩子的观测有缺口。
- R2–R4。套接字快照增加 UDP/IPv6、inode 和设备时间。应用经白名单检查后记录 libc connect、UDP send/recv 的端点和时间；归属按协议、双端 IP/端口、时间和 TCP stream 核对，快照归属要求同 inode 夹住报文时间。未知或共享 UID、端口复用反例和缺失时间的旧证据保留为未归属。pcap 排除 ICMP 引用的旧包头。根目录回归原先报告的超长文件与归属异常诊断一并处理。
- 网络夹具。自有临时 APK 仅使用设备回环。约 42 ms 的 TCP 流收到了独立服务端回执，应用 HTTP 归属为 2/21，余下 19 条保留未归属。普通 UDP 和由 aioquic 生成的标准 QUIC Initial 各 1 条，均按目标 socket 调用归属。证据见 `output/round3-network-20261115-191653/run/http-stats.json`、同目录 `attributed-udp.jsonl` 和独立 `sink/receipts.jsonl`。HTTP/3 正文、绕过已挂 libc 入口的调用及无法核实端点的流量仍有覆盖缺口。
- R5。移动构建入口 `node mobile/hooks/build.mjs` 改用项目 Python 的 Frida 编译器，按 npm 锁文件安装 Java bridge。源码编译 13 个入口通过，输出校验 UTF-8 字节长度和注入配置后原子替换。Gadget 与车载构建入口各自沿用现有配置。
- R6。4 个定位 getter 相同调用栈、线程与值的读取按 4 秒窗口聚合。保留首条原始证据，重复数及时间范围单记，正常结束刷盘。Blue 完成 GPS 复验，四类 getter 共 188 次，输出 36 条原始记录和 33 条汇总，保留 152 次重复计数，`MOB-R006` 仍命中。证据在 `output/round3-blue-20261115-191752/run/`。
- 检查与收尾。只用 socket 调用重放网络夹具，TCP 和 UDP 归属数保持一致，记录在 `output/round3-network-20261115-191653/event-only-replay.json`。临时测试 APK 已从用户 10 卸载，代理恢复为 `:0`，回环转发已清理。隔离目录 `npm ci` 复验仅安装锁定的 Java bridge，完整构建日志见 `output/round3-bundle/build-final.log`。
- 离线回归通过。仓库 23/23、内含移动侧 63/63，见 `output/round3-release-regression-20261115/verification.json` 与 `mobile/verification.json`。移动分支 26/26，见 `output/round3-release-branch-20261115/verification.json`。

## 2026-11-15 · AAOS 用户 10 的 Frida spawn 超时

- 复核 N3 的启动日志，检测显式传递 Android 用户 ID 后能否启动原授权 Roam 样本，并校验回退和启动期覆盖判据。
- 驱动按指定 Android 用户启动，未指定时读取当前前台用户。将用户 ID 传给 Frida，并按返回 PID 的内核 UID 核对用户。只在脚本装载、进程恢复均完成后发出 `FRIDA_SPAWN_READY`。流水线按实际启动方式判定，attach 回退会分开保留首段日志和事件文件。
- Frida 宿主与设备版本都是 17.18.0。最小探针显式传用户 10，在 0.234 秒返回 PID，内核 UID 为 1010276。记录在 `output/n3-spawn-user10-20261115/probe.log`。
- 原授权 Roam 在完整流水线两次获得目标用户 PID 并恢复。最终轮 `FRIDA_SPAWN_READY 18399 10 1010282`，首段有 4 条 `requestLocationUpdates` 调用记录，归档到 `output/n3-roam-final-20261115/run/spawn-attempt-reads.jsonl`。这批记录是订阅调用。随后同 PID 的 RenderThread 发生 `SIGABRT`，见该轮 `roam-spawn-crash.log`。回退 attach 完成 30 秒窗口、42 条运行时观测，验证为 `startup_mode=attach_fallback` 和 `startup_calls_covered=1`（检查退出码 1，启动覆盖有缺口）。未针对恢复后的崩溃更换 Frida 版本或调整业务钩子。
- 离线验证。共享目标选择、Frida 清理与设备工具共 41 项通过。移动回归 63/63。仓库回归 22/23，`completion` 仍报交接已有的两项守卫失败，分别是 `thirdparty_env_hook.py` 超长及 `http_attribution.py` 的静默异常。记录为 `output/n3-spawn-regression-20261115/verification.json` 和 `completion.log`。

## 2026-11-15 · 真实 APK 试点交接修复

- 复核试点交接 D1–D6，用原授权 Privacy Browser 3.20.1 重跑 AAOS 35 / user 10 的独立回执场景。
- D1 与归因。首个新窗口收到两条业务回执，但 pcap 只有 Frida 的 WebSocket HTTP 握手触发解码通过。解码器改为排除保留的回环控制端口，保留应用的同名 `/ws` 路由。新增 `--fixture-http-port`，限定自有回环业务端口，每轮使用独立设备端 pcap 路径。普通代理只持久化通过包名和 UID 核对的流，未确认流只留计数。第三方审计保留设备原有 QUIC 行为。
- D2 与 D4。汇总独立记录 APK SHA-256 和 versionCode，政策缺失时也可追溯。Proton Mail 3.0.17 离线重放的 `policy.available=false`，APK 摘要与 `version_code=33` 均已核对。设备 35 使用移动规则 36 时，汇总、证据包和报告标注适用性未经验证。移动规则库目前只登记 36，API 35 逐规则校准仍待完成。
- D3。新增具名零观测复核，保留确认依据及摘要。两类钩子就绪、日志可用、进程存活且窗口完整时，复核只将零观测降为可选失败，并将整轮标为降级。离线覆盖了钩子报错、坏日志、进程死亡和独立同意事件。未在设备上跑人工零观测分支。
- D5 与 D6。单次重跑拒绝已有运行的目录，跑批重试创建 `try-*`，续跑可识别成功子目录。实测同一目录重跑退出 2，原验证文件 SHA-256 一致。环境入口支持现成便携版，验收运行 `tshark --version` 核验可执行性，缺失时保留 pcap。换机使用已安装或预置的 tshark。
- 设备复验。连续两个指定端口窗口均还原 4 条请求、4 条响应及 4 份正文。最终轮位于 `output/pilot-repair-20261115-135141/`，验证 `passed=true`，窗口 45.1 秒，0 次死亡。按宿主窗口核对两条业务回执，再以请求路径和响应正文对到 pcap，见 `output/pilot-repair-complete-fixture/receipt-check.json`。末轮设备 pcap 时钟相对服务端约慢 1.45 秒，时间窗以宿主回执为准。首个失败窗口按最终解码器复解得到 0 条，见 `output/pilot-repair-complete-control/stats.json`。
- 回归时复现 OwnTracks 测试接收端的并发问题。客户端可先见到 503，服务端回执列表此时仍为空。接收端改为收齐正文、登记回执后再写响应。观测窗口起点文件写入失败也已加诊断。
- 离线回归通过。项目 Python 3.13 运行 `tools/run_regressions.py --mobile`，23/23 组通过，内含移动侧 63/63 项，记录为 `output/pilot-repair-delivery-root-20261115/verification.json` 与子目录 `mobile/verification.json`。`tools/check_mobile_branch.py` 26/26 组通过，记录为 `output/pilot-repair-complete-branch-20261115/verification.json`。
- 账号型实测仍缺授权测试账号和服务端回执。浏览器复验使用自有明文 HTTP 并跳过系统 CA，attach 模式的启动期会有观测缺口。多包实机负向归因、split APK、OEM 特权包以及换机部署均未验证。

## 2026-11-15 · YAABSA v1.17.0 发送归因与业务回执

- 范围：车载版 v1.17.0 隔离 Audiobookshelf 播放验收、请求级身份核对与同会话回执，另登记授权商用 APK 的试测条件。
- 改动：新增 `vehicle.lab.yaabsa_v117_run`。以同端口、同套接字 inode 的发送前后快照以及目标进程的 PID、启动标识、UID 核验回环进度请求。正文产物只保留通过身份校验的请求。前后台各一份独立 REST 回执在采集停止前登记，最后核验 SHA-256 与会话。每段均要求已归属请求与回执的服务端听音会话一致。
- 复现：`./tools/python313.ps1 -m vehicle.lab.yaabsa_v117_run --runtime <隔离ABS账本目录> --apk <v1.17.0 AAOS APK> --out <新目录>`。需自有 AAOS 35 模拟器、user 10、官方 x86_64 APK、回环 ABS 测试账户和已暂停的自有音频。
- 设备结果：`output/vehicle-aaos-readiness-20261114-213908/yaabsa-v117-business/playback-07/`。前后台均找到已归属的暂停位置提交及最终服务端进度提交。4 条请求归因通过，另 2 条缺少前后夹住发送时间的样本。两份服务端回执核验为 `binding_consistent`。客户端重复同步和超出 4 秒的对齐偏差仍可复现。
- 离线验证：`tools/run_regressions.py` 22/22 组通过，记录为 `output/vehicle-v117-binding-regression-20261115-000942/verification.json`。最终版本另跑 `vehicle.lab.test_abs_progress`、`vehicle.lab.test_business_receipts`、`vehicle.lab.test_evidence_repairs`，24 项全通过。
- 下一轮：先用 1–2 个有明确授权、可在 AAOS 35 普通安装的单 APK 做场景试点。逐个登记版本、APK 摘要、账号和后端前提、业务动作及独立回执。对缺少授权、设备前提或可见证据的场景分别记录阻断；split APK 和 OEM 特权包继续作为兼容性待办。准确率评估需要独立参考标签和重复设备轮次。

## 2026-11-15 · 授权真实 APK 首批试点（AAOS 35 / user 10）

- 范围：2 个单 APK 各一条可重复业务路径——Privacy Browser 3.20.1（无需账号，走自有回执端）与 Proton Mail 3.0.17（账号型，登记阻断）；核对运行时证据与独立回执；记录运行中暴露的项目缺陷。
- 改动：新增 `mobile/lab/pilot_receipt_sink.py`（独立回执端：GET/POST 逐条落 JSONL，含 UA/路径/时间/正文摘要，写盘即 fsync）。修 `mobile/tools/device_run_thirdparty_run1.py`：删掉写往 `sys.modules["device_run_thirdparty"]` 的死代码——脚本方式启动时该键不存在，入口在 install 前就 `KeyError` 退出（真正用的是 `ctx.prev_proxy`）。新增 [PILOT_COMMERCIAL_APK_20261115.md](PILOT_COMMERCIAL_APK_20261115.md)。
- 设备结果：三组窗口 110/100/90s 均未截断、0 次应用死亡，产物在 `output/pilot-20261115-0023/`。① 回环路径（`127.0.0.1` + `adb reverse`）：回执 2 条（窗口内），flows **0**，钩子 0 条业务外发——WebView 对回环绕过代理，Chromium 网络栈又不走 `libcore.connect`，双盲。② 同一动作改走局域网 IP：回执 2 条，flows **4**，但归因全部是 `single_package_fallback`（无 uid、无 user、无时间差）。③ Proton Mail：22 条 `WifiInfo.getSSID()` 读取、3 个后端域名、37 条连接，`--no-system-ca` 下 HTTPS 全部握手失败；无授权测试账号 → 0 条业务回执，按阻断登记。
- 判据：业务回执必须落在 `coverage.json` 的窗口内才计入，窗口外预试单列。同窗口内实测到 OwnTracks 的遗留流量，说明单包兜底归因在多包环境会记错账。
- 验证：`py_compile` 通过；`mobile/tools/run_mobile_checks.py` **63/63 通过**，记录为 `output/mobile-regression-20261115-004256-v_1evnvg/`，日志在 `output/pilot-20261115-0023/mobile-regression.log`。
- 待办：装 tshark 复解三份 pcap（现在 1.1–1.3 MB 解出 0 条报文）；修 `ui_taps_made` 与"外部注入动作"的冲突、`runtime_events_captured` 把装载事件算作观测事件；账号到位 + 解决 CA 后再跑账号型业务；split APK 与 OEM 特权包另开一轮。

## 2026-11-15 · 试点缺陷修复（P1-01/P1-02/P1-04/P2-02/P2-03/P2-04）

- 范围：修 [PILOT_COMMERCIAL_APK_20261115.md](PILOT_COMMERCIAL_APK_20261115.md) §4 里可修的六项。P1-03（回环双盲）是结构性边界，改写为跑批手册 §10.11 的操作约束；P2-01 是环境依赖（tshark 未安装），不改代码。
- 改动：
  - `device_run_thirdparty.py` / `_run3.py`：新增 `--action-log`。给了它就按"窗口内登记了几条动作"判 `business_action_made`，`ui_taps_made` 降为 optional——受控窗口下自动点击必然为 0，旧判据把每次试点判成失败。配套 `mobile/tools/log_action.py`。
  - `_helpers.py`：`LIFECYCLE_EVENTS` + `observation_events()`（装载事件不算观测）、`load_action_log()`（按窗口过滤）、`activity_namespace_matches()`（按命名空间而非完整包名）、`device_api()`。
  - `_run5.py`：`runtime_events_captured` 只认观测事件，并把 `egress.jsonl` 算进来（零读取的浏览器仍有 EGRESS_CONNECT）；correlate 增传 `--device-api`。
  - `correlate_mobile.py`：新增 `device_api` / `android_version_source`、`flows_by_attribution` / `flows_identity_verified`；兜底归因**混合场景也记缺口**（原来只在全部兜底时记）。聚合段拆到 `summary_sections.py`、归因段拆到 `flow_attribution.py`，本文件 316 → 295 行（回到 300 行硬线内）。
  - 新增 `mobile/tools/device_screencap.py`：解析 SurfaceFlinger display token、`-d` 截图、pull、PNG 校验、留证 sidecar；`screencap -d 0` 报 `Status:-2` 与 `exec-out` 写坏 PNG 两条坑都绕开。
  - 新增 `mobile/tools/test_device_tools.py`（10 例），并入 `device_tools` 组（原 `launcher_activity` 组，组数不变）。
- 验证：修复轮实跑 `output/pilot-20261115-0023/fixcheck/run`——`passed=true`、`failed=[]`、`business_action_made=0`（"窗口内 1 条动作：open_url"）、`runtime_events_captured=0`（观测 4 条）、`cross_package=false`、`device_api=35`、`android_version=36`、`flows_by_attribution={single_package_fallback:2}`、`flows_identity_verified=0`。
- 离线：`test_device_tools` 10/10、`test_analyze*` 40/40、全量移动回归 63/63，两轮：`output/mobile-regression-20261115-013702-nbahlshm/`（拆分前）、`output/mobile-regression-20261115-115411-i9s1_phi/`（拆分后）。
- 待办：tshark 仍未安装（pcap 解 0 条报文）；WebView 前台截不到内容属镜像限制，只能靠 uiautomator + 回执；`runtime_events_captured` 对"完全不读不连"的样本仍判红（有意，报告须说明）；split APK / OEM 特权包未测。

## 2026-11-15 · 便携 tshark 落地与试点结论复核

- 背景：上一轮把 pcap 解不出报文记成"环境依赖（tshark 未安装）"。核查后确认本机确实没有 Wireshark：`Program Files`/`Program Files (x86)`/`LocalAppData`/`AppData`/`C://Users`/`D://` 均无 `tshark.exe` 或 `Wireshark.exe`，无卸载注册项、不在 PATH；`winget` 源与 `wireshark.org` 均不可达，只有清华镜像 `mirrors.tuna.tsinghua.edu.cn/wireshark/` 可用。
- 做法：从镜像取 `Wireshark-4.6.9-x64.msi`（80,433,152 B），用 **MSI 管理安装** `msiexec /a <msi> /qn TARGETDIR=<临时目录>` 解出文件（不注册系统、不装 Npcap、不需要管理员），拷到 `output/_tools/wireshark`（270 MB，gitignore 范围内）。`pcap_http.find_tshark()` 增加**项目路径优先**的候选，以后不必设 `VSCAN_TSHARK`。
- 结果：`tshark -v` → 4.6.9。三份历史 pcap 复解：A1 **36** 条报文（19 请求 / 6 正文）、A2 **20** 条、B **51** 条；修复轮 pcap **24** 条。`test_pcap_pipeline.py` 全过（含 gzip/h2/缺 pcap 报错）。
- **结论更正**：A1（回环 `127.0.0.1:18899`）原先判"证据缺失"，复核发现 pcap 里完整存在 4 条 `/pilot/*` 请求与响应正文——代理与钩子确实盲，但 tcpdump（`-i any` 含 lo）抓到了。准确表述改为"代理+钩子盲、pcap 可解"，A1 判定从"证据缺失"改为"证据在第三通道"。P1-03 由"结构性"降为"部分"，P2-01 关闭。报告 §0/§3.1/§4/§5/§6/§7 与跑批手册 §10.11 已同步。
- 离线：`test_pcap_pipeline.py` 全过；全量移动回归 **63/63**（`output/mobile-regression-20261115-125542-i34h8scb/`）。
- 未变：TLS 仍有 16/5/23 帧未解（无 CA/keylog），账号型业务仍需账号 + CA；split/OEM 未测。

## 2026-11-15 · 本轮任务总结文档

- 新增 [TASK_SUMMARY_PILOT_20261115.md](TASK_SUMMARY_PILOT_20261115.md)：一页速览、执行过程、3 场景结果、9 个缺陷处置、**四类未决项**（能力边界 7 / 外部前置 3 / 未触碰 6 / 遗留待办 6）、验证状态、交付物清单、下一轮依赖顺序、操作纪律、复现命令。
- 口径修正：`verification.json` 无 `status` 字段，只有 `passed`；此前报告写的 `status=passed/failed` 已全部回改为 `passed=true/false`（本日志上一节同步更正）。
- 未新增代码改动，未重跑设备窗口。

## 2026-11-15 · 车载 APK 第二轮：3 个驾驶场景样本 + 6 项新缺陷

- 样本（F-Droid 清华镜像，sha256 与 index-v1.json 一致）：Blue Square Speedometer 1.2.1、Roam 1.2.0、AndrOBD V2.7.10。三个都是纯 Java、可装可起，但 **都不声明 `android.hardware.type.automotive`**——开源生态里的"车载 App"基本是驾驶场景手机应用。
- 业务回执第一次做到可计算：`adb emu geo fix <lon> <lat> <alt> <sats> <velocity>` 注入速度 → Blue 界面文本 `Speed=27`（7.72 m/s）、Roam 画布 36/53（10.29 / 15.43 m/s）。差值随速度增大，像一阶平滑，未深究。
- 缺陷（详见 [AUTOMOTIVE_APK_PILOT_20261115.md](AUTOMOTIVE_APK_PILOT_20261115.md) §4）：
  - N1 已修：pcap 把钩子宿主的 `GET 127.0.0.1/ws`（101）当应用报文，Blue 零流量仍判 `http_messages_extracted` 通过（假绿）。`pcap_http.decode()` 按 loopback + `/ws` 剔除整条流；重解 Blue 2→0（`control_channel_dropped=2`）。
  - N2 已修：动作比窗口早 1.3s 被整条丢弃。新增 `--action-grace-ms`（默认 5000）、`before_window_within_grace` 单列、`out/window-open.json` 标记；单测 2 例。
  - N3 未修：`--spawn-hook` 在本环境 frida spawn 超时（`TimedOutError`），回退 attach；启动期读取无可用覆盖路径。新增 `startup_calls_covered` 判据，attach 跑必提示。
  - N4 已修：解码阶段异常直接带走整轮（`keylog_from_events` 抛 `NameError: json`，进程退出、无 correlate/报告）。`_stage_decode` 包 try，降级为 `stats.ok=false`。
  - N5 未修：pcap 无应用归因。Roam 窗口 8 条报文全是系统 `connectivitycheck`/`google` CONNECT/`OwnTracks POST`（502），被测应用 0 条。
  - N6 未修（能力边界）：`requestLocationUpdates` 记 `observe/empty`，值经系统回调返回，钩子看不到 → MOB-R006 不触发，Blue 只有 2 条 over_permission candidate。
- 另修：`device_run_thirdparty_helpers.py` 缺 `import sys`（`load_action_log` 坏行分支会 NameError），单测抓到。
- 验证：`test_device_tools` 14/14；`py_compile` 通过；全量移动回归 **63/63**（`output/mobile-regression-20261115-134829-tx67vld6/`）。
- 运维：多轮间出现残留 `http_proxy=10.0.2.2:8888` + mitmproxy 监听（中断/失败轮次后）；设备上 OwnTracks 常驻并向 `10.18.80.25:18145` 重试，污染每个窗口。已还原 UXR/代理并停掉本轮三个样本。

## 2026-11-15 · 第二轮修复：N5 报文归属 / N6 定位取值点（N3 仍为环境限制）

- N5 根因不在 pcap，在 uid：`app_uid()` 固定用 `--user 0`，拿到 appId 10276，而 user 10 的内核 uid 是 1010276，`conn_probe` 一条也匹配不上（Proton 37 条连接、`conns.jsonl` 恒 0 行）。修 `thirdparty_env_hook.app_uid()`：先查 `am get-current-user`，再按 `user*100000 + appId` 换算（已是内核 uid 的不再加）；新增 `current_user_id()` 并由 `thirdparty_env` 导出。实采：OwnTracks 6s 15 行、Proton 窗口 7 行（uid 1010280）。
- 新增 `mobile/analyze/http_attribution.py`：按 conn_probe 的 `local_port` 与报文本地侧端口归属；`device_run_thirdparty_run4` 解码后调用，`http_messages_extracted` 改为"只认归属到被测包的报文"。实测 Blue 7 条 0 归属（判红并写明"不得写成被测应用的外发"）、Proton 28 条 4 归属（`target_ports=7`，通过）。
- N6：`seed/api_targets.json` 新增 `Location.getLatitude/getLongitude/getSpeed/getAccuracy`（read/direct/precise_location）→ `extract_android_apis` 62 facts → 重建 `rules_mobile.db`（58→62 API；旧库备份 `.bak-20261115`，其余表仅 `source_refs_json` 的 jar 路径由笔误 `D://Anroid//...` 更正为真实 SDK 路径）→ `gen_targets.py` 62 条。
- `node build.mjs hook_all` 不可用（`frida-compile` 依赖的 `frida_binding.node` 无预编译产物）。新增 `mobile/hooks/patch_bundle_targets.py`：只替换 `var WATCH` 数组、**重算 📦 包头每模块 UTF-8 字节数**（不重算会 `Frida bundle 长度校验失败`，本轮踩过一次），写完调 `bundle_config.configure()` 自检。WATCH 58→62。
- 实测 Blue（75s）：`PRIVACY_READ` 4 → **52**，`getSpeed/getLatitude/getLongitude/getAccuracy` 全 `obtained`；观测事件 4 → 124；结论 2 → **4**，出现 **MOB-R006 observed**。
- 回归：`test_rules` 13/13、`test_dispatch.mjs` 40/40、`test_privacy_implementation` 全过、`test_http_attribution` 5/5、`test_device_tools` 14/14、全量移动 **63/63**（`output/mobile-regression-20261115-181722-zun98fli/`）。首跑曾因新测试未登记、`MOB-E006` 断言过时而失败 2 项，已修（测试加进 analyze 组并实际执行）。
- N3 未修：`--spawn-hook` 仍 `frida.TimedOutError`，回退 attach 正常；保留 `startup_calls_covered` 判据让盲区可见。
- 文档：[FIXES_20261115_ROUND2.md](FIXES_20261115_ROUND2.md)；试点报告 §4 的 N5/N6 状态已同步为"已修"。

## 2026-11-15 · 车载 APK 第三轮：gpsdRelay 内容级回执 + 3 项工具缺口

- 样本（F-Droid 索引 4987 → 车域 70 → 纯 Java 26 里选 3 个跑窗口 + 1 个仅安装）：gpsdRelay 2.2、Stateful Speedometer 0.2.0、TpmsMonitor 0.0.1a、EDL Dashboard 1.7。四个 sha256 与 `index-v1.json` 一致，**均未声明 `android.hardware.type.automotive`**（第 2 轮结论再确认）。
- **第一个内容级回执**：gpsdRelay 是"自己监听、gpsd 来连"的模式（表单默认 `0.0.0.0` 即提示）。新增 `mobile/lab/nmea_tcp_sink.py`（监听/客户端双模式），经 `adb forward tcp:18961 tcp:18960` 连上去读，窗口内拿到 **333 行 NMEA**：框架流 105 条 RMC（校验和 105/105 正确）+ 应用自产 114 RMC + 114 GGA。注入 `velocity=15` → 110 行 15.00/14.999988，`velocity=22` → 107 行 22.00/21.99998，GGA 高度 50.0 与注入一致。**`geo fix` 第 5 参数单位是节**：15 节 → 内核 `vel=7.71666 m/s` → NMEA 15.00，三处自洽（这也解释了第 2 轮 Blue 27 km/h、Roam 36 的来历）。
- 样本缺陷：gpsdRelay 自产句的校验和是**常量 `*47`**，228 条里只有 11 条碰巧正确；GGA 的 geoid 写成 `0.,M`（缺小数位）。严格解析器会丢掉 95% 的自产句。
- 本轮工具缺口（详见 [AUTOMOTIVE_APK_PILOT_ROUND3_20261115.md](AUTOMOTIVE_APK_PILOT_ROUND3_20261115.md) §5）：
  - **D1 高 · pcap 解码只认 HTTP**：NMEA 载荷在 pcap 里可还原（629 包 @18960，`244750524d43…` = `$GPRMC`），但 `http_messages.jsonl` 0 条，判据只能写"27 条报文 0 归属"。MQTT/gpsd/LwM2M 这类车载上报全部落在盲区。
  - **D2 高 · 外发判定不覆盖"应用是监听方"**：`flows`（mitm）与 `egress`（`connect()`）都假设出站。gpsdRelay 持续外发精确位置，工具侧 **0 条 `data_egress` 结论**，只有 `over_permission` + `over_collection candidate`。
  - **D3 中 · 规则库缺 BLE 扫描**：只有 `getAddress/getBondedDevices/getName`，没有 `BluetoothLeScanner.startScan/stopScan`、`startDiscovery`；TpmsMonitor 用 `startScan`+`ScanCallback`，窗口内 0 条读取、1 条观测事件。
  - **D4 已修 · `--skip-install`**：默认 `uninstall` 会清掉"业务前提是既有配置"的夹具（服务器地址、传感器配对）。判据写 `pre-installed`，不冒充干净安装。
  - **D5 已修 · 回执端空连接重试**：`adb forward` 宿主侧 connect 总成功，设备侧端口没开时 adbd 立刻关闭 → "连上 0.01s、读到 0 行"，第一版当成"应用没发数据"退出。现在记 `PORT_NOT_READY` 重试（本轮实际发生 2 次）。
- 附带：应用内配置靠坐标点击，无声明式脚本；已导出 Room 夹具 `output/auto-apks-20261115/gpsd-clean.db`（`Server(type=1, ipv4=0.0.0.0, port=18960, relaying=1, generation=1)`），下轮 `adb push` 可跳过界面配置。
- 结果：三个窗口 `passed=true` / `failed=[]` / 未截断 / 0 死亡。gpsdRelay 10 条结论（`MOB-R006 observed` + 8 权限）；Stateful 4 条（与第 2 轮 Blue Square 完全同型）；Tpms 2 条、无业务数据。
- 验证：`py_compile` 通过；全量移动回归 **63/63**（`output/mobile-regression-20261115-202914-itmmoqoz/`）。

## 2026-11-15 · 第三轮修复：D1 行协议 / D2 外发通道 / D3 BLE 扫描 / 声明式 UI

- **D1 已修并真机验证**：新增 `mobile/tools/pcap_lines.py`（tshark 单趟取 `tcp.payload` → 按行切 → nmea/json/text 分类 + NMEA 校验和；HTTP 流整条剔除）。`device_run_thirdparty_run4._stage_decode` 并行跑一趟，产出 `line-messages.jsonl` 与 `line_*` 统计，并新增 optional 判据 `line_payload_attributed`。实机 `run-gpsd3`：**101 行 nmea，归属 101**，依据 `socket_inode_bracket=54 / listen_port=47`，监听端口 18960。
- **D2 已修（证据层）**：`summary_sections.egress_channels()` 把代理流 / 钩子 connect / pcap HTTP / pcap 行协议四路摊开，任何一路为空都不再等价于“没有外发”；只在 pcap 行协议有证据时写专门缺口，并明说“本轮未产出 data_egress 结论”。同时修了 `http-stats.json` 的查找位置（采集阶段写在运行根目录，findings 在 `<run>/out/`，原实现按 `out.parent` 永远找不到）。
- **D3 已落地、未实机验证**：seed 41→44（`BluetoothLeScanner.startScan/stopScan`、`BluetoothAdapter.startDiscovery`，observe/args_only）→ extract **68 facts / missing 0** → 规则库 `dangerous_apis` 62→**68**（其余 5 表零变化，旧库备份 `.bak-20261115b`）→ `gen_targets` WATCH **68** → `patch_bundle_targets` 注入并过 `bundle_config.configure()` 自检。两次实机尝试（点 `SEE ALL SENSORS READING`、`su 0 am startservice …/.services.BackgroundScanner`）均 0 条读取；`SKIPPED_JAVA` 只涉及 Camera/SensorManager/AudioRecord，蓝牙类未被跳过——说明是样本扫描触发条件未知，不是插桩问题。
- **附带项**：新增 `mobile/tools/ui_script.py`（声明式步骤：wait_text/tap_text/tap_desc/tap_xy/input_text/key/sleep/assert_text/screencap；按文本定位优先，找不到即失败）与夹具 `mobile/lab/scripts/gpsdrelay-add-tcp-server.json`。实机 **17/17 步通过**，落成 `Server(0.0.0.0:18960, enabled=1)`，导出 `output/auto-apks-20261115/gpsd-clean.db` 供下轮 push。脚本里写明“行内开关必须在按启动之前打开”（服务只读一次 enabled 列表）。
- 工程守卫：`pcap_lines.py` 补“仅用于授权测试”声明；3 处静默吞异常分别改为 `# noqa: BLE001 <理由>`（2 处）与计数（1 处）；`correlate_mobile.py` 300→300 行（压缩一处解包换出新增行）。
- 原始统计为回执 128 行、pcap 101 行。后续对账证实 27 行回执在审计窗口外，窗口内全部吻合。`conn_probe` 提前结束使 47 行缺少双侧快照，原实现以 `listen_port` 标注这些行。
- 验证：`test_pcap_lines` 10/10、`test_http_attribution` 8/8、`test_egress_channels` 5/5、`test_rules` 13/13；测试清单 `unregistered=0`；工程守通过；全量移动回归 **63/63**，两跑：`output/mobile-regression-20261115-204433-c1nukdmn/`（改查找位置前）、`...-205018-bryuyirw/`（最终）；实机 `run-gpsd3` `passed=true`。
- 文档：[FIXES_20261115_ROUND3.md](FIXES_20261115_ROUND3.md)；试点报告 §5 已标注 D1/D2/D3 状态。

## 2026-11-15 · 车载 APK 第四轮：AndrOBD × 假 ELM327，CR-only 行协议从 0 行到 4419 行

- 样本：`com.fr3ts0n.ecu.gui.androbd` **V2.7.10**（`targetSdk=36`，SHA-256 前缀 `71d3cecd69b644da`）。前三轮走的是"定位类"，这轮补**命令-应答型**车域业务：应用连 ELM327 → 读 ECU → 显示测量值。新增 `mobile/lab/elm327_tcp_sink.py`（宿主侧应答端，监听 35000，22 个 PID 值写死便于对账，`0902` 走 ISO-TP 多帧，逐条写 `receipts.jsonl`）。
- 夹具：root 直写 **user 10** 的 `shared_prefs`（`comm_medium=4` / `device_address=10.0.2.2` / `device_port=35000` / `protocol=0`），导出 `output/round4-elm-fixed/androbd-prefs.xml`。注意两点：`/data/data/…` 是 user 0 路径，user 10 要 `/data/user/10/…`；适配器类型列表一次只渲染一行，`NETWORK` 要滑动才出现（看起来像"只有 DEMO"）。
- **D6 高 · 已修**：`tcp_line_reassembly` 只按 LF 切行，ELM327 整条会话没有 LF → 修前窗口（2370 条请求 / pcap 4051 个载荷包）`line-messages.jsonl` **0 字节**、`pcap_line_from_app=null`。改成"有 LF 用 LF、只有 CR 时退到 CR"，并在 `pcap_lines.classify` 加 `obd`（`at/status/hex/pid`）与 `>` 提示符剥离。修后同一路径：**4419 行（obd 4418），归属 4419/4419**（`socket_inode_bracket=4389`、`tcp_stream_socket_inode=30`），`from_app 2210 / to_app 2209`，`pcap_line_from_app=2210`，`hook_egress=2`（首次非零）。同一份修前 pcap 离线重解也复现 0 → 4051 行。
- **D7 中 · 已修（环境）**：报告阶段 `ModuleNotFoundError: reportlab`，采集/关联/判据全过却整轮 `failed:["report"]`。按项目解释器装 `reportlab 5.1.0`，修后同命令 `status=passed`。建议后续在开跑前检查报告依赖，缺失时"不出 PDF 但不判失败"。
- **D8 中 · 已修（夹具）**：Windows 的 `SO_REUSEADDR` 允许两进程同时监听 35000，旧回执端没退干净时新回执端"在跑但一条收不到"。改为 Windows 用 `SO_EXCLUSIVEADDRUSE`、类 Unix 才用 `SO_REUSEADDR`。
- **D9 / D10 · 未解决**：`uiautomator dump` 在该样本上恒 `ERROR: could not get idle state`（界面持续重绘），本轮改用坐标点击 + 截图核对 + `log_action`，`ui_script` 的文本定位不可用；回执端按真实 ELM327 语义回 ISO-TP 头时，AndrOBD 探测完 ECU 后 6s 主动断链，原因未明，因此对照窗口用 `--header-mode off`。数值级回执（界面出现 1726 rpm / 88 km/h）**未取到**，如实记为缺口。
- 结果：修后窗口 `passed=true` / `failed=[]` / 未截断 / 0 死亡；10 条结论（8 权限 + `MOB-P002/P0xx` 类，全部 `candidate`）。
- 验证：`test_pcap_lines` 19/19（新增 CR-only 切分、LF 优先、AT/hex 分类、提示符剥离 4 条）、`test_egress_channels` + `test_http_attribution` 14/14。
- 文档：[AUTOMOTIVE_APK_PILOT_ROUND4_20261115.md](AUTOMOTIVE_APK_PILOT_ROUND4_20261115.md)。
