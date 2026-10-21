# 2026-09-25 缺口补齐与复现

仅用于授权测试（自有设备、自有 APK）。APK 静态反编译作为独立工作台加入（vehicle/workbench）；违规行号仍只取自运行时栈。
本文件描述当前交付；各 DECISIONS 的旧记录保留为历史证据，不能当成当前状态。

> **适用范围（2026-10-19 补注）**：本文主体是**车载线 + 共享内核**的交付与复现说明（写于 2026-09-25）。
> 移动端在 10-16 → 10-19 已独立成第二条产品线，当前状态**不在**本文里：
> 看 [mobile/README.md](mobile/README.md)（能力与边界）、[mobile/DECISIONS.md](mobile/DECISIONS.md)
> （M001–M040 决策）、[DELIVERY_INDEX.md](DELIVERY_INDEX.md)（移动端文档入口清单）。
> 合并 ch / junzhe 后的入口与回归基线见根 [README.md](README.md)。

交付索引与验收结果见 [DELIVERY_INDEX.md](DELIVERY_INDEX.md)。

## 当前实现

| 项目 | 实现与边界 |
| --- | --- |
| 域名/IP 归属 | `vehicle/analyze/ownership.py`：RDAP 注册信息、HTTPS IP 地理估计、可校验离线缓存、可选 MMDB。注册商不当成接收机构，注册国家不当成服务器位置；缺失明确标未知。 |
| 明文截图 | `vehicle/traffic/payloads.py` 捕获请求/响应字节和摘要；PDF 按真实载荷生成 PNG。原始捕获上限1MiB，报告展示上限160行；截断与旧 preview 单独标示。 |
| 时序存储 | `core/event_store.py`：SQLite WAL，按会话/包名/时间索引、范围查询、时间桶统计、JSONL 导入导出；采集时双写原始 JSONL。属于单机时序事件库。 |
| Gadget | `vehicle/hooks/gadget_prepare.py` 为自有源码生成 Gadget 构建变体，在 Application.attachBaseContext 加载，loopback:27044、on_load=wait；`run.py --gadget` 注入后恢复。 |
| OkHttp | 两个夹具增加错误 pin 的 OkHttp 4.12 请求按钮；已实测触发 CertificatePinner 绕过并收到200。 |
| 订阅 | 两夹具增加10秒订阅按钮；已实测 GEAR_SELECTION 回调。注册事件不算成功读取。 |
| 外发规则 | 每版 E001–E008 启用，window_ms=30000，revision=2；双版本共16条外发规则，全部44条风险规则启用。见 `vehicle/rules/EGRESS_CALIBRATION.md`。 |
| 关联加固 | 只关联同会话、同包、非歧义的请求内容；默认用主机接收时间，禁用规则不求值，启动日志与失败连接不参与归因。 |
| 覆盖缺口 | PDF 和看板按本轮数据计算无规则属性。核对备份库发现原库已含8属性规则，CURRENT_GEAR对应R004；不沿用“只有3属性”的旧描述。 |
| 接收端 | `vehicle/traffic/collector_server.py` 实现 POST /collect，返回200、字节数和摘要。 |

## 当前环境与入口

```powershell
. .\environment.ps1
& $VScanPython -m pip install -r requirements.txt
node vehicle/hooks/build.mjs
node vehicle/hooks/node_modules/frida-compile/dist/cli.js vehicle/hooks/fixture_control.js -o vehicle/hooks/dist/fixture_control.bundle.js
& $VScanPython tools/run_regressions.py
```

SDK 为 `D:\Anroid\SDK`，`JAVA_HOME=D:\Anroid\JDK`（JDK 21，不是 JBR 25）；使用 Python313 实际解释器，WindowsApps 是别名。
Gradle8.13、API36 与构建工具36 已装（Gradle 由各工程 gradlew 包装器提供，发行版缓存于 `~\.gradle\wrapper\dists`）。
`environment.ps1` 配置 JDK 的短临时目录，避免 Windows 非ASCII路径导致 NIO 本地套接字失败。
新建独立 AVD `VScanner_AAOS_35`，Android15，应用 user10，不改既有 Pixel AVD。

> 注：本文件早先段落里的 `E:\Android\android-sdk` / `.tools\jdk21` 是**旧开发机**（OneKyubey 用户）的
> 路径，已于 2026-10-12 拆分收尾时校正为当前主机；换机只改 `environment.ps1` 顶部三个 `$VScan*` 默认值。

## 设备验收

已启动 emulator-5554 且 Frida server 监听设备回环27043时：

```powershell
& $VScanPython tools/device_acceptance.py
& $VScanPython tools/gadget_acceptance.py
& $VScanPython tools/multi_acceptance.py
```

每轮保存到独立 `output/device-*`、`output/gadget-*`、`output/multi-*` 目录。
`output/latest-*.txt` 指向最近一次尝试；判断是否通过必须读该目录 `verification.json`，不能只看目录存在。

> **2026-10-19 状态**：`output/` 内历史跑批产物（208 项）与全部 `latest-*.txt` 已清理，
> 只保留 `pdf/`、`frontend-review/`、`completion/`、`dataset-quality-20261019/`、`frontend-shots/`
> 和指向 `D:/vscanner-tp` 的 `tp-*` 链接。下面的命令可直接重跑（各工具自建目录）；
> 但 `tools/verify_presentation.py` 依赖 `latest-delivery.txt`，须**先跑 `build_delivery.py`**。
> 因此本文其余章节中提到的 `output/<时间戳>/` 证据路径均为**历史轮次**，已不可访问；
> 需要证据请按本节命令重跑，不要引用旧目录路径。
Gadget 验收会安装 Gadget APK并在结束时停止等待型进程；multi验收会恢复普通 Debug APK。
multi使用ADB回环转发与真实双App，600ms错峰/50ms近同时触发；Wi-Fi/SLIRP轮次的超时证据保留。
夹具控制脚本只允许两个自有包，触发原有按钮；它是验收控制器，不是审计Hook。
代理临时证书仅匹配本机地址，不安装到系统证书库；它使 OkHttp 到达 pin 校验分支。
Wi-Fi 掉线会使连接失败，失败连接不再作为归因候选；恢复自建模拟器 AndroidWifi 后重试。

## 通用采集约定

所有 `run.py` 使用相同 `--session`，代理设置相同 `$env:VSCAN_SESSION`。
`VSCAN_EVENT_DB` 与 `--event-db` 可指向同一SQLite库；JSONL 各采集器独立文件。
新授权包同时配置 `--allow-package` 与 `VSCAN_PACKAGES`，默认仍仅两个夹具。
允许包名不等于已授权设备：只能在已获授权的自有测试环境使用。
Gadget需要自有源码构建和安装权限；该路径不重打包、不反编译、不做无授权注入。（独立的静态分析工作台见 vehicle/workbench，只读 APK、只分析已获授权样本。）
server attach只能观察附加后的行为；Gadget wait覆盖应用恢复后的行为，不能追溯加载前动作。

```powershell
& $VScanPython core/event_store.py --db output/session.sqlite --session SESSION --bucket-ms 1000
& $VScanPython core/event_store.py --db output/session.sqlite --session SESSION --start-ms START --end-ms END --export-jsonl output/range.jsonl
& $VScanPython vehicle/analyze/ownership.py --flows output/flows.jsonl --cache output/rdap-cache --out output/ownership.json
```

归属查询默认离线；显式 `--online` 才查询公网，仅发送域名/IP，不发送载荷。
可选 `--geo-db path/to/database.mmdb` 使用用户合法取得的 MMDB。
已实测HTTPS查询与离线缓存；MMDB适配器未随项目分发数据库，尚无真实MMDB端到端验收。
在线接口失效、限流、隐私隐藏均保留失败/未知状态，不编造机构与地理位置。

## 必须保留的适用范围

- native TLS、Cronet、MQTT、QUIC、自定义加密，以及 gRPC 消息解码不在当前捕获能力内；不能声称支持所有第三方 App 或所有协议。
- RDAP注册主体、IP网络机构、服务器实际运营者是不同事实；位置只是IP库/API估计。
- 同时外发无法可靠区分时标 ambiguous，Phase5不产生 correlated；3秒延迟仍不能消除统计归因的全部误差。
- 属性名/ID出现在请求中是内容线索，不证明具体属性值泄露；工具不产生 policy_violation。
- dex核对保留；只证明行号属于装机APK的方法行号表，不证明违规语义。它**不是**静态反编译流水线——静态分析是 vehicle/workbench 这个独立工作台，两条链不混用。
- 窗口30000ms是既有夹具实测校准参数，不能当成法律阈值或所有App通用参数。
- 订阅回调在运行时栈显示Native Method，2条位置记录无源码行号；保持INCOMPLETE，不推测行号。

## 资料

- Frida Gadget 官方契约：https://frida.re/docs/gadget/
- RDAP：https://about.rdap.org/
- IP位置接口：https://ipwhois.io/documentation

## 2026-09-28 证据链加固

同一台设备上重跑并全部通过：设备验收 6/6（新增 `no_unanswered_requests`）、
双应用 6/6、Gadget 23 条读取、交付 16 条结论（6 candidate / 5 observed / 5 correlated）、
dex 40 项核对（38 VERIFIED / 2 INCOMPLETE）、PDF 与看板 QA、前端 22 项 × 3 视口。
离线回归 108 项（含新增 21 项反例）。细节见 vehicle/traffic/D411、vehicle/analyze/D511。

新增的可见字段：`summary.json` 的 `inputs.bodies_truncated` / `bodies_undecodable`、
`provenance.json` 的 `unanswered_requests` 与 `session_manifest`、
会话目录的 `session-manifest.json`。

**新增的适用范围边界（实测，必须保留）**：无响应请求单独落盘（`flows-unanswered.jsonl`）
覆盖的是"**连上了、然后失败**"（对端断开、响应中途失败、协议错误）。实测 mitmproxy 12.2.3
反向模式下，**上游连接被拒时一个流 hook 都不调**（只有 `load`），客户端连接被直接丢弃——
这条路径当前无法观测，不得声称覆盖了"上游不可达"。三情形对照见 vehicle/traffic/D411。

**未做、且已想清楚为什么不做**（不是遗漏，是判断）：

- **内容证据分级**（属性标记命中 / 结构化字段+值匹配 / 有转换依据的匹配）：
  现行实现用 `content_match_basis: 'request_property_token'` 与 note 如实标注了
  "不证明具体值泄露"。仓促加"值匹配"会削弱这个诚实边界，而且车速、挡位等
  常见值重复率高，仅凭数值相等推不出来源。它需要自带评估方法的独立工作。
- **规模与实验矩阵**：连接复用、延迟上传、只读不发、同名不同值、采集器重启、断网、
  双应用并发；分别统计归因正确率 / 歧义率 / 无法归因率与关联准确率、召回率、采集开销。
  需要先建长时间采集基准。**30000ms 窗口是夹具校准参数，其适用范围应由这些实验给出**，
  在此之前不能当成通用阈值。

## 2026-09-28 量化实验

新增两套**离线、可复现**的量化实验，结论见 [EXPERIMENTS.md](archive/EXPERIMENTS.md)，
入口 `python tools/run_experiments.py`（结果写 `output/experiment-*`，与
`run_regressions.py` 分开：那边判"有没有坏"，这边只出数字）。

- 归因：容差与歧义窗都按设计工作（解析预测与实测 **228/228** 一致）；
  但**歧义保护只覆盖 ±500ms**，本包事件离流较远而竞争者更近时会被整条抢走且不标记。
  实测锚点（自己早 2ms）下从不出错——**夹具坐在安全区里**，所以单靠夹具看不出这个风险区。
- 关联：15 条语义场景 **precision 1.0 / recall 1.0**；30s 窗口覆盖两个夹具实测间隔。

边界：这些是**构造时序下的规则语义**结果，不是真实 App 的误判率——后者需要长时间真机
采集来估计事件迟到与读取→外发间隔的分布。**30s 仍是夹具校准值，不是通用阈值。**

## 2026-09-28 Phase 7：APK 静态分析工作台

新增独立工作台：拖入 APK → 现场看反编译源码 + 用**本项目 rules.db** 做静态匹配
+ 与某次采集会话做**四象限对照**。做法与坑见 [vehicle/workbench/CLAUDE.md](vehicle/workbench/CLAUDE.md)、
[vehicle/workbench/DECISIONS.md](vehicle/workbench/DECISIONS.md)（D701–D710）。

**这不是新增禁区，而是补上申报书原本就要的**：`vehicle/rules/spec_extract.txt:114`
（"违规代码行号（通过反编译对齐）"）与 `:138`（"从 APK 自动反编译、权限静态分析…"）
本来就是申报书条款；项目一度按用户要求把静态反编译排除（2026-09-28 由用户解除）。

**边界（必须保留）**：

- 静态证据等级**封顶 `candidate`**，`observed` 在本项目专指运行时观测。工具不产出
  `policy_violation`。静态结论**不写进 `code_locs`、不参与 dex 核对**——D507 的
  "违规行号只来自运行时栈"继续成立，两条链不混用。
- **不做数据流分析**：只能得出"代码里引用了 X"，得不出"运行时的实参是 X"。
  实测夹具里 8 个属性 ID 同时出现，单条属性的 ID 出现**没有区分力**，已按 `weak` 报告。
- 只读 APK：不重打包、不签名、不注入、不修改。只分析已获授权的样本。
- **不替代 vehicle/dashboard 看板**：D601 要求看板静态单文件，而上传+反编译必须有服务端。
  两者并存，`dashboard.html` 未改动，也未接进 `build_delivery.py` 的报告流水线。

端到端验收 8 项全过（当时指针 `output/latest-workbench.txt`，**该目录已于 2026-10-19 清理**；
复跑 `tools/workbench_acceptance.py` 会重建）：权限 8 条与动态路径一致、
3 个 dex 全扫、`GEAR_SELECTION` 在 `classes3.dex` 找到、静态等级封顶、
四象限 16 both / 6 static_only / 0 dynamic_only、身份证明为同一个 APK、
反编译 930 个类、5 个部分失败被记成缺口。

## 2026-10-11/12 增补：产品线拆分 + 内存 Hook + 透明代理

**拆分**（已提交，每步离线回归全绿）：仓库重构为 `core/`（平台无关内核）+
`vehicle/`（车载，原 phase1–7 语义化改名）+ `mobile/`（移动端）+ `frontend/`（车载前端壳）。
规则库分开（`VSC-` / `MOB-` 前缀，见 `core/rules_contract.py`）。进度与待办见 [AGENTS.md](AGENTS.md)。

**内存 Hook（车载 `vehicle/hooks/`，2026-10-11）**：补齐申报书「内存 Hook 截获明文 Buffer」缺口，
新增 `hook_cipher.js`（JCE `Cipher.update/doFinal`，截获自绘加密**加密前明文**）、
`hook_native_ssl.js`（BoringSSL `SSL_write/SSL_read`，截获 native TLS 明文）、共享 `stack_capture.js`；
夹具新增 `CipherSender`（AES/GCM）+ 按钮「4. 自绘加密外泄」。离线编译与 `test_runtime.mjs` 通过，
**设备端实测待跑**（AAOS 模拟器 + frida-server 27043）。边界：不覆盖静态链接自有 BoringSSL 且
符号不导出的栈（Cronet 常见）、不经 JCE 的手工加密。

**透明代理（移动 `mobile/traffic/transparent.py`，2026-10）**：模拟器级强制代理
（`emulator -http-proxy`）+ 系统级 CA，让第三方 App 流量无法绕过抓包——不依赖 App 是否读取
系统代理设置（实测 NewPipe 用 loopj/AsyncHttpClient 完全无视 `http_proxy`，而 `-http-proxy` 对其有效）。
之所以不走设备上 `iptables -t nat REDIRECT`：代理跑在宿主机时 `SO_ORIGINAL_DST` 查不到原目标，
必须代理与 iptables 同机。带 `test_transparent.py` 离线自检。
