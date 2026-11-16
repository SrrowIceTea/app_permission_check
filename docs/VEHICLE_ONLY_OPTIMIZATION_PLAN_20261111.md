# 仅车载端：缺陷评估与优化范围更正

> **历史快照（2026-11-11 归档，不作当前清单）**：现在什么状态、本周做什么见 [CURRENT_STATUS.md](CURRENT_STATUS.md)。

日期2026-11-11；源码基线0cc32a9。仅用于授权测试（自有AAOS设备与授权APK）。
用户最新约束：移动端暂不开发。本文替代上一版混合方案作为当前建议。
本次只修订文档、读取代码并运行合成函数反例，没有修改业务代码、操作设备或启动移动端开发。

## 1. 开发边界

- 主责目录：vehicle/hooks、vehicle/traffic、vehicle/privacy、vehicle/analyze、vehicle/pipeline、
  vehicle/scenarios、vehicle/bench、vehicle/policy、vehicle/webapp及现有vehicle/frontend。
- core仅在车载有明确需要时作最小共享修改；兼容验证不等于开发移动功能。
- 不修改mobile功能，不接手机Gadget/重打包、移动批处理、移动探索器；不安排手机商用APK批次。
- 不合并origin/ch整条移动分支。论文可借鉴方法，不因此引入另一条产品线。
- 车载商用App和数据集优先在AAOS上测试；不兼容AAOS的手机样本不计车载漏检。

## 2. 上一版哪些内容应撤出车载清单

| 上一版说法 | 核对后的车载事实 | 当前处理 |
|---|---|---|
| 批量静态复用只按包名/完成标记 | 反例针对mobile/tools/batch_*，不能直接套到vehicle | 撤出车载缺陷表 |
| 移动Hook入口没有传多进程/user | vehicle/pipeline/capture.py默认multi_process=True并传--multi-process及用户 | 不再安排“车载接入多进程”；保留晚启动/重启覆盖问题 |
| UDP/443主动DROP | 指向mobile/tools/device_run_thirdparty_run1.py，本次未在车载入口发现相同动作 | 撤出车载修复清单；保留车载QUIC观测边界 |
| 移植origin/ch Fastbot/LLM手机探索 | 该分支主要是另一条移动开发线 | 当前不移植；先完善车载已有场景/业务断言 |
| 手机原包/重签/Gadget三臂测试 | 属移动实验入口；不是车载当前主线交付 | 暂停 |

这些问题可以作为未来移动端备忘，但不是当前车载任务，也不应合并成车载检测率结论。

## 3. 当前车载真正要处理的问题

| 优先级 | 已核实的车载问题/边界 | 开发目标与验收 |
|---|---|---|
| P0 | vehicle/privacy/evaluation.py的通用外发pairs没有携带PID，paired_ids仅用evt_id；定位实验已修PID不代表其他路径已修 | 补充通用/VHAL/专用求值器的引用审计，保留PID及会话上下文；两PID同号不合并成唯一来源 |
| P0 | capture.py关闭TLS绕过时接受TLS_BYPASS_DISABLED，preflight.py通用模式仍要求PINNING_ARMED | 统一开关与健康契约；关闭/开启分别验证，不能把合法关闭当Hook失败，也不能免除真实就绪检查 |
| P0 | 新bundle/SDK/展示修复与旧采集时点不同 | 用当前实际加载bundle产生新会话，业务动作/回执与健康封存绑定；不继承旧签核 |
| P1 | core多进程是初次枚举/附加；晚启动、重启、PID重用仍有时间边界 | 增加不挂起、不篡改的生命周期观测，记录附加前区间与失败；覆盖缺口入报告 |
| P1 | Web车载live入口要求App已安装运行，capture本质是attach | 记录启动行为盲区；先优化可重放的业务流程，不能宣称首启全覆盖 |
| P1 | MG4等代理流可能无法绑定严格UID/user，短连接/NAT/复用有缺口 | 设备侧观测对照＋Hook/代理交叉核验；统计unknown/错误归因，不采用单白名单兜底 |
| P1 | 通用外发evaluate主要处理android_id/contacts；定位为五种整对字符串实验；专用业务路径仍多 | 按AAOS真实输入选有限通用source/sink与格式扩展，带负控/规则依据/窗口标定后才考虑默认接线 |
| P1 | gap_scheduler的收益比较是合成控制，不是实际设备业务探索效果 | 将已有场景、业务前提、执行断言与真实观测账本连接，固定预算比较有效触达 |
| P1 | SDK归属已实现前缀候选，但混淆宿主代码也可能落third_party_unknown | 未知来源不直接断言第三方；库指纹作为可选侧车，区分包含/链上出现/数据路径 |
| P2 | 完整动态范围主要实测API35；13/14/16的通用/规则登记范围各异，Web入口静态版本有固定值 | 做入口/版本能力矩阵，按当前支持范围运行，不直接宣称四版本完整验证 |
| P2 | device.ordinary_identity明确拒绝split APK；OEM系统签名/特权App不属于普通第三方入口 | 商用样本登记安装形态/权限/服务条件；split全集支持单独设计，系统包保持边界，不自动提权 |
| P2 | 车载政策关键词不能稳定表达主体/接收方/否定/必要性 | 增加结构化review材料与原文定位，保留人工必要性判断，不自动输出法律结论 |

第一个P0已经运行车载通用求值器合成反例：同UID的PID100和101各有evt_id=1、同值读取，
输出2个候选却报告source_ambiguous_flows=0，两个pair均read_pid=None、source_read_unique=True。
这是车载通用路径的代码级问题，不是移动问题；本次未修代码，也不是设备测量。
TLS项是当前两个入口事件要求的源码不一致；应以关闭/开启的独立用例确认修复，不降低门禁。

## 4. 车载实施顺序

| 阶段 | 车载交付 | 晋级条件 |
|---|---|---|
| 第一阶段：可信基线 | 通用引用PID修复、TLS就绪契约；当前构建的新采集/业务证据索引 | 跨PID/user/session、错误输入、关闭TLS等必选反例正确；新设备健康与实际bundle可追溯 |
| 第二阶段：增加真实观测 | 进程生命周期、连接归因对照；已有AAOS场景与断言接线 | 同预算增加真实取得/可核验正文；记录新增盲区、错误归因及运行开销 |
| 第三阶段：增加通用能力 | 有真实输入支持的定位/格式/转换链、SDK来源、车载政策结构化 | 不依赖新增整套专用App求值器；正负控与独立参考充分；实验不自动升级违规 |

若仅一周，限定第一阶段和少量真实AAOS样本，不承诺同时完成多协议、四版本、OEM适配。
前端已有，不重建界面框架；只按实际需要增加进程/连接/正文缺口、SDK置信度和复跑建议展示。

## 5. 车载商用APK与数据集的评测方式

先复测已有可运行的HA、MG4、YAABSA等授权车载工作流；OwnTracks定位对照继续区分专用事件与通用读取。
每个样本记录AAOS版本、user、普通安装身份、实际权限、登录/后端、USB媒体/车辆数据等前提。
平台/业务前提未满足，记兼容或场景阻塞；不能写为引擎阴性。
数据集分成：自有AAOS机制夹具、AAOS可运行开源/商用App、可用于通用Android隐私对照的兼容子集。
DroidBench等先选择本规则支持的source/sink与适用API；F-Droid不作为默认整批车载主测集。
兼容子集只评价通用来源，不用于声称VHAL或全部商用车载能力。

报告漏斗：健康会话→业务触达→真实取得→身份可核验→完整正文→内容关联→来源歧义/定位→规则与业务证据。
规则命中、实验候选、业务证据分列；不能把它们相加成“总检测率”。
有独立参考的命题才给P/R，并同时给失败、弃判、可评估比例；无参考商用App只给已核验证据与覆盖缺口。
固定设备/工作流/预算，至少3次重复，按App聚合；新会话不借旧标签，全量回归不替代设备验收。

## 6. 保留的论文与项目借鉴（仅服务车载）

- [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)：设备侧连接观察对照；先验证AAOS/user10可用性及短连接负控，不承诺全部UID可解。
- [DroidBot论文](https://ylimit.github.io/static/files/DroidBot_ICSE2017.pdf)／[Kea2](https://github.com/ecnusse/Kea2)：状态图与业务脚本/断言设计；AAOS模板界面、旋钮、多屏需单独适配，不引入手机批处理。
- [LibScout](https://github.com/reddr/LibScout)／[LibScan](https://www.usenix.org/system/files/usenixsecurity23-wu-yafei.pdf)：补SDK前缀识别的边界，先少量已知依赖侧车，不重复实现已有运行时栈归属。
- [FlowDroid](https://github.com/secure-software-engineering/FlowDroid)：按实测VHAL/通用API签名做有限静态source→sink侧车，输出候选与触发建议，不冒充实际读取。
- [ThirdEye论文](https://users.encs.concordia.ca/~mmannan/publications/ThirdEye-CCS2022.pdf)：借鉴已观测转换的关联；已有TLS/Cipher继续复用，不整体引入归档工具。
- [PoliGraph论文](https://www.usenix.org/system/files/usenixsecurity23-cui.pdf)：车载政策主体/车辆数据/目的/接收方结构化，中文适用性需参考集验证。
- [DroidBench](https://github.com/secure-software-engineering/DroidBench)／[ReproDroid](https://arxiv.org/abs/1804.02903)：借鉴机制拆分、固定真值与可比实验，建设自有AAOS微基准。

上述链接来自上一轮已核对的原始论文/官方项目。迁移到AAOS的收益仍是待测假设，不照搬论文检测率。
当前最先开的车载工单：通用关联PID引用、TLS关闭模式契约、当前bundle新采集验收。

## 7. 实施记录（2026-11-11 第二轮，已改业务代码）

第 5 行描述的是**上一轮**只出文档的状态；本节记录按本文 §4 第一阶段的落地。
改动范围严格限于 `vehicle/` 与 `tools/run_regressions.py`（新增车载回归组）；
**`core/` 与 `mobile/` 一行未动**，比 §1 允许的共享改动更保守。设备当轮未在线
（`adb devices` 为空），因此**没有产生任何新的真实采集**，也没有复用历史签核。

| 优先项 | 落地内容 | 代码级验收 |
|---|---|---|
| P0 通用关联 PID 引用 | 新增 `vehicle/analyze/event_ref.py` 统一引用契约；`pair_ambiguity` 分组键带 pid+session，缺引用一律不宣称唯一来源；通用/VHAL/HA/OwnTracks/定位五条求值器的 pairs 与 event_refs 全部补齐 pid/session；通用求值器改用完整引用选取 hits | 合成反例：两 PID 各发 evt_id=1、同值 → 2 候选、`source_ambiguous_flows=1`、两个 pair 均 `source_read_unique=False`；只匹配其中一个 PID 时不再把另一进程事件拉进 evidence |
| P0 TLS 开关与验收契约 | 新增 `vehicle/pipeline/readiness.py` 单一就绪集合，`capture.py` 与 `preflight.py` 共用；开关同时写入 verification 与 manifest 的 `capture_switches` | 开/关两态各自独立用例通过；关闭时仍要求 egress/privacy/VHAL/样本就绪，且必须有 `TLS_BYPASS_DISABLED` + `TLS_SWITCH{false}`；声明冲突、多进程残留 `PINNING_ARMED`、缺正向证据分别拒绝 |
| P0 当前 bundle 新会话/业务回执 | 新增 `vehicle/pipeline/session_binding.py`；采集结束写 `session-binding.json`（bundle 摘要/开关/健康/输入摘要/业务动作回执），preflight 交叉校验并拒绝旧产物签核 | 摘要、会话、bundle 身份、开关、健康、输入、回执七项校验；合成回执不算设备触达；未声明动作只记缺口不阻断；`verify_binding` 对无绑定目录返回 `not_declared` + 待执行步骤 |
| P1 晚启动/重启覆盖 | 新增 `vehicle/pipeline/process_lifecycle.py`，宿主线程 `pidof` 被动轮询；`capture_lifecycle.observe_with_lifecycle` 在既有等待外包一层，摘要与 gaps 自动进 manifest | 记录附加前区间、未附加新 PID、退出/新起事件、PID 重用嫌疑、轮询失败；只观测不 attach/不挂起/不改写；worker 异常时仍写摘要 |
| P1 归因/业务触达/通用关联 | 新增 `vehicle/analyze/observation_ledger.py` 并挂进 `audit.py` 的 summary | 输出健康→业务触达→真实取得→身份→完整正文→内容关联→来源歧义→规则命中→业务证据的独立计数；统计 unresolved/歧义/single_package_fallback/unknown_uid/短连接；列明五种整对字符串之外未支持的自然定位格式；`emits_findings=false`，不相加为总检测率 |

新增离线测试组 `vehicle-optimizations`（5 个文件、约 40 项），已并入 `tools/run_regressions.py`。
`vehicle/bench/test_ablation.py` 与 `test_window_calibration.py` 的合成事件同步补上 pid/session，
以适应更严格的引用契约；其余既有测试未放宽。

### 回归结果

- `tools/run_regressions.py`：**19 组全绿**（含新增 `vehicle-optimizations`）。
- `tools/check_mobile_branch.py`：24 组中 23 组绿；唯一失败组 `upstream_mobile` 展开后是
  `observed_surface`（JDK 17 跑 `-source 8` 编译失败）、`lab_domestic_formal`（output 路径边界）、
  `lab_nonroot_capture`（Windows 8.3 短名 `ONEKYU~1` 与长名不一致）三项移动侧**既有环境失败**。
  三者堆栈均不涉及本轮任何文件；本轮未改 `mobile/` 或 `core/`。
- 本机 `%LOCALAPPDATA%\Programs\Python\Python313\python.exe` 缺 `jsonschema`，
  直接跑 `check_mobile_branch.py` 会得到退出码 3 的**环境假红**；已改用项目 `.venv` 解释器复跑。

### 仍未完成（不得写成已完成）

1. **设备新采集未执行**：AAOS 模拟器当时不在线。P0-3 只完成代码门禁与可重放入口，
   没有新会话、没有业务动作、没有真实回执，`session-binding.json` 不会凭空出现。
2. 待设备执行顺序（与 `session_binding.PENDING_STEPS` 一致）：
   `vehicle.ps1 prepare`（确认 freshness=clean）→ 用新会话跑 `vehicle/pipeline/capture.py`
   并把业务动作/回执写入 `business-actions.jsonl` →
   `python -m vehicle.pipeline.session_binding <capture> --verify` → 再跑 preflight/audit。
3. §4 第二/三阶段未做：设备侧连接对照（PCAPdroid）、自然定位格式扩展与窗口标定、
   SDK 库指纹侧车、政策结构化、四版本能力矩阵、split APK/OEM 适配。
   这些仍需真实 AAOS 输入、负控与独立参考，本轮**没有默认接线**。
4. 前端未改；报告只在 summary 增加诊断账本，未新增 UI 展示。

## 8. 子代理 review 与修复记录（2026-11-11 第三轮）

派出 4 个只读子代理并行审查：逻辑正确性、项目约束合规、测试有效性、红队门禁绕过。
**三个代理独立发现同一条 P0 错误放行链**，红队用单个伪造 JSON 在零采集、零回执、
零摘要绑定的条件下让 `validate_capture` 返回 `passed`：

- `session_binding.verify_binding` 的摘要校验是 `expected is None or digest==expected`（可选），
  删掉 manifest 的 `session_binding_sha256` 即可绕过；其余 checks 也大量用「字段缺失即跳过」短路。
- `verify_binding` 从不重读 `business-actions.jsonl` 与回执文件，只信 binding 自述的
  `business_actions.observed`；`observation_ledger` 又把这个自述值直接当作「已核验业务触达」。
- `preflight` 只在 `status=='failed'` 时拒绝，`not_declared`/`incomplete` 一律放行。

### 已修（同一轮内完成）

| 项 | 修复 |
|---|---|
| P0 绑定 fail-open | 摘要改为**必填且必须匹配 64 位 hex**；所有 checks 不再因缺字段短路（bundle 身份、开关、健康、输入、会话、包均要求显式一致）；`verify_binding` **重读业务动作文件与每一个回执**并与自述逐字段比对；状态 `passed` 改名 `binding_consistent`，永远附 `device_acceptance=pending` 与 `DEVICE_GAP` |
| P0 账本信自述 | `business_touch` 只来自 `verify_binding` 判定为 `binding_consistent` 且 checks 全通过的结果，否则强制 0 并记 gap；`complete_body` 与 `verified_body` 分列，弱归因/unknown UID/fallback 不计入已核验正文 |
| P1 类型崩溃 | `resolve_switch` 对 `capture_switches` 非 dict 返回 `tls_switch_declaration_mismatch`，不再抛未捕获 AttributeError |
| P1 新采集缺开关证据 | `capture` 就绪判定要求本会话 `TLS_SWITCH`；声明了开关却缺该事件 → `tls_switch_missing`；真 legacy（两侧均未声明）仍只记 gap |
| P1 假唯一来源 | `pair_ambiguity` 增加不含 `flow_pid` 的粗分组，候选数取细/粗两组最大值；同一 flow 被写成两个 flow_pid 不再各报「唯一来源」；结构化引用独立核验 read/flow 会话 |
| P1 生命周期 | `poll_error` 改严格 `is None`（`0`/`False`/`""` 不再当作有效样本伪造重启）；`stop` join 超时后不再追加采样、避免挂住与丢样本；样本截断记 gap；preflight 校验声明了进程覆盖时摘要文件必须存在 |
| P1 诚实性 | `preflight` 返回 `device_acceptance` 与绑定状态；未取得一致绑定时 gaps 明确「不得计入新版本设备验收」；`actions_sealed` 改名 `host_actions_recorded` |
| P2 | 删 `bundle_has_tls_script` 死代码；`select_by_refs` 用 `.get()` 防 KeyError 并对空 hits 早退；样本模式仍扫描残留 TLS 标记；`business_evidence_receipts` 在 limits 中注明与 `business_touch` 同源 |

新增约 20 项反例（伪造回执、删摘要+篡改绑定、路径越界、非 dict 开关、
缺 TLS_SWITCH、`poll_error=0`、worker 异常真实落盘、flow_pid 拆组等）；
`vehicle/privacy/test_location_acceptance.py` 的合成夹具补 `TLS_SWITCH` 以符合新契约，
`test_general_pid_reference.py` 的恒真跨会话用例改写为真反例。
受影响 223 项测试全绿，根回归 **19 组全绿**；`check_mobile_branch` 仍为 23/24，
`upstream_mobile` 的 3 项失败与上一轮逐项一致（`observed_surface` / `lab_domestic_formal` /
`lab_nonroot_capture`），未新增失败。

### 仍保留的已知边界（不冒充已解决）

- PID 重用：同一 `(src,pid,evt_id,session)` 复用不同生命周期 epoch 时，引用层**无法区分**，
  只能在 `process_lifecycle` 标为 `pid_reuse_suspects` 并写入 gaps；`LIMITS` 已显式声明。
- `origin_proven` 当前恒为 False，相关断言只钉住「不得宣称已证明」，不构成强反例。
- 工作区未跟踪的 `start-platform.ps1/.bat`、`stop-platform.ps1/.bat`、
  `tools/service_bootstrap.py`、根目录两份 2026-11-10 `.md` 与
  `docs/REAL_APK_OPTIMIZATION_PLAN_20261111.md` 均为**本轮之前遗留**，不是本轮交付物，
  本轮未读取改写、也未删除；其中平台启动脚本默认拉起移动端服务，与本方案 §1 边界无关，
  若后续要纳入交付应先按「移动端暂不开发」收敛。本文自身（本方案文件）也是用户提供的
  未跟踪文件，仅追加 §7/§8 记录。

## 9. 第四轮：诊断账本前端展示（2026-11-11，仅前端）

§7 的遗留项 4「前端未改；报告只在 summary 增加诊断账本」本轮补齐。
设备仍不在线（`adb devices` 为空），因此**没有新采集、没有新设备验收结论**，
本节是纯离线前端交付，不改动 §7/§8 的任何「未完成」判定。

`/summary` 的 `project_summary()` 本来就逐字保留原键，账本与 `capture_validation`
已在响应里，所以**后端判定逻辑、事件库、规则库、`core/` 与 `mobile/` 一行未动**。

| 改动 | 文件 | 口径 |
|---|---|---|
| 诊断面板 | 新增 `vehicle/frontend/ledger.js` | 展示 11 个漏斗层、7 项归因质量、通用关联覆盖、`gaps`/`limits` 原文、会话绑定与采集校验；缺字段显示「—」不补 0；各层独立计数不相加为检测率 |
| 样式 | 新增 `vehicle/frontend/ledger.css` | 沿用既有灰阶与虚线警示，无「通过/安全/绿色」语义；窄视口自动折行 |
| 接线 | `app.html`、`results.js`、`vehicle/webapp/server.py` 资源白名单 | 动态结果页在隐私观测面板之后追加 `U.ledgerPanel(summary)`；零构建，无 CDN、无外链、无 `innerHTML` |
| 契约测试 | `vehicle/webapp/test_server.py` | 新增「JS/CSS 既被服务放行、又被 app.html 真正引用」断言，防止只放行不接线 |
| 离线回归 | 新增 `vehicle/frontend/test_ledger_panel.mjs` + `tools/run_regressions.py` 的 `vehicle-ledger-ui` 组 | vm + 极小 DOM 桩跑真实 `ledger.js`，13 项：缺账本/缺字段不伪造、漏斗不相加、pending 不写成通过、`passed` 仅门禁、四种绑定状态、后端文本含 XSS 串不生成标签、源码零外链 |

诚实性边界：面板只渲染后端给出的字符串与状态，不推断结论；`device_acceptance=pending`
恒显示「待设备验收」；采集门禁 `passed` 明确标注「仅门禁，不等于设备验收」；
`binding_consistent` 也保留「仍待设备验收」。后端若声明 `emits_findings=true` 或状态非
`diagnostic_only`，标题改为「后端状态异常，需复核」并给警示徽标，不冒充仅诊断。

### 回归结果（本轮实测）

- `tools/run_regressions.py`：**21 组全绿**（新增 `vehicle-ledger-ui`；既有 20 组无新增失败）。
- `tools/test_inventory_guard.py`：PASS，scanned=240 / referenced=233 / allowlisted=7 / unregistered=0。
- `node --check vehicle/frontend/*.js`：全部通过；`vehicle/webapp/test_server.py` 新增资产接线断言随
  `vehicle-webapp` 组通过。
- `tools/check_mobile_branch.py`：21/24 组绿；`mobile_workbench`、`ai_gates`、`mobile_lab`
  三组失败**全部**来自本机 `sitecustomize.py` 的 `SAFE_DELETE_BULK_CONFIRM_REQUIRED`
  （单轮删除临时目录数 50–58 超过阈值 50），堆栈落在 `tempfile.TemporaryDirectory` /
  `Path.unlink` 的收尾，不涉及本轮任何文件。三组单独复跑分别 125 / 161 / 263 项全绿；
  这是宿主环境的假红，不写成代码回归，也不绕过删除守卫去「刷绿」。

**未执行**：真实 Chrome/CDP 浏览器验收（`browser_acceptance.mjs` / `layout_acceptance.mjs`）、
任何设备采集与业务回执。离线单测不能替代 1440/1920/390px 几何检查；需要在设备与
Chrome 可用时补跑，不把本节写成「前端已通过浏览器验收」。
