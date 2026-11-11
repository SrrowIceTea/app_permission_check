# Phase 5 设计决策

## D501 结论上限由规则限定，引擎不抬高

三类规则各自声明了 `conclusion_level`：over_permission→`candidate`、
sensitive_read→`observed`、data_egress→`correlated`。引擎只产出到声明的那一级。

**不产出 `policy_violation`。** 那个级别回答的是"这是否构成违规"——政策判定，要人来下。
工具能给的是"值得复核的事实 + 可追溯的证据链"。
报告里专列一节写这件事：工具越界下判决比工具能力不足更糟。

## D502 时间窗 3000ms 小了整整一个数量级（实测校准）

规则的 `window_ms = 3000`，基线文档早已标注"项目实验参数【需实测校准】，不是法规阈值"。
**实测：靶子 App 的读取→外发间隔是 10634ms（HTTP）与 20292ms（HTTPS）。**

原因不是抖动，是**模式**：应用先读、缓存，等用户另行触发外发，不是即读即发。
研究文档在 Phase 5 之前就预告过——"应用普遍缓冲后批量上报，时间窗要放宽"。

用规则声明值跑，**外发结论一条都不会产出**：

| 窗口 | 结论数 | 分布 |
| --- | --- | --- |
| 3000ms（声明值） | 4 | candidate×3, observed×1 |
| 30000ms（实测校准值） | 5 | candidate×3, observed×1, **correlated×1** |

**没有改规则库里的值**，只加 `--window-override-ms` 作校准旋钮。理由是那个值是政策参数：
它写的是"多近算相关"，那是项目对人车交互节奏的判断，该由人改、并留下记录，不该被工具悄悄改掉。
结论里同时记 `window_ms` / `window_declared_ms` / `window_overridden`，报告里明写"用了校准值覆盖"——
读者必须能看出这条结论依赖一个被调过的参数。

## D503 内容匹配扫完整报文，不扫 preview

第一版用 `request_preview`（截断 400 字符）做匹配，`content_match` 恒为 False——
而载荷有 2463 字节，被匹配的属性名落在截断点之后。**这等于把最强的那条证据丢掉**，
而且失败方式是静默的：结论照样产出，只是永远停在"仅时间相邻"。

规则里写着 `content_match: required_to_upgrade_beyond_temporal_correlation`，
它就是"时间相近"与"确实发了这个数据"之间的分界线。改为 addon 在扫**完整报文**时记录命中字面量
（`request_tokens`），Phase 5 查该列表。

## D504 归因来源路径必须可配，不能硬编码

采集中曾把 egress 事件写到 `vehicle/analyze/logs/`，而 addon 读的是 `vehicle/traffic/logs/egress_events.jsonl`。
后果：代理流照常落盘，但每条 `package=null`——**看起来像"归因算法不行"，实际只是路径没对上**。
`addon.py` 因此支持 `VSCAN_ATTRIB_SOURCES` 环境变量显式指定来源。显式可配比隐式约定安全。

## D505 被拒绝的读取不计入 sensitive_read

`outcome=error`（SecurityException）的读取不构成"读取事实成立"，因此不触发 R 类规则。
它是另一个信号——**应用试图获取它拿不到的权限**——值得单独建模，但不是本阶段的规则。
把它混进 sensitive_read 会让两类完全不同的行为看起来一样。

## D507 违规代码行号取自运行时栈，不来自反编译对齐

申报书写的是"反编译对齐"，实际做法更好：**Android 运行时自己就提供了行号**。
在应用进程里调 `Thread.currentThread().getStackTrace()`，每一帧形如

```
com.vscanner.targetapp.VhalReader.readOne(VhalReader.kt:128)
```

类、方法、源文件名、行号全都有，而且是**运行时报的，不是从 dex 里推的**。
不需要反编译、不需要 jadx、不存在"反编译版本与装机 APK 不一致"的问题。

于是问题从"怎么对齐"变成"**怎么从一条几十帧的栈里挑出该负责的那一帧**"。三件事：

1. **栈顶一定不是答案**。栈顶永远是钩子自己（`VMStack.getThreadStackTrace`、
   `Socket.connect`、`CarPropertyManager.getProperty`），应用代码在下面。
2. **不能按位置取舍，要按归属**（D308 的教训）。取"第一个类名以被测包名开头的帧"。
3. **合成帧必须排除**。R8/D8 会生成 `$r8$lambda$…`、`$$ExternalSyntheticLambda…`、
   `D8$$SyntheticClass:0`、`Unknown Source:0`——它们**长得和真帧一样**（有类有方法有括号），
   行号是 0。把 0 当行号，报告里就会出现「违规位置：MainActivity.kt:0」这种
   看着具体、实则没有的定位。判据是"行号 ≤ 0 就不是行号"，不是"正则匹配上了就算"。

**`frame` 与 `chain` 一起给，不拿单帧当唯一证据**：R8 会内联，最内层那一帧有时是
内联进来的代码，它的行号未必是开发者写的那一行。给人看的应该是整条应用链：

```
read   VhalReader.kt:128   VhalReader.readOne
       ↳ VhalReader.readAll(VhalReader.kt:105)
       ↳ MainActivity.doRead$lambda$9(MainActivity.kt:118)
```

## D508 行号必须用装机 APK 的 dex 独立核对，不能自称可信

栈里报出来的 `VhalReader.kt:128` **看起来**可信，但在核对之前，没有任何东西证明
这个行号在真正装到设备上的那个 APK 里成立。APK 一旦重新构建，栈里的行号就是陈的——
**而陈行号不会报错**，它只会指到一个可能完全不相干的位置，让审计结论看起来有据可查。

所以加了一步 `dexlines.py`：读 APK 里 dex 的 LineNumberTable，逐条核对
「这个方法里真的有第 128 行吗」。工具是 SDK 自带的 `dexdump -d`，不需要额外依赖。

四种结果**必须能分开**，因为"查不到"和"查到了但不符"对排查的意义完全不同：

| 状态 | 含义 |
| --- | --- |
| `VERIFIED` | 类、方法、行号、源文件名都对得上 |
| `LINE_NOT_IN_METHOD` | 类与方法在，方法里没这一行（APK 过期，或 R8 内联改写了归属） |
| `METHOD_NOT_FOUND` | 类在，方法名不在 |
| `CLASS_NOT_FOUND` | 类都没有（代码被改名，或 dex 取错了） |
| `DEX_UNAVAILABLE` | **没提供 APK = 没核对，不等于通过** |

**解析 dexdump 时有个坑**：字段和方法用的是同一种 `name : 'x'` 行。
不按 section（`Instance fields` / `Direct methods`）区分的话，`context`、`specs`
这些**字段名会被当成方法名**收录，核对时报"方法不存在"——看起来像 APK 对不上，
实际是解析器认错了。`test_codeloc.py` 里钉死这条。

实测：6/6 全部 VERIFIED（1107 个类）。**语义另行复核**：`VhalReader.kt:128` 正是
`cpm.getProperty<Any?>(...)` 那行，`EgressSender.kt:46` 正是把载荷写进 socket 那行。

**核对证明的边界**：它证明"该行号存在于该方法的行号表中"，**不证明**该行号就是
违规行为的语义所在（R8 内联会改变行号归属）。所以报告里这句话必须留着。

## D509 取不到位置时要说明为什么取不到

`code_locs` 为空**无法区分**两种情况：

- 这条结论本来就没有代码位置（清单权限——MANIFEST 不是运行时代码）；
- 有代码位置，但工具没找到。

两者对读者的意义完全不同，前者是"到此为止"，后者是"这里缺了一块证据"。
所以空的时候一定带 `code_loc_note`，写明是哪一种。

**更隐蔽的是只取到一半**：`read_then_egress` 这类结论**读取侧和外发侧都该有位置**，
如果只取到读取侧，`code_locs` 非空——列表里躺着东西，看上去一切正常，
没人会想到另一侧根本没定位到。实测就撞上过（egress 侧因为 D308 的栈截断而取不到）。
所以另记 `code_loc_gaps`，摘要里单列 `findings_with_partial_loc`。

## D506 未验证 / 边界

- **归因按时间就近配对（容差 2000ms），只在单应用场景实测过。** 同时刻多应用外发时可能配错。
  Phase 4 D402 已记此项；Phase 5 未改善它。
- `CURRENT_GEAR` 实测可读，但规则库里没有对应规则——**覆盖缺口**。
  规则只覆盖 INFO_VIN / PERF_VEHICLE_SPEED / GEAR_SELECTION 三个属性。
- 非 HTTP 协议（MQTT/gRPC/QUIC）与 native TLS 解不了内容，只能按"主机+时序+属性值指纹"弱匹配。
- PDF 的中文字体靠系统 TTF（SimHei/DengXian）；在没有这些字体的机器上会退回
  reportlab 内置 CID 字体，不嵌入字形、依赖阅读器自带字体。
- ~~报告的"违规代码行号"一项**未实现**~~ —— 已实现并实测（D507–D509）。
  复核要点：行号核对只能证明"该行号属于该方法"，**不证明**它是违规语义所在，
  且只在 Java/Kotlin 层有效——native（BoringSSL/Cronet/gRPC）路径拿不到 Java 栈帧。
- 代码位置只对**运行时有栈帧**的证据成立：清单权限类结论本质没有位置（D509）。
- 钩子只注入白名单包名，因此**未在白名单外的第三方应用上验证过**——
  这是本方案最大的落地缺口：真实车机上装的第三方 App 不能预先注入钩子。

## D510 会话隔离、接收端信息与真实定位缺口（2026-09-24至25）

禁用规则不求值；同包同session、主机时钟、请求token、非歧义流才关联。保留政策结论上限。
Phase5双应用真实验收通过：两包均产出correlated、无串包、歧义流被排除。
RDAP与IP位置缓存保留来源/时间/摘要，默认离线；注册商不充当注册组织，注册国家不充当位置。
自有接收端是私网IP，最终报告如实写non_public，不用公网示例结果替换接收端事实。
PDF从捕获载荷渲染截图，旧preview/截断单独说明；中文按像素宽度折行。
新设备会话输出16结论(6 candidate/5 observed/5 correlated)。装机APK核对40记录：
38 VERIFIED，2 INCOMPLETE来自订阅回调Native Method，无源码行号；保留调用链和定位缺口。
不能从dex表挑一行补成运行时证据。dex缓存须与APK SHA256一致。
最终产物见../output/delivery-20260924-193039/，原始采集见../output/device-20260924-133521/。

## D511 证据归属的三处静默漂移与会话清单（2026-09-28）

**一、失败连接不得用于代码定位。** D408 已写明"仅成功连接可作为候选"，但这条判定
只落在 `vehicle/traffic/attribution.py`；`codeloc.nearest_egress` 只比包名 + 时间，
于是"流量归属正确、报告里的外发代码位置却来自一次失败连接"，而 dex 核对照样通过
（它只证明行号在装机 APK 里成立，不证明选对了连接）。
现把 `is_ok_outcome` 放进 `attribution.py` 由两边共用；`is_egress_connect` 保持
**只在 egress_hook 来源生效**——uid_sampler 写的是 `ev: PROXY_CONN`，把它当成通用
候选过滤器会把 uid 兜底来源整个静默废掉（现有夹具全是 EGRESS_CONNECT，覆盖不到）。
判定必须是**否定式**（只有 `outcome == 'error'` 才排除）：历史证据与多处夹具都缺
`outcome` 字段，改成"必须等于 ok"会静默丢弃全部旧事件。
范围内只有失败连接时给**第三类**理由，不能沿用"没有本包的出站事件"——那是假话。

**二、目标包无观测必须与"分析完成、无命中"分开。** `correlate.py` 的判空原在包名
过滤**之前**，于是"只喂 App B 的数据、却要求分析 App A"会写空 findings 并 `exit 0`，
把"这个包根本没有观测"报成"该应用没有风险"。判定移到过滤之后，`exit 2`
（先例见 `verify_multi_app.py`），诊断写 stderr 且**不写 summary/findings**——
`report.py` 对 summary 是直接下标访问，残缺的 summary 会把清晰的拒绝变成后续 KeyError，
空 findings 文件本身就是一份"没有风险"的伪造产物。
只在 reads 为空时报错：flows/egress 为空但 reads 非空是合法运行（确实没观测到外发）。

**三、`evt_id` 撞号不猜测。** 钩子与代理的编号都从 1 重新开始，`{evt_id: record}`
字典推导让后一条静默覆盖前一条，结论挂到别人的栈上。实测
`vehicle/traffic/evidence/egress-multi-A.jsonl` 里 evt_id 1/2/3 各出现两次，且 `src` 与
`session_id` **都相同**（两次追加进同一文件），所以复合键消解不了历史日志的歧义——
只能把"不止一条"本身记成缺口。歧义时绝不产出两条 loc：`findings.js` 用 `.find()`
首个匹配，同 role+event_id 的两条会让看板把第一条的徽章显示两次。

**四、零条 dex 核对不算通过。** 歧义转成缺口后 `by_status` 可能为空，而
`set({}) - {'VERIFIED','INCOMPLETE'}` 是空集，`build_delivery` 原样通过，
于是"一条都没核对"与"全部核对通过"在报告里长得一模一样。已加 `checks_total` 守卫。

**五、会话清单。** 原检查只证明"现在装机的 == 现在构建的"，证明不了它就是产生这批
日志的版本。`device_acceptance` 现在在 `finally` 写 `session-manifest.json`
（装机 APK / 规则库 / 每个 bundle 的 sha256 + 设备指纹 + 采集参数；APK 哈希用
`exec-out cat` 在主机侧算，与 `build_delivery` 的 pull+digest 可直接比对），
`build_delivery` 把清单里的哈希与实际拉下来的比对后写进 `provenance.json`。
对加固前的旧会话用具名报错说明缺什么，不静默跳过。

拆分了 `codeloc.py`（超 300 行上限）："先确定说的是哪条事件"这一层移到
`event_lookup.py`，`codeloc.MATCH_TOLERANCE_MS` 仍转出以兼容既有调用方。
证据：../output/device-20260928-015125/、../output/delivery-20260928-015231/provenance.json。

## D512 关联规则的语义基线与窗口依据（2026-09-28 量化）

新增 `vehicle/analyze/experiment_correlation.py`：15 条场景声明"应当产出哪些 (read, flow) 配对"，
与真实 `evaluate_data_egress` 比对，**precision 1.0 / recall 1.0 / 15 条全过**。
覆盖：窗口内/边界（含 +1ms 不命中）/窗口外、只读不发、只发不读、内容不匹配、
先后次序倒置、读取失败（D505）、跨包、跨会话、归因歧义、归因未解析、禁用规则、
多属性只命中一个。

两条做法值得沿用：
- **禁用规则必须用"本会命中"的输入去验**。空输入永远产出空结果，拿它验禁用是假通过；
  现在有对照：同一输入 `enabled=1` 产出配对、`enabled=0` 不产出。
- **场景表用具名字典，不用元组**。早先用元组漏了"规则是否启用"这一维，
  「禁用规则」实际拿 `enabled=1` 跑，凭空多出一个 FP，算出的 precision 0.8
  是**脚本自己的错**——实验的错误会伪装成被测系统的结论。

**「同名不同值」当前仍判命中**，这是已记录的边界而非缺陷：匹配依据是
"属性名/ID 出现在报文里"（`content_match_basis: request_property_token`），不是值。
实验把它钉在语义基线上，将来做值级匹配时能对照起点；**它不证明发生了泄露**。

窗口依据：30s 覆盖两个夹具实测间隔（10.6s HTTP / 20.3s HTTPS）并留余量，
30 001ms 起不命中。**仍是夹具校准值**，通用性需要真实间隔分布。


## D513 车载值级证据、用户隔离与复核排序（2026-11-01）

研究依据见 docs/VEHICLE_RESEARCH_PLAN.md。match_content 区分属性名与属性绑定原值/派生值；显式不同值不回退为属性名命中，普通短数字不做全文搜索。历史缺原值/载荷的事件保留 value_match=false。身份冲突拒绝关联，读取统计按 UID/会话分组。上下文不把权限拒绝当作隐私同意拒绝，采集频率按 API 展示且不冒充物理采样率。复核关注分仅为未校准工程排序，置信度独立展示，不改变严重度和结论上限。

## D514 真实设备验证发现与最终边界（2026-11-01）

真实 AAOS 35 上先出现 Wi-Fi ENETUNREACH、延迟归因漏 UID、多个 Java bridge 卸载时 DeleteGlobalRef abort，随后发现前台字段为 topResumedActivity。已分别补就绪检查、统一身份刷新、单 agent 采集与实际前台状态核验。场景测试有原 PID 存活断言；用户切换用身份去除对照证明隔离非空。该镜像不承诺并发用户显示、真实同意 UI、驾驶状态和厂商接口覆盖。所有失败轮次保留于 output。

## D515 普通第三方范围、采集前置检查与政策证据（2026-11-02）

独立 vehicle 入口明确普通第三方安装身份，API 35 仍为动态基线，13/14/16 的来源/计划状态分别保留。
audit 在任何分析前校验健康、会话、白名单、API、规则和实际使用 Hook 摘要；新版 capture 绑定输入文件摘要。
代理回调的结构化健康状态必须正常收尾；日志中的异常不能被当成正常零流量。
summary.json 在全部请求阶段成功后提交；健康无 VHAL 读取是有限无观测结果，不能声称无隐私行为。
规则库当前版本的空权限映射字段必须暴露，不能拿策略镜像或另一版本定义冒充设备验证。
覆盖链按实际库/Hook 生成；Android 通用隐私 API 尚未接入 vehicle 的部分明确列缺口。
平台无关政策正文/格式解码提升到 core/policy，mobile 旧路径兼容；车载使用 APK 绑定的本地快照、
正文字符位置与项目复核条款。用户协议不替代主政策，关键词不决定披露充分性，必要性始终人工复核。
场景的 consent/vehicle_state/network 标签须有摘要绑定的执行证据；合成输入不充当设备验收。
公开样本下载、静态、动态和独立人工标注分别统计，空分母/无标注的 precision/recall 为 null。

## D516 OwnTracks 侧载对照进入常规审计（2026-11-05）

仅对预检已验证的固定 APK、AAOS 35 与专用采集契约执行。回调中的有效定位记录为 observed。
成功代理 POST 只有在隔离 HTTP 路径、严格归因、同会话和同 UID/用户，且 30 秒内坐标摘要和定位时间同值时才生成 candidate。
审计报告只保留事件引用及关联结果，独立回执继续由业务验收核对。采集原件保留原有访问范围。
历史隐私目录通过显式快照重放，同时核验配套政策和签名文件字节摘要。一般定位规则和盲评评分范围保持各自口径。

## D517 完成后继续核验证据来源（2026-11-05）

审计清单同时绑定采集验收、采集器健康、采集清单封存的附加输入、实际校验的 Hook 文件，以及导出的隐私目录与来源文件。
报告生成和后续校验使用同一份摘要清单。文件缺失或内容变化时按 artifact 键定位，并拒绝生成报告。
旧报告按各自的清单核验；重跑审计才会补齐新增摘要。

## D518 进程内事件引用与诊断账本（2026-11-11）

evt_id 是进程内序号。通用/VHAL/HA/OwnTracks/定位所有求值器的 pairs 统一经
`vehicle/analyze/event_ref.py` 构造引用，携带 src/evt_id/pid/uid/user/session/设备序列号；
`pair_ambiguity` 的分组键带 pid+session，缺 PID 或会话的旧证据标 `reference_incomplete`，
绝不宣称 `source_read_unique`。按裸 evt_id 选取命中事件的路径一律改为按完整引用选取，
否则两进程同号事件会被拉进同一条 finding。引用缺口计入 finding 与 stats 的 `reference_audit`。

`observation_ledger.py` 只做诊断：漏斗各层独立计数、归因质量（unresolved/歧义/
single_package_fallback/unknown_uid/短连接）与未支持的自然定位格式显式列出，
挂到审计 summary，不新增 finding、不产出违规结论、不相加为总检测率。
合成控制与固定预算比较不等于真实设备业务探索效果。

## D519 子代理 review 后收紧引用与账本（2026-11-11）

四个只读子代理交叉审查发现：同一 flow 写成两个 flow_pid 会把多来源拆成各自「唯一」，
而账本直接采信 `session-binding.json` 自述的回执数。现 `pair_ambiguity` 增加不含 flow_pid
的粗分组并取细/粗候选数最大值；结构化引用独立核验 read/flow 会话；`select_by_refs`
用 `.get()` 且空命中早退。`observation_ledger` 的 `business_touch` 只消费
`verify_binding` 判定为 `binding_consistent` 的结果，`complete_body` 与 `verified_body` 分列，
弱归因不计入已核验正文。PID 重用仍是已声明边界：引用层无法区分 epoch，只由生命周期观测标记嫌疑。
