# 评估统计

## B001 失败测试臂与通用隐私计数（2026-11-02）

开销统计仅接纳 passed=true 且有完整 CPU/墙钟数据的测试臂；任一失败则排除整个配对，
在 failed_runs/skipped_pairs 保留失败原因、Hook 错误与清理状态。带计时的失败也不能混入中位数。
read_events/successful_reads 为 VHAL 与 PRIVACY_READ 合计，另列两类字段；通用成功只认
read_state=obtained，不能把 call_only/empty/unknown/denied/error 或矛盾的返回证据算作取得数据。
历史产物保留原貌，需要新统计时按原始 runs.jsonl/事件文件重新汇总。

## B002 三家样本重放与事件来源（2026-11-03）

重放清单用 SHA-256 封存 APK、会话清单和业务回执。审计重放与实验产物交叉核对分开记录。
配对 v2 同时使用读取源和流来源。旧三元组遇到同号跨来源时拒绝评分。
各案例独立保留采集健康、身份归因、正文证据和签核状态。已有业务证据用于准备待签材料，人工标注从独立参考重建。

## B003 证据契约与分层复核（2026-11-03）

O5 的审计摘要、PDF 与离线重放共享规则、覆盖链及输入摘要。缺失文件与存在的空文件分别记录。
跨会话输入、摘要变化和覆盖文件篡改阻止正常报告发布。证据类别与原有规则结论等级分别保存。
O3 只对独立双标和仲裁的配对范围计算指标。出现范围外预测时该层待复核，其他层可独立计量。
业务路径回执独立登记；自有夹具与独立样本分层，使用不同规则或覆盖摘要的结果分别统计。

## B004 开销基准绑定装机身份与独立动作回执（2026-11-04）

每个测试臂用唯一动作 ID 和独立 Frida 会话，防止重复取到历史回执。装机 APK 摘要和实际执行的 bundle 一同封存。
验收核对每动作 8 次读取、每属性主读取次数、外发次数、原进程存活及刷盘确认。合并数和主读取数分别记录，
P95 使用最近秩。设备转发仅清理本轮成功创建的映射；设备不存在时不启动采集。

## B005 盲标材料与组织者材料分开（2026-11-04）

首轮从摘要匹配的原始事件和独立回执生成材料，禁止将旧判定送入审阅包。HA 电量候选取全组合，
业务链问题单列。答卷绑定证据与配对表摘要，证据不足留待补证。双人结果和分歧清单保持待签。

## B006 脱敏交接与历史契约（2026-11-04）

HA 电量与 OwnTracks 可在无原始会话的源码副本重放最小证据投影。导出前校验源会话、APK、实际 Hook
和规则快照，历史目录快照须与会话及 Hook 就绪事件摘要一致，且调用、状态、规则与现行对应版本相同。
历史目录的来源文件摘要独立记录。OwnTracks 固定 APK 业务证据超出当前通用外发规则的求值范围，独立于 O3 评分。
与采集清单未绑定的旧 dumpsys 快照在 VHAL 导出显式标记。

## B007 盲审区分代理观测、身份归属和签核来源（2026-11-04）

代理可见 POST、回执标记一致和可归因 flow 数分别投影到浏览器证据卡。摘要变化重新冻结，旧答卷保留原摘要。
两份 AI 初评的配对共识与第三份 AI 复核登记为待签材料。配对正例和四项配对负控单列，HTTP 503 与
WebView 归因缺口作为业务负控。计分检查复核者类型和签核状态，显式 AI 或未确认身份的记录不能参与人工计分。

## B008 真人签核与规则快照重放（2026-11-04）

两份真人答卷齐全且配对证据充分时生成独立签核表。第三位复核者确认负控和配对分歧，签核表绑定题目、证据、
两份答卷的摘要。正式标注重新从冻结材料和三份答复生成。业务题的分歧与配对指标分开。
基准可显式传入历史规则库，仍须与采集摘要相同，覆盖矩阵、分析和报告共用该库。

## B009 默认 subagent 独立复核与签核（2026-11-05）

用户明确将本项目默认签核改为 subagent。新 prepare 默认 review_mode=subagent，
human 模式需显式选择。A/B 使用全新上下文分别只看冻结审阅包，第三个全新上下文 C
复核证据、负控和分歧。三个 agent_id、review_session_id 必须分别不同，context_mode=fresh；
普通 ai 初评、身份缺失、继承上下文或混用人/agent 的记录不能直接升级成已签结果。

subagent 标签使用 origin=subagent_review、subagent_signoff=signed、human_signoff=not_applicable。
保留真实身份、会话、时间、原答卷及证据/计划/答卷摘要。配对题证据不足仍阻断签核；
业务题不足独立登记。旧冻结材料、AI 初评和真人记录保留原貌，不追溯改写。
指标按标签来源分层；真人与 subagent 的样本量和验收门槛各自统计，不互相补足。

独立模型上下文并非文件权限隔离，程序只能校验声明的来源与摘要，不能凭 JSON 证明执行过工具。
实际启动记录另留 run.json。相同模型可能共享错误，subagent 共识不等于人工参考真值，
也不证明准确率提高。签核模式本身不改变基准的样本规模门槛或业务证据边界。

## B010 后补业务证据与计分资格分开（2026-11-08）

新 MG4/OwnTracks 材料另冻结为 expanded_round，不改旧 W03、旧 HA 配对标签或正式 pair kind。
新包仅投影原始身份/事件/正文哈希/回执/权限，A/B/C 独立复核业务命题及资格，不从预测复制标签。
MG4 没有敏感读取，OwnTracks 专用路径仍 workflow_only；denied 空流不能伪造双事件负配对。
业务签核输出 not_measured 和零新增正式参考数；前端单独发布本轮摘要，不能与当前任务混用。
普通精度/召回仍由原有规则与参考范围决定，不通过派生字段或评审一致性扩大求值口径。

## B011 命题↔求值器契约与三态观测门控（2026-11-17，一周任务周二～周四）

复现了四种判定口径缺陷并各留一个合成反例（`vehicle/bench/claim_scope.py::counterexamples`，
产物 `output/week-mao-20261110/counterexamples.json`）：

| 口径 | 旧缺陷 | 位置 |
| --- | --- | --- |
| C1 观测充分 | `observed = bool(evaluators_ran)`，任意求值器跑过就算本题观测充分 | `claim_verdicts.py:42`（旧） |
| C2 命题与证据对应 | `business_evidence_total` 是整轮合计，未按命题裁剪 | `claim_verdicts.py::report`（旧） |
| C3 未运行/不可判 | `read_detection` 用 `or 0` / `or []` 补齐，统计结构缺失 ≡ 跑了且 0 命中 | `claim_verdicts.py::read_detection`（旧） |
| C4 计分/投影一致 | 报告「运行求值器数」被当作本命题观测证据 | `tools/real_sample_result.py`（旧） |

修复：`claim_scope.py` 是「case → 所需求值器」与三态判定的唯一权威来源，映射出处为
`aaos35-suite.json` 的 kind、`suite.py::_replay` 分支与 `detection_summary.EXTRACTORS`，
单测强制校验出处；三态语义直接复用 `core/evidence/decidability.py`，不复制不改。
`claim_verdicts` 只补投影字段（`observation_state` / `required_evaluators` /
`matched_evaluators` / `business_evidence_scoped` / `observation_reason` 及顶层状态计数），
**七个 STANCES、counts、三个比率一律不动**；未登记契约的 case 沿用旧口径并显式标
`legacy_unscoped`，不得据以声称观测充分。结构存在但 `business_evidence={}` 记 `0`，
结构缺失记 `None`，不混（FIELD_CONTRACT.md §6 约定）。

冻结重放（`output/week-mao-20261110/compat-matrix.json`，输入
`output/claim-verdicts-20261110/verdicts.json` + `output/real-detection-20261110/`）：
6 项状态、counts、三个比率**全部不变**，新增 `not_applicable=1`（W03 mg4-post，
所需 `mg4_native_http` 未运行）；采集副本交叉核对 5/6 一致，W05 无 audit 产物如实记为
结构性不可计分。**修复是口径加固，不是改冻结批次的结果**。

报告投影只改一处：表格第 5 列「运行求值器数」→「本命题观测」（`report_cell` 三态），
表头与一段口径提示同步，8 列结构与所有函数签名不变；旧产物无该字段时显示
「无观测状态」，不按数量推算。其余三项（业务证据列仍是整轮值、`limitations()` 未覆盖
`missed_without_observation` / `not_applicable`、unscored 行无状态标签）登记为
`output/week-mao-20261110/projection-candidates.json` 的候选，按「只修一处」约束未改。

不迁移证据库、不重编号 `finding_uid`、不改 `vehicle/webapp/presentation.py`；
新测试 `test_claim_scope.py`（14 项）已并入 `tools/run_regressions.py` 的 `vehicle-method` 组，
方法层 177→191 项全绿，`test_inventory_guard.py` PASS（unregistered=0）。

## B012 独立 subagent 复核与评审修复轮（2026-11-10 晚）

按既有独立双标惯例冻结 A/B/C 三个**内容一致**的评审包
（`output/week-mao-review-20261110/`，33 个材料文件、`evidence_sha256=6c54e5b1…`），
三个隔离上下文的 subagent 各出一份带 `文件:行号` 依据的 `review.json`。
Q01–Q10：6 题三票一致 `present`，Q03/Q09 为多数 `present`（A 因证据层级与措辞口径判
`insufficient`），Q04/Q06 三票一致 `insufficient`——包内缺独立 diff 与证据库/前端快照，
**如实保留、不追溯改判**；组织者另补 mtime 证据，但不回灌评审包。

确认并修复的 findings：

- **F1（3/3，medium）**：`report()` 对未登记契约 case 过去落 `stance()` 兼容路径，仍以
  `bool(evaluators_ran)` 决定七态，等于把「任意求值器运行」当成本题观测充分。现生产路径
  一律传三态，`UNSCOPED` ⇒ `observed=False`，新增 `status_basis` 标注，并补 F1 反例单测。
  `stance()` 兼容路径仅为历史纯函数测试保留，docstring 明示禁止生产使用。
- **F2（2/3）**：`limitations()` 对 `not_applicable` 的 W03 仍输出「absent 来自没有运行任何
  求值器」（C3 反例点名的编造原因）。改由 `observation_state` 同源生成，并把
  `missed_without_observation` 纳入；`projection-candidates.json` P3 描述同步订正。
  周四「只修一处」的约束在评审轮被显式放宽为「修确认问题」，不再主张全程只修一处。
- **F3（2/3）**：`scope_selfcheck.crosscheck()` 用 `None == None` 把「双方都无采集副本」
  写成「一致」。note 改以 `agrees` 为准，区分一致 / 无采集副本 / 不一致三种文案。
- **F4（3/3）**：`observation_reason` 重复「不可判定（不是阴性结论）」前缀。去掉自有前缀，
  保留内核 `statement` 与逐条 `missing_reasons`。
- **F5（1/3，部分成立）**：branch/solo 两份 `verification.json` 逐字节相同，单凭产物不能
  佐证独立复跑。已补两次运行的目录/日志 mtime（22:37:07 / 22:39:22，日志均含守卫堆栈），
  并收紧 `acceptance.json` 与交付文档措辞：verification 不含时间戳，逐字节相同是预期，
  独立性由时间戳佐证而非文件差异。

**组织者层级判定 F6**：三个 slot 自报 `model_id` 同为 `hy4free`，`model_family` 只是同一
家族的不同写法。本轮是**同模型 subagent 复核（`subagent_signed`），不是
`cross_model_signed`，不能作金标准**；引用必须带 `no_human_in_the_loop` /
`model_identity_is_self_declared` / `families_can_share_upstream_weights` 三条限定。

冻结重放结论不变：`status_changes=[]`、`counts_changed=false`、`ratios_changed=false`
（修复只作用于未登记 case 与文案，冻结 6 个 case 全部已登记）。评审修复后回归：
`test_claim_scope` 14→16 项、结论级 28 项、方法层 191→193 项全绿；
`test_inventory_guard.py` PASS；根回归 19/19、移动侧 63/63、分支 24/24（隔离环境守卫后），
固定目录 `output/week-mao-20261110/verify-{root,mobile,branch}/`。

独立复验（`output/week-mao-review-20261110/FIX-VERIFICATION.md`）结论：F1/F2/F3/F4/F6
`fixed`、F5 `partially_fixed`、无 `not_fixed`、无 `regression`；并补强 F5 证据——两次
`mobile_lab.log` 的 sha256 不同（随机临时名、耗时 4.054s vs 3.697s、各含 4 处守卫堆栈），
直接佐证两次独立进程。复验者同为 `hy4free` 同模型 subagent、无人工介入，不作金标准。

## B013 双人计划B侧报告尾项（2026-11-11）

real_sample_result的业务证据列只读business_evidence_scoped；缺字段显示未知，不借整轮total。
unscored细分无审计产物、审计结构损坏、裁决缺失、裁决不一致及非二元裁决，投影同源说明。
有效既有记录的七态和三个比率公式不变；无效裁决/损坏输入不能冒充可计分阴性。
未观测的漏检不再用“碰巧正确”描述；不从旧SLIRP或样本状态推断本轮能力。
独立定位验收可由--location-acceptance加入报告，候选不进入规则、业务计数和总体P/R。
新增反例与交接验收测试由B登记根回归；历史冻结盲评产物缺失时不补造兼容重放通过。

## B014 推送前验收审查（2026-11-11）

B05必须逐案具有显式true的只读证明，不能过滤缺staging记录后凭all(empty)通过。
环境诊断只报告实际日志特征，普通断言失败不能硬编码为与改动无关的环境问题；
未提供隔离配置时保留not_recorded，不声称使用过关闭开关。
反例、影响及验证见[推送前审查](../../docs/DUO_PREPUSH_REVIEW_20261111.md)。

## B015 关联窗口的历史规则库绑定（2026-11-18）

窗口重放可显式指定与会话 SHA-256 相符的规则库快照。VHAL 和通用规则一并从该快照加载，
逐窗口事件引用通过 `--include-pairs` 导出。已用断网夹具核对 10 条主读取及五项不同值负控。
30 秒仅窗口命中 5 条、额外候选 23 个，60 秒命中 10 条、额外候选 46 个。
该轮批次令牌在五档均命中 10 条、额外候选为零。建议常规审计沿用 30 秒，等待人工复核。
见 [校准记录](WINDOW_CALIBRATION.md)。

## B016 B1 采用 subagent 签核（2026-11-21）

复用 B009 的 A/B 独立盲审与 C 仲裁。B1 只从摘要绑定的自有夹具原始事件、回执和冻结源码
构造候选。签核标签保留 `sample_origin=owned_fixture`，可用于窗口重放。已有初评保持原样。
旧会话缺原始采集与回执。11-21 补采会话已签核 45 项，确认 10 项同源配对和 5 项不同值负控。
五档批次令牌重放均完整命中，跨应用阈值仍待独立样本验证。见 [重放结果](WINDOW_CALIBRATION.md)。

## B017 第二自有 APK 与独立样本资格（2026-11-22）

用第二自有 APK 的三个 UI 读取和独立接收回执判定主读取批次，15 项正例和 30 项跨批反证经 A/B/C 签核。
30 秒漏掉 39.370 秒批次的 5 项，60 秒补齐且额外候选增至 25 项。额外候选保留已审跨批与未审事件范围。
显式 `reference_evidence` 无需旧 `business` 别名。独立候选 Car Stats Viewer 的 `speed` 键尚无已验证映射，暂不计入。
见 [第二 APK 对照](WINDOW_CALIBRATION.md#2026-11-22-第二个自有-apk-对照)。

## B018 VScanBench 自有夹具最小基准（2026-11-23）

复用已签核的两个自有 APK、各自的封存会话和规则库。对原始值、签核普通反证和窗口候选交叉核验，
分别列出同值跨批、专设负控、其他已审反证和范围外候选。两次重放结果字节一致。
Car Stats Viewer 补传通过 SQLite 主键和 HTTPS 摘要重验，证据粒度单列为业务验收。
独立应用仍缺可唯一定位原始读取的延迟证据。见 [最小基准](README.md#b2-vscanbench-最小基准)。

## B019 AAOS 只读负控与发送对照（2026-11-23）

同一自有 debug APK 分两个会话执行 `read_only` 和 `plain`。零请求须同时具备健康采集、成功读取和独立接收端记录。发送轮绑定动作令牌、上游原始正文摘要和主读取，分别展示经核对的配对及全部窗口候选。回环转发仅供夹具显式代理使用，逐轮读回验证释放。工作流复验复用已有 APK，按 `window_scored=false` 隔离于签核计分。见 [对照复验](README.md#aaos-只读负控与发送对照)。

## B020 配对模式回归与适用范围（2026-11-23）

只读和发送对照对比确切事件引用，附加窗口候选必须能定位到夹具诊断复读。缺失或重复批次标识时保留窗口候选的原依据及未确认状态。历史签核重放按事件集合逐档列出正例得失和同值跨批变化，两个令牌模式仅在已封存且支持批次声明的自有夹具上计分。见 [回归口径](README.md#配对模式回归)。

## B022 AAOS 后台动作证据（2026-11-25）

后台对照从同会话原始 Activity 记录确认主屏目标已停止且不可见。定义夹住单次动作的前后快照，并绑定实际只读负控、主读取和独立接收端。同一 APK 的两个新会话留在工作流，五档签核计分沿用已冻结标签。 [验收方法](README.md#aaos-后台读取与发送对照)

## B021 独立车速上传只计业务工作流（2026-11-24）

Car Stats Viewer 车速上传从原始 HTTPS 正文、VHAL 动作读回和同一会话的读取事件重验。正文车速校验负值转绝对值，时间先后仅用于展示各回执的候选事件。线上车速与离线行驶点按两条工作流展示，仍归属同一个应用。扩展清单绑定证据摘要，原冻结清单可独立重放。见 [车速复验](WINDOW_CALIBRATION.md#2026-11-24-复跑并保存车速原始正文)。
