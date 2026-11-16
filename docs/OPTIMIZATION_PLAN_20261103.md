# 车载端优化方案（2026-11-03）

> **历史快照（2026-11-11 归档，不作当前清单）**：现在什么状态、本周做什么见 [CURRENT_STATUS.md](CURRENT_STATUS.md)。

> 状态：规划稿 v1。**本轮只做规划**：未改任何代码、未执行 git 操作、未启动模拟器或 adb。
> 范围：车载产品线（`vehicle/` + 共享内核 `core/`）；`mobile/` 不在本轮改造范围，
> 但 `core/collector`、`core/frida_host` 的改动会同时影响移动端，必须跑移动回归（见 §5）。
>
> 硬口径（沿用项目约束）：
> - 不输出 `policy_violation`；结论只到 observed / candidate / static。
> - “未观测到读取/外发”不等于安全；拒绝读取不等于已采集。
> - 批次令牌证明“属于哪个批次”，不证明“数据因果传播”。
> - 无独立标注时 `precision/recall` 保持 `null`，不用未命中反推准确率。

---

## 1. 现状基线与短板

### 1.1 上轮评估条目（后续清单逐条对应）

| 编号 | 短板 | 当前可核对的证据 | 影响 |
| --- | --- | --- | --- |
| E1 | 工程闭环已通，实证基线薄 | 三家样本业务轮均能采集；但早期 0 次读取，补充后仅部分通过；`vehicle/lab/P1_P2_RESULTS.md` | 结论无法外推到普通第三方 |
| E2 | 无独立人工标注 | `vehicle/lab/P1_P2_RESULTS.md`：三家 `human_signoff=pending`；`precision/recall` 为空 | 任何规则新增都无法证明有效 |
| E3 | 外发解析只覆盖出站 JSON 字符串叶子 | `core/collector/body.py`、`core/collector/payloads.py`、`vehicle/traffic/tagging.py`；MG4 10 条 flow 未归因、YAABSA Flutter 无正文 | 非 JSON/表单/二进制/截断正文会静默落成 0 标签 |
| E4 | 30 秒窗口漏配 | `vehicle/bench/WINDOW_CALIBRATION.md`：5/10/30 秒均 14/28，60 秒 28/28 但多 28 个候选 | 调大窗口换漏配，额外候选同步上升 |
| E5 | VHAL 权限映射未闭环 | `vehicle/coverage/generated/COVERAGE.md`：8 行 `required_permissions.op=unknown`、`definition_status=pending`、`source_refs=[]`；`vehicle/lab/vhal_acceptance.py` 5 ok / 3 denied | 属性→权限不可追溯；25Q2 能力未接入 |
| E6 | Hook 开销高 | `vehicle/bench/README.md`：`--pairs 4 --actions 12` 中位 CPU +845 ms；276 条 `VHAL_READ` + 12 条外发 | 长时采集与真实 App 可用性受限 |
| E7 | 证据产物字段不齐 | `vehicle/pipeline/audit.py` 有 `generated_at`/`rules_sha256`/`coverage_chain.sha256` + **简化版** `input_completeness`（无每类输入 count/sha/parse 状态）；`vehicle/analyze/correlate.py` 摘要无 `generated_at`/`coverage_sha`；finding 只有 `conclusion_level`/`evidence_kind` | 跨轮对比与第三方复核缺少统一指纹 |
| E8 | 产品化入口不完整 | `vehicle/pipeline/prepare.py` 要求依赖已装；`vehicle/bench/samples.py` 只产出单批下载清单，APK/来源/会话/采集/审计分散 | 换机/交接需要人工拼路径 |

> E1–E8 是对上一轮评估结论的编号化；后续 O 项逐条回指，避免“优化项很多、不知道修哪条”。

### 1.2 已具备、不要重复造

| 能力 | 入口 | 说明 |
| --- | --- | --- |
| 四态读取区分 | `vehicle/privacy/evaluation.py` | 调用/空值/拒绝/取得数据分开，拒绝不算采集 |
| 值级 + 派生值匹配 | `core/collector/derive.py`、`vehicle/analyze/value_match.py` | 原值、md5/sha*/base64/urlencode/hex/gzip+b64 |
| WebSocket 同连接消息 ID | `vehicle/privacy/ha_socket_evidence.py`、`vehicle/hooks/hook_ha_socket.js` | 已有配对思路，可复用到常规协议 |
| 30 秒规则默认值 | `vehicle/rules/rules_library/rules.db` 的 `window_ms` | **保留，不改默认** |
| 标注 schema | `vehicle/bench/README.md`、`vehicle/bench/metrics.py` | `pair_schema=2` 已能区分 read/flow 的 `src` |
| 开销配对实验 | `vehicle/bench/overhead.py` | 有/无 Hook 双臂交替，产物可复现 |
| 三家样本封存重放 | `vehicle/bench/aaos35-suite.json`、`vehicle/bench/suite.py` | 摘要校验 + 失败保留 |

---

## 2. 按价值排序的优化清单

排序依据：**先让结论可被采信，再让结论更完整，最后降成本**。
“价值”不只看工作量，还看能否把“0 发现”翻译成可对外解释的覆盖结论。

| 排名 | 编号 | 优化项 | 对应短板 | 主要依赖 | 粗估工作量 |
| --- | --- | --- | --- | --- | --- |
| 1 | O3 | 独立标注 mini-benchmark 与 P/R 口径 | E2 | 设备 + 外部样本 + 人工签核 | 代码 2–3 人日；数据/标注 10–15 人日 |
| 2 | O1 | 协议适配层与显式 `unparsed` | E3 | 离线可验证；真实协议样本需设备 | 5–7 人日 |
| 3 | O2 | 批次令牌 / 因果配对（保留 30 秒） | E4 | 离线可验证（冻结 002/004 证据） | 3–5 人日 |
| 4 | O6 | VHAL 权限映射回填 + 25Q2 + AAID | E5 | 离线规则 + 设备验收/GMS 镜像 | 5–8 人日 |
| 5 | O4 | Hook 开销 845 ms → ≤400 ms | E6 | 需要设备 | 4–6 人日 |
| 6 | O5 | 证据产物一致性 | E7 | 离线可验证 | 2–3 人日 |
| 7 | O7 | 产品化：`prepare` 自建 venv + 样本 manifest | E8 | 离线可验证；首次装依赖需网络 | 3–4 人日 |

> O3 排第一不是因为它最快，而是因为**没有它，后面所有改动都无法用数字验收**，且它需要最长
> 的外部准备时间（样本、双人标注、签核），必须最早启动。O1/O2 是 O3 口径的前置。
> O6 排第四：它把“只承诺官方可访问面”变成有 source_refs 的事实，属对外定位的核心；
> O4 排第五：它降低采集成本，不改变结论真假。
> O8（API 33/36 矩阵）与 O9（可见性/后台）属 P2，列在 O7 之后，不参与前 7 项排序。

---

### O1 协议适配层与显式 `unparsed`（P0）

**解决短板**：E3。当前 `body.py` 只返回文本与 `decode_error/truncated`，`tagging.py` 只在整段文本上跑正则；
遇到 multipart、protobuf、二进制响应、WebSocket 文本帧时，标签为空与“根本没解析”无法区分。

**改动文件（精确路径）**

- 新增 `core/collector/parse.py`（≤300 行）：唯一解析入口，**任何失败都返回状态，不抛异常**。
- `core/collector/body.py`：保留 `scan_body`（向后兼容），解析入口在 `parse.py`。
- `core/collector/flow_entry.py`：`answered()` / `unanswered()` 增加 `request_parse` / `response_parse`；
  `request_payload` 保留原字段并新增 `retention` 标记正文持久化策略。
- `core/collector/addon.py`：扫描时优先用 `parse_body` 的字段结果；无 `parse` 的旧路径保底用文本。
- `vehicle/traffic/tagging.py`：新增 `tag_fields(fields) -> (labels, tokens)`；`tag_sensitive(text)` 保留。
  契约扩展为“可选 `tag_fields`”，移动端未实现时回退文本，不破坏现有 `VSCAN_TAGGING`。
- `vehicle/analyze/correlate.py`：`body_scan_totals` 扩为 `body_parse_totals`
  （`parser` / `parse_status` / `unparsed_reason` / `truncated` / `decode_error` 计数）。
- `vehicle/bench/metrics.py`：`observation_stats` 增加 `flows_parsed` / `flows_unparsed` / `by_parser`。
- `vehicle/privacy/pipeline.py`：摘要 `inputs.parsing` 同步该块。
- 测试：`core/collector/test_parse.py`（新增）、`core/collector/test_body.py`、
  `vehicle/traffic/test_tagging.py`、`vehicle/analyze/test_vehicle_evidence.py`。

**合并口径**：正文保留策略由 `request_payload.retention` / `response_payload.retention` 明示。
已脱敏正文、超限正文及无法安全保留的正文不落原始 Base64。请求与响应独立统计，
旧证据缺解析状态计入 `legacy_unrecorded`。真实空正文有空字节摘要，未观察到的响应仅留缺口。
multipart 文件部分保留大小和摘要。Protobuf 启发式只记录解析覆盖。
WebSocket 文本适配器需可信帧来源，常规 HTTP 代理的帧采集仍待设备验证。

**实施步骤**

1. 定义 `parse_status` 封闭枚举（只允许这些值，禁止空值）：
   `parsed_json`、`parsed_form`、`parsed_multipart`、`parsed_websocket_text`、
   `parsed_protobuf_heuristic`、`unparsed_binary`、`unparsed_truncated`、
   `unparsed_decode_error`、`unparsed_empty`、`unparsed_unknown_content_type`。
2. 解析器按 Content-Type + 内容形状分派；JSON 解析全量叶子（数组/嵌套对象），
   form 解析键值，multipart 只取文本字段（文件部分只记 `name/size/sha256前16`，不落内容）。
3. protobuf/msgpack 只做启发式：wire type 合法 + 可打印长度字段；恢复不到字段就整体标
   `unparsed_binary` + `payload_sha256` + `bytes`，不输出假字段。
4. 每个 `request_parse` 固定字段：
   `parser / parse_status / content_type / bytes / truncated / decode_error /
   field_count / field_paths_sha256 / unparsed_reason / payload_sha256`。
5. 打标同时扫“解析后的字段”和“原文”，两者都进 tokens；解析失败时只扫原文并带
   `scan_basis=raw_text`，避免把未解析误报成无敏感字段。
6. 新增离线夹具 `vehicle/bench/fixtures/parse/`（JSON/form/multipart/protobuf/截断/二进制/WS 文本各 ≥3 条）。

**验收（可量化、可复现）**

- 50 条 flow 语料（现有 `output/` 采集 + `fixtures/parse/`）：**100%** 的 flow 有 `parser` 与
  `parse_status`；`parse_status` 为空或缺失 = 0。
- 静默丢弃 = 0：任何未解析 flow 必须带 `unparsed_reason`、`content_type`、`payload_sha256`。
- 回归：≥20 条既有 JSON flow 的 `request_tags` / `request_tokens` 与改动前逐项一致（golden 对比）。
- 负控：在 10 条 flow 的非敏感字段注入 VIN 形态字符串，`tag_fields` 不得把它标成
  `vin_like` 的“外发值匹配”；误报 ≤10%。
- 命令：
  `. ./environment.ps1; & $VScanPython -m unittest core.collector.test_parse vehicle.traffic.test_tagging`
  再接完整回归（§5）。

**依赖资源**：主体离线可验证；protobuf/WS 的真实样本需要设备采集，离线先用合成夹具。
**风险**：启发式 protobuf 可能产生假字段 → 必须 `heuristic=true`，且**不允许**仅凭启发式字段升级
`value_match`；multipart 文件正文不解析 → 报告要显式写“文件正文未覆盖”，不能写“无敏感内容”。
**工作量**：5–7 人日。

---

### O2 批次令牌 / 因果配对，保留 30 秒默认（P0）

**实装与验收修订**。旧动作窗口标注的 28 项含 18 项仅用于诊断的交叉读取。
配对目标改为独立调用栈确认的 10 项主读取，旧标注继续用于窗口兼容性回归。
封存断网 002 的严格令牌模式与混合模式均命中 10/10，额外候选为 0。
批次配对通过离线重放显式启用。分析阶段从完整的已落盘 JSON 读取主张，
输出令牌摘要和事件引用。缓存流必须携带原始批次令牌，同值集合不构成跨窗依据。
细节见 [窗口校准](../vehicle/bench/WINDOW_CALIBRATION.md)。

以下保留实施前的设计与原动作窗口目标，供追溯口径变更。

**解决短板**：E4。冻结夹具上 30 秒漏 14/28，60 秒补齐但额外候选 28。
现有夹具上传正文已经带 `scenarioToken` / `sourceBatchTokens` 和逐条 `reads[].readAtUtcMs`
（`AuditScenarioState.kt`、`window_run.py` 已核验），
但 **`vehicle/analyze/evaluation.py` 的 `evaluate_data_egress` 完全没消费它**，
仍只按“值匹配 + 时间窗”配对。

**改动文件（精确路径）**

- `core/collector/parse.py`（O1 产物）：JSON 解析时显式提取两类结构：
  1. `batch_tokens`：`sourceBatchTokens` / `scenarioToken` / `batchToken` / `batch_id`；
  2. `read_claims`：正文 `reads[]` 里的 `{property, propertyId, result, value, readAtUtcMs}`。
- `core/collector/flow_entry.py`：写入 `request_batch_tokens` 与 `request_read_claims`
  （无令牌/无 claims 时为空数组，不伪造）。
- `vehicle/analyze/evaluation.py`：`evaluate_data_egress` 增加配对依据与令牌优先逻辑；
  每条 pair 增加 `read_src` / `flow_src` / `pair_basis` / `origin_proven` /
  `token_sha256` / `claim_match_ms`。新增常量 `TOKEN_TS_TOLERANCE_MS=50`。
- `vehicle/analyze/value_match.py`：增加批次值集合提取（同一请求正文中属于同一属性族的多个值），
  仅用于 `batch_value_set`，不改变原值匹配的单点语义。
- `vehicle/hooks/hook_vhal.js`（可选、非离线必需）：协作 App 可由控制脚本注入
  `batch_token`；第三方 App 该字段为 `null`，不伪造。
- `vehicle/bench/window_calibration.py`：增加 `--pairing token|window|both` 重放；
  输出每个窗口的 `token_aligned / token_missed / extra_candidates`。
- `vehicle/bench/WINDOW_CALIBRATION.md`：实现后追加“令牌配对”一节（本轮不动）。
- 测试：扩展 `vehicle/analyze/test_vehicle_evidence.py`、`vehicle/bench/test_window_calibration.py`。

**配对规则（写死在代码里，评审可见）**

1. `token_read_claim`（**离线可用、主路径**）：flow 正文带 `reads[]` 与批次令牌，且存在一条
   claim 同时满足 `propertyId == read.prop_id`、结果一致（`ok` 比值，`denied` 比拒绝）、
   `abs(claim.readAtUtcMs - read.ts) <= 50ms` → `pair_basis=token_read_claim`、
   `origin_proven=true`；**不受 30 秒限制**，但仍要求同包同会话。
   `read.ts` 与 `readAtUtcMs` 已在冻结样本上实测同一时钟（示例差 7 ms），不需要重采。
2. `token_hook`（仅协作 App）：read 事件带 `batch_token`，与 flow 令牌相等 →
   `origin_proven=true`。第三方 App 不适用，不得伪造。
3. `batch_value_set`：flow 正文包含 ≥2 个同批属性值，且 read 的值在正文中**唯一**出现
   → `pair_basis=batch_value_set`、`origin_proven=false`；允许放宽到
   `batch_max_age_ms=120000`，但结论封顶 `candidate`。
4. `value_in_window`：现有逻辑，`0 <= delta <= window_ms`，默认 30000。
5. `content_tag_in_window`：现有“属性名/ID 命中”逻辑，默认 30000，结论仍受归因置信约束。

> 反向约束：令牌不得升级为“因果证明”。`origin_proven=true` 的含义固定为
> “本请求正文声称的批次包含该读取，且正文里的读取时间与独立采集到的读取事件在 50ms 内一致”，
> 报告必须原样写出这句限定；`origin_proven` 不区分“读取成功”与“读取被拒绝”，
> 拒绝行只能说明“批次包含该次拒绝”，不得写成“数据已外发”。

**验收（可量化、可复现）**

- 冻结的离线重放样本 `output/vehicle-offline-window-20261103-002/`
  （原始采集对应 `output/vehicle-window-20261103-002/`、`-004/`）重放：
  `token` 模式参考配对 **28/28**、漏 **0**、额外候选 **≤14**（不劣于 30 秒基线）；
  28 条全部 `pair_basis=token_read_claim`、`origin_proven=true`。
- `window` 模式必须逐字复现现状：5/10/30 秒 14/14/14，60 秒 28/28（作为回归 golden）。
- `both` 模式：28/28，且每条 pair 有 `pair_basis`；`batch_value_set` 的条目
  `origin_proven=false` 且有 `token_absent_reason`。
- 负控 1：样本里的 `window_..._mismatch` flow（值为 `CONTROL-DIFFERENT-VALUE`）不得与真实
  读取配对，token 配对数 = 0。
- 负控 2：把 claim 的 `readAtUtcMs` 人为偏移 +1000 ms，token 配对必须失效并回退到窗口逻辑，
  不能因为“有令牌”就强配。
- 负控 3：跨 session、跨包名、跨批次的同名令牌不得配对；只有令牌但正文无 `reads[]` 不得配对。
- 拒绝行：可以 `origin_proven=true`（批次包含该次拒绝），但 finding 不得升级为“数据外发”。
- 命令（先 golden 后新口径）：
  1. 现状 golden（改代码前后应逐字一致）：
     `. ./environment.ps1; & $VScanPython -m vehicle.bench.window_calibration --capture output/vehicle-offline-window-20261103-002/capture --labels output/vehicle-offline-window-20261103-002/labels.json --out output/window-replay-golden.json`
  2. 实现 `--pairing` 后：`--pairing window` 必须得到与 golden 相同的 5/10/30/60 秒行；
     `--pairing both` 输出 `pair_basis` 分布与 `origin_proven` 计数。

**依赖资源**：离线可验证（002/004 已冻结）。若要新采一轮带令牌样本，需要设备。
**风险**：令牌/`reads[]` 都是 App 自报内容，只对自有夹具或愿意自报批次的协作 App 有效，
**不能宣称普通第三方 App 也能令牌配对**；`readAtUtcMs` 可能被 App 写错，必须有独立采集的
`read.ts` 在 50ms 内佐证，否则回退窗口；`batch_value_set` 放宽到 120 秒会引入额外候选，
必须与 `token` 分列报告，不合并成“窗口覆盖率”。
**工作量**：3–5 人日。

---

### O3 独立标注 mini-benchmark 与 precision/recall 口径（P0）

**实装状态**。已提供双人标注、仲裁、配对事件引用校验、分层 Wilson 区间和负控统计。
三家应用业务证据与 O2 自有夹具分开进入复核包。独立样本与签核量仍待积累，
当前对外准确率为 `not_measured`。复核格式见 [基准说明](../vehicle/bench/README.md)。

**解决短板**：E2。当前 `pair_metrics` 只有单一 TP/FP/FN，无置信区间、无分层；
三家样本是 `agent_review`，`human_signoff=pending`，`accuracy` 仍为 `not_measured`。

**改动文件（精确路径）**

- `vehicle/bench/metrics.py`：新增 `stratified_metrics`：
  - 分层键（取现有 `src` 实际值，不新造枚举）：
    `read_source` = `vhal` / `privacy`（通用隐私源）/ `lab_power` / `ha_socket`；
    `flow_path` = `proxy` / `ha_transport` / `lab_power`（出现 `hook_egress` 时单独成层）；
    `sample_origin` = `owned_fixture` / `independent`；
    `label_origin` = `agent_review` / `independent_review`。
  - 每层 `tp/fp/fn`、`precision/recall`、Wilson 95% CI、分母为 0 时 `null`。
  - `cohens_kappa`（两位 reviewer 的 pair 标签）；`negative_control_fp_rate`。
  - `label_set_sha256`；`not_measured_reasons`。
- `vehicle/bench/labels.py`（新增，≤300 行）：标签校验、双人一致性、仲裁记录、版本化。
- `vehicle/bench/evaluate.py`：每个样本写 `metrics.json`；汇总写 `benchmark-metrics.json`
  （含 `generated_at` / `rules_sha` / `coverage_sha` / 分层指标 / label hash）。
- `vehicle/bench/suite.py`：`review-packet.json` 增加分层视图与 `human_signoff` 状态。
- `vehicle/bench/README.md`：写入口径、命令、分母为空的处理。
- `vehicle/lab/THIRD_PARTY_ACCEPTANCE.md`：登记每个样本的正例/负例/漏采/归因不确定。
- 样本侧：`apk/vehicle/` 自有样本 + 可在 AAOS 安装的 F-Droid 普通 App；`vehicle/bench/aaos35-suite.json` 补标签。

**计算口径（必须按此写进报告）**

- 统计单位：`[rule_id, read_src, read_event_id, flow_src, flow_event_id]`（`pair_schema=2`）。
- `TP = 检测到的 pair ∩ 标注 pair`；`FP = 检测到但未标注`；`FN = 标注但未检测到`。
- **按数据源与传输路径分开报**：VHAL 读取 / 通用隐私读取 / 实验室电源读取分开；
  proxy 正文 / 进程内出站 / 长连接分开。禁止先合并再算一个总分。
- 夹具与独立 App 分开；`agent_review` 与 `independent_review` 分开；
  `not_measured` 的层保留原因，不填 0。
- `accuracy` 只在同一层、同一标注集下给出 `n` + CI + label hash，不作为全局单一数字。

**验收（可量化、可复现）**

- ≥10 个独立 App、≥100 对参考配对；2 名 reviewer 独立标注 + 1 次仲裁；Cohen's κ ≥ 0.80。
- 每层输出 P/R + 95% Wilson CI；空分母返回 `null`；夹具与独立样本不合并。
- 负控（不同值/未读取/未外发）false positive ≤10%，单列。
- `accuracy` 从 `not_measured` 变为带 `n / CI / label_set_sha256` 的实测值。
- 至少一份真实样本 `human_signoff=signed`；有 reviewer、时间、参考证据路径 + SHA-256。
- 离线可先验：扩展 `vehicle/bench/test_metrics.py`，验证 CI、κ、空分母、分层键。

**依赖资源**：需要设备采集 + 外部样本 + 人工签核；代码与统计口径可离线先做。
**风险**：小样本 CI 很宽，不能外推；标注成本高；**不得用标注集回调规则参数**（留出集）；
样本可用性受 AAOS 安装限制，手机侧载样本单列，不计入原生 AAOS 分母。
**工作量**：代码 2–3 人日；数据/标注 10–15 人日（与设备时间强相关）。

---

### O4 Hook 开销从 845 ms 压到 ≤400 ms（P0）

**进展（2026-11-04）**：重载现测基线为中位 1000 ms、P95 1340 ms。首轮优化实测
中位 420 ms、P95 970 ms；减少重复取值和栈处理后，最终版中位 **205 ms**、P95 **260 ms**，
达到重载目标。每臂 96 次主读取、12 次外发；156 条读取与 120 次嵌套合并对齐基线 276 条。
最终版轻载六组全部通过，CPU 增量中位 35 ms、P95 110 ms。
O2 封存重放和最终版新采集分别对齐 10 条自有夹具参考记录，其中各 5 条超过 30 秒，通用窗口保持原值。
详见 [O4 复测记录](../vehicle/bench/README.md)。

**解决短板**：E6。`vscan_runtime.js` 每条事件做两次 `JSON.stringify`、一次 `send()`、
一次设备端 `File` 打开/写/flush/关闭（SELinux 拒绝但每次都尝试）、一次 `console.log` 序列化；
`hook_vhal.js` 同时挂 `getProperty` 与 `getIntProperty/getFloatProperty/getBooleanProperty`，
高层 API 内部再调 `getProperty`，同一读取产生多层重复事件（12 动作产生 276 条）。

**当前实现**

- `vehicle/hooks/vehicle_transport.js`：全量 bundle 启用 VHAL 批传，20 条或 50 ms 刷出；
  外发与错误事件会先刷出积压读取。批传路径直接回传宿主，省去设备文件与重复日志。
- `vehicle/hooks/hook_vhal.js`：合并同线程、同属性和区域的已知同步委托，输出 `nested_suppressed`；
  保留应用帧和前 12 帧，订阅回调仍独立记录。
- `core/frida_host/run.py` 与 `message_stream.py`：批量追加 JSONL、逐条写 SQLite，退出前调用
  `vscanFlush` 并核对落盘数量；兼容旧的单条回传。
- `vehicle/bench/overhead.py` + `vehicle/bench/overhead_report.py`：报告同时给中位数、P95、
  原始事件数、`nested_suppressed`、唯一读取数。

**验收（可量化、可复现）**

- 同夹具同工作负载 `./vehicle.ps1 overhead --pairs 4 --actions 12`：
  中位 CPU 增量 **≤400 ms**（相对 845 ms 降幅 ≥50%），同时给 P95。
- 12 动作 × 8 属性 = **96 次主读取**全部可定位；基线 276 条记录与最终版 156 条读取加
  120 次 `nested_suppressed` 可对账；保留 12 次外发并确认 `hook_errors=0`。
- `--pairs 6 --actions 4` 单独复核轻载中位与 P95；既往 0 ms 中位出现在测量噪声内。
- 优雅收尾：`--stop-file` 触发后先 `flush` 再 detach；强杀/崩溃场景保留失败日志，
  不以空 JSONL 冒充成功。
- 离线：`tools/test_hook_bundles.py`、`vehicle/bench/test_overhead.py`、
  `core/frida_host/build.py --platform vehicle` 通过；shared core 改动跑移动回归（§5）。

**依赖资源**：需要设备 + 自有夹具；离线只能验证 bundle 构建与单测。
**风险**：批处理会延迟证据落盘 → detach/stop 必须强制 flush；嵌套去重可能掩盖真实独立调用
→ 只压“同一线程同一调用栈的内层”，保留 `suppressed` 计数；栈压缩可能削弱代码行号
→ `codeloc` 仍保留应用帧的完整索引，只裁剪系统帧。
**工作量**：4–6 人日。

---

### O5 证据产物一致性：摘要指纹 + finding 三类（P1，但依赖低）

**实装状态**。契约 v2 已接入审计、独立关联、重放和 PDF。
新契约的 `coverage_sha` 使用覆盖矩阵导出字节计算。
失败运行使用 `run-status.json` 登记缺件和摘要错误，报告完成校验后发布。

**解决短板**：E7。`audit.py` 已有 `generated_at`/`rules_sha256`/`coverage_chain.sha256`，
但缺顶层 `coverage_sha`，`input_completeness` 只有状态词（无 count/sha/parse 状态）；
`correlate.py` 摘要没有 `generated_at/coverage_sha`；finding 只有
`conclusion_level` 与 `evidence_kind`，没有统一的 observed/candidate/static 分类。

**改动文件（精确路径）**

- `vehicle/pipeline/contracts.py`：新增 `SCHEMA_VERSION` 与 `artifact_digest`。
- `vehicle/pipeline/audit.py`：摘要增加顶层 `rules_sha`（保留 `rules_sha256` 兼容）、
  `coverage_sha`；把已有 `input_completeness` **扩展**为下文的 count/sha/parse 结构，
  旧键（`capture_integrity`/`apk`/`static`/`policy`/`scenarios`）原样保留。
- `vehicle/analyze/correlate.py`：独立运行时同样写这四项；`coverage_sha` 取自本模块生成的
  `coverage` 对象的规范化 JSON 摘要，缺输入时写 `null` + 原因。
- `vehicle/privacy/pipeline.py`：`initial_summary` / `append_general` 补齐四项。
- `vehicle/analyze/evaluation.py`：`evidence()` 增加 `finding_class`：
  - `observed`：有同会话、同包名的读取事件 `outcome=ok` 且值取得；或外发正文直接命中且
    `origin_proven=true` 的令牌配对。
  - `candidate`：`read_then_egress` 仅相关、归因歧义、窗口配对、`batch_value_set`。
  - `static`：清单/静态扫描结果；**不得带 code_locs**。
  同时写 `finding_class_reason`；`conclusion_level` 保持原值，不改旧语义。
- `vehicle/analyze/report.py` / `report_extras.py`：展示三类标签。
- `vehicle/bench/suite.py`：汇总层带上四项指纹。
- 测试：`vehicle/pipeline/test_audit.py`、`vehicle/analyze/test_vehicle_evidence.py`、
  `vehicle/privacy/test_evaluation.py`。

**`input_completeness` 固定结构**

```
inputs: {
  reads:      {path, exists, count, sha256, parse_status_totals},
  flows:      {path, exists, count, sha256, parse_status_totals, unattributed},
  egress:     {path, exists, count, sha256},
  permissions:{path, exists, count, sha256},
  manifest:   {path, exists, sha256}
}
complete: true/false
missing:  [原因...]
```

**验收（可量化、可复现）**

- 每份 `correlation-summary.json` / `audit` 摘要：`generated_at`、`coverage_sha`、`rules_sha`、
  `input_completeness` 四项均非空（允许 `null` 但必须带 `reason`）。
- `coverage_sha` 与 `coverage/coverage.json` 的 SHA-256 相等；`rules_sha` 与 `rules.db` 相等。
- findings.jsonl：**100%** 有 `finding_class ∈ {observed,candidate,static}`；
  `static` 的 `code_locs` 为空；`candidate` 必有 `correlation_scope` 与 `origin_proven`。
- 负向用例：删掉 `flows.jsonl` 重跑 → `input_completeness.complete=false` 且摘要明确写
  “外发未采集”，不得出现“未发现外发”。
- 重放 `vehicle/bench/aaos35-suite.json`：结论等级与计数逐项不变（只增字段，不改结论）。
- 离线可全验。

**依赖资源**：离线。
**风险**：字段新增可能破坏下游按固定键集解析 → 只做**加法**；golden 测试先冻结旧键集。
**工作量**：2–3 人日。

---

### O6 VHAL 权限映射回填 + AAOS 25Q2 + AAID（P1）

**解决短板**：E5。8 行覆盖链 `required_permissions.op=unknown`、`definition_status=pending`、
`source_refs=[]`；25Q2 官方第三方属性未接入；AAID **读取已覆盖**（`vehicle/privacy/AAID_POLICY.md`、
`VSC-GR-advertising_id`），**外发关联未覆盖**。

**改动文件（精确路径）**

- `vehicle/rules/python/fetch_seed_sources.py`：抓取 AOSP special-properties / AAOS 25Q2
  官方页面，原文 + SHA-256 落盘（离线缓存，不编造）。
- `vehicle/rules/python/parse_sources.py`：解析官方权限表达式（`all_of`/`any_of`/`none`），
  生成 `read_permission_expr_json`。
- `vehicle/rules/python/build_multiversion_rules.py`：写入
  `definition_status`（仅官方项 `defined_by_official_source`）、`source_refs_json`、
  `protection_level_raw`、`protection_level_normalized`、`protection_level_source`。
- `vehicle/rules/python/build_rules.py` / `build_seed.py`：按需同步。
- `vehicle/rules/rules_library/rules.db` + `rules.manifest.json`：重新生成（不入库由用户决定）。
- `vehicle/coverage/export.py`：保护等级规范化映射（`normal/dangerous/signature/privileged/vendor/unknown`），
  `unknown` 必须带原因。
- `vehicle/lab/vhal_acceptance.py`：逐属性 `ok/denied/empty/unavailable` + 设备指纹；
  保留 5 ok / 3 denied；GEAR_SELECTION 订阅回调单独标记。
- `vehicle/privacy/catalog.py` + `vehicle/rules/python/privacy_rows.py` +
  `vehicle/hooks/hook_privacy.js`（由 catalog 生成 targets）：新增 AAID
  `AdvertisingIdClient.getAdvertisingIdInfo/getId` 四态。
- `vehicle/COMPATIBILITY.md`：API 35 上 25Q2-only 能力标 `not_applicable_api_level`。

**验收（可量化、可复现）**

- `coverage.json`：现有 **8 行 VHAL** 每行都有非空 `source_refs`（官方未覆盖的行写
  `definition_status=not_covered_by_official_source` + 原因，不再留 `pending`）；
  25Q2 新增属性只允许 `defined_by_official_source` 或 `not_applicable_api_level`，
  不允许“猜测常量”。
- `required_permissions.op` 只允许 `all_of/any_of/none/unknown`，`unknown` 必须带官方原因。
- `protection_level_normalized` 覆盖所有非 `unknown` 原始值；0 个未映射；`protection_level_source` 非空。
- `vhal_acceptance.py`：8 行都有 `outcome` + `device fingerprint`；5 ok / 3 denied 保留；
  GEAR_SELECTION 有订阅回调证据；拒绝行不得写成“已采集”。
- AAID：GMS 镜像上四态（`obtained/denied/empty/unavailable`）齐全；无 GMS 标 `unavailable`；
  不与 Android ID 混同；有对应规则/测试。
- API 35 报告把 25Q2-only 能力标 `not_applicable_api_level`；API 36 有镜像则 `verified`，
  无镜像则 `blocked_no_image` + 证据链接。
- 防编造守卫：构建时任何新增 `prop_id` 若 `source_refs` 为空则失败。

**依赖资源**：规则回填离线可做；AAID/属性验收需要设备与 GMS 镜像；API 36 镜像可能不可得。
**风险**：官方页面非机器可读 → 手工转录必须带原文 SHA 与引用位置；25Q2 能力在 API 35 不存在
→ 只能标 not_applicable；OEM 属性继续不做。
**工作量**：5–8 人日。

---

### O7 产品化：`prepare` 自建 venv + 统一样本 manifest（P1）

**解决短板**：E8。当前 `prepare` 只校验依赖，缺依赖直接报错；样本 APK/sha/来源/会话/采集/审计
分散在多个 JSON，交接要人工拼。

**改动文件（精确路径）**

- `vehicle/pipeline/prepare.py`：新增 `--bootstrap-venv`：
  用当前解释器创建 `.venv`，`pip install -r requirements.txt`，再用 `.venv` 解释器重跑校验；
  写 `bootstrap.json`（基础解释器、venv 路径、requirements SHA、pip 日志、安装结果）。
  `--check` 只校验不联网。
- `vehicle/__main__.py`：暴露新开关；`environment.ps1` 已优先 `.venv`，不改。
- 新增 `vehicle/bench/manifest.py`（≤300 行）：统一 manifest 读写与查询。
- `vehicle/bench/samples.py`、`vehicle/bench/evaluate.py`、`vehicle/bench/suite.py`：
  接入统一 manifest；哈希不符即失败，不降级。
- 测试：`vehicle/pipeline/test_environment.py`、新增 `vehicle/bench/test_manifest.py`。

**统一 manifest 字段（一处可查）**

```
sample_id / family / classification
apk:      {file, sha256, source_url, release_tag, license, license_sha256}
install:  {package, user, application_class, installed_apk_sha256, signature_verification}
capture:  {dir, session, capture_health, android_version, device_fingerprint}
audit:    {dir, rules_sha, coverage_sha, findings_total, input_completeness}
labels:   {origin, reviewer, reviewed_at, human_signoff, sha256}
status / gaps / failed_runs
```

**验收（可量化、可复现）**

- 全新机器（只有基础 Python）：`./vehicle.ps1 prepare --bootstrap-venv` 退出 0；
  `.venv/Scripts/python.exe` 存在；`verification.json` 记录 `bootstrap`、pinned 版本、
  requirements SHA；第二次运行不重复安装（幂等）。
- `./vehicle.ps1 prepare --check` 不触网、不建 venv，只报告缺什么。
- 三家现有样本生成统一 manifest；`manifest show --id <id>` 一条命令输出
  APK/sha/来源/会话/采集/审计 六类字段。
- `benchmark` 读统一 manifest；APK 哈希不符 → 该样本 `failed`，不产生“正常零发现”。
- 离线单测覆盖：字段必填、哈希、缺失输入 → 明确失败原因。

**依赖资源**：离线可验证；首次建 venv 需网络（可用阿里云/本地缓存）。
**风险**：pip 网络失败、venv 体积、Windows 权限；提供 `--no-bootstrap` 与清晰错误，
绝不修改全局 Python。
**工作量**：3–4 人日。

---

### O8（P2）API 33 / 36 版本矩阵

**解决短板**：E5 的版本外推风险。`vehicle/COMPATIBILITY.md` 已写明 API 33/36 只有离线解析，
无设备验收；API 36 本轮官方索引没有 x86_64 车载镜像。

**改动文件**：`vehicle/compatibility.py`、`vehicle/COMPATIBILITY.md`、
`vehicle/lab/` 的版本验收脚本、`vehicle/pipeline/prepare.py`（`profiles` 输出）。

**验收**：API 33/34/35/36 每格有“规则基线 / 设备验收 / 镜像来源 / 未覆盖原因”；
API 36 无镜像只能 `blocked_no_image` 并附索引证据；API 34 的通用来源四类正反例沿用；
禁止把 API 35 规则伪装成 36；每个版本的四类通用来源与 VHAL 行分开报。

**依赖资源**：需要 API 33/36 车载镜像（36 可能不可得）。
**风险**：把“离线可解析”写成“已验证”；跨版本常量猜测。**工作量**：5–7 人日。

---

### O9（P2）可见性状态与后台流量

**解决短板**：E1 的实证基线薄。当前只记录读取/外发，未记录 App 前后台状态，
无法回答“后台是否仍在读/发”。报告建议把可见性作为可解释性增强，而非新结论。

**改动文件**：`vehicle/privacy/catalog.py`、`vehicle/rules/python/privacy_observation.py`、
`vehicle/hooks/hook_privacy.js`、`core/collector/flow_entry.py`、
`vehicle/privacy/evaluation.py`、`vehicle/bench/metrics.py`。

**验收**：每条 read/flow 有 `visibility_state ∈ {foreground, background, unknown}` +
`connection_id`（长连接时）+ WS `message_id`；≥10 个 App、≥3 条后台 flow；
前台/后台分开统计；`unknown` 有原因；后台读取不得直接写违规，只进 candidate。

**依赖资源**：设备 + 样本；**工作量**：4–6 人日。

---

## 3. 明确不做什么

### 3.1 报告已判定“效果有限 / 不建议重复投入”的方向

| 不做 | 理由（报告 §3.3） | 本项目替代做法 |
| --- | --- | --- |
| 纯静态污点作为违规结论 | 反射/native/混淆是盲区；DroidBench 精度不能外推 | 只做候选与覆盖差集，不写 `policy_violation` |
| 纯权限过度申请作为结论 | 91%/83% 衡量“申请超出”，不是“读取或外发” | 只做风险排序 |
| 纯政策关键词/NLP | 否定/例外会反转语义；关键词 precision 有限 | 条款级 + 否定标注 + 人工复核（不在本轮） |
| 纯流量字符串匹配 | TLS、派生值、二进制、长连接都会打断 | 值级 + 派生 + 显式 `unparsed` + 后续 ML 兜底 |
| 全系统动态污点 | 需改 ROM/ART，不能注入任意第三方 APK | 保持 Frida 观察路线 |
| 多用户特权提升 | 多数向量需 shell/系统权限，普通第三方威胁面窄 | 只做 exported component + URI grant 矩阵（P2） |
| 厂商 VHAL 属性枚举 | vendor properties 仅 system APIs；OEM 有 156–753 个自定义属性 | 只做官方 8 个；OEM 必须授权镜像 |
| AdID 退出作为合规证明 | 禁用后仍有 App `opted_in` | 记录实际请求/响应与 SDK 行为，不看设置 |
| 大规模 tracker 名单匹配 | 域名归类是先验，不是值级证据 | 只作域名先验与报告分类 |

### 3.2 本轮/本项目暂不投入的具体项

| 不做 | 理由 | 何时再评估 |
| --- | --- | --- |
| 把 60/120 秒设为默认窗口 | 60 秒虽补齐 28/28，但额外候选 28；会把误配洗成“覆盖提升” | 仅在令牌可对齐的复核/实验使用 |
| 训练 PII 机器学习分类器 | 没有独立标注训练集；先有 O3 的标签再谈 | O3 完成且标签≥100 对之后 |
| 追 Flutter/WebView/native 全量明文 | 成本高且受协议/符号限制；当前先标 `unparsed`，不承诺全量 | O1 落地、缺口量化后单独立项 |
| OEM 镜像厂商属性 | 无授权镜像；不得生成常量 | 拿到授权镜像 |
| 100–300 App 规模跑批 | 没有标注口径时规模只会放大不可解释的数字 | O3 口径稳定后 |
| 公开 benchmark / 12 个月纵向 / 法律条款映射 / 硬件 provenance | 需要 OEM、学术、律师、芯片厂合作 | 外部资源到位 |
| 改 `mobile/` 产品线功能 | 本轮范围是车载；但共享内核改动必须移动回归全绿 | 单独任务 |
| 重打包/绕过签名/账号规避样本 | 违反授权测试与项目边界 | 不评估 |

---

## 4. 分批实施顺序

### 4.1 批次与依赖

| 批次 | 包含 | 能否并行 | 依赖 | 完成后可解锁的结论 |
| --- | --- | --- | --- | --- |
| A（离线，先做） | O1 → O2 → O5；O7、O3 离线部分、O6 离线规则回填并行 | 同 worktree 内 O1/O2/O5 **必须串行**（共享 `flow_entry.py`、`evaluation.py`、`correlate.py`）；O7、O3-offline、O6-offline 可与其他 worktree 并行 | 无设备 | 能对外说：每条 flow 有解析状态与哈希；未解析不再静默；令牌配对在冻结夹具 28/28 且额外候选不增加；摘要四指纹齐全；样本一处可查；官方属性权限有源 |
| B（设备，串行采集） | O4（开销）、O6（AAID/VHAL 设备验收）、O2 可选重采令牌样本 | 代码可并行（hooks vs rules/lab）；**设备采集必须串行**（单模拟器/单前台/单端口） | A 完成（O1 的 parse 字段进事件；O6 离线规则已回填） | 能对外说：Hook 开销 ≤400 ms；AAID 四态可复现；属性权限映射有设备证据 |
| C（数据与签核） | O3 全量、O6 收尾 | 必须串行于 B 的设备时间；标注可与 C 内代码并行 | A + B；外部样本/双人 reviewer | 能对外说：首个 n≥100、κ≥0.80、带 95% CI 的 P/R，按数据源/路径分列 |
| D（P2，另排期） | O8 API 33/36 矩阵、O9 可见性/后台 | 可并行（不同目录） | O8 依赖 O6；O9 依赖 O1/O2 | 版本矩阵与后台流量统计；仍不自动判违规 |

> 并行边界：**代码并行可以，设备运行不行**。`vehicle/bench/overhead.py`、`vehicle/lab/*`、
> `capture` 全部争用同一 `emulator-5554`、8888 端口与单前台，必须串行（M020/D413 教训）。
> 同一 worktree 内共享文件的改动也要串行；建议每批用独立 worktree/branch，由用户决定入库。

### 4.2 建议的首批开工顺序（可直接照做）

1. **O1**：先加 `core/collector/parse.py` 与离线夹具；只加字段不改结论，跑 core 单测。
2. **O2**：在 O1 的 `batch_tokens / read_claims` 上实现
   `token_read_claim → token_hook → batch_value_set → value_in_window → content_tag_in_window`
   的降级顺序；用冻结 002/004 重放，先出 `window` 模式 golden，再出 `both` 模式数字。
3. **O5**：最后加摘要指纹与 `finding_class`，避免前面调试时字段反复变。
4. 同时并行：**O7**（独立目录）、**O3-offline**（`metrics.py` 的 CI/κ/分层，不碰 `evaluate.py`
   的动态流程）、**O6-offline**（规则源抓取/解析，不碰采集）。
5. A 全绿后进入 B：先 O4（设备收益最快），再 O6 设备项；B 期间启动 O3 的样本采集与标注。

### 4.3 关键依赖图

```
O1 parse ──► O2 token ──► O5 evidence ──► O3 full ──► (对外 P/R)
   │                          ▲
   └──────────────► O9 visibility
O6 rules ──► O8 API33/36
O7 prepare/manifest ──► O3 sample reproducibility
O4 overhead（独立设备线）
```

---

## 5. 回归与证据门禁

### 5.1 每批必须跑

```powershell
. ./environment.ps1
& $VScanPython tools/run_regressions.py --mobile
& $VScanPython mobile/tools/run_mobile_checks.py
& $VScanPython tools/check_mobile_branch.py
```

钩子/共享内核改动额外：

```powershell
& $VScanPython core/frida_host/build.py --platform vehicle
& $VScanPython core/frida_host/build.py --platform shared
./vehicle.ps1 prepare
```

### 5.2 证据门禁（写进 PR/评审，不靠口头）

- 每个数字必须能指向：命令 + 输出目录 + 输入 SHA；失败轮次保留，不以“文件存在”宣称通过。
- 新增字段只做加法；旧键集有 golden，改动前后对比。
- 任何“未观测到”必须同时给 `input_completeness` 与 `unparsed` 计数，否则不得写“无外发/无读取”。
- 任何配对数字必须给 `pair_basis` 分布与 `origin_proven` 计数，禁止只报一个总数。
- 任何 P/R 必须给分层、n、CI、label hash；夹具与独立样本不合并。

---

## 6. 需要用户确认的三个决策

1. **O3 的 10–20 个独立样本来源**：只用 `apk/vehicle/` 自有样本 + F-Droid 可在 AAOS 安装的
   普通 App，还是追加需要申请的数据集（AndroZoo）？前者可立即开工，后者周期更长。
2. **双人标注的人力**：谁做 reviewer 2 与仲裁？没有第二人时，`independent_review` 不能成立，
   只能保留 `agent_review`，P/R 继续为空。
3. **`prepare` 默认是否建 venv**：建议默认 `--bootstrap-venv`，并保留 `--check`/`--no-bootstrap`
   给 CI/离线环境；需确认是否接受首次联网安装。

---

## 7. 结论摘要（给负责人的三句话）

1. **先把“看不见”变成“看得见”**：O1 让每条报文都有解析状态，`unparsed` 必须带哈希与原因；
   否则“0 条发现”无法解释，precision 会被静默丢弃的流量抬高。
2. **再用令牌修窗口**：O2 在冻结夹具上把 30 秒漏配从 14/28 修到 28/28，且不引入 60 秒的
   28 个额外候选；30 秒仍是默认，令牌只证明批次身份，不证明因果。
3. **最后用标注把话说实**：O3 产出首个按数据源/传输路径分层的 P/R（n≥100、κ≥0.80、95% CI）；
   在此之前，任何“检测有效”的对外表述都缺少数字支撑。
