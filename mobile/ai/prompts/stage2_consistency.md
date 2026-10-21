# 阶段二：行为—政策一致性比对

> version: 1.4
> 输入：阶段一输出 + 动态读取/同意时序 + 网络流 + 工具规则结论 + 类目必要范围
> 输出：逐数据类别、逐同意链路的比对结论

## 任务

把**观察到的事实**（reads / consent / flows / findings）与**政策声明**（阶段一输出）
逐项对齐，判断二者是否一致。你只做对齐与判断，**不要**给出整份报告的总评——那是阶段三的事。

## 输入说明

- `observed.reads`：每条含 `evidence_id`(R#)、`data_type`、`sensitivity`、`outcome`、
  `collection_state`、`non_empty`、`count`、`value_len`、`value_hash`、`ts`。
  仅 `collection_state=obtained` 表示已取得非空数据/非空结果集。
  `empty`、`denied`、`error`、`call_only`、`unknown` 不等于收集；`outcome=ok` 单独不足以证明收集。
- `observed.consent_timeline`：`PERM_REQ`（请求）/`PERM_RESULT`（用户选择）/
  `PERM_CHECK`（自查）/`POLICY_VIEW`（打开疑似政策页）。
  `PERM_RESULT granted` 只证明运行时权限授予，不证明接受隐私政策。
  `POLICY_VIEW` 只证明打开页面，也不证明政策接受。当前采集器没有直接政策接受信号，
  `policy_consent_state` 必须为 `unknown`；不能把缺事件等同于未同意。
- `observed.flows`：含 `request_tags`（标签）与 `request_tokens`（**哈希令牌**，
  形如 `digit15_shape:9f2c…`）。令牌与读取事件的 `value_hash` 相同 ⇒ **值级匹配**。
  `scheme` 是代理上游协议，不能代替客户端 TLS 状态；`intercepted_tls=true` 是客户端 TLS，
  `false` 是客户端明文；缺失、null 或非布尔值为未知，不能判明文传输。
- `tool_findings`：工具规则已有结论（含 rule_id 与结论等级）。它们是可追溯的规则输出，不是最终事实。
  可以引用，但必须结合 collection_state、证据强度和 gaps 复核，不能把工具候选结论升级为确定结论。
- `app_category.necessary_data`：该 App 类目的「必要个人信息」范围（可能为 null）。

## 判定口径

对**每个观察到的数据类别**，把「政策怎么说的」与「行为有什么风险」拆成两个**正交维度**
分别判定。两轴独立填写，不再用单一枚举加优先级（旧 `assessment` + `also_applicable`
把披露状态与行为风险混排，vague/明文传输 谁排前面无法定论；M046 后正式废弃）。

### 披露状态轴 `disclosure_status`（单值，对齐 GNChecker OD/VD 定性）

| 值 | 条件 |
| --- | --- |
| `clear` | 政策**明确逐项**声明该类别，措辞足以定位到具体数据类型 |
| `vague` | 政策有声明，但用**宽泛上位词**覆盖具体数据类型（如"必要的信息""其他信息"），无法确定是否包含该类别。GNChecker 判定口径即「政策写宽泛上位词覆盖具体数据类型」；**政策声明层是误报主源**——把 vague 判成"已声明"或"未声明"都可能是错的，不得据此升级为确定结论 |
| `ambiguous` | 政策措辞模棱两可、可作多种互斥解读（同一句既可读作声明也可读作未声明），与 vague 的区别是存在难以调和的解释冲突 |
| `omitted` | 政策**未声明**该类别（对完整取得的政策正文逐字核实后未提及；unclear 或未取得政策必须走 not_applicable，不得判 omitted） |
| `incorrect` | 政策声明与实际观察**矛盾**（如明示"不收集某类信息"，但观察到读取） |
| `not_applicable` | 无政策正文、观测证据不足（见 `gaps`）、或该类目不适用披露判定——缺输入不硬判 |

### 行为风险轴 `behavior_risk`（列表，可为空 `[]`，只记录本轮观测到的行为风险，不依赖政策声明）

| 值 | 条件 |
| --- | --- |
| `over_collection` | 观察到读取，政策有声明，但该类目**不属于** `app_category.necessary_data`（该类目必要范围已知时） |
| `plaintext_transmission` | 该类别出现在 `flows` 的敏感标签中，且该流明确 `intercepted_tls=false`（客户端未使用 TLS） |
| `read_before_consent_unknown` | 存在敏感读取，但**政策接受时序无法判定**（当前采集器没有直接政策接受信号）。只标 unknown，不判违规；**禁止**输出不带 `_unknown` 后缀的肯定式 `read_before_consent` |

某一轴无风险/不适用时写 `not_applicable` / `[]`，两轴互不影响（例如披露 omitted 同时
行为明文传输：`"disclosure_status": "omitted", "behavior_risk": ["plaintext_transmission"]`）。

## 输出 schema（严格 JSON）

```json
{
  "stage": "consistency",
  "per_data_type": [
    {
      "data_type": "clipboard",
      "data_type_zh": "剪贴板内容",
      "observed_collection": true,
      "read_evidence_refs": ["R5", "R6"],
      "declared": false,
      "policy_quote": null,
      "disclosure_status": "vague",
      "behavior_risk": ["plaintext_transmission"],
      "policy_consent_state": "unknown",
      "consent_gap": {"earliest_read_ts": 1750000000000,
                      "earliest_consent_ts": null,
                      "note": "政策接受时刻未知，运行时权限不能代替政策同意"},
      "value_level_transfer": [
        {"read_evidence_ref": "R1", "flow_evidence_ref": "F2",
         "basis": "value_hash_in_payload", "token": "digit15_shape:9f2c…"}
      ],
      "plaintext_flow_refs": ["F2"],
      "confidence": "high",
      "needs_human_review": true,
      "reason": "一句话说明判定依据"
    }
  ],
  "policy_only_declared": [
    {"data_type": "sms", "note": "政策声明收集短信，但本轮未观察到读取——不构成违规，仅记录差异"}
  ],
  "storage_crypto_review": [
    {"finding_ref": "SCF1 或 null（没有技术观察时）",
     "assessment": "configuration_risk|provider_default_unknown|encrypted_write_observed|api_observed_no_sensitive_binding|insufficient_evidence",
     "evidence_refs": ["SCF1", "SC1"],
     "disk_persistence_proven": false, "plaintext_leak_proven": false,
     "personal_data_binding": "not_established", "reason": "具体 API 边界、风险或未知及其限制"}
  ],
  "requirement_followups": [
    {"req_id": "PP-06", "verdict_from_stage1": "unclear",
     "observed_relevant": true,
     "comment": "政策未逐项列出剪贴板，而实际存在剪贴板读取", "evidence_refs": ["R5"]}
  ],
  "tpl_matrix": [
    {"data_type": "clipboard", "collector_ref": "TPL-01",
     "disclosure_status": "vague",
     "note": "政策只写'与第三方共享必要信息'，未指明接收方与该类别",
     "evidence_refs": ["R5"]}
  ],
  "insufficient": [
    {"item": "SMS 读取", "missing": "consent.jsonl 缺失，无法判断同意时序"}
  ]
}
```

## TPL 矩阵（数据类别 × 收集方 × 披露状态）

`tpl_matrix` 是阶段一 `third_parties`（PP-TPL 条款组，TPL-xx）在一致性层的展开：
对每条既被政策记录**也被本轮观察到**的「第三方/共享收集」关系，填一行
`data_type` × `collector_ref`（必须是阶段一真实存在的 TPL-xx）× 该类别对该接收方的
`disclosure_status`（取值同 disclosure 轴六枚举）。矩阵行只记录观察与声明之间的对位关系；
政策声明了但本轮没观察到的三方共享不写这里（那是政策侧差异，进 policy_only_declared）。

## 硬性要求

1. `read_evidence_refs` 等引用必须来自输入里真实存在的 ID，不得自造。
2. `disclosure_status` 只能是上面六个值之一；`behavior_risk` 必须为数组、数组元素只能
   是上面三个值之一，两项缺一不可（缺输入时 disclose 走 not_applicable、risk 写 []）。
3. **禁止**输出 `read_before_consent`（无 `_unknown` 后缀）：当前没有直接政策接受信号，
   同意的唯一合法表述是 `read_before_consent_unknown`；`policy_consent_state` 只能为 `unknown`。
4. `value_level_transfer` **只在**读取事件的 `value_hash` 与流的某个 `request_tokens`
   完全相同时填写，并原样复制那个 token 字符串。**不得**因为"都是 15 位数字"就填。
5. `policy_only_declared` 是**差异记录**，不是违规：政策声明了但本轮没观察到，
   不应写进 `per_data_type` 的违规判定。
6. 只要 `gaps` 里存在影响本项判定的缺项，相关条目必须走 `not_applicable` / `[]`
   或写进 `insufficient`，不得硬判。
7. available=true 时，`storage_crypto_review` 必须为非空列表，并逐条覆盖全部 SCF。
   每条 finding_ref 只能是该 SCF 原 ID，evidence_refs 包含该 SCF 和它所有 SC 依据。
   explicit_weak_configuration/repeated_iv_fingerprint 对应 configuration_risk，
   provider_default_mode_unresolved 对应 provider_default_unknown，
   encrypted_stream_write_relation 对应 encrypted_write_observed；证据受限也可用 insufficient_evidence。
   无 SCF 但有 SC 时用 api_observed_no_sensitive_binding 并引用实际 SC；无 SC 时写不足。
   这些不是个人信息收集类别，不要把它们塞进 per_data_type；不凭文件头、任意字符串或算法名造泄露。


## 补充告知来源
阶段一带 `policy_document_ref=SUP-...` 的条目仅为独立补充文档声明，受其功能/平台范围限定。
引用这类 `policy_quote` 时保留相同 `policy_document_ref` 以及
`supplementary_scope: "document_scope_only"`，逐字引用同一份文档；不当作 SDK 使用、
实际收集或同意证据。没有可用主政策时仍不得判断整体政策一致性。
