# 阶段二：行为—政策一致性比对

> version: 1.2
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
- `tool_findings`：工具规则已有结论（含 rule_id 与结论等级）。**它们是事实，不是你的判断对象**；
  你可以引用它们，不要推翻，也不要重复计算。
- `app_category.necessary_data`：该 App 类目的「必要个人信息」范围（可能为 null）。

## 判定口径

对**每个观察到的数据类别**，按下列顺序判定，得到唯一的 `assessment`：

| assessment | 条件 |
| --- | --- |
| `undisclosed_collection` | 观察到读取，且政策**未声明**该类别（阶段一 verdict 为 not_met/unclear 或未出现在 declared_collection），且该类别不属于该类目必要范围 |
| `over_collection` | 观察到读取，政策有声明，但该类目**不属于** `app_category.necessary_data`，且该类目必要范围已知 |
| `read_before_consent` | 当前输入不支持此判定，禁止输出；政策同意时序只能标记未知 |
| `plaintext_transmission` | 该类别出现在 `flows` 的敏感标签中，且该流明确 `intercepted_tls=false`（客户端未使用 TLS） |
| `consistent` | 仅声明与观察的类别一致，且必要范围匹配；不代表政策同意有效、整体合规 |
| `insufficient_evidence` | 关键输入缺失（见 `gaps`），无法判断 |

一条数据类别可以同时满足多条时，**按上表从上到下取第一条命中的**，
其余写进 `also_applicable`（例如同时是未声明且同意前读取）。

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
      "assessment": "undisclosed_collection",
      "also_applicable": [],
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
  "requirement_followups": [
    {"req_id": "PP-06", "verdict_from_stage1": "unclear",
     "observed_relevant": true,
     "comment": "政策未逐项列出剪贴板，而实际存在剪贴板读取", "evidence_refs": ["R5"]}
  ],
  "insufficient": [
    {"item": "SMS 读取", "missing": "consent.jsonl 缺失，无法判断同意时序"}
  ]
}
```

## 硬性要求

1. `read_evidence_refs` 等引用必须来自输入里真实存在的 ID，不得自造。
2. `value_level_transfer` **只在**读取事件的 `value_hash` 与流的某个 `request_tokens`
   完全相同时填写，并原样复制那个 token 字符串。**不得**因为"都是 15 位数字"就填。
3. `policy_only_declared` 是**差异记录**，不是违规：政策声明了但本轮没观察到，
   不应写进 `per_data_type` 的违规判定。
4. 只要 `gaps` 里存在影响本项判定的缺项，相关条目必须走 `insufficient_evidence`
   或写进 `insufficient`，不得硬判。
