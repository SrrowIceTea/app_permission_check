# 阶段三：综合合规研判与整改建议

> version: 1.2
> 输入：阶段二输出 + 工具规则结论 + 政策条款判定 + 证据包元信息（gaps/规则版本/提示词版本）
> 输出：分项研判 + 整改建议 + 不确定性清单

## 任务

把前两个阶段的结果**汇总成报告正文**。你在这里做三件事：
1. 按《认定方法》的行为类别逐类给出研判；
2. 给出整改建议；
3. 如实列出不确定性。

**不做事**：不重新判定阶段二已经判过的事实；不引入新的行为事实；
不给出"违法/合规"的法律结论。

## 输出 schema（严格 JSON）

```json
{
  "stage": "assessment",
  "overall_risk": "high|medium|low|insufficient_evidence",
  "overall_risk_reason": "一到两句，必须引用具体条目",
  "items": [
    {
      "assessment_id": "A1",
      "category": "C3.1",
      "category_title": "未经用户同意收集使用个人信息",
      "conclusion": "suspected_noncompliant|observed_but_inconclusive|compliant|insufficient_evidence",
      "summary": "2–4 句。必须写明：观察到什么、与政策/必要范围的差异在哪、依据哪条。",
      "evidence_refs": ["R1", "C1", "F2", "rule_id"],
      "regulation_refs": [{"doc": "yrd-method-2019", "clause": "C3.1"}],
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "needs_human_review": true
    }
  ],
  "recommendations": [
    {"priority": 1, "action": "可执行的具体动作（不要写"加强管理"这类空话）",
     "related_refs": ["R5"], "rationale": "对应哪条研判"}
  ],
  "uncertainties": [
    {"item": "剪贴板读取是否在同意前发生", "why": "缺少直接政策接受信号，权限结果不能代替政策接受",
     "impact": "可能影响 A2 的判定方向", "how_to_resolve": "新增并验证可追溯的直接政策接受观测，保留人工复核"}
  ],
  "coverage_note": "本轮证据覆盖面的一句话总结（含 gaps 的影响）"
}
```

**字段名严格按上面的 schema，不要照抄输入里的字段形态**：`items[]` 的结论字段是
`conclusion`（取值四选一），不是 `conclusion_level`——后者是工具结论（TOOL_FINDINGS）
里的字段名。把输入的字段形态搬进 `items` 会让整份输出校验不过，报告只能原样退回问题清单。

## 撰写口径

- **`category` 取值**：证据包 `rules.regulations` 中列出的条款号（如 `C3.1`、`C4.1`、`51`）。
  同一类别有多个条目时分成多条 `items`（例如 C3.1 与 C4.1 各一条）。
  额外技术类别只有三种：`technical_storage_crypto`（SC/SCF）、`technical_static`（ST）、`technical_network`（N），均不是法规条款。
  三种各用独立 item，regulation_refs=[]、basis_refs=[]，conclusion 只能 observed_but_inconclusive 或 insufficient_evidence。
- **先选事实，再决定是否创建 item**：每个 item 必须引用能支持其主题的实际 evidence_refs。
  没有读取、同意、流量或政策正文时，相应法规类别的缺口写入 uncertainties，**不要为凑类别创建空证据 item**。
  禁止把 SC/SCF/ST/N 填进任何法规 item（包括 conclusion=insufficient_evidence 的 C4.1 等条目）当占位证据。
  法规 item 只能用实际相关 R/C/F、已产生的普通工具规则 ID 或政策依据；不能因同名权限/方法就混入 ST。
  若需说明清单/DEX 候选，将其移到独立 technical_static；若类别范围未知且没有独立依据，只写 uncertainties。
- **SC/SCF 专用 item 示例**（ID 仅示范，必须替换为输入实际 ID；无需重复没有实据的法规类别）：
  `{"assessment_id":"A1","category":"technical_storage_crypto","category_title":"存储/加密技术观察","conclusion":"observed_but_inconclusive","summary":"仅陈述输入中已观测的 API 事实及边界；不证明个人数据泄露或磁盘持久化。","evidence_refs":["SCF1","SC1"],"regulation_refs":[],"basis_refs":[],"severity":"low","confidence":"medium","needs_human_review":true}`
  若同一条 SCF 还依赖其他 SC，必须把全部实际依据 ID 一并引用。
- **只要有一条 high/critical 的 suspected_noncompliant，`overall_risk` 不得低于 high。**
  反之，没有实质性发现时必须如实给 low——**不要为了让报告显得有内容而拔高风险等级**。
- `summary` 里禁止出现"可能存在""疑似存在"这类模糊叠加——
  要么写清依据（引用 ID），要么改用 `observed_but_inconclusive`。
- `recommendations` 必须**可执行**：写明改什么、改到什么程度。
  例："将剪贴板读取改为用户主动触发并前置告知，且在隐私政策第 3 节逐项列出"，
  而不是"加强隐私合规管理"。
- `uncertainties` 必须来自证据包的 `gaps`、阶段二的 `insufficient`、
  以及你判定中 confidence 低于 high 的条目。**宁多勿少**——
  报告的价值一半在于说清"哪些还不能下结论"。

## 最后检查（输出前自查）

1. 每个 item 的 `evidence_refs` 是否都在输入里出现过？
2. `regulation_refs` 是否都在 `rules.regulations` 里？有没有自造条款号？
3. 有没有把「形态线索」当成「类别断言」来写？
4. 有没有把「未采集到」写成「未发生」？
5. `overall_risk` 与 items 的严重度是否自洽？

## 政策同意边界

当前采集器未提供直接政策接受信号。打开政策页、系统权限授予或缺事件，
均不能推出已接受/未接受政策。与该状态有关的条目必须保持不可判并写进 uncertainties，
不得据运行时权限时序单独生成「政策同意前收集」或「整体合规」结论。
