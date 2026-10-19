## 输入

### 阶段二输出：逐数据类别与逐同意链路的比对结论

```json
{{CONSISTENCY}}
```

### 工具规则结论

```json
{{TOOL_FINDINGS}}
```

### 存储/加密脱敏事实与技术观察（不得遗漏，不得升级成泄露证明）

```json
{{STORAGE_CRYPTO}}
```

available=true 且有 SC 时，items 至少有一条技术观察摘要。全部 SCF 必须被 items.evidence_refs 引用；
SCF 同时引用其 SC 依据。无 SCF 也用实际 SC 摘要，不把没有加密事件写成未加密。
纯技术观察的 category 固定 technical_storage_crypto，regulation_refs=[]，
conclusion 仅 observed_but_inconclusive 或 insufficient_evidence；不能臆造法规适用性。
如输出 basis_refs，这类技术观察也必须 basis_refs=[]。不要将 SC/SCF 引用添加到 C3.1 等法规 item。
没有相关 R/C/F/规则事实的法规类别，不创建空 evidence_refs 的 item；缺证据原因只写 uncertainties。

### 隐私政策确定性检查的汇总计数（text_present 是正则代理指标，不是合规结论）

```json
{{POLICY_LINT}}
```

### 允许引用的法规条款与本地正文摘录（**只能**从这里取 {doc, clause}；不得把摘录冒充法规全文）

```json
{{REGULATIONS}}
```

### 本轮证据缺口

```json
{{GAPS}}
```

### 元信息（规则库摘要 / 证据包版本 / 脱敏说明）

```json
{{META}}
```


### ST#/N# 独立技术证据

```json
{{SUPPLEMENTAL}}
```

若存在 ST，items 至少一条引用实际 ST，category=technical_static；若存在 N，items 至少一条引用实际 N，category=technical_network。
两类 conclusion 只能 observed_but_inconclusive 或 insufficient_evidence，regulation_refs=[]，如有 basis_refs 也须=[]。
ST 与 N 不混为一个条目，不混入法规条目或声称读取、外发、明文或合规/不合规成立。
**引用隔离硬要求（即便已另写技术摘要也不能破例）：**
- ST# 只能放在 category=technical_static 的 item.evidence_refs；N# 只能放在 category=technical_network 的 item.evidence_refs。
- 不把 ST#/N# 和 R#/C#/F#、普通 MOB-* findings、SC/SCF 混在同一 item。技术 item 只放该技术层实际 ID，regulation_refs=[]、basis_refs=[]。
- 错误示例：C4.1 item 的 evidence_refs=["ST1","R1","MOB-P015"]，即使结论 insufficient_evidence 也会被拒。
- 正确拆分：独立 technical_static item 引用["ST1"]且法规引用空；如果另有真实 R1/MOB-P015 支持法规主题，可另写法规 item，但那里不得再出现 ST1。没有独立事实时不创建该法规 item，缺口放 uncertainties。
- 不要只增加一条 technical_static 后仍把 ST 留在其他法规 item；输出前逐 item 扫描 evidence_refs，先按 ID 所属层确认 category 和空法规引用。

完整静态候选在阶段二须逐一覆盖；阶段三可汇总，网络分组投影省略不能被写成已全面审阅。
网络元数据只能说明观察到的 API/包；PCAP 无独立逐包 UID，opaque TLS 未解密；握手/DNS 不证明业务传输或泄露。

## 输出

按 `stage3_assessment.md` 的 schema 输出**纯 JSON**。
`overall_risk` 必须与条目严重度自洽；没有实质发现时如实给 low。
只输出 JSON，不要任何其他文字。
