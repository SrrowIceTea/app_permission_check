## 输入

### 阶段二输出：逐数据类别与逐同意链路的比对结论

```json
{{CONSISTENCY}}
```

### 工具规则结论

```json
{{TOOL_FINDINGS}}
```

### 隐私政策确定性检查的汇总计数（text_present 是正则代理指标，不是合规结论）

```json
{{POLICY_LINT}}
```

### 允许引用的法规条款（**只能**从这里取 {doc, clause}）

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

## 输出

按 `stage3_assessment.md` 的 schema 输出**纯 JSON**。
`overall_risk` 必须与条目严重度自洽；没有实质发现时如实给 low。
只输出 JSON，不要任何其他文字。
