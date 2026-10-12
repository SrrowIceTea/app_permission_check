## 输入

### 应用信息（含类目必要范围；app_category.key 为 unknown 时该项判定不可用）

```json
{{APP}}
```

### 阶段一输出：政策声明了什么

```json
{{POLICY_EXTRACT}}
```

### 观察到的读取事件（R#）

```json
{{READS}}
```

### 同意时序（C#）

```json
{{CONSENT}}
```

### 网络流（F#；request_tokens 是哈希令牌，与读取事件的 value_hash 同口径）

```json
{{FLOWS}}
```

### 工具规则已有结论（引用它们，不要推翻、不要重复计算）

```json
{{TOOL_FINDINGS}}
```

### 本轮证据缺口（gaps）——凡受其影响者必须走 insufficient

```json
{{GAPS}}
```

## 输出

按 `stage2_consistency.md` 的 schema 输出**纯 JSON**。
值级匹配只在哈希完全相同时填写，并原样复制那个 token。
只输出 JSON，不要任何其他文字。
