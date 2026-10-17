# 隐私风险量化评估模型 —— 方案与实现

仅用于授权测试（已获授权的样本与设备）。

> 状态：v1 已实现并通过 16 项离线回归；已接入 `tools/check_mobile_branch.py`。
> 代码：`mobile/analyze/risk_score.py`　测试：`mobile/analyze/test_risk_score.py`

---

## 一、要解决的问题

关联引擎（`correlate_mobile.py`）产出的是**一条条彼此独立的结论**，每条带
`severity` 和 `conclusion_level`。这适合逐条复核，但回答不了三个跨条目问题：

1. 这个 App 总体多危险？需要一个可比较的量。
2. 14 条 `candidate` 和 1 条 `correlated`，哪个更该先看？
3. 某数据类别「被读到」和「被读到并明文发出」，差多少？

举例：真实样本跑出 18 条结论，其中 **8 条 `over_permission`（仅清单声明了权限）
和 1 条 IMEI 外发证据**。人工浏览时它们看起来同样"是条结论"，但实际危害相差
两个数量级。量化模型就是把这个差距显式化。

**模型不回答的问题**：这条行为是否违法。工具不产出 `policy_violation`
（`DECISIONS.md` M012），评分层同样不做定性。

---

## 二、现有字段能支撑什么

模型完全建立在规则库与分析引擎的既有输出上，不引入新的事实来源。

| 输入字段 | 来源 | 在模型中的作用 |
| --- | --- | --- |
| `data_type` → `sensitivity` | `sensitive_data_types` 表（GB/T 35273 §3.2 分级） | 数据维度权重 |
| `evidence_kind` | 求值器（4 种取值） | 危害路径权重 |
| `conclusion_level` | 规则自带（candidate/observed/correlated） | 证据强度权重 |
| `severity` | 规则自带（info/low/medium/high/critical） | 量级乘数 |
| `content_match_basis` / `value_match_form` | C1 派生值溯源 | 值级命中加成 |
| `coverage.inputs_present` | summary.json | 置信度（输入完整度） |
| `coverage.data_types_coverage_pct` | summary.json | 置信度（观测覆盖） |
| `gaps` | summary.json | 原样带出，作为分数解释的一部分 |

**一个重要的观察**：现有 `severity`是规则生成时的**静态标签**——同一数据类别下
所有规则类型的 severity 完全相同（见 `rule_gen.py` 第 173 行）。它无法区分
"清单声明"和"确实发出"。这正是模型要补的维度，而不是重复造一个 severity。

---

## 三、模型结构

### 3.1 单条 finding 的条目分

```
item_score = data_weight × path_weight × evidence_weight × severity_weight × value_bonus
```

四个维度乘一个加成，**每个乘数都在输出里写明依据**（`score_derivation`），
保证任何一条分数都可追溯到具体字段。这是可审计性的要求。

### 3.2 四个维度的取值

**数据敏感度**（依据 GB/T 35273-2020 §3.2 与附录 B.1）

| 取值 | 权重 | 含义 |
| --- | --- | --- |
| `children` | 4.0 | 14 岁以下儿童信息，单独加档 |
| `sensitive_personal` | 3.0 | 泄露可危害人身/财产安全 |
| `unknown` | 2.0 | 类别未标，取中值，**不假设安全** |
| `personal` | 1.0 | 一般个人信息 |

**危害路径**（依据 M011 值级匹配三重要求）

| `evidence_kind` | 权重 | 事实含义 |
| --- | --- | --- |
| `manifest_permission` | 0.2 | 仅清单声明，连读取都没观测到 |
| `read_event` | 1.0 | 观测到非空读取：数据进了 App 内存 |
| `flow_sensitive_payload` | 2.0 | 报文出现该类别标识（形态级） |
| `read_then_egress` | 3.0 | 读到 + 窗口内发出（关联级） |

**证据强度**（直接映射 `conclusion_level`，不新增等级）

| 等级 | 权重 |
| --- | --- |
| `candidate` | 0.5 |
| `observed` | 1.0 |
| `correlated` | 1.5 |

**值级加成**（仅 `read_then_egress` 生效）

| 情形 | 加成 |
| --- | --- |
| 原值哈希命中 | ×1.3 |
| 摘要形态命中（md5/sha1/sha256） | ×1.2 |
| 仅形态标签匹配 | ×0.7 |

摘要命中的加成低于原值，是因为报文里出现摘要而非明文，直接可读性弱一档；
但它仍属值级证据（摘要可由原值算出），所以**高于**纯形态匹配。

**severity 乘数**：`info 0.2 / low 0.5 / medium 1.0 / high 1.5 / critical 2.0`

### 3.3 聚合：为什么不能简单求和

18 条结论直接相加会得出荒谬的结论——8 条"声明了权限"能顶上半条真实外发。
所以同一处重复命中必须衰减：

```
total = Σ item_score_i × decay(k_i)
decay(k) = 1 / (1 + α·(k-1))，α = 1.0 → decay(k) = 1/k
k = 该 (数据类别, 危害路径) 组内第几条
```

取 `α=1.0` 不是随手定的：它使 `decay(k)=1/k`，即第 k 次命中只贡献 1/k，是
**边际信息量递减**的标准形式。同一个 IMEI 被读 5 次，新信息远少于第 1 次。

这个取值也经过反向验证：α 小于 0.8 时会出现「同一类别重复 3 次 ＞ 3 个不同
类别各 1 次」的荒谬结果，与「信息种类比次数重要」相悖（见
`test_diverse_types_outweigh_repeats`）。我最初取 0.35，正是被这条测试挡下来的。

### 3.4 风险档位（仅用于排序与展示）

| 分数 | 档位 |
| --- | --- |
| ≥ 60 | critical |
| ≥ 25 | high |
| ≥ 8 | medium |
| ≥ 2 | low |
| < 2 | info |
| — | **undetermined**（置信度 very_low 时强制改标） |

`undetermined` 是一个专门的档位：采集没跑起来时如果标 `info`，会被读成
"查过、没问题"——这是最危险的一种误读。所以置信度落到 `very_low` 时，
档位强制改为 `undetermined`，含义写明"这不等于安全，应先修复采集再重跑"。

**阈值依据**：一条敏感数据被关联级发出的典型分值是
`3.0 × 3.0 × 1.5 × 1.5 × 1.3 ≈ 26`，单条即进入 high 档——这与"存在可关联的
敏感信息外发证据"的实际严重程度相符。而一条 `over_permission` 约 0.23 分，
需要堆到 100 条才能进 medium，配合衰减后几乎不可能。

> ⚠️ 这套阈值是**工程设定，未经真实样本统计校准**。跨 App 比较时必须同时看
> confidence，否则会把"没查到"读成"安全"。

### 3.5 置信度：与分数正交，不乘进分数

```
confidence = 0.5 × 输入完整度 + 0.5 × √(数据类别覆盖率)
```

- 输入完整度：`inputs_present` 五项加权（reads/flows/consent 各 1.0，
  permissions/policy 各 0.5——政策是辅助判据，不是行为证据）
- 覆盖率取平方根：数据类别覆盖 14% 是常态（28 类里多数 App 用不到），
  不应线性惩罚

**关键设计**：置信度**绝不与分数相乘**。低置信度不等于低风险，乘进去会制造
"没查到所以安全"的假象。两者作为两个独立数字并列呈现。

---

## 四、实测结果

在仓库已有的真实回归产物上验证（`output/mobile-regression-20261016-221127/e2e/`，
18 条结论）：

```
总分 50.54 ｜ 档位 high ｜ 置信度 medium (0.689)
说明：存在敏感信息外发或明文传输的可关联证据
```

| 数据类别 | 贡献 | 条数 | 最高等级 |
| --- | --- | --- | --- |
| IMEI | 32.70 | 4 | correlated |
| Android ID | 11.25 | 2 | observed |
| 精确定位 | 4.50 | 1 | candidate |
| 应用安装列表 | 1.42 | 3 | observed |
| （无类别，权限声明） | 0.68 | 8 | candidate |

| 规则类型 | 条数 | 贡献 |
| --- | --- | --- |
| data_egress | 1 | 26.32 |
| plaintext_transmission | 1 | 9.00 |
| third_party_share | 2 | 6.75 |
| sensitive_read | 2 | 5.50 |
| policy_mismatch | 2 | 1.38 |
| over_collection | 2 | 0.92 |
| over_permission | **8** | **0.68** |

**这张表就是模型的价值**：8 条权限声明合计 0.68 分，1 条 IMEI 外发证据 26.32 分。
条数与风险完全脱钩，排序直接可用。

---

## 五、怎么用

```bash
PY="C:/Users/OneKyubey/.workbuddy/binaries/python/envs/default/Scripts/python.exe"

# 关联引擎产出 findings 后，直接评分
"$PY" mobile/analyze/risk_score.py \
      --findings output/xxx/e2e/findings.jsonl \
      --summary  output/xxx/e2e/summary.json \
      --out      output/xxx/e2e/risk_score.json
```

输出 `risk_score.json` 包含：
- `total_score` / `risk_band` / `confidence`
- `by_data_type`：哪些信息最该关心
- `by_rule_type`：哪类行为贡献最大
- `top_items`：Top 10 待复核条目（直接作为人工复核队列）
- `all_items[*].score_derivation`：每个乘数的依据
- `gaps` / `caveats`：输入缺口与使用限制

---

## 六、诚实性约束（写进代码，不只是文档）

模型的三条硬约束都用测试锁死了：

| 约束 | 依据 | 测试 |
| --- | --- | --- |
| 不改写结论等级 | M012 | `test_conclusion_level_passed_through_unchanged` |
| 输入含 `policy_violation` 直接报错 | M012 | `test_policy_violation_input_is_rejected` |
| 敏感度缺失时不假设为 personal | M009 | `test_missing_sensitivity_is_not_assumed_personal` |
| 未登记 evidence_kind 不归零 | M009 | `test_unknown_evidence_kind_does_not_floor_to_zero` |
| 值级 > 形态匹配 | M011 | `test_value_hash_beats_shape_tag` |
| 摘要命中弱于原值命中 | C1 | `test_derived_form_weaker_than_raw_value` |
| 覆盖不足不拉低分数 | M009 | `test_low_coverage_does_not_lower_score` |
| 采集失败不标 info | M009 | `test_broken_collection_is_undetermined_not_info` |
| 重复命中必须收敛 | — | `test_repeated_hits_decay` |
| 种类多于次数 | — | `test_diverse_types_outweigh_repeats` |

---

## 七、落地路径

### 已完成（v1）

- [x] `risk_score.py`：评分核心 + CLI
- [x] `test_risk_score.py`：17 项回归
- [x] 接入 `tools/check_mobile_branch.py`（检查组 `risk_score`）
- [x] 真实样本验证

### 建议后续（按优先级）

**P0 — 校准阈值（最有价值的一步）**

当前阈值是工程设定。要让分数有学术与评审说服力，应该在多个真实样本上
标定：取 5–10 个已知结论的 App（如 `SAMPLE_RUN_5APPS.md` 里的样本），
人工给出"该优先复核"的排序，再看模型排序是否一致（可用 Spearman 秩相关）。
这能把"我说它 high"变成"它在 8 个样本中的排序与人工判断一致"。

**P1 — 报告集成**

在 `mobile/report/report_sections.py` 增加 `section_risk_score()`，
放在「证据」之后、「结论」之前，输出：总分 + 档位 + 置信度 + 按数据类别贡献表。
须遵守 M009：置信度不足时在正文写明。

**P2 — 与 AI 章节对接**

把 `top_items` 作为 AI 研判的优先输入（现在 AI 是逐条看）。

**P3 — 权重敏感性分析**

对 `DATA_WEIGHT` / `PATH_WEIGHT` 做扰动测试（±20%），检查档位是否稳定。
若档位随小扰动跳变，说明阈值定得太靠近分界点。

---

## 八、已知局限

1. **阈值未校准**——见 P0。当前档位只能用于同一个版本内的横向比较。
2. **权重是序数而非基数**——`3.0` 不代表"敏感信息比一般信息危险 3 倍"，
   只代表"排序更高"。不要用它计算绝对危害。
3. **无类别结论计分保守**——`over_permission` 一类没有 `data_type`，
   路径权重 0.2 已是最低档，不会虚高，但也无法体现"这个权限本身多危险"
   （规则库 `permission_protection_level` 尚未断言，见 `rules_mobile.summary.json`）。
4. **不覆盖未观测维度**——加固壳、QUIC 等能力边界（见 `CLAUDE.md`）造成的盲区，
   模型看不到，只能由 `gaps` 与 `confidence` 间接反映。
