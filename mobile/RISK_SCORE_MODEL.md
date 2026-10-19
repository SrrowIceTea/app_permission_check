# 隐私风险量化评估模型 —— 方案与实现

仅用于授权测试（已获授权的样本与设备）。

> 状态：v1.3 已实现并通过 38 项离线回归；已接入 `tools/check_mobile_branch.py`。
> 代码：`mobile/analyze/risk_score.py`　测试：`mobile/analyze/test_risk_score.py`
>
> v1.3 变更：修复衰减分组键——`data_type=None` 的 over_permission 结论不再坍缩成一个
> 组被错误衰减（8 个不同权限是 8 个独立事实，依据聚合权限研究的「权限越具体、独立，
> PII 暴露越多」）；`aggregate`/CLI 接受 `--calibrate-from` 把 `calibrate_bands` 的
> 自适应阈值真正接入评分路径（此前只定义未调用）。
> v1.2 变更：移除 `severity_weight`（与 sensitivity 同源、双重计数，对齐 Zhu 四参数）；
> 值级加成正确读取 `value_match_form` 且缺失保守计；移除 `children` 死档（PIPL 第 28 条
> 需数据主体年龄，动态分析不产出）；`calibrate_bands` 分位点修正为高尾分位
> [P99, P93, P80, P60]；补全 `map_navigation` 必要数据的 `precise_location` 映射。
> v1.1 变更：新增 necessity 维度（越权收集加成）、单调性保证、阈值标定函数；
> 方法论对齐四篇论文（见 §二）。

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
| `data_type` → `necessary_data` | `app_categories.necessary_data_json`（必要个人信息规定 39 类） | 必要性（越权）权重 |
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

## 二、方法论依据（与论文的对齐）

模型的每个维度都不是凭空设定，而是有文献支撑。本节说明「哪个维度来自哪篇论文」，
以及「为什么这样落地」，供评审与后续改进追溯。

### 2.1 Peng et al., CCS 2012 —— 单调性 desiderata

《Using probabilistic generative models for ranking risks of Android apps》
（ACM CCS 2012，被引 500+）首次系统提出「风险评分」概念，并列出好的评分方案
必须满足的三条 desiderata，其中**单调性**（monotonicity）是核心：多一条危险
证据，分数只增不减。

本模型显式保证这一性质。取 `decay(k)=1/k` 并按条目分降序排列后，追加任意一条
finding 都不会让总分下降——这是可以数学证明的（见 §3.3），并有
`test_monotonicity` 锁死。很多早期评分方案（如按权限使用率反比）会在某类权限
使用率超过 50% 时破坏单调性，本模型特意避开这个坑。

### 2.2 Zhu et al., 中国科学·信息科学 2021 —— 异常度

《基于权限的移动应用程序隐私风险量化》（中国科学：信息科学，51(7)）提出四参数
模型：权限敏感度、权限列表异常度、App 使用率、权限调用者数量。其中**异常度**
是关键洞见：风险不仅来自数据本身的敏感度，也来自「这类 App 本不该碰这个数据」。

本模型的 `necessity_weight` 正是这一维度的落地——同一数据类别，对需要它的 App
是正常行为，对不需要它的 App 是越权收集，应加成。

### 2.3 CMU PrivacyGrade（Hong et al.）—— 期望—实际 gap

PrivacyGrade（USENIX SOUPS 2014 等）给 100 万+ Android App 打 A+~D 分，核心是
衡量「用户期望的 App 行为」与「App 实际行为」的差距：地图 App 用定位是正常的，
游戏 App 用定位是异常。这与 Zhu 的异常度同源，都指向 necessity 维度。

### 2.4 CNKI 2026 —— 自适应阈值

《APP 形式化程序个人信息过度收集风险告警算法》用「自适应阈值」——分级阈值由样本
分布的分位数决定，而非拍脑袋定死。本模型的 `calibrate_bands()` 落地这一思路
（见 §3.4）。

### 2.5 聚合权限研究 —— 每条权限是独立风险项

《Personal Information Classification on Aggregated Android Application's
Permissions》（Applied Sciences, 2019）在聚合多个 App 的权限做 PII 暴露分类时指出：
「权限越具体、越独立，PII 暴露越多」——`READ_CONTACTS`、`ACCESS_FINE_LOCATION`、
`READ_PHONE_STATE` 是三个互不隶属的权限，各自对应不同的 PII 暴露面。这条结论直接
支撑 v1.3 的衰减分组修正：`data_type=None` 的 over_permission 结论必须按 `permission`
区分「不同事实」，不能因为 `data_type` 缺失而坍缩成一个组被当成「同一权限重复声明」。

### 2.6 有意**不**引入的方法（并说明理由）

- **概率生成模型（Peng）**：本模型是确定性证据评分，不是概率模型。概率模型需要
  大量标注样本训练，且其输出是「风险概率」而非「已证实的证据强度」——与工具
  「只报告观测到的事实、不猜测」的诚实性原则（M009）冲突。
- **自学习权重（SPRisk, TDSC 2021）**：SPRisk 用模糊聚类自动学权重，需要 19 万
  正常 + 7 千恶意样本。本项目的样本量（五个真实样本 + 合成会话）不足以支撑，
  强行自学习会过拟合。故权重保持人工设定但**可配置 + 可标定**（见 §七 P3）。

---

## 三、模型结构

### 3.1 单条 finding 的条目分

```
item_score = data_weight × path_weight × evidence_weight
             × necessity_weight × value_bonus
```

五个维度乘一个加成，**每个乘数都在输出里写明依据**（`score_derivation`），
保证任何一条分数都可追溯到具体字段。这是可审计性的要求。

### 3.2 各维度的取值

**数据敏感度**（依据 GB/T 35273-2020 §3.2 与附录 B.1）

| 取值 | 权重 | 含义 |
| --- | --- | --- |
| `sensitive_personal` | 3.0 | 泄露可危害人身/财产安全 |
| `unknown` | 2.0 | 类别未标，取中值，**不假设安全** |
| `personal` | 1.0 | 一般个人信息 |

> v1.2 移除 `children` 档：PIPL 第 28 条虽将「不满十四周岁未成年人信息」列为敏感信息，
> 但那是**数据主体年龄**属性，动态分析观测的是 App 行为、无法判断数据是否属于儿童；
> 设一个永不命中的档等于虚假承诺，故从数据敏感度维度移除（见 §八.5）。

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
| 原值哈希命中（`value_match_form=raw`） | ×1.3 |
| 摘要形态命中（md5/sha1/sha256） | ×1.2 |
| `value_match_form` 缺失 | ×1.2（保守，不假设原值） |
| 仅形态标签匹配（`shape_tag`） | ×0.7 |

摘要命中的加成低于原值，是因为报文里出现摘要而非明文，直接可读性弱一档；
但它仍属值级证据（摘要可由原值算出），所以**高于**纯形态匹配。

**severity**（v1.2 起不再是乘数）：规则库的 severity 与 sensitivity 同源（都来自
`sensitive_data_types` 同一行，见 `rule_gen.py`），乘进公式会把「敏感度」这一个信号
计两遍。对齐 Zhu et al. 四参数模型——敏感度是**单一维度**，不存在独立的 severity 乘数。
仅当 `data_type` 缺失（`over_permission` 等无数据类别的规则）时，severity 才作为数据
敏感度的替代映射进 `data_weight`（`info 0.5 / low 1.0 / medium 1.5 / high 2.0 /
critical 3.0`），保住「这个权限本身多危险」的信息。

**必要性（越权）加成**（依据 Zhu 异常度 + PrivacyGrade 期望 gap）

| 情形 | 权重 | 含义 |
| --- | --- | --- |
| 属于该类 App 必要数据 | 1.0 | 正常行为，不加成 |
| 超出必要范围 | 1.5 | 越权收集的异常加成 |
| 无必要数据定义/类别未知 | 1.0 | 不猜，中性（**不是**「都越权」） |

必要性来自 `app_categories.necessary_data_json`（《常见类型移动互联网应用程序
必要个人信息范围规定》三十九类）。未提供必要数据定义时该维度整体不启用，
绝不会把「没查必要性」误读成「全部越权」。

> ⚠️ **粒度局限（已在实测中暴露）**：必要数据定义的粒度可能粗于数据类别。
> 例如 `map_navigation` 的必要数据只映射到 `coarse_location`（位置信息），
> 而 `precise_location`（精确定位）是独立 key——导航 App 读精确定位会被误判为
> 「非必要」。这不是模型缺陷，而是上游 `necessary_data_json` 的映射粒度问题。
> 解决办法是补全映射（把 precise_location 也纳入导航类必要数据），或人工复核
> necessity 加成命中的条目。当前版本在 `necessary_data` 输出里原样暴露用了哪些
> 定义，便于发现这类粒度错配。

### 3.3 聚合：为什么不能简单求和

18 条结论直接相加会得出荒谬的结论——8 条"声明了权限"能顶上半条真实外发。
所以**同一处重复命中**必须衰减：

```
total = Σ item_score_i × decay(k_i)
decay(k) = 1 / (1 + α·(k-1))，α = 1.0 → decay(k) = 1/k
k = 该「底层事实」组内第几条
```

关键在「底层事实」怎么定义（`_decay_key`）：

- **有 `data_type`**：按 `(数据类别, 危害路径)` 分组。同一个 IMEI 被读多次、或
  多条规则都指向"读到 IMEI"这同一事实时收敛。
- **无 `data_type`**（over_permission 等）：每条对应一个**不同的权限**，是独立事实，
  按 `permission` 分组，**不互相衰减**。v1.2 曾把这里坍缩成 `(None, manifest_permission)`
  一组，导致 8 个不同权限被当成"同一权限重复声明 8 次"、贡献被打到 0.47——这是
  把「不同事实」误当「重复事实」，v1.3 修正。

取 `α=1.0` 不是随手定的：它使 `decay(k)=1/k`，即第 k 次命中只贡献 1/k，是
**边际信息量递减**的标准形式。同一个 IMEI 被读 5 次，新信息远少于第 1 次。

这个取值也经过反向验证：α 小于 0.8 时会出现「同一类别重复 3 次 ＞ 3 个不同
类别各 1 次」的荒谬结果，与「信息种类比次数重要」相悖（见
`test_diverse_types_outweigh_repeats`）。我最初取 0.35，正是被这条测试挡下来的。

**单调性（Peng desiderata）**：按条目分降序排列、`decay(k)=1/k` 时，追加任意
一条 finding 总分不减。证明：设组内第 j 位插入一条分数 s_new（s_new ≥ 第 j 位
原条目 s_j），新增贡献 s_new/j 减去原条目整体右移的损失 Σ_{i≥j} s_i/(i(i+1))。
因 s_new ≥ s_j 且 Σ_{i≥j} 1/(i(i+1)) = 1/j（望远镜级数），差值
(s_new − s_j)/j ≥ 0。故单调性严格成立，由 `test_monotonicity` 锁死。
（分组键怎么改都不影响单调性——它是逐组的性质，任何一致的分组都保持它。）

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
敏感信息外发证据"的实际严重程度相符。而一条 `over_permission` 约 0.05~0.2 分
（路径 0.2 × 证据 0.5 本就压得很低），8 条合计约 1.15，依然远低于一条真实外发——
「条数与风险脱钩」靠的是**路径/证据的低权重**，不需要靠衰减去压 over_permission。

> ⚠️ 这套阈值是**工程设定，未经真实样本统计校准**。跨 App 比较时必须同时看
> confidence，否则会把"没查到"读成"安全"。necessity 维度加入后，总分普遍抬升，
> 旧阈值更需重新标定——这正是下面 `calibrate_bands` 存在的意义。

**阈值标定**（CNKI 自适应阈值思路）：`calibrate_bands(scores, labels)` 用一组样本
的分数的高尾分位数（默认 5 档取 **P99/P93/P80/P60**，降序对应 critical/high/medium/low
门槛）自动生成档位阈值，替代拍脑袋定死的 BANDS——「告警」应只挑落在样本极端尾部的
少数，而不是让四成样本都进 high 以上。v1.3 起可直接从 CLI 接入，不必再手动改代码：

```bash
# 攒一批真实样本的总分后，用 --calibrate-from 重新标定阈值（scores.json 为总分数组）
"$PY" mobile/analyze/risk_score.py \
      --findings output/xxx/e2e/findings.jsonl \
      --summary  output/xxx/e2e/summary.json \
      --calibrate-from scores.json \
      --out      output/xxx/e2e/risk_score.json
```

也可在代码里手动标定：`risk_score.BANDS = risk_score.calibrate_bands(sample_totals)`。
这比固定阈值更可信：阈值落在样本分布的真实分界上，而不是恰好卡在分布最密集处。

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

在当时的回归产物上验证（`output/mobile-regression-20261017-162715/e2e/`，
18 条结论，App 类别 map_navigation；**该目录已于 2026-10-19 随 `output/` 清理删除**，
下列数字为当时实测留档，需复跑重验）：

```
总分 48.20 ｜ 档位 high ｜ 置信度 medium (0.689) ｜ necessity 已启用
说明：存在敏感信息外发或明文传输的可关联证据
```

| 数据类别 | 贡献 | 条数 | 最高等级 |
| --- | --- | --- | --- |
| IMEI | 30.68 | 4 | correlated |
| Android ID | 11.25 | 2 | observed |
| 精确定位 | 3.00 | 1 | candidate |
| 应用安装列表 | 2.13 | 3 | observed |
| （无类别，权限声明） | 1.15 | 8 | candidate |

| 规则类型 | 条数 | 贡献 |
| --- | --- | --- |
| data_egress | 1 | 24.30 |
| plaintext_transmission | 1 | 9.00 |
| sensitive_read | 2 | 6.00 |
| third_party_share | 2 | 5.25 |
| policy_mismatch | 2 | 1.50 |
| over_collection | 2 | 1.00 |
| over_permission | **8** | **1.15** |

**这张表就是模型的价值**：8 条权限声明合计 1.15 分，1 条 IMEI 外发证据 24.30 分。
条数与风险完全脱钩，排序直接可用。v1.3 前 over_permission 因衰减分组键错误被压到
0.47（8 个不同权限被当成同一权限重复声明 8 次），修正后恢复为 1.15——仍是 IMEI
外发的 1/20，但不再系统性低估权限过度声明的风险。

**necessity 维度的效果**：与 v1（无 necessity，总分 50.54）相比，v1.1 曾因 necessity
抬升到 75.48，但那是**双重计数**——severity 与 sensitivity 同源也被乘了进去。v1.2
移除 severity 乘数后，总分回到 47.52（high 档），反映的是「一条 IMEI 外发证据 +
若干越权读取」的真实量级。v1.3 修正衰减分组后总分微升到 48.20（over_permission
不再被错误衰减），档位仍为 high。necessity 仍在起作用：导航类 App 读了 IMEI、Android ID
等越权数据各 ×1.5，而精确定位经映射补全后不再误判（见 §八.4）。

> ⚠️ 但请注意：v1.1 曾出现「加一个维度就跨档位」的现象（high→critical），这暴露了
> 固定阈值的脆弱性。v1.2 移除冗余乘数后阈值与分数重新对齐，但 60/25 这套阈值仍是
> 工程设定，必须用 `calibrate_bands` 在攒够样本后重新标定。这也正是 CNKI 论文主张
> 「自适应阈值」的原因。

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
| 越权数据加权（necessity） | Zhu'21 | `test_unnecessary_data_gets_higher_score` |
| 无必要数据定义不启用 | M009 | `test_none_necessary_data_disables_dimension` |
| 追加 finding 不降分（单调性） | Peng'12 | `test_adding_finding_never_lowers_total` |
| 阈值标定有序且覆盖零分 | CNKI'26 | `test_calibrate_bands_are_ordered_and_cover_zero` |
| 值级形态缺失保守计（不默认原值） | M009 | `test_value_match_form_missing_is_conservative` |
| severity 不二次计权（data_type 存在时） | Zhu'21 | `test_severity_not_double_counted` |
| 无 data_type 时 severity 映射进 data_weight | — | `test_over_permission_severity_maps_to_data_weight` |
| 阈值标定取高尾分位（非 40% 进 high） | CNKI'26 | `test_calibrate_bands_uses_high_tail_percentiles` |

---

## 七、落地路径

### 已完成（v1.3）

- [x] `risk_score.py`：评分核心 + CLI
- [x] `test_risk_score.py`：38 项回归
- [x] 接入 `tools/check_mobile_branch.py`（检查组 `risk_score`）
- [x] 真实样本验证
- [x] necessity 维度（Zhu 异常度 + PrivacyGrade 期望 gap）
- [x] 单调性保证（Peng desiderata）
- [x] `calibrate_bands` 阈值标定函数（CNKI 自适应阈值）
- [x] **v1.2** 移除 severity_weight 双重计数（对齐 Zhu 四参数）
- [x] **v1.2** 值级加成正确读取 value_match_form、缺失保守计（M009）
- [x] **v1.2** 移除 children 死档（PIPL 第 28 条能力边界）
- [x] **v1.2** calibrate_bands 分位点修正为 [P99, P93, P80, P60]
- [x] **v1.2** 补全 map_navigation 必要数据的 precise_location 映射
- [x] **v1.3** 衰减分组键区分「不同事实」——over_permission 按 permission 分组，不再坍缩
- [x] **v1.3** `--calibrate-from` 把自适应阈值接入 CLI/aggregate，结束「只定义未调用」
- [x] **v1.3** `calibrate_risk_bands.py` 一键标定工具（扫样本→总分→标定→Spearman 自检）
- [x] **v1.3** 重跑关联引擎验证顶层 `value_match_form` 端到端流动（`raw` → 值级加成 1.3）

### 建议后续（按优先级）

**P0 — 校准阈值（最有价值的一步，necessity 加入后更紧迫）**

当前阈值是工程设定，necessity 维度加入后总分普遍抬升，档位已不可靠。应攒
5–10 个真实样本的总分，用 `calibrate_risk_bands.py` 一键标定，再人工核对排序
（Spearman 秩相关）。这能把"我说它 critical"变成"它在 8 个样本中的排序与
人工判断一致"。

> ⚠️ **标定数据前提仍不满足（2026-10-19 更新）**：
> ~~5 个真实第三方样本因插桩 bug 运行时数据为零~~ → **该 bug（A1）已于 2026-10-16 修复**
> （M031/M032：bridge 补丁 + 单 agent 合并；夹具 5/5、真实样本 `e2e-1` passed）。
> 所以现在**能**采到真实样本，卡点从"采不到"变成"**样本量不足**"：
> 真实第三方批次的成功样本还没攒到 5–10 个，且 `output/` 已于 2026-10-19 清空、
> 历史 e2e 产物不再可用。
> 工具已就绪：`python mobile/analyze/calibrate_risk_bands.py --samples output/*/e2e`
> 会自动标注「真实样本 N 个」并在 <5 时输出演示性警告。
> **不要再用「插桩 bug 导致无法标定」的老说法**——那是 A1 修复前的状态。

**P0.5 — 补全必要数据映射粒度**

`app_categories.necessary_data_json` 目前把「位置信息」只映射到 `coarse_location`，
导致导航类 App 读 `precise_location` 被误判为非必要。应补全这类细分映射，
或在评分前对 necessity 命中做人工复核。

**P1 — 报告集成**

在 `mobile/report/report_sections.py` 增加 `section_risk_score()`，
放在「证据」之后、「结论」之前，输出：总分 + 档位 + 置信度 + 按数据类别贡献表。
须遵守 M009：置信度不足时在正文写明。

**P2 — 与 AI 章节对接**

把 `top_items` 作为 AI 研判的优先输入（现在 AI 是逐条看）。

**P3 — 权重敏感性分析**

对 `DATA_WEIGHT` / `PATH_WEIGHT` / `NECESSITY_WEIGHT` 做扰动测试（±20%），
检查档位是否稳定。若档位随小扰动跳变，说明阈值定得太靠近分界点。

---

## 八、已知局限

1. **阈值未校准**——见 P0。necessity 加入后档位已不可靠，必须重新标定。
2. **权重是序数而非基数**——`3.0` 不代表"敏感信息比一般信息危险 3 倍"，
   只代表"排序更高"。不要用它计算绝对危害。
3. **无类别结论计分保守**——`over_permission` 一类没有 `data_type`，
   路径权重 0.2 已是最低档，不会虚高，但也无法体现"这个权限本身多危险"
   （规则库 `permission_protection_level` 尚未断言，见 `rules_mobile.summary.json`）。
4. **necessity 粒度受必要数据定义约束**——`necessary_data_json` 的映射粒度
   可能粗于数据类别（如 coarse/precise 位置），导致边界误判。v1.2 已补全
   `map_navigation` 的 `precise_location`，其余类别若发现同类错配需继续补全。
5. **儿童信息不评分**——PIPL 第 28 条将「不满十四周岁未成年人信息」列为敏感信息，
   但判定它需要**数据主体年龄**，动态分析观测不到，故 v1.2 移除 `children` 档、
   如实声明为能力边界。若要支持，需外部输入「该 App 是否面向儿童」的标注。
6. **不覆盖未观测维度**——加固壳、QUIC 等能力边界（见 `CLAUDE.md`）造成的盲区，
   模型看不到，只能由 `gaps` 与 `confidence` 间接反映。
