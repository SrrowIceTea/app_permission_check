# 真实样本 RL 落地路径 —— 工具链与使用说明

仅用于授权测试（已获授权的公开第三方样本）。

> 状态：**静态基线阶段已完成并端到端验证**。用 60 个 F-Droid 真实样本的静态
> 发现，跑通了「样本 → 场景 → 专家预标注 → RL」全链路，并修复了 ES 的一个
> 次序约束缺口。动态采集阶段待推进（见 §五）。

---

## 一、现状与目标

`RISK_SCORE_RL.md` 里已经用**合成场景 + 手工构造的演示标注**验证了 RL 链路可行。
本阶段把这条链路搬到**真实样本**上：

- 样本：`数据集/static-batch-fdroid60/` 的 60 个 F-Droid APK（每 App 有
  `static.json` + `static_mobile_supplement.json` 静态产物）。
- 目标：让 RL 用「真实静态发现 + 专家规则排序」做奖励信号，验证能否在真实
  数据上学习，并为后续动态采集阶段的真实专家标注铺路。

## 二、落地工具链（新增 3 个脚本，均在 mobile/analyze/）

| 脚本 | 职责 |
| --- | --- |
| `build_real_scenarios.py` | 把 `static-batch-fdroid60/*/` 转成 `risk_rl` 的 `scenarios_real.json`（每个 App = 一个场景，finding 字段对齐 `risk_score` 契约） |
| `prelabel_expert.py` | 基于八谓词 + 敏感度 + 证据强度的专家规则，产出**候选**风险排序 `groundtruth_real_draft.json` + 可审计明细 `prelabel_report.json` |
| `risk_rl.py`（修改） | ES 优化器，补上「权重相对次序」约束（见 §四） |

## 三、怎么用

```bash
PY="C:/Users/OneKyubey/.workbuddy/binaries/python/versions/3.13.12/python.exe"
cd mobile/analyze

# 1. 静态样本 → 场景（60 App，1004 finding）
"$PY" build_real_scenarios.py

# 2. 专家规则预标注（候选排序，供人工校正）
"$PY" prelabel_expert.py

# 3. 跑 RL（真实样本 + 候选标注）
"$PY" risk_rl.py --scenarios scenarios_real.json \
      --ground-truth groundtruth_real_draft.json \
      --steps 500 --popsize 24 --sigma 0.2 --seed 7 \
      --out rl_real_result.json
```

## 四、本次修复：ES 的权重次序约束

**问题**：`risk_rl.py` 的 `_clamp_params` 原本只做 `[lo, hi]` 边界 clamp + 档位阈值
降序，**没有**跨参数的「相对次序」约束。真实静态样本里没有 `correlated` 证据
（等级封顶 `candidate`），奖励信号覆盖不到 `w_correlated`，ES 就把它无意义地压到
比 `candidate` 还低（0.6），破坏「证据越强权重越高」的语义（`RISK_SCORE_MODEL.md`
§三.3 单调性要求）。

**修复**：新增 `_ORDER_CONSTRAINTS` + `_enforce_order()`，在 `_clamp_params` 里强制：

- 数据敏感度：`sensitive ≥ unknown ≥ personal`
- 危害路径：`egress ≥ flow ≥ read ≥ manifest`
- 证据强度：`correlated ≥ observed ≥ candidate`
- 必要性：`unnecessary ≥ necessary`
- 值级加成：`raw ≥ digest ≥ shape`

修复后 learned 权重全部满足次序约束（见 `rl_real_result.json`）。回归：38 项
`test_risk_score` / `test_risk_band` 全部通过；合成自检仍保持 Spearman=1.0 不退化。

## 五、当前结果与诚实边界

- **baseline Spearman = 0.9511**（现有确定性权重 vs 专家规则排序，已高度一致）
- **learned = 0.9755**（+0.0244，小幅微调）

这说明：**静态阶段，现有评分模型与专家规则没有明显冲突**——不像演示里的那个
刻意构造的盲区。这是好现象（模型本身设计合理），但也意味着静态数据对 RL 的
「纠偏」空间有限。

**两个必须诚实指出的局限**：

1. **静态 `data_egress` ≠ 真外发**。`static_mobile_supplement.json` 的 `data_egress`
   命中只是「dex 引用了外发相关 API」，被预标注规则给了最高权重（+4/条）。这会让
   「仅静态引用」的 App 在候选排序里偏高（如前 10 名的 `biometric_data`、
   `camera_capture`）。真正的泄露判定需要动态关联证据（`read_then_egress`），
   这正是下一步动态采集要补的。

2. **预标注是候选，不是金标准**。`groundtruth_real_draft.json` 是专家规则自动生成
   的初稿，**必须人工校正**后才可作为 RL 的 gold 标准。校正重点：并列分数、以及
   「静态引用」vs「真实外发」的语义区分（见 `prelabel_report.json` 明细）。

## 六、下一步：动态采集阶段（未开始）

1. 启动 pipeline（`mobile/pipeline/`）对 60 个 APK 做动态采集（模拟器 + Frida +
   关联），产出含 `read_then_egress` / `correlated` 的 `findings.jsonl`。
2. 用 `calibrate_risk_bands.score_sample` 读真实 findings 转成场景。
3. 请安全专家对真实样本给出风险排序（重点看动态外发证据），替换掉静态预标注。
4. 重新跑 RL，此时奖励信号覆盖到 `correlated` 维度，学到的权重才真正有意义。
5. 交叉验证：RL 学到的阈值 vs `calibrate_risk_bands` 分位标定的阈值，一致处更可信。

## 七、交付物清单（本次）

- `mobile/analyze/build_real_scenarios.py`（新增）
- `mobile/analyze/prelabel_expert.py`（新增）
- `mobile/analyze/risk_rl.py`（修改：加次序约束）
- `mobile/analyze/scenarios_real.json`（60 App / 1004 finding）
- `mobile/analyze/scenarios_real_meta.json`（每个 App 的命中统计）
- `mobile/analyze/groundtruth_real_draft.json`（候选排序，待人工校正）
- `mobile/analyze/prelabel_report.json`（排序依据明细）
- `mobile/analyze/rl_real_result.json`（RL 结果，baseline 0.9511 → learned 0.9755）
- 本文档
