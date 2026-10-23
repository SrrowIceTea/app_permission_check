# 隐私风险量化模型的强化学习（RL）优化 —— 方案与实现

仅用于授权测试（已获授权的样本与设备）。

> 状态：v0.1 已实现，用进化策略（ES）以人工风险排序为奖励信号，联合优化
> 权重相对次序与档位阈值；已通过合成场景 + 人工标注演示的端到端验证。
> 代码：`mobile/analyze/risk_rl.py`　演示数据：`gen_rl_demo.py`
> 结果：`rl_demo_result.json` / `rl_selfcheck.json`

---

## 一、为什么是强化学习，以及放在哪

`RISK_SCORE_MODEL.md` 已经定义了一个确定性、可审计的乘法评分模型：

```
item_score = data_weight × path_weight × evidence_weight
             × necessity_weight × value_bonus
total      = Σ item_score_i × decay(k_i)
```

它的权重是**人工设定**的「相对次序」，档位阈值是**工程设定**的固定值。
两个地方都天然适合用数据去校准——这正是强化学习（更准确地说是
**黑盒优化 / 学习排序**）的用武之地：

1. **权重**：`DATA_WEIGHT` / `PATH_WEIGHT` / `EVIDENCE_WEIGHT` /
   `NECESSITY_WEIGHT` / 值级加成 / 衰减系数 α —— 学习「敏感信息到底比一般信息
   该重多少」这类相对量。
2. **档位阈值**：`BANDS` 的 60/25/8/2 —— 学习「多少分算 critical / high」。
3. **复核优先级**：`top_items` 的人工复核队列排序 —— 让高危条目排前面。

## 二、方法：进化策略（ES），不是 DQN/PPO

风险评分是「一组权重 → 一个 App 排序」的**确定性黑盒函数**，没有序列、
没有状态转移。对这种目标，深度 RL（DQN/PPO）是杀鸡用牛刀：它们擅长序列决策，
而这里只有一个「参数向量 → 标量奖励」的映射。

因此采用**进化策略（Evolution Strategy）**——文献依据 Salimans et al.
（OpenAI, 2017）《Evolution Strategies as a Scalable Alternative to
Reinforcement Learning》。它：

- 零梯度、零第三方依赖（纯标准库实现）；
- 样本高效，适合「少量人工标注」的现实；
- 天然可解释：每一步的参数与奖励都记录在 trace 里，可审计。

### MDP 形式化

| 要素 | 定义 |
| --- | --- |
| 状态 s | 当前权重+阈值向量（19 维，见 `PARAMS` / `BAND_PARAMS`） |
| 动作 a | 对参数向量施加高斯扰动 `p ← p + ε`，ε ~ N(0, σ·(hi−lo))，再 clamp 到合法区间 |
| 奖励 r | 模型分数排序与人工名次的 **Spearman 秩相关** ∈ [−1, 1] |
| 终止 | 固定步数（episode 长度 = `--steps`） |

奖励的方向：人工名次「1 = 最危险」，模型分数「越高越危险」，两者方向相反，
故取 `Spearman(模型分数, −人工名次)`，完美一致 = +1。

## 三、关键边界（写进代码，不是口号）

1. **M046**：学到的权重/阈值只落到 `hint` / `review_priority` /
   `needs_human_review` 三个槽，**绝不**改写 `conclusion_level` / `severity`，
   也不替代确定性评分作为唯一真值。八谓词与风险档位仍由证据链派生事实决定。
2. **可审计**：权重仍是「相对次序」不是「基数」；每步参数、奖励、最终
   derivation 全部落盘。
3. **单调性**（Peng'12）：所有权重 clamp 到 `[lo, hi]`（lo > 0），衰减 α ≥ 0，
   保证追加 finding 不减分。
4. **不伪造金标准**：奖励只来自 `--ground-truth` 的人工排序；无标注时只用
   合成场景自检，并显式标注「演示性结果」。

## 四、验证结果

### 4.1 合成场景自检（`--self-check`）

8 个严格递进的合成场景，现有权重已完美排序（Spearman = 1.0），RL 保持 1.0
不退化——证明 RL **不会破坏**已有正确排序。

### 4.2 人工标注演示（`gen_rl_demo.py`）

构造一个现有权重的**真实盲区**：人工认为「越权声明 3 个敏感权限」（暴露面大）
比「读到一条一般个人信息」更危险，但现有权重下前者（0.60）低于后者（1.50）。

| 阶段 | Spearman | 排序 |
| --- | --- | --- |
| 训练前（基线权重） | 0.5 | C > E > **A > B** > D ❌ |
| 训练后（RL 权重） | **1.0** | C > **B** > E > D > **A** ✓ |
| 人工名次 | — | C > B > E > D > A |

RL 学到的关键调整（贴合专家判断的方向）：

| 参数 | 基线 | 学到的值 | 含义 |
| --- | --- | --- | --- |
| `w_manifest` | 0.2 | 0.506 | 调高「权限声明」暴露面的权重 |
| `w_read` | 1.0 | 0.637 | 相对调低「读取」路径权重 |
| `w_personal` | 1.0 | 1.835 | 个人信息的基数抬升（因 manifest 用 personal 做基准） |

结果：越权声明 3 权限（1.10）重新排到读一般信息（0.28）之前，排序贴合人工。

> ⚠️ 这是**演示**：5 个场景、1 份人工标注，不足以推导生产权重。它的价值在于
> 验证「RL 能从次优权重收敛到贴合专家标注的权重」这条链路是通的、方向是对的。

## 五、怎么用

```bash
PY="python"   # 或本机 python

# 1. 纯合成自检（不碰真实数据）
"$PY" mobile/analyze/risk_rl.py --self-check --steps 300 --out rl_selfcheck.json

# 2. 用真实人工标注训练
"$PY" mobile/analyze/gen_rl_demo.py            # 生成演示标注（换成你自己的标注）
"$PY" mobile/analyze/risk_rl.py \
      --scenarios scenarios_rl_demo.json \
      --ground-truth groundtruth_rl_demo.json \
      --steps 400 --sigma 0.2 --seed 7 \
      --out rl_demo_result.json
```

输出 `rl_result.json` 包含：
- `baseline_reward` / `best_reward` / `improvement`：训练前后 Spearman
- `suggested_weights` / `suggested_bands`：学到的权重与阈值（**建议值，非自动生效**）
- `hint` / `review_priority` / `needs_human_review`：M046 挂接点
- `ranking_before` / `ranking_after`：训练前后排序对比
- `convergence`：收敛轨迹摘要

## 六、落地到真实样本的路径（下一步）

1. **攒真实标注**：对 5–20 个真实 App 样本，让安全专家给出风险排序（名次 1=最危险），
   写成 `groundtruth.json`。
2. **把真实样本转成场景**：用 `calibrate_risk_bands.score_sample` 读出每个 App 的
   findings，聚合成 `scenarios.json`（每个 App = 一个场景）。
3. **跑 RL**：`risk_rl.py --scenarios ... --ground-truth ...`，得到学到的权重。
4. **人工复核**：`review_priority` 为 high 时，人工核对学到的权重改动是否合理，
   再决定是否回写进 `risk_weights.py`（**回写必须人工确认**，RL 不自动改核心权重表）。
5. **对比**：用 `--calibrate-from`（分位标定）与 RL 学到的阈值做交叉验证，
   二者一致的部分更可信。

## 七、与现有模块的关系

- **不改动** `risk_score.py` / `risk_weights.py` / `risk_calibrate.py`：
  RL 是**旁路优化器**，复用它们的评分逻辑与 `calibrate_risk_bands.spearman`。
- **不冲突**：`calibrate_bands`（CNKI 分位标定）仍可用作独立基线，与 RL 阈值交叉验证。
- **M046 兼容**：RL 输出严格落在三个提示槽，不进入八谓词/档位判定输入。
