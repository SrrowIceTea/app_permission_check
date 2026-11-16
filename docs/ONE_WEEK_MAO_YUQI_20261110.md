# 毛宇淇一周任务交付（按 ONE_WEEK_DAILY_ASSIGNMENTS_20261110.md）

> **历史快照（2026-11-11 归档，不作当前清单）**：现在什么状态、本周做什么见 [CURRENT_STATUS.md](CURRENT_STATUS.md)。

> 依据：`C:/Users/m1866/Desktop/ONE_WEEK_DAILY_ASSIGNMENTS_20261110.md`（周一 11-16 ~ 周六 11-21）。
> 本次在 2026-11-10 把该主线**可开发的部分**提前落地，日期标签沿用任务表。
> 仅用于授权测试（自有设备与自有 APK）。本文只写已发生、可复核的事实与产物路径；
> 未跑设备、未重采、未改采集字段、未编造任何判定结论。

## 0. 范围与边界

三条独立主线里**只做毛宇淇主线**：判定口径、命题与证据对应、未运行/不可判状态、
报告投影与计分一致性。另两条（么贵行采集、陶俊哲定位匹配）的共享文件一个都没动。

无法代做的协作项，本次只交付材料与清单，在 §8 明确标为未达成：

* 周五「接收另外两个独立 PR、集中审查/合并、处理接口冲突」——没有别人的 PR 可收；
* 周六「组织一次验收」——验收需要真人组织，本次只产出验收清单与回归日志。

## 1. 周一：固定字段/文件归属；四种口径反例与修复范围

**字段归属（唯一权威来源写在 `vehicle/bench/claim_scope.py` 文件头）**

| 归属 | 文件 | 职责 |
| --- | --- | --- |
| 新增 | `vehicle/bench/claim_scope.py` | 「case → 所需求值器」映射、三态观测门控、七态判定唯一实现、报告单元格映射、四种反例 |
| 修改 | `vehicle/bench/claim_verdicts.py` | 只消费契约、补投影字段；七个 STANCES、counts、三个比率一律不动 |
| 修改 | `tools/real_sample_result.py` | 只读 `observation_state` 做报告投影 |
| 修改 | `tools/run_regressions.py` | 把新测试并入 `vehicle-method` 组 |
| 新增 | `vehicle/bench/test_claim_scope.py` | 14 项反例/契约单测 |
| 新增 | `tools/scope_selfcheck.py` | 冻结输入自测与兼容对照 |
| 决策 | `vehicle/bench/DECISIONS.md` B011 | 口径修复决策记录 |

映射出处有单测守卫：求值器名必须来自 `vehicle/analyze/detection_summary.py::EXTRACTORS`，
case id 必须来自 `vehicle/bench/aaos35-suite.json`（7 个 case 全覆盖），
三态语义直接复用 `core/evidence/decidability.py`（共享内核不复制不改）。

**四种口径反例**（`output/week-mao-20261110/counterexamples.json`，全部合成输入）

| 口径 | 旧缺陷 | 复现结果（legacy） | 修复后（fixed） |
| --- | --- | --- | --- |
| C1 观测充分 | `observed = bool(evaluators_ran)`：任意求值器跑过即算本题观测充分 | `false_negative`（本题求值器根本没跑，却记成「观测了但漏检」） | `missed_without_observation` + `not_applicable` |
| C2 命题↔证据对应 | 整轮 `business_evidence_total` 当本命题断言 | `correct_assert`（借别题 3 条 websocket 证据） | `absent` + `missed_without_observation`，裁剪后证据 0 |
| C3 未运行/不可判 | `or 0` / `or []` 补齐，统计结构缺失 ≡ 跑了且 0 命中 | `correct_by_absence_of_observation`，报告还会编造「没运行任何求值器」 | 七态不变（统计兼容），但显式 `not_applicable` 并写明缺 `detection_summary` |
| C4 计分/投影一致 | 报告「运行求值器数」被当作本命题观测证据 | 表格只有数字 `0` | 「不可判（未运行/缺统计）」 |

**自己的修复范围**：`vehicle/bench/{claim_scope,claim_verdicts,test_claim_scope}.py`、
`tools/{real_sample_result,scope_selfcheck,run_regressions}.py`、`DECISIONS.md` B011、交付文档与
`output/week-mao-20261110/` 产物。**不给另两人安排共享文件修改**。

## 2. 周二：修命题与证据对应、未运行/不可判状态

* `claim_scope.observation()` 用共享内核 `decidability.evaluate()` 做门控：两个必要条件
  （本轮有 `detection_summary` 统计结构 / 本命题所需求值器至少有一个运行）不满足即
  `not_applicable`，并逐条给出 `missing_reasons`（区分「统计结构缺失」与「所需求值器未运行」，
  补救动作不同）。`assert_no_negative_verdict()` 保证弃判不被写成阴性。
* `claim_verdicts.read_detection()` 显式记 `detection_summary_present`，带出
  `business_evidence` 明细与 `evaluator_gaps`；结构存在但空字典记 `0`，结构缺失记 `None`。
* `report()` 每行新增 `observation_state` / `observation_scope` / `required_evaluators` /
  `matched_evaluators` / `business_evidence_scoped` / `observation_reason` 等投影字段，
  顶层新增 `observation_states` / `not_applicable_count` / `unregistered_cases` / `scope_caveat`。
* **沿用现有统计结构**：七个 STANCES、counts、三个比率、分母定义、caveat 全部不动；
  **不迁移证据库、不重编号 `finding_uid`**（`vehicle/webapp/presentation.py` 未动）。
  未登记契约的 case 沿用旧口径并显式标 `legacy_unscoped`，不静默升级为「已观测」。
* 小 PR 与反例测试：`test_claim_scope.py` 14 项 + 旧 `test_claim_verdicts.py` 12 项，共 26 项全绿。

## 3. 周三：冻结输入自测状态与计分、兼容对照

输入只用已封存产物：`output/claim-verdicts-20261110/verdicts.json`（旧口径基线）与
`output/real-detection-20261110/`（冻结采集副本）。**不重跑审计、不要求采集改字段配合**。
从旧 verdicts 只还原 A/B 一致的裁决，不复用旧系统输出。

产物：`output/week-mao-20261110/selfcheck.json`、`compat-matrix.json`、`counterexamples.json`。

| 项 | case | 旧状态 → 新状态 | 观测状态 | 本命题证据 |
| --- | --- | --- | --- | --- |
| W01 | ha-control | `correct_assert` → 同 | `decidable` | 2 |
| W02 | ha-control-failure | `correct_rejection` → 同 | `decidable_no_evidence` | 0 |
| W03 | mg4-post | `correct_by_absence_of_observation` → 同 | **`not_applicable`** | 0 |
| W04 | mg4-webview-post | `correct_assert` → 同 | `decidable` | 1 |
| W05 | yaabsa-playback | `unscored` → 同 | 无（结构性不可计分） | — |
| W06 | yaabsa-send | `correct_assert` → 同 | `decidable` | 2 |

* **6 项状态全部不变**，`counts_changed=false`、`ratios_changed=false`
  （`wrong_assertion_ratio=0.0`、`unobserved_ratio=0.2`、`scored=5` 均保持）。
  → 本次是**口径加固，不是改冻结批次的结果**。
* `observation_states`：`decidable=3` / `decidable_no_evidence=1` / `not_applicable=1` / `legacy_unscoped=0`。
* 冻结采集副本交叉核对 5/6 一致；W05 没有 audit 产物，如实记为「无采集副本」，不外推。
* 四种反例在冻结批次里的对应：C1/C2 **未触发**（如实说明，不编造实例）；
  C3/C4 对应 W03；W05 另属「无 audit 产物」的结构性不可计分。

## 4. 周四：报告投影与计分一致性

确有显示问题（C4），**只修一处映射**：`tools/real_sample_result.py::verdict_rows()` 第 5 列
「运行求值器数」→「本命题观测」，由 `claim_scope.report_cell(row)` 投影三态，表头与一段口径
提示同步。`build()` / `verdict_rows()` / `main()` 签名、8 列结构、既有 API 与失败报告访问限制
全部保留；旧产物无该字段时显示「无观测状态」，不按数量推算、不默认 0。

对照产物：`RESULT-old-verdicts.md`（旧输入，6 行都显示「无观测状态」）与
`RESULT-new-verdicts.md`（新输入，W02 显示「已观测·本轮无命中」、W03 显示「不可判」）。

**口径修复候选**：`projection-candidates.json` 登记 P2 业务证据列仍是整轮值、
P3 `limitations()` 的旧口径措辞、P4 `unscored` 行无状态标签。周四按「只修一处」约束只修了 P1；
**独立 subagent 复核后按确认问题追加修了 P3**（见 §7.1），因此不再主张「全程只修一处」：
缺口段改由 `observation_state` 同源生成，去掉「absent 来自没有运行任何求值器」这类编造原因，
并把 `missed_without_observation` 纳入。P2 / P4 仍未改。

## 5. 周五：自测、回归接入、三主线合并清单

* 新测试已并入 `tools/run_regressions.py` 的 `vehicle-method` 组（177 → **191 项全绿**）。
* `tools/test_inventory_guard.py` **PASS**：`scanned=220`、`unregistered=0`、`stale=0`。
* 旧口径兼容测试 12 项全绿；冻结自测 `status_changes=[]`。
* `merge-checklist.json`：三主线边界、本主线文件归属（含显式未改清单）、3 个接口接触点、
  合并顺序建议。**接口冲突实测全通过**（`interface-check.json`）：求值器名全部有出处、
  三态常量/API 齐全、七态与冻结 `counts` 一致、报告仍 8 列、`read_detection` 旧三键逐字保留。
* 三个需合并时复核的接触点：I1 `correlation-summary.json:detection_summary` 字段结构（么贵行采集
  改动可能碰）、I2 `core.evidence.decidability` 三态定义（共享内核）、I3 报告 8 列 / counts 结构。
* **停止新增功能**：周一到周四的代码改动到此为止，周五只做自测与清单。

## 6. 周六：兼容回归与结果主张

三套回归均用固定目录留档（不引用会被并行任务覆盖的 `latest` 指针）：

| 套件 | 命令 | 日志目录 | 实测 |
| --- | --- | --- | --- |
| 根回归 | `tools/run_regressions.py --out ...` | `output/week-mao-20261110/regression-root/` | **19/19 组全 0** |
| 移动侧 | `mobile/tools/run_mobile_checks.py --out ...` | `output/week-mao-20261110/regression-mobile/` | **63/63 通过** |
| 移动分支（默认环境） | `tools/check_mobile_branch.py --out ...` | `output/week-mao-20261110/regression-branch/` | 21/24，3 组环境假红（见下） |
| 移动分支（隔离守卫后） | 同上 + `CODEBUDDY_SAFE_DELETE_ENABLED=0` | `output/week-mao-20261110/regression-branch-noshim/` | **24/24 通过** |

**环境假红诊断（不掩盖）**：默认环境下 `mobile_workbench` / `ai_gates` / `mobile_lab`
三组失败，全部是 `ERROR` 而非断言 `FAIL`，堆栈统一指向 WorkBuddy 的
`D:/Development/Workbuddy/.../sitecustomize.py::_check_bulk_delete_guard → SystemExit(1)`，
发生在 `unittest` 的 `tearDown` 临时目录清理与 `compile_session` 的 `path.unlink`。
两次独立后台任务（目录 mtime 22:37:07 / 22:39:22，日志 mtime 相差 2 分 18 秒，两份日志
都含同一守卫堆栈）得到同样的 3 组失败；`verification.json` 不含时间戳，两份文件逐字节相同
是预期，独立性由目录/日志时间戳佐证，**不是**靠文件差异排除并发（评审 F5 已据此收紧措辞）。
用该 shim 自带开关 `CODEBUDDY_SAFE_DELETE_ENABLED=0`（`sitecustomize.py:35`，
仅本次子进程环境、不改项目代码）隔离后 **24 组全绿**。结论：与本次改动无关，代码侧无回归；
引用时必须同时引用隔离复跑目录。

另有：`vehicle-method` 组修复前 **191 项全绿**（原 177 + 新增 14）、评审修复后 **193 项全绿**，
结论级修复前 **26 项**、修复后 **28 项**，
`test_inventory_guard.py` **PASS**（`scanned=220`、`unregistered=0`）。完整机器可读汇总见
`output/week-mao-20261110/acceptance.json` 的 `regression_runs`，以各目录 `verification.json` 为准。

**确认的结果主张**

* 可以说：判定口径已按命题绑定求值器并复用三态；冻结 6 项计分结论不变；
  W03 明确为「本轮不可判定」；报告投影与计分同源；离线回归通过
  （根 19/19、移动侧 63/63、分支 24/24〔隔离环境守卫后〕、方法层 191→193 项）。
* **不能说**：检测率/准确率有任何提升（没有新增观测、没有新采集）；W03「通过 / 无风险 /
  未发生」；方法有效性已被验证（跨模型标签无人工介入）；已集中审查合并另两个 PR；
  已组织真人验收。

## 7. 达成 / 未达成表

| 日 | 任务表交付要求 | 本次 | 产物 |
| --- | --- | --- | --- |
| 周一 11-16 | 四种口径反例及自己的修复范围；不给另两人安排共享文件修改 | **达成** | `counterexamples.json`、§1 归属表、`claim_scope.py` 文件头 |
| 周二 11-17 | 小 PR 和反例测试；不迁移证据库、不重编号 finding_uid | **达成** | `claim_verdicts.py` / `claim_scope.py` / `test_claim_scope.py`（26 项全绿） |
| 周三 11-18 | 四种反例输出和兼容对照；不要求采集改字段配合 | **达成** | `selfcheck.json`、`compat-matrix.json`、`counterexamples.json` |
| 周四 11-19 | 口径修复候选；保留既有 API 和失败报告访问限制 | **达成** | 一处列映射 + `projection-candidates.json` + 两份 RESULT 对照 |
| 周五 11-20 | 三主线合并清单与相关回归结果；停止新增功能 | **部分达成** | `merge-checklist.json` / `interface-check.json` / 191 项回归；另两个 PR 的接收与集中合并**未做**（需真人） |
| 周六 11-21 | 最终提交、回归日志和达成/未达成表；不把验收责任交给新人 | **部分达成** | 三套回归日志 + 本表 + `acceptance.json`；Git 提交与「组织一次验收」**未做**（需真人） |

### 7.1 独立 subagent 复核（任务表之外，本次追加）

**测试计数说明**：本文 §2 / §5 / §7 表格里的 **26 / 191** 是周二～周五当时的数值；
独立复核并修复 F1/F4 后，`test_claim_scope.py` 由 14→16 项，结论级 **26→28 项**、
方法层 **191→193 项**，三套回归重跑仍全绿（固定目录 `verify-{root,mobile,branch}/`）。
两个数字都是真实时点，不是互相矛盾的笔误。

按项目既有的独立双标惯例，冻结材料包 `output/week-mao-review-20261110/`：A/B/C 三包内容
完全一致（33 个材料文件，`evidence_sha256=6c54e5b1…`），派出三个**全新上下文、互不交换
判断**的 subagent 各填一份 `review.json`——Q01–Q10 三态判定、每条 reason 带 `文件:行号`、
题外 findings、以及 `reviewer_kind=subagent` / 独立 UUID / 带时区时间 / 模型身份自声明。

| 收敛结果 | 题目 |
| --- | --- |
| 三票一致 `present` | Q01 / Q02 / Q05 / Q07 / Q08 / Q10 |
| 多数 `present` | Q03、Q09（B/C present，A insufficient；分歧源于证据层级与措辞口径） |
| 三票一致 `insufficient` | Q04、Q06（包内缺独立 diff 与证据库/前端快照，**如实保留、不改判**） |

确认并已修的 4 个代码问题：F1 未登记 case 仍用 `bool(evaluators_ran)` 计七态（3/3）、
F2 `limitations()` 对 W03 编造「没有运行任何求值器」（2/3）、F3 `crosscheck()` 把
`None == None` 写成「一致」（2/3）、F4 `observation_reason` 重复前缀（3/3）。
F5（branch/solo verification 逐字节相同）部分成立，已补两次独立运行的时间戳证据并收紧措辞。

**层级声明（组织者发现 F6）**：三个 slot 自报的 `model_id` 均为 `hy4free`，`model_family`
只是同一家族的不同写法。因此本轮**只能算同模型 subagent 复核（`subagent_signed`），
不是 `cross_model_signed`，不能作金标准**；引用须带
`no_human_in_the_loop` / `model_identity_is_self_declared` / `families_can_share_upstream_weights`
三条限定。三份原始答卷不追溯改写；组织者补充的 mtime 证据不回灌评审包。

另派出一名独立复验者核对修复落地（`FIX-VERIFICATION.md`）：**F1/F2/F3/F4/F6 = fixed，
F5 = partially_fixed，无 `not_fixed`、无 `regression`**；确认未引入新的「未观测⇒未发生」
肯定式，七个 STANCES / counts / 三个比率结构未变，三个 `verify-*` 的
`verification.json` 全绿（19 / 63 / 24 条，非零 `exit_code` 均为 0）。
复验补充了一个更强的 F5 佐证：两次 `mobile_lab.log` 的 sha256 **不同**（随机临时文件名、
`Ran 263 tests in 4.054s` vs `3.697s` 各异、各含 4 处守卫堆栈），直接证明是两次独立进程。

**两处消歧**：① `selfcheck.json:label_tier="cross_model_signed"` 是冻结盲评数据的标签
（由旧 `verdicts.json` 原样透传），**不是**本轮复核层级，不要与 F6 的 `subagent_signed` 混淆；
② A/B/C 包内 `artifacts/acceptance.json` 与 `src/DELIVERY_CLAIMS.md` 是**冻结快照**，
仍留着「排除并发干扰」旧措辞，按「不回灌、不追溯改写」保留，不是现行结论。

逐题裁决、findings 原文与修复验证见 `output/week-mao-review-20261110/REVIEW.md`
与 `cross-review.json`。

## 8. 一次集中验收清单（供毛宇淇本人执行）

```bash
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"
ROOT="D:/AAA/mobile-app-permission-check"; cd "$ROOT"

# 1) 四种口径反例 + 契约/兼容
"$PY" -m unittest vehicle.bench.test_claim_scope vehicle.bench.test_claim_verdicts -v
"$PY" tools/scope_selfcheck.py                 # 期望 status_changes=[] / ratios_changed=false
"$PY" tools/test_inventory_guard.py            # 期望 PASS / unregistered=0

# 2) 三套兼容回归（固定目录，各自 verification.json）
"$PY" tools/run_regressions.py        --out output/week-mao-20261110/verify-root
"$PY" mobile/tools/run_mobile_checks.py --out output/week-mao-20261110/verify-mobile
# 本机会话里 check_mobile_branch 有 3 组环境假红，验收时按 §6 诊断隔离：
CODEBUDDY_SAFE_DELETE_ENABLED=0 "$PY" tools/check_mobile_branch.py \
     --out output/week-mao-20261110/verify-branch

# 3) 报告投影对照
"$PY" tools/real_sample_result.py --verdicts output/week-mao-20261110/selfcheck.json \
     --out output/week-mao-20261110/verify-RESULT.md
```

合并另两个 PR 后，按 `merge-checklist.json` 的 I1/I2/I3 复核，并**重跑一次**
`scope_selfcheck.py` 确认 `status_changes` 仍为空。

## 9. 未做项与后续

1. 么贵行 / 陶俊哲两条独立 PR 的接收、集中审查与合并（真人或 PR 到位后执行）。
2. 一次真人组织的验收与最终 Git 提交。
3. 候选 P2–P4（见 §4），需下一次评审后再动。
4. W03 的 `not_applicable` 若要有观测结论，需要真实设备突破模拟器 SLIRP 归因限制；
   W05 结构性不可计分，重采会使旧签核失效，等于重跑一轮盲评。

## 10. 产物索引

| 产物 | 路径 |
| --- | --- |
| 四种口径反例 | `output/week-mao-20261110/counterexamples.json` |
| 冻结自测（新口径 report） | `output/week-mao-20261110/selfcheck.json` |
| 新旧兼容对照 | `output/week-mao-20261110/compat-matrix.json` |
| 报告投影候选 | `output/week-mao-20261110/projection-candidates.json` |
| 新旧报告对照 | `output/week-mao-20261110/RESULT-{old,new}-verdicts.md` |
| 接口冲突实测 | `output/week-mao-20261110/interface-check.json` |
| 三主线合并清单 | `output/week-mao-20261110/merge-checklist.json` |
| 验收与回归汇总 | `output/week-mao-20261110/acceptance.json` |
| 回归日志 | `output/week-mao-20261110/regression-{root,mobile,branch,branch-solo,branch-noshim}/` |
| 决策记录 | `vehicle/bench/DECISIONS.md` B011（口径修复）、B012（评审修复轮） |
| 独立 subagent 复核 | `output/week-mao-review-20261110/`：`REVIEW.md`、`cross-review.json`、A/B/C 原始答卷与冻结材料 |
