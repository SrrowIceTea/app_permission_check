# V-Scanner 工程健康度评估与未来一周优化任务清单

> 评估时间：2026-11-11（本机实测）｜代码基线：HEAD `81f14dc`，工作区 4 个未提交改动
> （`docs/VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md`、`vehicle/frontend/README.md`、
> `vehicle/frontend/ledger.js`、`vehicle/frontend/test_ledger_panel.mjs`）。
> 数据口径：只读代码调研 + 三条离线回归实测（Python 3.13.9 / Node 24）+ 全仓行数与文件统计。
> 本文只做评估与排期：**不改业务代码、不接设备、不删除或移动任何文件**。
> 统计范围排除 `output/`、`__pycache__/`、`vehicle/hooks/node_modules/`（273 个 vendored .py）。

---

## 0. 范围判定（先读这一节，否则会排错工单）

项目里同时存在四份互相制约的口径，本次清单必须先把边界钉死：

| 来源 | 原文要点 | 日期 |
| --- | --- | --- |
| `docs/VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:4,11-12` | 「用户最新约束：**移动端暂不开发**」；「不修改 mobile 功能，不接手机 Gadget/重打包、移动批处理、移动探索器」 | 11-11 |
| `docs/REAL_APK_OPTIMIZATION_PLAN_20261111.md:3-4` | 「本文包含移动端内容，**保留为历史调研，不作为当前开发清单**」 | 11-11 |
| `docs/ONE_WEEK_DEVELOPMENT_PLAN_20261110.md:4,26-36` | 建议周期 11-16 至 11-22，三条车载功能主线 M1 结果判定 / M2 采集基线 / M3 定位外发 | 11-10 |
| `AGENTS.md:43`、`.workbuddy/memory/2026-11-11.md:82` | 60 样本 F-Droid 跑批、断点续跑与自动恢复是长期关注点；但数据集 `D:/数据集/数据集/F-Droid-60` **本机不存在** | — |

**本清单默认执行边界：**

1. 主体任务（§3，A 组）只覆盖**平台无关与车载侧**，不改任何移动端业务功能。唯一触及 `mobile/` 的 A1 只改测试落盘的原子性，属测试基础设施，不新增也不变更 AI/审核功能。
2. 已有一周功能计划（M1/M2/M3）继续有效；本清单是**工程横切补充**，不重复其结果口径、采集、定位三类功能开发，也不假设团队人数。
3. 移动端跑批相关的 4 项列为 §4 的 **B 组条件任务，不进默认排期**，需用户明确解冻移动端后按给定插入点执行。它们不是被漏掉，是被 11-11 的书面约束挡住。
4. 需要真实设备、正负控或人工签核的缺口（`observed_findings` 恒为 0、`protection_level_value` 180/180 为 NULL、B1 窗口签核、Hook 第三层）**排除在本周清单外**：一周内无法给出可信结论，硬排只会产出不可用的数字，见 §6。

---

## 1. 项目整体评估

**一句话结论：功能交付完成度高，工程防线偏薄。** 两条产品线拆分已完成、回归体系规模不小（三条入口共 108 组注册项、224 个测试文件、2147 个 `def test_`），但「回归能跑绿」和「门禁能拦住错误」不是一回事。本周最该修的不是再加能力，而是四个会让人误判结果的地方：回归口径漂移与环境假红、质量门禁没进 CI、动态批次异常直接终止且不落盘、静默失败与硬约束没有机器检查。

| 维度 | 评级 | 核心判断 |
| --- | --- | --- |
| 代码质量 | 中 | 规范齐备但未强制执行；16 个 `.py` 超 300 行、前端 3 个文件远超限、68 处 `except → pass` |
| 架构合理性 | 中偏强 | 拆分完成、core 复用真实存在；但 `load_rules` 存在三份实现，共享契约被两线绕过 |
| 性能表现 | 中 | 静态段已并行、动态段串行有充分理由；SSE 事件读是 O(n²)，`output/` 已 37.7 GB |
| 可维护性 | 弱 | 18 份 DECISIONS + 十余份互相重叠/滞后的计划文档；环境表三处互相矛盾；口径数字漂移 |
| 测试覆盖 | 中 | 以行为测试为主（约 92%），但无覆盖率工具、17 阶段流水线仅 5 个用例、批入口无直接测试 |
| 潜在风险 | 弱 | 结论可信度缺口（无 observed finding）、合规冲突（默认 DROP UDP/443）、Windows 假红、悬空 junction |

### 1.1 代码质量 —— 中

- 规范是写全的：`AGENTS.md:17-28` 八条全局约束、`ruff.toml`（E/F、100 列、py313）、`.pre-commit-config.yaml` 的 ruff + 300 行守卫。但 `.git/hooks/` 里没有任何生效的自定义钩子，`Jenkinsfile:21-25` 与 `.github/workflows/ci.yml:39-40` 都只跑 `run_regressions.py`，**lint、format、行数守卫在 CI 里一步都没有**。
- 约束实际被违反：项目自有 736 个 `.py` 中 **16 个 >300 行**（`mobile/analyze/risk_rl.py` 593、`mobile/tools/pcap_http.py` 543、`mobile/ai/test_ai.py` 384 等）；`frontend/app.css` 2271 行、`frontend/app.js` 900 行、`landing.css` 456 行，而守卫 `files: \.py$`（`.pre-commit-config.yaml:22`）只覆盖 Python。
- 异常处理：`except` 共 665 处，其中 **68 处块体仅 `pass`**（10.2%）、8 处只 `print` 不落盘；裸 `except` 与空块为 0。集中在 `mobile/tools/validate_native_migration.py`(5)、`batch_dynamic.py`(3)、`conn_probe.py`(3) 等。与 `AGENTS.md:26`「失败可诊断、区分没数据与脚本崩了」直接冲突。
- 做得好的一面：`core/io_utils.py:70,76` 用 `on_bad_line`/`skipped` 把坏行显式化，`mobile/tools/observed_surface.py:60` 用 `ScanError` 区分「扫失败」与「扫到但没命中」，`vehicle/pipeline/execution.py:33-35` 把超时转成带诊断信息的 `AuditError`。这些是现成范式，A4 应复用而不是另造一套。

### 1.2 架构合理性 —— 中偏强

- 拆分是真实落地的：`core` 被 vehicle 引用 119 条 import / 79 个文件、被 mobile 引用 71 条 / 59 个文件；`core/io_utils`、`core/evidence/codeloc`、`core/static/analysis`、`core/collector` 都是两线共用；`core` 生产代码没有反向 import vehicle/mobile（仅 `core/collector/test_parse.py:17` 等 5 处测试层回边）。
- **最硬的绕过证据**：`core/rules_contract.py:15-16` 明写「凡是要按平台多读/少读一张扩展表的地方，都必须走这里的 `load_rules`，不得在别处重写一份」，但 `vehicle/analyze/correlate.py:81-93` 与 `mobile/analyze/correlate_mobile.py:60-80` 各自实现了一份 `load_rules`（返回 `list[dict]`），都不 import 契约层，形状也与 core 的 `dict` 不同。`core/static/static_rules.py:28,38` 才是正确转发壳。
- 其他重复：`core/frida_host/build.py` 与 `vehicle/hooks/build.py` 是两套同名打包实现；`vehicle/hooks/gadget_prepare.py` 与 `mobile/fixture-app/gadget_prepare.py` 两套 Gadget 准备；vehicle 侧仍用 `events.jsonl` 追加写（`vehicle/pipeline/execution.py:22-25`），mobile 侧用 `core/event_store.py` 的 SQLite。事件机制分裂，但两者都有明确会话语义，不宜一周内强行统一。
- 前端契约硬编码：`frontend/app.js:19` 把 `http://127.0.0.1:8771` 写死并在 6 处拼内部路由；`mobile/pipeline/stages.py:5-9` 才是事件 schema 唯一来源。

### 1.3 性能表现 —— 中

- 已做过针对性优化且理由充分：`batch_static.py:139` 静态 jadx 默认 3 路并行（M041 实测 3 样本 7m42s、同批 `--resume` 3.1s）；`batch_dynamic.py:7-16` 明确动态段必须串行（8888 单端口 / 全局 http_proxy / 单前台 / 固定 pcap 路径，并发会串归因）。**不要把动态段改成线程池**。
- 未解决：`stages.py:75` 每次 `read_text()` 读全量 `events.jsonl`，`server.py:249-264` 每 0.5s 轮询一次 → 随事件数增长呈 O(n²) 读放大；`read_events` 的 offset 是「已读行数」，改成 seek 增量读即可，契约不变。
- 未解决：`docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md:182-184` 实测 `--static-reuse` 指错目录时**不命中也不报错**，白跑一遍 jadx（3 样本约 2.5 分钟）；`static_scan_thirdparty.py:151-157` 自身没有「已有产物就跳过」的判断，跳过完全依赖编排层。
- 产物增长：`output/` 只读盘点为 **37.73 GB / 262,893 文件 / 347 个顶层目录 / 10 个 junction**（跳过 reparse point 后统计；junction 会让 `du` 外溢）。日志一律 `open("a")` 无轮转（`batch_dynamic.py:46`、`supervise_batch.py:60,204`、`stages.py:59`）。`AGENTS.md:207-210` 明确警告**不要按历史条目删 `output/` 现存内容**，因此本周只做只读盘点，不做清理。

### 1.4 可维护性 —— 弱

- 文档口径漂移是成片的：根回归实际 `CHECKS` 有 **21 组**（`--mobile` 22、`--prepare --mobile` 23），而 `AGENTS.md:115` 写 18 组、`docs/REGRESSION_CI.md:14` 写「18 组 + 1 组」、`:59` 写 19 组、`:66` 写「现行 18/19」、`VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:109` 写 19 组。**没有任何一处与代码同步**。
- 环境事实互相矛盾：`environment.ps1:3-4` 头注释称本机是 `D:\Anroid\SDK + D:\Anroid\JDK`，同文件 `:12-13` 默认值却是 `%LOCALAPPDATA%\Android\Sdk` + `D:\Android\JDK`；`AGENTS.md:35,108` 说 `Anroid` 是原开发机拼写；`.agents/README.md:137` 说 `D:\Anroid\*` 与 `D:\Android\SDK` 都不存在；`VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:114` 又说本机 Python313 缺 `jsonschema`，而 `.agents/README.md:136` 说依赖已齐（本次实测：Python 3.13.9 三条入口均未被 `env_guard` 拦下，依赖可用）。
- 计划文档高度重叠：`docs/` 下 55 份 md，其中一周/三周/双人/实名任务类至少 12 份（`ONE_WEEK_*`、`THREE_WEEK_*`、`TWO_PERSON_ONE_WEEK_PLAN_CURRENT`、`THIRD_PERSON_ONE_WEEK_TASK`、`DUO_*` 等），多份自称「替代上一版」。缺少一份唯一的「当前状态 + 本周工单」入口。
- 数据集路径 `D:/数据集/数据集/F-Droid-60` 在 `AGENTS.md:43` 等处被当作既定事实，但本机不存在（`.workbuddy/memory/2026-11-11.md:82`）；缺失时是「0 个样本」还是「路径错」目前没有区分。

### 1.5 测试覆盖 —— 中

- 规模与质量都比想象中好：三条入口共 108 个注册组，224 个 `test_*.py` + 16 个 `.mjs`、2147 个 `def test_`；约 92% 是行为测试（真实起 `ThreadingHTTPServer`、读 sqlite 规则库、子进程跑 CLI、e2e 干跑出 PDF），仅约 8% 是文件存在/schema 字符串类检查。全仓无 pytest/conftest/coverage 配置，靠自定义子进程调度。
- 覆盖盲区很具体：`mobile/pipeline/` 17 阶段只有 `test_formal_runner.py`/`test_history.py` 共 **5 个用例**（`pipeline_api` 组实测 `python_tests_direct=5`），`runner.py`/`server.py`/`device_boot.py` 无直接测试；`mobile/tools/batch_thirdparty.py` 无对应测试；`core/privacy/`、`core/policy/` 0 测试；`frontend/` 5 个 JS 只有 `audit-results.js` 被引用。
- 三条入口都是**纯离线**（无设备、无网络、无 AI key），设备类脚本不进回归。这既是优点也是边界：真实采集链路的健康度只能靠跑批手工验证。

### 1.6 潜在风险 —— 弱

- **结论可信度**：`docs/PROJECT_STATUS_20261110.md:90-107` 七条已知缺口按「会不会导致结论出错」排序，首条是 `observed_findings` 恒为 0（round2 9 样本、breezy 12 条都只到 `candidate`），即当前结论不能说明任何一条「某 App 把某数据发出去了」。这不是工程任务能一周补齐的，但所有报表口径必须继续守住「未观测 ≠ 安全」。
- **硬约束冲突**：`mobile/tools/thirdparty_env_adb.py:179` 的 `QUIC_RULE` 默认 DROP UDP/443 逼 HTTP/3 回退，与 `AGENTS.md:22`「观察不改写」冲突，`docs/REAL_APK_OPTIMIZATION_PLAN_20261111.md:54` 已定性为 P0；`mobile/tools/pcap_http.py`（pcap → 完整 HTTP 重组的核心抓包文件）全文无「仅用于授权测试」声明，而 `AGENTS.md:19` 要求所有抓包/Hook 代码写明。抓包相关 `mobile/traffic/*.py` 9 个中仅 4 个含声明。
- **Windows 假红**：默认环境下 `sitecustomize.py` 的 bulk-delete guard 会把 3 组分支回归打成 `SystemExit(1)`；设 `CODEBUDDY_SAFE_DELETE_ENABLED=0` 后 3 组转绿，但 `ai_gates` 仍偶发 `PermissionError: [WinError 5]`（见 §2）。两类假红会盖住真实回归失败。
- **产物风险**：10 个 junction 指向 `D:/vscanner-tp/` 等外部路径，历史清理曾出现悬空链接（`memory/2026-11-10.md:307-313`）；`output/` 不入库，但体积已影响遍历与备份。

---

## 2. 实测回归基线（2026-11-11，本报告的一手判据）

用本机 `%LOCALAPPDATA%\Programs\Python\Python313\python.exe`（3.13.9）实测，产物在 `output/assess-20261111-231325/{root,mobile,branch}/`：

| 入口 | 实测 | 结论 |
| --- | --- | --- |
| `tools/run_regressions.py` | **21 组全 0**，`ROOT_EXIT=0` | 全绿（未带 `--prepare/--mobile`） |
| `mobile/tools/run_mobile_checks.py` | **63 项**，`failed: []`，`MOBILE_EXIT=0` | 全绿 |
| `tools/check_mobile_branch.py` | **24 组，23 绿 1 红**，`failed: ["ai_gates"]`，`BRANCH_EXIT=1` | 未全绿 |

`ai_gates` 的红不是断言失败，是 Windows 文件占用：

```
ERROR: test_tampered_review_rejected (test_benchmark_review_attach.AttachmentTests...)
  File "mobile/ai/benchmark_review.py", line 24, in save
    os.replace(temp, path)
PermissionError: [WinError 5] 拒绝访问 ... ai-review.json.tmp -> ai-review.json
Ran 127 tests in 2.898s / FAILED (errors=1)
```

现成的正确实现就在仓库里：`core/regression_output.py:9,32-39` 定义了 `REPLACE_ATTEMPTS = 10`（win32）与 `PermissionError` 有界退避重试，`core/test_regression_output.py:47` 已有注入 `PermissionError` 的测试。而 `mobile/ai/benchmark_review.py:24`、`mobile/ai/benchmark_review_attach.py:18` 的 `os.replace` 都没有这层保护。这是 A1 的直接依据，不需要重新设计。

另：本次实测设了 `CODEBUDDY_SAFE_DELETE_ENABLED=0`。不设时 `mobile_workbench`/`ai_gates`/`mobile_lab` 三组会因 `sitecustomize.py` 的 bulk-delete guard 变成环境假红（`memory/2026-11-10.md:666-671`），A1 也要把这一步固化下来。

---

## 3. 本周任务清单（A 组：默认执行；按优先级排序）

工作量按**单人有效工时**折算，不假设团队人数。三条承诺档：
**必做集 A1+A2+A3 = 13 人时**（任何情况下都要完成，是后续所有改动的门禁）；
**标准集 +A4+A5+A6 = 27 人时**（本周正式承诺范围）；
**余量项 A7–A9 = 11 人时**（有余力再做，未完成顺延不算失败）。

---

### A1 [P0] 回归可信化：修 Windows 原子替换偶发失败并固化假红隔离

- **对应问题**：§2 实测 `ai_gates` 因 `mobile/ai/benchmark_review.py:24` 的裸 `os.replace` 抛 `PermissionError [WinError 5]`；默认环境下另有 3 组被 `sitecustomize.py` 的 bulk-delete guard 打成假红。两类假红会让「回归红了」这个信号失去意义。
- **优化目标**：三条入口在同一台 Windows 主机上稳定可判定；失败只可能来自被测代码。
- **影响范围**：`core/regression_output.py`（抽出 `atomic_replace`，保留 `publish_latest` 行为）、`mobile/ai/benchmark_review.py`、`mobile/ai/benchmark_review_attach.py`、`core/test_regression_output.py`、`docs/REGRESSION_CI.md`、`Jenkinsfile:10-13`、`.github/workflows/ci.yml:18-21`。**只改落盘原子性，不改 AI 评审逻辑、不改移动端功能。**
- **预估工作量**：5 人时（抽 helper + 2h、注入测试 +1h、CI 环境变量 +0.5h、三条回归连跑 3 次 +1.5h）。
- **依赖关系**：无；A2/A3/A5/A7/A9 都依赖本项先给出可信基线。
- **完成标准**：
  1. `atomic_replace` 复用 `REPLACE_ATTEMPTS` 与退避语义，两个 AI 落盘点改调它；新增注入 `PermissionError` 的用例（首次/前 N 次失败后成功、10 次全失败仍抛出）。
  2. 两条 CI 的 environment/ env 显式设置 `CODEBUDDY_SAFE_DELETE_ENABLED=0`，`docs/REGRESSION_CI.md:16-34` 新增「环境假红」小节，与已有的「解释器缺库退出码 3」并列。
  3. 三条入口连续各跑 3 次，`verification.json` 均为 `passed=true / failed=[]`，`ai_gates` 127 项无 `PermissionError`。
- **范围**：平台无关（测试基础设施）。

---

### A2 [P0] 统一回归组数口径，并让 CI 覆盖第三条入口

- **对应问题**：`tools/run_regressions.py:13-117` 实际 21 组（`--mobile` 22、`--prepare --mobile` 23），而 `AGENTS.md:115`、`docs/REGRESSION_CI.md:14/59/66`、`VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:109` 分别写 18/19/19；`Jenkinsfile:23` 与 `ci.yml:40` 都只跑 `run_regressions.py`，**`check_mobile_branch.py` 从未进 CI**，所以 §2 里分支回归的红在 CI 上根本不会暴露。
- **优化目标**：组数由代码单一来源产生，CI 判据覆盖全部三条入口，文档不再手工维护数字。
- **影响范围**：`AGENTS.md:111-131`、`docs/REGRESSION_CI.md:14,59,66`、`docs/PROJECT_STATUS_20261110.md:75-77`、`Jenkinsfile:21-25`、`.github/workflows/ci.yml:39-40`、新增 `tools/test_regression_manifest.py`（并入 `run_regressions.py` 的 `completion` 组或新组）。
- **预估工作量**：3 人时。
- **依赖关系**：A1（否则 CI 加第三入口会立刻被假红染红）。
- **完成标准**：
  1. 新增测试从 `CHECKS` / `MOBILE_GROUP` / `prepare` 真实计算 21/22/23/63/24，并断言文档中的组数与该值一致；故意改错一处文档数字时测试报红。
  2. 两条 CI 各加一步 `tools/check_mobile_branch.py --out ...`，失败同样归档日志；`docs/REGRESSION_CI.md:59` 的「19 组验收」改为按 `verification.json` 判通过，不再写死组数。
  3. 本地按 CI 命令跑一遍，`output/ci-*/` 下三份 `verification.json` 齐全且全绿。
- **范围**：平台无关（CI / 文档）。

---

### A3 [P0] 把已有质量守卫接进 CI，覆盖 .js/.css 与合规声明

- **对应问题**：ruff 与 300 行守卫只存在于 `.pre-commit-config.yaml`（本机未 install，`.git/hooks/` 无生效钩子），CI 里一步都没有；守卫 `files: \.py$` 不覆盖 `frontend/app.css`(2271 行)、`app.js`(900 行)、`landing.css`(456 行)；项目自有 16 个 `.py` 已超限，直接开拦会立刻全红。同时抓包/Hook 文件的「仅用于授权测试」声明没有机器检查（`mobile/tools/pcap_http.py` 全文无声明）。
- **优化目标**：守卫对**新增与本次改动文件**强制生效，存量违规登记为可核查基线；授权声明成为可扫描的硬约束。
- **影响范围**：`.pre-commit-config.yaml`、新增 `tools/check_engineering_guards.py`、新增 `tools/engineering_guard_baseline.json`（16 个 .py + 3 个前端文件 + 声明缺口清单）、`Jenkinsfile`、`.github/workflows/ci.yml`、`ruff.toml`（不改规则集，仅补 `--output-format` 说明）。
- **预估工作量**：5 人时。
- **依赖关系**：A2（CI 步骤已能跑第三入口）；A4 复用本项产出的守卫框架。
- **完成标准**：
  1. CI 新增 `ruff check`（沿用 `ruff.toml` 的 E/F 与 per-file-ignores）+ `ruff format --check`，**仅对本次 diff 文件**强制；存量 16+3 个违规项逐条写入 baseline，含路径、行数、登记日期与「后续拆分」标记，不得悄悄豁免。
  2. 行数守卫扩展到 `.py/.js/.css`；现场验证：临时造一个 301 行文件 → 守卫返回非 0，删除该文件 → 放行。
  3. 新增一条离线守卫：扫描 `mobile/traffic/`、`mobile/tools/pcap_*.py`、`vehicle/hooks/*.js`、`mobile/hooks/*.js` 中抓包/Hook 文件是否含「仅用于授权测试」或 `Authorized tests only`；缺口清单落盘，当前允许以 baseline 登记，不允许新增缺口。
  4. `requirements.txt` 或独立 `requirements-dev.txt` 固定 ruff 版本（`ruff-pre-commit` 已是 v0.8.4），CI 不再因工具版本漂移产生新红。
- **范围**：平台无关（工程门禁；含车载 Hook 声明检查，不含移动端功能开发）。

---

### A4 [P1] 静默异常治理：只治采集与关联主链路，并防新增

- **对应问题**：68 处 `except → pass`、8 处只 `print` 不落盘，与 `AGENTS.md:26`「失败可诊断」冲突；`AGENTS.md:71-72` 与 `mobile/DECISIONS.md:3-4` 反复记录「几乎每个坑都是静默失败」。典型：`core/collector/uid_sampler.py:186`（`terminate()` 失败静默）、`core/ai/llm_client.py:147-148`、`core/collector/health.py:39`、`vehicle/workbench/server.py:308`。全量清理不现实，需限定范围。
- **优化目标**：本批次相关路径上的异常要么转成带 reason 的落盘/缺口，要么显式标注为「允许忽略」并给出理由；新增静默吞异常由 A3 的守卫拦下。
- **影响范围**：限定 3 组共约 12 处——① `core/collector/` 采集与健康链路；② `vehicle/workbench/server.py`、`vehicle/webapp/server.py` 的服务端响应路径；③ `core/frida_host/message_stream.py:32-34`（先吞 OSError 再 print）。`mobile/tools/` 与 `mobile/lab/` 的其余 50+ 处**本周不动**，只登记到 baseline。
- **预估工作量**：5 人时。
- **依赖关系**：A3（守卫框架）；已有范式 `core/io_utils.py:70,76` 与 `mobile/tools/observed_surface.py:60` 直接复用，不新造异常体系。
- **完成标准**：
  1. 12 处逐条二选一：改为 `logger`/落盘并写 reason，或在代码内加 `# noqa: BLE001 + 允许忽略的理由`；不允许保留无注释的裸 `pass`。
  2. A3 守卫新增规则：除 baseline 外，新增 `except ...: pass` 或只 `print` 的块直接判红。
  3. 对应模块既有单测全绿；根回归 21 组、移动 63 项不新增失败。
- **范围**：平台无关 + 车载；`mobile/tools/` 仅登记不修改。

---

### A5 [P1] 规则加载收敛到单一实现，并用对拍测试钉住

- **对应问题**：`core/rules_contract.py:15-16` 明令不得重写 `load_rules`，但 `vehicle/analyze/correlate.py:81-93`、`mobile/analyze/correlate_mobile.py:60-80` 各有一份，返回形状还与 core 的 `dict` 不同；`core/static/static_rules.py:28,38` 是唯一正确转发壳。两线各自读 sqlite，扩展表分发逻辑一旦变更就会静默分叉。
- **优化目标**：两线改为走契约层，字段逐条等价；不改动规则库 `.db`、不改规则启用状态、不改判定语义。
- **影响范围**：`core/rules_contract.py`（新增 `load_rule_rows()` 或等价适配器）、`core/static/static_rules.py`、`vehicle/analyze/correlate.py`、`mobile/analyze/correlate_mobile.py`、`core/test_rules_contract.py`。**触及 `mobile/analyze/`，但只做等价转发，不改移动端判定逻辑；若范围从严，本项可整体顺延到 B 组解冻后。**
- **预估工作量**：6 人时（适配器 2h、两线改造 1.5h、对拍测试 1.5h、回归 1h）。
- **依赖关系**：A1（回归基线可信）；与 `vehicle/rules/` 四版本 116 条 / 移动库 `MOB-*` 前缀契约对齐，需先读 `core/rules_contract.py:54-57` 的历史重复说明。
- **完成标准**：
  1. 两线不再各自定义 `load_rules`；新增测试对四版本 `rules.db` 与 `rules_mobile.db` 逐字段对拍（rule_id、revision、android_version、enabled 等 14 字段），条数一致（车载 116 行 / 启用 96 条）。
  2. `core/test_rules_contract.py` 增加一条守卫：全仓不得再出现第二处 `def load_rules`（转发壳除外）。
  3. 根回归 `correlate`/`rules-contract` 组、移动 `risk_score`/`report_gates` 组全绿；`docs/PROJECT_STATUS_20261110.md:60-61` 的规则库哈希结论不变。
- **范围**：core + 车载为主（含一处移动端等价转发，见上）。

---

### A6 [P1] 环境与数据集口径一次对齐，缺失路径显式报错

- **对应问题**：`environment.ps1:3-4` 与 `:12-13` 自相矛盾；`AGENTS.md:35,108`、`.agents/README.md:135-140`、`VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:114` 对 SDK/JDK/Python 依赖是否齐全各说一套；`core/sdk_paths.py:29-31` 仍保留 `D:/Anroid/*` 最后兜底；数据集 `D:/数据集/...` 本机不存在（`.workbuddy/memory/2026-11-11.md:82`），而多处文档把它当既定事实。
- **优化目标**：一台机器上只有一份权威环境表；缺数据集时明确报「路径不存在」而不是「0 个样本」；**不新增任何要用户做的环境探测**（`AGENTS.md:27` 约束 7）。
- **影响范围**：`environment.ps1`（头注释）、`AGENTS.md:30-39`、`.agents/README.md:129-141`、`docs/REGRESSION_CI.md:16-36`、`core/env_guard.py`（增加可选的数据集路径存在性诊断，只在跑批入口调用）、`docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md:49`。不改 SDK/JDK 解析逻辑、不删 `LEGACY_*` 兜底常量。
- **预估工作量**：3 人时。
- **依赖关系**：A2（文档口径统一机制）；数据以本次实测与 `.agents/README.md §6` 为准，不要求用户再跑一遍环境探测。
- **完成标准**：
  1. 三处环境表对 Python / SDK / JDK / AVD / frida 端口给出同一组值，并统一注明「`D:\Anroid` 是原开发机拼写，本机是 `%LOCALAPPDATA%\Android\Sdk` + `D:\Android\JDK`」；删掉「缺 jsonschema」与「依赖已齐」这类未标注时点的结论，改为「以 `env_guard` 退出码为准」。
  2. 跑批入口在 `--apk-dir` 不存在或 0 个 APK 时，输出区分「路径不存在 / 目录为空 / 全被 `--only` 过滤」三种原因，并附一个离线用例。
  3. `AGENTS.md:43` 补一句数据集不在本机的现状与替代样本目录，避免照抄路径。
- **范围**：平台无关（文档 + 诊断）。

---

### A7 [P2·余量] 补三处离线行为测试盲区

- **对应问题**：`mobile/pipeline/` 17 阶段只收集到 5 个用例（`pipeline_api` 组实测 `python_tests_direct=5`），`runner.py:99-218` 的失败分支、设备不可用降级、报告生成即算完成等路径无直接测试；`mobile/tools/batch_thirdparty.py` 无对应测试；`frontend/` 5 个 JS 仅 `audit-results.js` 被引用。
- **优化目标**：用 mock 子进程/回环 HTTP 补行为测试，全部离线、不接设备、不依赖在线 AI。
- **影响范围**：新增 `mobile/pipeline/test_runner_branches.py`、`mobile/tools/test_batch_plan_resume.py`、`frontend/test_pipeline_contract.mjs`；`tools/run_regressions.py` / `tools/check_mobile_branch.py` 注册；`tools/test_inventory_allowlist.json` 与 `tools/test_inventory_guard.py` 保持 0 未登记。
- **预估工作量**：6 人时。
- **依赖关系**：A1；测试须走 `tools/test_inventory_guard.py` 的登记守卫，避免变成第 8 个「僵尸测试」。
- **完成标准**：至少覆盖 `runner` 的静态失败/设备不可用/动态 rc!=0 但报告存在 3 条分支、`batch_plan._finished` 的「目录存在但 `verification.json.passed != true`」反例、前端 `/api/stages` 与 17 阶段时间线一致性；三项进入 runner 后 `test_inventory_guard` 报 0 未登记、三条回归全绿。
- **范围**：平台无关（测试）；含对移动端脚本的只读断言，不改其功能。

---

### A8 [P2·余量] `output/` 只读盘点与日志增长上限

- **对应问题**：37.73 GB / 262,893 文件 / 10 个 junction（junction 会让遍历外溢）；`batch_dynamic.py:46`、`supervise_batch.py:60,204`、`stages.py:59` 日志一律追加无轮转；历史清理曾出现悬空 junction（`memory/2026-11-10.md:307-313`）。`AGENTS.md:207-210` 明确禁止按历史条目删现存内容。
- **优化目标**：让体积与链接状态可见、让**新增**日志有上限；本周**不删除、不移动、不重命名任何文件**。
- **影响范围**：新增只读盘点脚本 `tools/inspect_output.py`（输出 `output/output-inventory-*.json`）、`docs/REGRESSION_CI.md` 或新文档的一节；`batch_dynamic.py` / `supervise_batch.py` 的日志写入改为有大小上限的滚动或按批次分文件（只影响新批次）。
- **预估工作量**：3 人时。
- **依赖关系**：无；可与其它项并行，但不得与设备采集抢同一份日志目录。
- **完成标准**：盘点报告列出顶层目录体积/mtime/是否 reparse point/是否可由回归重建；`inspect_output` 跳过 junction 且能在 60 秒内完成；新增日志文件超过设定阈值（如 20 MB）自动分卷，旧文件保持不动；`git status` 无新增跟踪文件（`output/` 已被 `.gitignore:24` 忽略）。
- **范围**：平台无关。

---

### A9 [P2·余量] 建立唯一「当前状态 + 本周工单」入口

- **对应问题**：`docs/` 下 55 份 md，一周/三周/双人/实名任务类至少 12 份且多份自称「替代上一版」；`docs/PROJECT_STATUS_20261110.md` 是 11-10 快照（HEAD `a115850`），`AGENTS.md:176-180` 的 6 项未完成、`mobile/CLAUDE.md:210-218` 的 4 项未完成、`VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:117-128` 的 4 项未执行分散在三处。
- **优化目标**：一份文档回答「现在什么状态、本周做什么、什么没做完」，其余计划文档标注为历史快照，不再互相替代。
- **影响范围**：`docs/PROJECT_STATUS_20261110.md`（更新为 11-11/12 状态，或新建 `docs/CURRENT_STATUS.md` 并从本文链接）、`AGENTS.md:111-123` 回归段、`DELIVERY_INDEX.md`。不改任何历史计划正文，只加状态标注。
- **预估工作量**：2 人时。
- **依赖关系**：A2、A6（口径与环境事实先统一）；A1/A3 的完成结果要回填。
- **完成标准**：单页含 ① 代码基线 HEAD 与工作区状态；② 三条回归最新 `verification.json` 路径与结论；③ 未完成清单合并去重（6+4+4 项，逐条标来源）；④ 本周 A 组工单状态表；⑤ 「已知 7 条结论缺口」原文链接。历史计划文件顶部各加一行「历史快照，不作当前清单」。
- **范围**：平台无关（文档）。

---

## 4. B 组：条件任务（移动端；默认不排期）

> 触发条件：用户明确解除 `docs/VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:4` 的「移动端暂不开发」约束。
> 触发后的插入方式：用 B 组替换 §3 的 A7–A9 余量项（约 11 人时），或单列一份人力；**不要**挤掉 M1/M2/M3 功能主线。
> 注意：`supervise_batch.py` 已经实现了自动恢复与断点续跑，B2 是「接线与验证」，不是重新造轮子。

### B1 [条件·P0] 动态批次异常兜底与汇总必落盘

- **对应问题**：`batch_dynamic.py:44-51` 的 `subprocess.run(..., timeout=3600)` 未捕获 `TimeoutExpired`（`batch_static.py:116-118` 与 `mobile/pipeline/legacy_command.py:16-21` 都有正确范式）；异常经 `dynamic_step()`(107-116 的 `finally` 只收代理) → `batch_thirdparty.py:237-241`（动态循环无 try）→ `main()` 直接 `SystemExit`，**`_summarize()` 不执行，`batch-summary.json` 与 `latest-thirdparty-batch.txt` 都不写**（`batch_thirdparty.py:273-275`）。夹具自检 `run(..., timeout=1800)`(168 行) 同路径。
- **优化目标**：单样本任何异常转成 `device_failed` + 原因落盘；批次无论怎样结束都产出汇总。
- **影响范围**：`mobile/tools/batch_dynamic.py`、`mobile/tools/batch_thirdparty.py`、新增离线测试（mock 超时与 `OSError`）。
- **预估工作量**：5 人时｜**依赖**：范围确认 + A1。
- **完成标准**：注入超时/`OSError`/`JSONDecodeError` 三种异常，批次均返回非 0 且写出 `batch-summary.json`，失败样本带 `error`/`error_type` 与 `run.log` 路径；`--resume` 复跑时该样本不因目录存在被误判为已完成（判据仍以 `batch_plan.py:27-40` 的 `verification.json.passed` + 报告 PDF 为准）。

### B2 [条件·P1] 已有守护进程的接线、验证与手册补齐

- **对应问题**：`mobile/tools/supervise_batch.py:3-7,248-267` 已实现「设备掉线 → 复位模拟器 → 带 `--resume` 重跑」，`batch_plan.py:27-40` 的完成判据也已正确（不是「目录存在即跳过」）；但 `docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md` 全文未提及该脚本，§7:353-355 只写「换 `--out` 或 `--resume`」，且 `supervise_batch.py` 没有离线测试。用户长期关注的「模拟器异常后自动恢复 + 断点续跑」实际是**有了实现但没有标准入口与验收证据**。
- **优化目标**：把守护进程变成文档化的标准跑批方式，并用离线测试钉住续跑判据。
- **影响范围**：`docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md`（新增 §7.x）、`AGENTS.md:41-46`、新增 `mobile/tools/test_supervise_progress.py`（mock `adb devices` 与 `batch_progress`）。
- **预估工作量**：3 人时｜**依赖**：B1（先保证异常不会吞掉汇总）。
- **完成标准**：手册给出守护入口命令、`--max-restart`/`--boot-timeout` 取值依据与「每轮进度从哪读」；离线用例覆盖「设备在线直接跑」「设备掉线复位」「已达 100% 提前退出」「达到 max-restart 返回 1」四种；不改 `device_ok()`(69-82) 与 `start_emulator()`(106-168) 的行为。

### B3 [条件·P0] 合规硬约束：默认改写行为与授权声明

- **对应问题**：`mobile/tools/thirdparty_env_adb.py:179,182-203` 默认执行 `iptables ... udp/443 -j DROP`，与 `AGENTS.md:22`「观察不改写」冲突，`docs/REAL_APK_OPTIMIZATION_PLAN_20261111.md:54` 已定性 P0「应优先修正」；`mobile/tools/pcap_http.py` 全文无授权声明，`mobile/traffic/` 9 个 `.py` 仅 4 个有声明，违反 `AGENTS.md:19`。
- **优化目标**：默认不改变被测设备网络行为；所有抓包/Hook 文件声明可扫描。
- **影响范围**：`mobile/tools/thirdparty_env_adb.py`、`mobile/tools/device_run_thirdparty_run1.py:74-86`、`mobile/tools/pcap_http.py`、`mobile/traffic/` 相关文件头、A3 的守卫规则（复用，不另起一套）。
- **预估工作量**：3 人时｜**依赖**：A3 守卫框架 + 范围确认。
- **完成标准**：DROP 改为显式 opt-in 开关（默认关），开启时批次汇总与逐样本 `verification.json` 必须记录「本轮改变了设备网络行为」；声明补齐后 A3 守卫报 0 个新增缺口；不修改 `ssl_pinning_bypass.js` 的唯一例外约定。

### B4 [条件·P1] SSE 增量读与前端 16/17 阶段契约

- **对应问题**：`mobile/pipeline/stages.py:75` 每次全量 `read_text()`、`server.py:249-264` 每 0.5s 轮询 → O(n²) 读放大；`frontend/app.html:126` 写「17 STAGES」但 `:132` 显示 `/ 16`、`:137-140` 的 `stage-rail` 只有 16 个 `<i>`，而 `mobile/pipeline/stages.py:24-42` 是 17 个阶段。
- **优化目标**：事件读与阶段数都以 `STAGES` 为单一来源；不改事件 schema（`stages.py:5-9`）。
- **影响范围**：`mobile/pipeline/stages.py`、`mobile/pipeline/server.py`、`frontend/app.html`、`frontend/app.js`、前端契约测试。
- **预估工作量**：4 人时｜**依赖**：A1（回归基线）。
- **完成标准**：`read_events` 改为按 offset seek 增量读，10,000 行事件的读取耗时不随已读行数线性增长（离线基准断言）；前端 rail/计数由 `/api/stages` 或同一份常量生成，改后端阶段数时前端契约测试报红。

---

## 5. 排期与依赖

```
D1  A1（回归可信化，先做完，后续所有判据才可信）
D2  A2（口径 + CI）→ A3（门禁上 CI）        【必做集 13 人时完成】
D3  A4（静默异常，复用 A3 守卫）  ∥  A5（规则加载收敛）
D4  A5 收尾 + A6（环境/数据集口径）
D5  集成复跑三条回归、回填 A9 状态页       【标准集 27 人时完成】
D6  A7 / A8 / A9 余量项，或 B 组（仅在范围解冻时）
```

- 依赖链：`A1 → A2 → A3 → A4`；`A1 → A5/A7`；`A2 → A6/A9`；A8 独立；`B1 → B2`，B3 依赖 A3，B4 依赖 A1。
- 与 `docs/ONE_WEEK_DEVELOPMENT_PLAN_20261110.md`（11-16~11-22）并行时：本清单的 A1–A3 应作为 M1/M2/M3 各主线**开工前的门禁**（先有可信回归基线），A4/A5 由不持有设备采集主线的人承担；不新增人员假设，也不要求么贵行/陶俊哲放下设备工作。
- 本清单不安排任何需要 AAOS 设备在线、真实 APK 采集、在线 AI key 或真人签核的任务；这类事项见 §6。

---

## 6. 明确不做（避免超出项目范围）

| 不做的项 | 原因（现状依据） |
| --- | --- |
| 提升 `observed_findings`（当前恒为 0）、宣称检测率/准确率 | `docs/PROJECT_STATUS_20261110.md:90-107`：缺真实第三方外发正样本、可达性 9 样本 7 个失效、签核主体是 AI。一周内给不出可信数字，硬做只会产出不可用的结论。 |
| `protection_level_value` 180 行标定、B1 窗口人工签核、B2 VScanBench、F1 类加载归因、G1 UI 覆盖率 | `AGENTS.md:176-180` 明列「仍未做」，需设备实测或人工签核，属研究专项。 |
| Hook 第三层 pinning 设备验收、商用 APK 整批评测、四版本能力矩阵、split APK/OEM 适配 | `VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md:117-128` 列为未完成，需真实 AAOS 输入与独立参考。 |
| 动态批次改并发、把静态并行再提速 | `batch_dynamic.py:7-16` 与 `mobile/DECISIONS.md` M020 / `core/collector/DECISIONS.md` D413：并发会串归因；静态已 3 路并行、M041 已验证收益。 |
| 删除/移动 `output/` 现存内容、清理历史目录 | `AGENTS.md:207-210` 明确「不要按本条去删 `output/` 里的现存内容」；A8 只做只读盘点。 |
| 引入 pytest/coverage、React/Vue/Tailwind、新证据库迁移、整站改版 | 与 `frontend/README.md` 零构建约束、`ONE_WEEK_DEVELOPMENT_PLAN_20261110.md:36` 本周删除项、现有自定义回归体系冲突。 |
| 再做一次环境探测交给用户 | `AGENTS.md:27` 约束 7；A6 只用已有实测数据。 |

---

## 7. 验收入口（改完代码统一复跑）

```powershell
# 本机 PowerShell 执行策略若拦截 .ps1，用：
# powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\python313.ps1 <脚本及参数>
# 或直接调用本机 Python 3.13 绝对路径（本次实测采用该方式）
.\tools\python313.ps1 tools/run_regressions.py
.\tools\python313.ps1 mobile/tools/run_mobile_checks.py
.\tools\python313.ps1 tools/check_mobile_branch.py
```

通过判据：三份 `verification.json` 均 `passed=true / failed=[]`；`ruff check` 与行数守卫在 diff 文件上 0 违规；`test_inventory_guard` 0 未登记；文档中的组数/环境值与代码一致。缺库时 `env_guard` 退出码 **3** 是环境假红，不是测试失败；`1` 才是真失败（`docs/REGRESSION_CI.md:33`）。

---

## 8. 落地记录（A1–A6 代码已落地；经 §9 复核后修订，2026-11-12）

用户指示「先完成 P0 与 P1」，A1–A6 代码已落地并跑通三条全量回归。产物在
`output/p01-20261112-000339-4489/{root,mobile,branch}/`：
根回归 **22/22 全绿**、移动侧 **63/63**、分支 **26/26 全绿**（`ai_gates` 由红转绿），
退出码均 0。**初版本节把「跑通回归」写成了「完成」**：§9 的五路独立复核发现守卫
存在可复现的假绿路径，已做修复轮；下表与偏差段按修复后的实际状态重写。

| 任务 | 落地要点 |
| --- | --- |
| A1 | `core/regression_output.py` 抽出 `replace_with_retry` / `atomic_write_text`，`publish_latest` 与两个 `mobile/ai/benchmark_review*.py::save` 共用；`core/test_regression_output.py` 新增 3 个反例（重试后成功 / 耗尽仍抛且清理 .tmp / 非 PermissionError 不重试）。两条 CI 固定 `CODEBUDDY_SAFE_DELETE_ENABLED=0`，`docs/REGRESSION_CI.md` 新增「Windows 环境注入假红」小节。 |
| A2 | `tools/test_regression_manifest.py` 把 `CHECKS` 数量、页首机器标记、`EXPECTED_CHECKS`、两条 CI 配置对拍；`run_mobile_checks.py` 新增 `EXPECTED_CHECKS = 63` 自证；`AGENTS.md` / `REGRESSION_CI.md` 的 18/19 组历史口径已订正。两条 CI 均新增 `check_mobile_branch.py` 步骤。 |
| A3 | 新增 `tools/engineering_guards.py`（全树扫描 + 行数含 `.js/.css/.html`、文件头授权声明、语义 AST 静默异常判定、语法错误）+ `tools/engineering_guard_baseline.json`（复核后口径：**38** 个超限 / **15** 个声明缺口 / **202** 处静默异常，含 `registered_at`/`split_plan`/`rule_version=3`）+ `tools/test_engineering_guards.py`（**13** 项）。两条新测试模块并入根回归 `completion` 组；`log-rotation` 组由并发会话单列，故根组数 21→22。`requirements-dev.txt` 固定 `ruff==0.8.4`。 |
| A4 | 治理 8 处 `except → pass` 与 2 处只 print 的主链路位置；其中 3 处初版只是加 `# noqa` 注释（复核 H1 判定为注释粉饰），修复轮已改为真实诊断输出。`vehicle/workbench/server.py` 316→319 被守卫拦回原状、`mobile/analyze/correlate_mobile.py` 318→320 压到 316（净减少 2 行），不是「均净减少」。静默异常数在旧守卫下 60→52；守卫收紧为全树+语义判定后基线为 202，**两个口径不可直接比较**。 |
| A5 | `core/rules_contract.py::load_rule_rows` 成为 `risk_rules` 唯一读库入口（其余表仍由各模块自读）；两线 `correlate` 等价转发，移动侧 14 字段投影不变。`core/test_rules_contract.py` 复核后共 **11** 项：四版本/移动库逐字段对拍、两线全字段对拍、移动 14 字段逐字段相等、运行时连接计数守卫、116 行/96 启用基线、AST 守卫（覆盖改名/拼接）。初版只比 `rule_id` 的假绿已修。 |
| A6 | `environment.ps1` 头注释、`AGENTS.md` 环境表、`.agents/README.md` 漂移索引、`REGRESSION_CI.md`、runbook 已对齐；依赖状态统一以 `env_guard` 退出码为准。`core/env_guard.py::diagnose_apk_dir` 区分「目录不存在 / 空目录 / `--only` 全过滤」，`batch_thirdparty.py` 接线。 |

**与计划的偏差（§9 复核后补全，共 9 条）：**

1. A3 的 `ruff format --check` **未强制**，且 `ruff check` 只覆盖 3 个硬编码的新增守卫入口，不是原计划的「本次 diff 文件」；并发会话新增的 8 个文件零 lint。本机没有 ruff、全仓格式基线未建立，直接开会造成与本次改动无关的假红。
2. A3 基线初版缺 `registered_at` / `split_plan`（已补），且**基线缺失时会自动重建并返回 0**——干净检出的 CI 恒绿（复核 H2，已改为判红）。`--update` 现只允许收紧，判定规则升级需 bump `RULE_VERSION`。
3. A1 完成标准 3「三入口各连跑 3 次」的 `verification.json` 证据**未提供**；修复轮只对 `ai_gates` 做了连跑 3 次，其余两入口仍只有单轮产物。
4. A4 原写「约 12 处」：定位到 8 处 `except → pass` + 4 处只 print，其中 2 处是 `KeyboardInterrupt` 正常停机提示；改写 10 处，但初版有 3 处只是加注释（已修）。按 `AGENTS.md:26` 字面「日志落盘」衡量，全部 10 处仍只到 stdout/stderr，**未写入日志文件**，此项只能算「可见性改善」，不算完成约束 6。
5. A5 触及 `mobile/analyze/correlate_mobile.py`，只做等价转发；初版 14 字段对拍缺失（已补）。措辞应为「`risk_rules` 表唯一读库入口」，`load_data_types` 等仍各自连库。
6. **B 组条件任务未执行**：11-11「移动端暂不开发」未解除。并发会话确实改了 `batch_dynamic.py` / `supervise_batch.py` / `batch_plan.py`，但只换日志分卷方式，**B1–B4 的验收标准一条都没落地**；初版「并发落地 B 组」表述已更正。
7. 工作区存在并发会话落地 A7/A8/A9（新增 `log-rotation`、`batch_plan`、`pipeline_frontend_contract`、`docs/CURRENT_STATUS.md`、`core/log_rotation.py` 等），组数由 21/24 变为 **根 22 / 分支 26**；机器标记、文档与清单守卫已同步到 `22/23/24、63、26`。三份共享文件（`tools/run_regressions.py`、`docs/REGRESSION_CI.md`、`AGENTS.md`）存在两路交错编辑，git 层面无法拆分归属。
8. **14 个新增文件未被 git 跟踪**，其中 6 个被 CI / runner 硬引用（`requirements-dev.txt`、`tools/engineering_guards.py`、`engineering_guard_baseline.json`、两个 `test_*`、`docs/ENGINEERING_WEEK_TASKS_20261111.md`）。提交前必须逐一点名 `git add`，不能只用 `git add -u`；漏提交在干净检出会直接红（基线缺失已改为判红，不会再自愈洗白）。
9. §7「三份 `verification.json` 均 `passed=true / failed=[]`」判据不准确：根回归产物是 22 项 `{name, exit_code}` **list**，无 `passed` 字段；只有 mobile/branch 是 dict。活跃入口文档（README/CLAUDE/DELIVERY_INDEX/mobile/CLAUDE）的旧 18/19/24 组数字已在修复轮订正。

---

## 9. 独立 subagent 复核与修复轮（2026-11-12）

用户要求「派出 subagent 来 review」，共派 **5 路只读 Explore 子代理**：逻辑正确性、
测试有效性与假绿、项目约束合规、红队门禁绕过、并发集成风险。五路一致判定
**`usable_as_gold = false`**（同模型多上下文、工作区存在并发写入，按项目惯例不作金标准）。
完整报告见 [output/review-20261112/REVIEW.md](../output/review-20261112/REVIEW.md)。

去重后的 High 级发现与修复：

| 编号 | 复核发现 | 修复 |
| --- | --- | --- |
| H1 | `atomic_write_text` 固定 `.tmp` 名，并发写同一路径互相覆盖/删对方临时文件；`write_text` 在 try 外，编码/磁盘满失败残留半截文件 | 改用 `NamedTemporaryFile` 唯一名、写操作移进 try；补并发 16 写者与写失败清理反例 |
| H2 | 基线缺失时守卫自动重建并返回 0（干净检出 CI 恒绿）；基线可任意调大 / `--update` 洗白 | 缺失即判红；`--update` 只允许收紧；新增 `rule_version`、`registered_at`、`split_plan`；补 4 项反例 |
| H3 | `silent_except_sites` 只认字面 `pass`，12/14 种等价写法绕过；授权声明全文子串可被一行注释伪造；扫描只覆盖 5 个目录 | 改为「有无可观测副作用」语义 AST、文件头/docstring 声明、os.walk 全树剪枝扫描；授权范围扩到 traffic/frida_host/collector/pcap_*；补语义反例与常量钉住 |
| H4 | A5 两线对拍只比 `rule_id`，13 个字段篡改全绿；AST 守卫改名/helper 下沉可绕过 | 补 14 字段逐字段对拍、vehicle 全字段对拍、运行时 `sqlite3.connect` 计数守卫、AST 守卫覆盖改名与字符串拼接 |
| H5 | 清单守卫的 CI 断言只是 4 个 `assertIn`；`--update`、摘除两个守卫测试、注释里写关键字都能全绿；`root+2` 硬编码 | 改为「取非注释命令行 → 精确判据」；从 `main()` AST 推导 prepare 增量；断言 `CHECKS[0]` 含两个守卫测试模块；活跃文档旧组数扫描 |
| H6 | A4 三处纯 `# noqa` 注释粉饰，未产生任何运行时诊断 | 改为带异常类型的真实诊断输出；守卫 noqa 豁免收紧为「理由 ≥8 字且字符多样」 |
| H7 | `replace_with_retry` 对永久 `PermissionError`（目标是目录）白重试 10 次；`diagnose_apk_dir(only=str)` 字符拆分；`persist_error` 被 `[:600]` 截断挤出 | 目标为目录立即抛；字符串 only 归一化；失败诊断单独打印一行；均补/更新反例 |
| H8 | `verification.json.failed` 混入诊断串；`batch_thirdparty` 丢失样本获取指引 | 诊断改独立 `count_mismatch` 字段；empty/missing 文案补 `apk/README.md` 指引 |

**修复轮后仍未闭环（如实保留）：** 15 个授权声明缺口已登记基线待补（其中 2 个是声明写在第 36 行、超出文件头阈值）；38 个超限文件待拆分；`contextlib.suppress` 等不产生 `ExceptHandler` 的写法 AST 守卫仍覆盖不到；`ruff format` 与全仓 diff lint 未开；A1 连跑 3 次证据仍缺两入口；14 个新文件待逐一点名入库；基线若被恶意 PR 改 `RULE_VERSION` 仍可重建，需 CODEOWNERS / 分支保护这类仓库治理手段（超出代码范围）。
