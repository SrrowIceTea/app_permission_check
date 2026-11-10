# 项目真实状态（2026-11-10 只读核对）

> 本文只陈述核对得到的事实与出处。核对方式：`git status/diff/log`、直接读代码、`sqlite3` 查规则库、
> 读 `output/` 现有产物。**未改代码、未改规则库、未跑设备、未提交、未暂存**；
> `vehicle/frontend/`、`vehicle/hooks/`、`vehicle/targets/` 下的文件只读不改。
> 结论出处以「文件:行号」或「output 目录 + 字段」给出，不引二手转述。

## 0. 工作区快照

- HEAD = `a115850`（`Merge remote-tracking branch 'origin/main'`），前 5 条提交见 `git log --oneline -5`。
- `git diff --stat`：**114 个已跟踪文件有内容改动，+1773 / −707**。四个 `.db` 为二进制改动：
  `vehicle/rules/rules_library/rules.db`、`.../android/app/src/main/assets/rules.db`（均 983040→995328）、
  `baseline_android13|14/rules.db`（303104→307200）、`baseline_android16/rules.db`（258048→262144）。
- `git status --porcelain -uall` = **161 行** = 115 `M` + 46 `??`。115 个 `M` 里 **114 个有内容差异**
  （与 `diff --stat` 的 114 一致），另 1 个是 `vehicle/rules/baseline_android14/POLICY.md` 仅时间戳/行尾变动，
  `git diff --raw` 对该文件无输出，**提交时可不加**。
- `output/` 已被 [.gitignore](file:///d:/AAA/mobile-app-permission-check/.gitignore#L24) 第 24 行忽略，
  因此**截图/跑批产物不会出现在未跟踪列表里**，也不需要额外清理才敢提交。

已改文件按目录（115 个）：`vehicle/rules` 30、`mobile/*` 28（`tools` 10、`*.md` 6、`pipeline` 4、`hooks` 3、
`workbench` 2、`lab`/`rules`/`traffic` 各 1）、`docs/` 7、`core/collector` 7、`vehicle/frontend` 6、根目录 5、
`vehicle/webapp` 5、`core/frida_host` 4、`vehicle/hooks` 4、`vehicle/targets` 4、`tools/` 2、
`vehicle/{dashboard,lab,traffic}` 各 2，其余 `.agents/`、`apk/`、`skills/`、
`vehicle/{analyze,workbench,COMPATIBILITY.md,P0_P1_DELIVERY.md}` 各 1。

未跟踪文件分类（46 个 = `core` 11、`mobile/tools` 10、`docs` 10〔边界文档 1 + 本文 1 + 设计参考 8〕、
`vehicle/webapp` 7、`vehicle/frontend` 3、`mobile/hooks`/`vehicle/hooks` 各 1（`tls_relax.js`）、
`vehicle/rules/python` 1、`tools` 1、`vehicle/targets` 1）：

| 类别 | 文件 | 建议 |
| --- | --- | --- |
| 采集内核源码 | `core/collector/{origin,parse_registry,parse_result,parse_text,response_observation,websocket_frames}.py`、4 个对应 `test_*.py`、`core/env_guard.py` | 入库 |
| 可达性源码 | `mobile/tools/{dex_callgraph,reachability,apk_entrypoints,wrapper_map,graph_reach,reach_report,static_supplement}.py` + 3 个 `test_*` | 入库 |
| 车载工作台源码 | `vehicle/webapp/{presentation,finding_reviews,rule_titles}.py`、`rule_titles.zh.json`、`test_presentation.py`、`test_finding_reviews.py` | 入库 |
| 契约文档 | `vehicle/webapp/FIELD_CONTRACT.md`（239 行） | 入库 |
| 规则/工具/夹具 | `vehicle/rules/python/general_permissions.py`、`tools/python313.ps1`、`vehicle/targets/target-app/.../SslLoopbackProbe.kt` | 入库 |
| 前端源码 | `vehicle/frontend/{components.js,components.css,upload.js}` | 入库（本次未改动） |
| 边界文档 | `docs/MOBILE_REACHABILITY_BOUNDARIES_20261110.md`（135 行） | 入库 |
| 设计参考产物 | `docs/vehicle-frontend-design-20261108/` 8 个 html/css/js | 可入库，非必需 |
| **残留生成物（已清理）** | `mobile/hooks/.entry.hook_all.js` | 同日已删除，不在上面 46 个之内；不入库（见 §5） |

## 1. 声称 vs 实测

| 声称 | 实测 | 判定 |
| --- | --- | --- |
| 规则库 `13/14/15/16` 四版本 | `rules_library/rules.db` 中 `permissions` 按版本 10/10/150/10（180 行）、`risk_rules` 29/29/29/29（116 行，启用 19/29/29/19=96）、`vhal_properties` 8×4 | ✅ |
| 两份 `rules.db` 同哈希 | 均 `DDF57F6F4F05E8B6CBC773BB4A5AFD7C0657E402748C9724B2F1BADE23026F29` | ✅ |
| `summary.json` 13/14/16 各 10 条权限、15 为 150 | `rules.db.summary.json` 的 `counts.permissions` = 10/10/150/10 | ✅ |
| 前端 A/B/C 三档，新增 `components.js`/`components.css`/`upload.js`，零构建 | 三个文件存在；`components.js:1`、`upload.js:1` 注释为「B 档」，`app.js:17` 为「C 档」；**代码里没有「A 档」字样**，A 档证据只有 `typography.css`/`vehicle.css` 改动 + `output/vehicle-frontend-a-tier-20261109/` 截图目录 | ⚠️ 部分（见 §5） |
| 后端 `/api/pipeline` 有 `findings_by_conclusion_level`（四档恒有键）、`stage_timings`、`apk_sha256` | `presentation.py:10` 定义 `('correlated','observed','candidate')`+`unjudged`；`:79-106` `count_bands` 保证键恒在（无数据为 `null`）；`:115` `stage_timings`；`:158-188` `apk_sha256`；`:191` `decorate` 由 `jobs.py:132-133` 的 `snapshot()` 调用，`rows()`（`:135`）复用同一路径 | ✅ |
| `/findings` 返回 `finding_uid`、`review_status`、`rule_title` | `artifacts.py:55-58` `findings()` 先补 `finding_uid` 再走 `with_titles`（`:27-44`）+ `review_rows`；`review_status` 由 `finding_reviews.py:129-139` 写入（无记录为 `null` 并给 `review_status_reason`） | ✅ |
| 存在 `POST /api/pipeline/<id>/finding-reviews` | `server.py:72-75` 路由；`:142` `save_review` 强制同源 | ✅ |
| Hook 第一层/第二层有真实设备证据，第三层只有方案 | `output/memhook-evidence-20261109/`：JCE 正控 3 条记录（1 ARMED / 1 CIPHER_PLAINTEXT，AES/GCM/NoPadding 2080B）；native SSL 正控 7 条（ARMED 2 hooks+2 dlopen watchers、SSL_WRITE 2 / SSL_READ 2）；`layer2-negative.log:12-14` `hook_jsonl_exists=False`、`result=events 0`，同场景 logcat 有按钮 4/5 执行记录；第三层停在 `output/memhook-pinning-samples-20261110/` 静态结论 + `DEVICE-VALIDATION-PLAN.md` | ✅ |
| 可达性已落地，文档写 9 样本里 7 个失效 | 4 个文件齐（另加 `graph_reach.py`/`reach_report.py`）；`run_mobile_checks.py:53-58` 挂了两组测试；`docs/MOBILE_REACHABILITY_BOUNDARIES_20261110.md:86`「9 个样本中 7 个触发『本方法对该样本失效』声明」 | ✅ |
| `output/thirdparty-round2-20261109*`、`thirdparty-round3-20261109-reach` 存在 | 四个目录均在（`-reach` 下各 9 个 per-sample `.log`）；另有今天新增的 `thirdparty-dynamic-20261110/` | ✅ |
| `observed_findings` 至今为 0 | `round2/findings-summary.json` `totals` = `{samples:9, scan_ok:9, static_candidates:156, observed_findings:0, candidate_findings:0}`；`breezy/out/summary.json` `findings_by_conclusion_level={"candidate":12}`、`observed` 缺键 | ✅（但外发原始事件已存在，见 §3） |

## 2. 已闭环

- **规则库四版本**：13/14/15/16 同库（权限 180 条、风险规则 116 条），13/16 的 `data_egress` 10 条登记但未启用
  （启用 0），14/15 各启用 10 条 —— 实测 `select android_version, count(*), sum(enabled) from risk_rules`。
- **规则库与 App 资产同源**：两份 `rules.db` SHA-256 相同（见 §1）。
- **前端 B/C 档落地**：结论汇总条/证据链卡片/三态组件在 `components.js`(295 行)，上传前校验在 `upload.js`(90 行)，
  任务头耗时为 `app.js:17` 起的 C 档；`app.html` 内无任何 `http(s)://` 外链、`vehicle/frontend/` 无 `package.json`，仍是零构建。
- **后端字段契约与写入口**：`FIELD_CONTRACT.md` 239 行覆盖 `findings_by_conclusion_level`（四档+`unjudged`）、
  `stage_timings`、`apk_sha256`、`rule_title`（五级来源）、`finding_uid`、复核写接口防护；配套
  `test_presentation.py`、`test_finding_reviews.py` 已并入 `run_regressions.py:60-63` 的 `vehicle-webapp` 组。
- **内存 Hook 第一/二层**：正控（JCE 1 条明文、native SSL 2 写 2 读）与负控（0 事件、无 jsonl 落盘）均在同一份
  `output/memhook-evidence-20261109/` 内，含 Frida 17.18.0 版本号与清理阶段 6 项 `FRIDA_CLEANUP` passed。
- **可达性过滤**：4 个模块 + 3 个测试入库，`run_mobile_checks.py:53-58` 已有 `static_supplement` 与 `reachability` 两组；
  失效边界写进 `docs/MOBILE_REACHABILITY_BOUNDARIES_20261110.md`（9 样本、7 个触发失效声明）。
- **跑批手册补 AAOS 章节**：`docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md:388` §10「AAOS 车载模拟器：单样本动态采集
  （2026-11-10 实测补充）」，10.1–10.9 共 9 小节，其中 5 个已知坑（多显示器 tap、UXR 吞触摸、周期性
  `EGL_NOT_INITIALIZED`、verity 导致系统 CA 装不进、TLS 绕过反噬致 OkHttp NPE）各自带现象与复现命令。
- **回归现状**：`output/regression-20261110-092827-u_wp8kmz/verification.json` 18 组全 `exit_code:0`（今天 09:28）；
  移动侧 `output/mobile-regression-20261109-235954-j4kc8imu` 31/31 passed、分支
  `output/mobile-branch-20261109-235701-kxyefwdp` 24/24 passed（均在 11-09 23:5x，早于今天的 core 改动）。

## 3. 进行中

- **第三方样本动态采集**：今天新开 `output/thirdparty-dynamic-20261110/`。breezy 有读数（`inputs.reads=65`）但
  `flows=0`、`egress_connections=0`，只出 12 条 `candidate`（`over_permission`）；organicmaps 走手动会话，
  抓到 1 条 `PRIVACY_READ`（`SensorManager.registerListener` / `sensor_data`）与大量 `SSL_WRITE_PLAINTEXT`(272) /
  `SSL_READ_PLAINTEXT`(15633) 到 `*.omaps.app` 的明文，**但没有 `out/` 目录**，没进 `findings`，所以不算 `observed`。
  卡点：流量侧没有把连接绑到读数上（`flows=0`），没跑出关联结论。
- **Hook 第三层（pinning）**：`output/memhook-pinning-samples-20261110/` 已静态确认 Proton Mail 3.0.17（首选，
  带 `<pin-set>`、四 ABI）与 Wire 4.36.0（备选，代码硬编码 pin），Proton Pass 1.41.5 被判不达标；设备验证方案
  写在 `DEVICE-VALIDATION-PLAN.md`，尚未执行。卡点：宿主对 `mail-api.proton.me` / `*.wire.com` 的解析与连接异常。

## 4. 已知缺口（按“会不会导致结论出错”排序）

1. **`observed_findings` 恒为 0**：所有批次（round2 9 样本、breezy 12 条）都只到 `candidate`。
   → **当前结论不能说明任何一条“某 App 把某数据发出去了”**；`data_egress` 类规则在真实第三方样本上一次也没被证实过。
2. **可达性在 9 个样本里 7 个失效**：`unknown` 桶 169 个命中点（`reason_code` 逐条计），四桶合计 110 条候选。
   → **`unknown` 不能读成“不可达”，也不能读成“没有被调用”**；这 7 个样本的静态候选可信度等同于“未判定”。
3. **Hook 第三层无设备结论**：pinning 样本只有静态证据（`verdict: confirmed_static`），
   → **不能声称“证书固定场景下 Hook 仍能拿到明文”**；第一/二层只证明夹具 + 无 pinning 路径可用。
4. **缺真实第三方外发正样本**：没有一条 observed，`risk_score` 的“外发”维度在第三方样本上未被验证。
   → 报告里任何“外发风险评分”都只能算静态候选的排序，不能当实测。
5. **`protectionLevel` 未标定**：`permissions` 表 `protection_level_raw` 180/180 有值，但
   `protection_level_value` **180/180 为 NULL**，`device_calibration_json` 未落到权限行。
   → **不能按库内字段解释“该权限是 dangerous 还是 signature”**；AGENTS.md 里“0/40”的说法与两列实测都对不上（见 §5）。
   （同日已订正文档口径：AGENTS.md 改为按两列分别描述；`protection_level_value` 的标定本身**仍未做**。）
6. **盲评/指标需真人**：`vehicle/bench/` 侧签核主体是 AI（`ai_adjudicator`）。
   → **precision/recall 现阶段不可对外**，只能说明标注与证据可追溯。
7. **规则库基线文档口径滞后**：`DELIVERY_INDEX.md:23` 与 `AGENTS.md` 仍写“双版本 44 条风险规则”，
   实测是四版本 116 行 / 启用 96 条。不影响判定，但会误导读库的人。
   （同日已订正：`DELIVERY_INDEX.md:23` 与 `AGENTS.md` 均已改为四版本 116 条 / 启用 96（19/29/29/19）。）

## 5. 口径易错点

- **“未观测到” ≠ 安全**：`observed=0` 只说明本轮没抓到关联证据（甚至可能只是 `flows=0`），不是“没外发”。
- **`unknown` ≠ 不可达**：可达性失效的 7 个样本里，`unknown` 是“方法没解析出来”，不是“没有这条路”。
- **`candidate` ≠ 违规**：`candidate` 是静态候选，必须有运行时证据才能升级；工具不输出 `policy_violation`。
- **规则标题中文映射 ≠ 结论**：`rule_title`/`rule_title_locale=zh` 只是展示层映射，
  `rule_title_source` 会写明来源（库内原值 / 展示映射 / 缺失原因），缺失时是 `null` 而不是空串。
- **三种计数不能混**：静态候选 156（`findings-summary.totals`）、可达四桶候选 110（边界文档:77）、
  `unknown` 命中点 169（:40）——单位不同（条目 vs 命中点），不可相加、不可互相替代。
- **四档计数恒有键但可能为 `null`**：`null` 表示“这一轮没有该字段/摘要缺失”，不是 0；
  `unjudged` 由 `findings_total` 减各档推算，摘要不自洽时会被置 `null` 并写 `field_gaps`。
- **`stage_timings` 是主机墙钟**（`presentation.py:16`），跨阶段间隙不计入任何阶段，不能当 CPU 耗时。
- **“A/B/C 三档”只在输出目录与提交说明里成体系**：代码里只有 `B 档`（`components.js:1`、`upload.js:1`）与
  `C 档`（`app.js:17`）注释，**A 档没有任何代码内标记**，别按字面去代码里找“A 档”。
  （2026-11-10 复核仍成立：A 档改动已存在，但代码内仍无 A 档标记。）
- **`mobile/hooks/.entry.hook_all.js` 是生成残留**：`core/frida_host/build.py:126` 生成的是
  `.entry.<script>.<uuid>.js` 且用后即删，`core/frida_host/test_build.py:48` 断言不得残留；这个文件不提 uuid，属旧命名遗留。
  （同日已删除：该残留已清理，且它本来就不被 git 跟踪。）

## 6. 提交前必须补的项

1. 删掉 `mobile/hooks/.entry.hook_all.js`（生成残留，入库会把临时入口当源码）。
   （同日已完成：文件已删除，`git status` 无残留。）
2. 重跑移动侧两套：核心 `core/collector/` 与 `mobile/tools/` 今天有改动，但
   `mobile-regression`/`mobile-branch` 最后一次通过是 11-09 23:5x，**早于今天的改动**；
   至少跑 `mobile/tools/run_mobile_checks.py` 与 `tools/check_mobile_branch.py` 各一次留档。
   （同日已复跑：31 项 / 24 组，退出码均 1，各只有 1 项未过且同为 `hooks_parity`
   真回归——不是缺库假红；待 parity 修复后**再复跑一次**才算闭环。）
3. 决定 `docs/vehicle-frontend-design-20261108/`（8 个设计对照文件）是入库还是不入库——现在挂着未跟踪，
   两种选择都需要显式记录，否则提交后会变成“不明来源的 html”。
   （**未闭环**：2026-11-10 复核仍为未跟踪 `?? docs/vehicle-frontend-design-20261108/`，待定。）
4. 订正 `DELIVERY_INDEX.md:23` 的“双版本 44 条”与 `AGENTS.md:176` 的“`protection_level_raw` 仍 0/40”，
   两处都已与规则库实测不符（前者四版本 96 条启用，后者两列实测为 180/180 与 0/180）。
   （同日已完成：`DELIVERY_INDEX.md:23` 改为四版本口径，`AGENTS.md:176` 改为两列分别描述。）
5. 确认 `vehicle/webapp/FIELD_CONTRACT.md` 与 `presentation.py` 中的四档定义在 `observed` 恒为 0 时，
   前端展示依然不出现“通过/失败/合规”字样（本轮只读核对未在浏览器验证）。
   （**未闭环**：仍只做了只读核对，`observed=0` 下的浏览器渲染未验证。）
