# 前端 app.html ↔ workbench 后端 契约审计报告

- 日期：2026-10-15
- 范围：`frontend/app.html` + `frontend/app.js` ↔ `vehicle/workbench/server.py` + `core/static/*`
- 方法：静态逐行比对 + **真实起服务端到端实测**（用脚本按 app.js 的真实请求顺序模拟全部调用）
- **总结论：契约层面全部对得上（10/10 端点、全部消费字段逐一命中）；发现 1 个会向用户显示错误数据的问题（P1），2 个中等问题（P2/P3），若干轻微问题。**

---

## 一、实测环境与证据

| 项 | 值 |
| --- | --- |
| 服务 | `python server.py --port 8770`（本次实测临时启动，测完已停） |
| 工具链 | jadx 1.5.3（含自带 JRE）/ aapt2 36.1.0 / dexdump 36.1.0 —— 全部就绪 |
| 样本 | `.cache` 中 3 份历史分析产物（fossify.contacts 5379 类 / targetapp 930 类 / privacydemo 731 类） |
| 模拟来源 | `Origin: http://localhost:8080`（README 建议的前端起法），与跨域白名单一致 |
| 原始记录 | `%TEMP%\vscan_verify\verify_report.txt` |

---

## 二、逐端点契约对照（实测结果）

| # | 前端调用（app.js） | 后端实现（server.py） | 实测响应 | 判定 |
| --- | --- | --- | --- | --- |
| 1 | `OPTIONS /api/apk`（原始字节 POST 前浏览器必发预检） | `do_OPTIONS` → 204 | 204 + `ACAO` 回显来源 + `ACAM=GET, POST, OPTIONS` + `ACAH=Content-Type` | ✅ |
| 2 | `POST /api/apk?name=..`，body=File | `_upload`：分块落盘 + 边写边算 sha256 | `{digest, job, cached, note}`；digest == 缓存目录名；cached=true 正确复用 | ✅ |
| 3 | `GET /api/jobs/<id>` 轮询（700ms） | `job.as_dict()` | `state/stage/percent/done/total/error/cancelled` 全在；终态 `done` | ✅ |
| 4 | `GET /api/apk/<digest>/tree` | `jadx.index_json` → 缓存文件 | `{files:[{path,size}]}`，5379 条，首条 `A/a.java` | ✅ |
| 5 | `GET .../source?path=..` | `jadx.read_source`（512KiB 截断） | `{path,size,truncated,text}`；越界 `../summary.json` → 400「路径越界」 | ✅ |
| 6 | `GET .../static` | `static.json` | findings 各字段与前端表列逐一命中（见 §三） | ✅ |
| 7 | `GET .../summary` | `summary.json` | 字段结构全对，**但存在 P1 覆盖问题** | ⚠️ |
| 8 | `GET .../crosscheck` | 四象限对照 | 无 session 时 `{comparable:false, reason:"没有提供采集会话目录…"}`，前端如实显示「无法静动对照」 | ✅ |
| 9 | `POST /api/jobs/<id>/cancel` | `REGISTRY.cancel` | 已完成任务返回 `{"cancelled":false}`；前端不消费响应（P7） | ✅ |
| 10 | `GET /api/tools` | `toolchain.describe()` | 正常返回四工具路径——**前端从未调用**（P3） | ⚠️ |

静态核对（非实测，逐行比对）：

- **导航闭合**：5 个 `data-page`（source/static/dynamic/ai-report/pdf-report）↔ `page-<x>` DOM id ↔ `switchPage` 分支，全部一一对应；`initNavigation`/`initUpload`/`initSourceFilter`/`initPdf` 各自绑定的 DOM id 在 app.html 中全部存在。
- **findings 字段**：前端静态页 7 列（规则/标题/类型/强度/等级/信号/依据）对应 `rule_id/title/rule_type/static_strength/conclusion_level+declared_conclusion_level/signals/note` —— 与 `static_rules._finding()` 输出完全一致；用 targetapp 的 22 条真实 findings 验证（signals 四键、等级封顶 candidate 的「（声明 xx）」逻辑均正常）。
- **summary 消费字段**：`apk.{package,version_name,version_code,min_sdk,target_sdk,permissions}`、`static_context.{cpm_read_api_referenced,known_property_ids,known_property_ids_present_in_dex,discrimination_note}`、`apk_gaps[].{kind,detail}`、`dex_gaps[].dex` —— 全部真实存在（注意两种缺口结构不同，前端分别取字段，均正确）。
- **PDF 页**：下拉 4 个选项与 `frontend/pdfs/` 下 4 个文件文件名逐一相同；`file://` 协议下有降级提示。PDF 不经后端 API，属静态快照（README 已声明）。
- **安全约定实测**：`read_source` 越界防护 400；非法 digest（非 64hex）400；CORS 只回显本机来源；highlight.js 只用 `textContent`+`createTextNode`（README「零 innerHTML」属实）；AI 报告页 `addSectionRaw` 的所有字符串插值都过了 `esc()`。
- **CSS 引用**：`.notice/.notice.ok/.notice.bad`、`.kpi-*` 四类、`.static-summary`、`.perm-chip` 等被 JS 生成的类名全部有样式定义。
- **首页链路**：`index.html` → `enterDashboard()` → `landing.js` → `app.html` ✅。

---

## 三、发现的问题（按严重度排序）

### P1【重要 · 会显示错误数据】缓存命中重跑把 `summary.decompile` 覆盖为 null → AI 报告显示「反编译 0 个类」

**实测复现（有 diff 铁证）**

1. 上传 `.cache` 已有的 `org.fossify.contacts.apk` → 服务返回 `cached: true`（走「复用缓存重跑规则」路径）；
2. 任务完成后 `GET /summary` → `decompile: null`；
3. 同一时刻同一目录里：tree 端点返回 **5379 个文件**、`decompile.json` 记录 `classes_written=5379, errors=20`；
4. 覆盖**前**（用户首次分析的产物，已备份对比）：`decompile = {"returncode":1,"errors":20,"classes_written":5379,"files":5379,"gap":{...partial_decompile...}}`；覆盖**后**：`null`。

**前端表现（app.js:500-512、562）**

- `var dec = summary.decompile || {}` → `classes_written || 0` → 报告显示**「反编译 0 个类」**；
- 「已知缺口」里 `partial_decompile`（「jadx 报了 20 个类反编译失败」）提示**消失**；
- 与源码查看页（5379 个文件正常浏览）**同一界面自相矛盾**。

**根因（在后端，但前端零防御）**

`server.py:266-268` 缓存命中时 `_work(..., decompile=not cached)` → `analysis.py` 的 `analyze(decompile_source=False)` 显式写入 `summary["decompile"] = None` 后 `_save(summary.json)` **无条件整体覆盖**旧文件（analysis.py:93-95）。`decompile.json` 本身没被覆盖，但前端不读它。

**触发条件**：任何重复上传同一 APK（缓存设计的目的本来就是让用户快速重看，属日常必然路径）。

**修复建议（择一或都做）**

- 后端（推荐）：`analyze(decompile_source=False)` 时不覆盖已有 summary 的 `decompile` 段（保留旧值），或从 `decompile.json` 回填；
- 前端兜底：`summary.decompile == null` 时不要落成 0，显示「（复用缓存产物，源码树 N 个文件）」之类。

### P2【中】`identity.same_apk === null` 被渲染成绿色 OK

`crosscheck.identity()` 是三态：`true`（同一 APK）/ `false`（确认不同）/ `null`（**无法证明**——没有会话清单或缺 APK 哈希）。前端 `renderDynamicView`（app.js:447-451）只处理两态：

```js
var idNote = el('div', 'notice' + (cc.identity.same_apk === false ? ' bad' : ' ok'), ...)
```

`null` 落入 `' ok'` 分支 → 显示**绿色左边框**。而 CSS 里 `.notice.ok` 是 success 色（app.css:521）。可达路径：服务带 `--findings` 但不带 `--session`（或 session 目录无 session-manifest.json）。此时「无法证明静态与动态针对同一个 APK」被渲染为正面状态，与 crosscheck 模块「没有清单不等于一致」的设计意图相悖。

建议：三态三样式（null → 中性色 + 明确文案「无法证明同一 APK」）。

### P3【中】后端 `/api/tools` 没有前端入口

端点真实存在（实测返回四工具路径与错误信息），README 的 API 表也列了它，但 app.js 完全没有调用，UI 没有「工具链就绪情况」展示。用户环境缺 jadx/aapt2 时，上传后只能看到任务失败文本，而 `/api/tools` 正是为「提前告知哪件工具缺了」设计的。

建议：工作台加载时拉一次 `/api/tools`，缺失工具在顶栏或上传区给出警示条。

### P4【低】多 APK 无切换 UI

`state.apks` 数组完整保存了历次分析结果（按 digest 去重），但没有 API 消费这个列表的 UI——「当前 APK」永远只是最后上传的一个；回看历史 APK 只能重新拖入文件（会触发 P1）。属功能不完整。

### P5【低】缓存命中时进度文案退化为裸 `running`

实测中间态：`{state:"running", stage:"", percent:null, done:0, total:0}`（缓存命中重跑规则没有 stage 文案、无类进度）。前端 `pollJob`（app.js:160-164）fallback 为 `stage = job.stage || job.state` → 显示「running」+ 15%。首跑时（反编译阶段）则是正常的「反编译中（N / M 个类）」。建议对空 stage 给中文兜底文案。

### P6【极低】嵌套树文件点击的 active 高亮清理不彻底

`renderTreeLevel`（app.js:318-321）点击文件时只清理当前同级容器（`host.querySelectorAll`）内的 `.active`，深层其它文件夹里已高亮的文件不会被清掉——可能出现两处同时高亮。

### P7【极低】取消按钮的两个边界

- 对**已完成**任务点「取消」：后端返回 `{"cancelled":false}`（实测），前端不消费响应、无任何反馈；
- `cancel` 后轮询不停（靠 `state==='cancelled'` 自然收敛，行为正确，无实际影响）。

---

## 四、设计边界观察（非缺陷，但值得知道）

1. **平台与规则库**：手机 APK（`apk/mobile/`）也能拖入，但服务端默认加载**车载**规则库（`vehicle/rules/rules_library/rules.db`，22 条 `VSC-` 规则求值）。实测手机 App 命中 0 条——不会报错，但结果语义上是「车载规则对手机 App 的结论」。UI 无「当前规则库/平台」提示，也没有规则库切换（移动端静态审计应走 mobile 产品线入口）。
2. **双前端并存**：后端 `/` 与 `/static/` 路由仍在服务一套旧界面 `vehicle/workbench/web/`（title「V-Scanner · APK 静态分析工作台」），README 未提及；日常使用 `frontend/app.html`。两套并存有维护分叉风险。
3. 前端对 `loadApkData` 的 `job.result` 参数未使用（数据统一走各 GET 端点重取）——一致性好，仅一次多余传参。

---

## 五、总体判定

| 维度 | 结论 |
| --- | --- |
| 端点存在性 | 前端调用的 10 个端点全部真实存在，路径/方法/参数格式全部正确 |
| 响应字段 | 前端消费的每个字段都在后端真实输出中（findings 7 列、summary 8 组、crosscheck 8 键、tree/source/jobs 全字段） |
| 跨域/预检 | 实测通过（含预检、错误响应带 CORS） |
| 安全约定 | 越界防护、零 innerHTML、如实报缺口在前端侧均落实 |
| 逻辑正确性 | **P1 一项会导致报告显示错误数据（缓存命中的日常路径必触发）；P2/P3 需修；其余为轻微打磨项** |

建议修复顺序：**P1 → P2 → P3**（P1 在后端 `analysis.py` 加一行合并逻辑即可根除，前端加兜底更稳）。

---

## 六、修复记录（2026-10-15，已实施并回归验证）

| 问题 | 修复 | 位置 |
| --- | --- | --- |
| P1 | 后端 `analyze()` 缓存命中时从磁盘 `decompile.json` 回填（新增 `existing_decompile()`），不再清成 null；前端 AI 报告加兜底（decompile 缺失时用源码树长度标注「复用缓存产物」） | `core/static/analysis.py`、`frontend/app.js` |
| P2 | identity 三态：`null` → 中性黄色 `.notice`（不再误标绿色 OK） | `frontend/app.js` |
| P3 | 前端加载时拉 `/api/tools`，缺工具显示顶部警示条 | `frontend/app.js` + `app.html` + `app.css` |
| P5 | 缓存命中进度文案兜底「分析中」 | `frontend/app.js` |
| P6 | 文件树 active 高亮改为全局清理 | `frontend/app.js` |
| P4 | 历史 APK 切换下拉：回看历史不必重拖（也避免触发 P1 的重跑覆盖） | `frontend/app.js` + `app.html` + `app.css` |
| P7 | 取消按钮：点击后「正在取消…」反馈 + 消费 `{cancelled}` 响应 | `frontend/app.js` |

**验证**

- 新增 `core/static/test_analysis.py`（3 条离线用例：回填/缺失/损坏），并纳入 `tools/run_regressions.py` 的 workbench 组。
- workbench 组离线回归 **43 条全绿**（test_static_rules + test_crosscheck + test_jobs + test_analysis）。
- `node --check frontend/app.js` 通过。
- **端到端复验 P1**：上传 `.cache` 已有的 fossify.contacts（cached=true）→ `GET /summary` 的 `decompile` 返回 `{classes_written:5379, errors:20, gap:{...}}`（修复前为 null）✅

> P1–P7 已全部处理完毕；P4 / P7 为第二轮（同日）补齐，均通过 `node --check` 与逐项代码复查。
