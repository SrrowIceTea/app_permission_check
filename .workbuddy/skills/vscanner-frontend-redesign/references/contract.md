# 前端 ↔ 后端 契约（改样式前必须逐条确认）

**唯一事实来源是代码，不是文档。**
`frontend/README.md` 与 `frontend/CONTRACT_AUDIT.md` 记录的是 `vehicle/workbench`（8770）时期的契约，
而当前 `app.js` 已改为对接 `mobile/pipeline`（8771）。两份文档都**已漂移**，以本文件 + 代码为准。

---

## 1. 允许改动的范围

| 可以改 | 不可以改 |
| --- | --- |
| `frontend/index.html` / `landing.css` / `landing.js` | `vehicle/**`、`mobile/**`、`core/**`、`tools/**` |
| `frontend/app.html` / `app.css`（结构与样式） | `frontend/pdfs/**`（四份快照，删了 PDF 页就空） |
| `frontend/assets/**`（新增背景图/字体） | `frontend/highlight.js`（源码高亮依赖） |
| `app.js` 末尾**追加一段自包含补丁**（≤ 70 行，必须带存在性判断） | 把 `app.js` 重写成模块/框架/TS；改动任何现成函数体 |

**零构建**：不允许出现 `package.json`、`vite.config.*`、`node_modules`、`import ... from`，
不允许 Tailwind CDN / React / Vue / Svelte。页面必须能 `python -m http.server` 直接打开。

---

## 2. DOM 契约（缺一个就白屏或报错）

`app.js` 用 `getElementById` 硬取以下节点，**没有 null 判断**，必须保留 id：

```
ai-report            apk-switch           code-view            current-apk-name
dynamic-results      file-tree            pdf-open-external    pdf-select
pdf-viewer-container pipeline-apk-input   pipeline-dropzone    pipeline-job
pipeline-progress    pipeline-result      pipeline-timeline    source-filter
static-results
```

页面容器（`switchPage()` 按 `page-<x>` 查找，并切换 `.page.active`）：

```
#page-pipeline  #page-source  #page-static  #page-dynamic  #page-ai-report  #page-pdf-report
```

导航（`initNavigation()` 读 `dataset.page`）：

```
.nav-item[data-page="pipeline|source|static|dynamic|ai-report|pdf-report"]
```

**结构约束**

- `#pipeline-apk-input` 必须是 `<input type="file" accept=".apk" hidden>`；`#pipeline-dropzone` 点击时调用它。
- `#pipeline-progress` 初始必须带 `style="display:none"`；`app.js` 用**行内样式**控制显隐，
  CSS 里不要再给它写 `display`（否则行内样式清空后会落到你的规则上，可能一直隐藏）。
  要给形状只用 `position / inset / padding / border / background`。
- `#pipeline-result` 初始 `style="display:none"`，同上。
- v3 新增的外壳（**只增不减**，不参与 `getElementById`，可以自由取名）：
  `#audit-stage`（三态容器，带 `data-state`）、`.stage-brand`、`.stage-slot`、
  `[data-rail]`（16 段进度轨）、`.shelf-book`（书脊按钮）。
  加壳时**不得移动**上面 17 个 id 所在的节点层级关系（`#pipeline-dropzone` 与
  `#pipeline-progress` 必须仍在同一父节点内，`#pipeline-result` 跟在其后）。
- `#pdf-open-external` 内部必须有一个 `<a>`（`loadPdf()` 会 `querySelector('a')` 后赋 href）。
- `highlight.js` 必须在 `app.js` **之前**加载（`openSourceFile()` 依赖 `window.VSCAN_HL.render`）。
- `#source-filter` 必须是 `<input type="search">`（监听 `input` 事件）。

---

## 3. 由 JS 动态生成、CSS 必须覆盖的类名

改样式时**不要删这些选择器**，否则数据出来了但看不见：

| 分组 | 类名 |
| --- | --- |
| 结果卡（**只有结果卡**） | `.pipeline-card` `.pl-kv` `.pl-links` `.pl-btn` `.pl-btn.primary` `.pl-warn` `.pl-status` |
| 阶段行（`<li>` 上的类） | `.pl-pending` `.pl-running` `.pl-done` `.pl-failed` `.pl-skipped`，内部 `.pl-dot` `.pl-label` `.pl-msg` |
| 结果徽标 | `.result-badge` + `.s-good` `.s-warning` `.s-muted` `.s-critical` `.info` `.warning` `.critical` |
| 空态 / 提示 | `.empty-state` `.empty-state.large` `.notice` `.notice.bad` `.notice.ok` |
| 源码 | `.file-tree-item` `.file-tree-item.active` `.ft-icon` `.ft-name` `.ft-children` `.code-meta` `.code-content` |
| 表格 | `.results-table` `.mono` `.hint` `.static-summary` |
| 报告 | `.report-section` `.report-section-title` `.report-content` `.perm-list` `.perm-chip` |
| PDF | `.pdf-frame` `.has-frame` |

> 阶段状态类直接由 `el('li', 'pl-' + st.status)` 拼出，取值只有
> `pending / running / done / failed / skipped` 五种——五种都必须有可见差异。
> **注意**：时间线条目是 `li.pl-running` 这种形式，**不是** `.pipeline-card.pl-running`；
> `.pipeline-card` 只出现在 `#pipeline-result` 的结果卡里。写错选择器 = 样式完全不生效。
>
> 另一个坑：`renderPipelineTimeline()` 每次事件都会 `host.textContent=''` 后重建整个列表，
> 所以**只有入场动画能生效，过渡动画全部无效**；也只能给 `.pl-running` 加入场动画，
> 否则所有历史行会跟着一起闪。

---

## 4. API 契约

基址写死在 `app.js` 第 19 行：

```js
var PIPELINE_API_BASE = 'http://127.0.0.1:8771';
```

| 方法 | 路径 | 用途 | 前端消费字段 |
| --- | --- | --- | --- |
| GET | `/api/stages` | 阶段列表 | `[{id, label}]`（顺序即时间线顺序） |
| POST | `/api/pipeline?name=<urlencoded>` | 上传 APK，**raw body 不是 multipart** | `{id, name}` / `{error}` |
| GET | `/api/pipeline/<id>/events` | SSE 阶段流 | `{stage,status,message}`；`event: end` → `{state,result}` |
| GET | `/api/pipeline/<id>/static` | 静态结果 | `{findings[], rules_evaluated, caveat}` |
| GET | `/api/pipeline/<id>/tree` | 源码树 | `[{path,size}]` 或 `{files:[]}` |
| GET | `/api/pipeline/<id>/source?path=` | 源码文本 | `{path,size,truncated,text}` / `{error}` |
| GET | `/api/pipeline/<id>/report` | PDF 报告 | 二进制（`<a target=_blank>` 直链） |
| GET | `/api/pipeline/<id>/bundle` | 证据包 | JSON（直链） |

**SSE 事件 schema**（三方契约，改不得）：

```json
{"ts": 1760000000.0, "stage": "static", "status": "running|done|failed|skipped", "message": "..."}
```

`end` 事件：

```json
{"state": "done|static_only|failed",
 "result": {
   "static": {"package":"", "app_label":"", "findings_total":0, "supplement_findings":0,
              "rules_evaluated":0, "decompile":{"classes_written":0,"errors":0}},
   "device_unavailable": "", "error": "",
   "report": "path|null", "bundle": "path|null",
   "verification": {"passed": true, "failed": ["..."]}
 }}
```

`findings` 每项字段（表格 8 列直接映射）：

```
rule_id, title, rule_type, severity, static_strength,
conclusion_level, declared_conclusion_level, signals{}, note
```

**16 个阶段 id（顺序不可改）**：

```
prepare, boot, static, frida_server, network, install, launch, conn_probe,
mitm, hooks, explore, death_probe, correlate, bundle, ai_review, report
```

---

## 5. 行为契约

| 行为 | 现状 | 改造时必须保留 |
| --- | --- | --- |
| 首页入口 | `enterDashboard()` → `app.html` | `onclick` 或 `<a href="app.html">` 皆可，但必须能跳转 |
| 直达流水线 | `app.html#pipeline` | `location.hash` 逻辑在 `app.js`，不要移除 |
| 上传 | 拖拽 / 点击 / `input.change` | 三条路径都要通；只接受 `.apk`（JS 有 `alert`） |
| 上传后 | SSE 实时刷新时间线 | 不能改成轮询 `/api/pipeline/<id>`（会拖慢且无事件粒度） |
| 历史样本 | 上传多个后出现 `#apk-switch` 下拉 | 切换要重新渲染当前页 |
| 源码 | `textContent` / `VSCAN_HL`，**零 innerHTML** | 不得改成 `innerHTML` 拼接 |
| PDF | `file://` 下显示降级提示 + 外链 | 降级分支不能删（本地双击打开时会用到） |
| 空态 | 每个页面有中文空态 | 不能出现"白板" |

---

## 6. `app.js` 允许的增量补丁（最多 70 行）

形式固定：**在文件末尾追加一个 IIFE**，不改任何现成函数体。只做下面四件事：

1. **舞台三态**：`MutationObserver` 监听 `#pipeline-progress` 与 `#pipeline-result` 的 `style`
   属性，把 `idle / running / done` 写到 `#audit-stage` 的 `data-state` 上；
2. **进度轨**：数一数 `#pipeline-timeline` 里 `.pl-done / .pl-failed / .pl-skipped` 的条数，
   写进 `[data-rail]` 的 `--p`；
3. **跟随滚动**：每次列表重建后 `list.scrollTop = list.scrollHeight`；
4. **书架**：遍历 `#pdf-select option` 生成 `.shelf-book` 按钮；点击时
   `sel.value = opt.value; sel.dispatchEvent(new Event('change', {bubbles:true}))`。

参考实现见任务书 §6.4。以下仍然禁止：

- 改 `PIPELINE_API_BASE`、端点路径、请求方法。
- 改 SSE 解析逻辑、阶段 id 列表、`state` 结构。
- 改写 `renderPipelineTimeline()` / `loadPdf()` / `switchPage()`。
- 用 `setInterval` 轮询代替观察器。
- 给 `<li>` 追加新 class（会让 `check_contract.py` 的动态类名清单失效）。
- 把 `#pdf-select` 换成自绘组件（`loadPdf()` 依赖 `<select>` 的 `change`）。

不允许：

- 改 `PIPELINE_API_BASE`、端点路径、请求方法。
- 改 SSE 解析逻辑、阶段 id 列表、`state` 结构。
- 引入 `async/await` 之外的构建期语法（可选链可以，但要确认目标浏览器）。
- 把 `var` 风格整体改成 `const/let`（无意义 diff，且容易漏改）。

---

## 7. 已知漂移与坑（不要"顺手修复"）

1. **产品只做移动端**：`mobile/pipeline` 是移动端流水线（MOB-* 规则）。
   首页旧文案讲 AAOS 车载，属于历史遗留，**v3 已全部删除**。任何新文案都不得出现
   AAOS / 车载 / 车机 / IVI；表达规模用 `16 STAGES`，不要写规则条数。
2. `README.md` 的 API 表是 8770 旧版，`CONTRACT_AUDIT.md` 的 P1–P7 已修复；
   两者只能当历史参考。
3. `frontend/pdfs/` 四份是**手工快照**，不是流水线产物。不要改成动态列表。
4. `app.js` 里 `state.history` 只在内存中，刷新即失。不要声称"历史持久化"。
5. 旧首页底栏的 `44 车载规则 / 223 移动规则`（来自两个 `rules.db` 的 `risk_rules` 表）
   **v3 已整条删除**。不要"顺手恢复"。
6. `#pipeline-job` 的文案由 JS 写入（"正在上传…"、"任务 xxx · 流水线启动中…"），
   不要用 CSS `content` 覆盖。
7. `#pdf-select` 里那条 `car-audit-report.pdf` 的 option 应当删掉（文件留在 `pdfs/` 不动），
   书架是按 option 渲染的，删了 option 就不会出现在书架上。

---

## 8. 回归命令

```bash
PY=python   # 换成你环境里的 Python 3.13

# 1) 契约静态检查（本技能自带）
"$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py

# 2) JS 语法
node --check frontend/app.js
node --check frontend/landing.js
node --check frontend/highlight.js

# 3) 起后端 + 前端（workdir 是产物目录，会自动创建）
"$PY" mobile/pipeline/server.py --port 8771 --workdir ./.cache/pipeline
"$PY" -m http.server 8090 --directory frontend

# 4) 截图验收（需 playwright）
"$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py
```

**通过标准**：`check_contract.py` 全 PASS；`node --check` 三条无输出；
手工走通「上传 → 时间线跑完 → 源码 → 静态 → 动态 → AI 报告 → PDF → 切历史样本」。
