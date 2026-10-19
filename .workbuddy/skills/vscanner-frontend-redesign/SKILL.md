---
name: vscanner-frontend-redesign
description: 改造 V-Scanner 的 frontend/index.html 与 frontend/app.html——不规则暗场首页 + Kling 式工作台 + 覆盖式审计流程 + 扇形书本历史报告，并在替换背景、重排侧边栏、重做流程揭示时保证 mobile/pipeline 后端的 DOM/API 契约不被破坏。当任务涉及 V-Scanner 前端美化、首页改版（凹槽面板）、工作台布局、拖入 APK 后的流程覆盖、PDF 历史报告书架、hero 背景图、侧边栏图标、落地页排版时使用。
agent_created: true
---

# V-Scanner 前端改版

## 用途

把 `frontend/` 的两个页面从"深蓝紫渐变仪表盘"改造成**近黑底 + 巨型字 + 发丝线**的高级暗场界面，
同时一行后端代码都不动。视觉依据与契约依据是两份 reference，不是临场发挥。

## 何时使用

- 用户说"美化首页 / 工作台""换成 BMW 那种感觉""参考 Kling""背景换成图片""图标要透明高级"；
- 用户说"拖入后覆盖上传区""做到哪里显示哪里""历史报告做成一本书 / 扇形排列""字太多要少"；
- 需要调整 `index.html`、`landing.css`、`landing.js`、`app.html`、`app.css` 的版式与动效；
- 需要检查改版有没有把 `app.js` 依赖的节点、类名、接口改坏。

不适用：新增审计功能、改后端、改规则库、做 PPT/报告。

## 开工前必读（按顺序）

1. `references/contract.md` —— 17 个必需 id、6 个页面、动态类名清单、8 个端点、已漂移文档清单。
2. `references/design-system.md` —— token、字号、线框、逐页规格、动效纪律、自评清单。
3. `references/tools-map.md` —— 哪个 skill/MCP 用在哪一步，哪些必须禁用。
4. `skills/anthropics-skills/skills/frontend-design/SKILL.md` —— 设计方法论与"AI 味"清单。
   该仓库副本不入库，本地缺失时先按 `skills/SKILLS.md` §2 拉最小集再读。
5. `prompts/assets/` 三张构图板：`composition-index.svg`（不规则面板）、`composition-app.svg`（初始 / 覆盖两态）、`composition-library.svg`（扇形书架 / 抽出封面）。

## 四条红线

1. **后端零改动**：`vehicle/`、`mobile/`、`core/`、`tools/` 只读。
2. **契约零破坏**：不改 `PIPELINE_API_BASE`、端点路径、SSE schema、阶段 id；
   `app.js` 的 `getElementById` 目标一个都不能少；`.pl-*` 五种状态样式一个都不能缺。
3. **零构建**：不新增 `package.json`、不引 React/Vue/Tailwind、不用 CDN 组件库。
   页面必须能 `python -m http.server` 直接跑。
4. **只做移动端**：不出现 AAOS / 车载 / 车机 / IVI；不写规则条数（44 / 223 已废弃），
   要表达规模用 `16 STAGES`。

## 工作流

### 第 1 步：契约快照

```bash
PY=python   # 换成你环境里装有 requirements.txt 依赖的 Python 3.13
"$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py
```

先跑一次记录基线。**未改造前的基线是 PASS 15 / WARN 6 / FAIL 1**：
唯一 FAIL 是「index.html 仍在加载 `<video>`」——改完首页后这条必须消失；
另外 4 条 WARN 在「— v3 增量项 —」小节里（`.pl-pending` 未隐藏、没有 `clip-path`、
首页还有 AAOS/车载字样、`#pdf-select` 还有车载报告），改造完成后它们应逐条转 PASS。
不要跳过基线，否则改坏了分不清是谁弄坏的。

### 第 2 步：落 token

把 `design-system.md` §1 的 `:root` 原样写进 `landing.css` 与 `app.css`，两份保持一致。
删掉旧的 `--accent: #7c8aff` 一类紫蓝变量，避免残留引用。

### 第 3 步：背景图

- 优先 ImageGen：用 `design-system.md` §6.2 的英文提示词，`size=1536x1024`、`quality=high`；
  **调用前必须告知用户会消耗额度并取得同意**。
- 落盘 `frontend/assets/hero-bg.jpg`（≤550KB）+ `hero-bg@1280.jpg`（≤220KB）。
  用 Pillow 压：

  ```bash
  "$PY" -c "from PIL import Image; im=Image.open('raw.png').convert('RGB'); im=im.resize((2560,1440)); im.save('frontend/assets/hero-bg.jpg', quality=84, optimize=True, progressive=True)"
  ```

- 没有图也要能看：CSS 兜底渐变（左侧纯黑 + 右侧一条冷白细光）。
- 删除对 `assets/cyber-security-bg.mp4` 的引用；文件可保留，但页面不得再加载 `<video>`。

### 第 4 步：首页

按 `design-system.md` §4 重写 `index.html` 的 body 结构与 `landing.css`。

- 先落 `.stage-panel` 的 `clip-path`（12 点多边形，含右凹槽与右下切角），**截图确认形状对了再排字**；
- 再放 `.notch-tag` 竖排字（面板的兄弟节点，否则会被裁掉）；
- 文案只有：品牌 / `V-SCANNER` / `移动应用数据安全审计` / `进入工作台` / `AUTHORIZED TESTING ONLY`。
  **不要**加底栏、规则数、状态栏、术语排比。
- 保留 `enterDashboard()` / `enterPipeline()`；去掉 GSAP 依赖，入场动画全部 CSS。

### 第 5 步：工作台

按 `design-system.md` §5 重排 `app.html`：

- 左侧 rail 保留 `.nav-item[data-page]` 六个，图标内联 Lucide，默认 `opacity:.34`；
- 主区保留全部 17 个 id 与 `.page#page-*` 结构；
- `#page-pipeline` 外层加 `.stage[data-state]`，内部「品牌 → `.stage-slot`（拖拽区 + 流程层）→ 结果卡」；
- 拖拽区 640×128，只写「拖入 APK / 或点击选择 · 仅 .apk」，**不要**写流程解释；
- `#pipeline-progress` / `#pipeline-result` 的初始 `style="display:none"` 必须保留；
- 流程层用绝对定位铺满 `.stage-slot`，**覆盖**上传区（页面不长高、不跳动）；
- 未来阶段 `display:none`，当前阶段一张大卡，已完成折叠成 34px 一行。

只允许在 `app.js` 末尾追加 ≤70 行自包含补丁（见 contract §6）；能不改就不改。

### 第 5.5 步：历史报告书架

按 `design-system.md` §6：书脊 44×280、角度 −21/−7/+7/+21、最新一册青色书签；
点击抽出成 296×400 封面；只读 `#pdf-select` 的 option，**不要编风险数/页数**。

### 第 6 步：验收

```bash
node --check frontend/app.js && node --check frontend/landing.js
"$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py
"$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py
```

截图看五件事：首屏无滚动、巨字不溢出、凹槽/切角看得出来、拖入后页面不跳动、
书脊是扇形不是并排矩形。
再手工走一遍：上传 APK → 16 阶段跑完 → 源码树 → 静态表 → 动态判据 → AI 报告 → PDF → 切历史样本。

## 交付时必须说明

- 改了哪些文件、新增了哪些资源；
- `check_contract.py` 的输出（PASS/FAIL 行数）；
- 截图路径；
- 哪些验收没做（例如后端未启动、没跑真实 APK），**如实写**。

## 常见失败模式

| 现象 | 根因 | 处理 |
| --- | --- | --- |
| 页面全白 | 删了 `.page` 默认 `display:none` 或 `active` 规则 | 补 `.page{display:none}.page.active{display:block}` |
| 时间线不出现 | 给 `#pipeline-progress` 写了 CSS `display:none` | 删除该规则，显隐交给行内样式 |
| 状态点全灰 | 只写了 `.pl-done`，漏了 `.pl-pending/.pl-running/.pl-failed/.pl-skipped` | 五种补齐 |
| 上传无反应 | `#pipeline-apk-input` 被删或不在 DOM | 恢复 `<input type="file" accept=".apk" hidden>` |
| 源码页空白 | `highlight.js` 加载顺序被改到 `app.js` 之后 | 恢复顺序 |
| PDF 页一直空 | 删了 `#pdf-open-external` 里的 `<a>` | 补回 `<a>` |
| 字体像"拉伸的面条" | `font-stretch` 作用到了中文 | 只给拉丁 display 字体加 |
| 离线打开白屏 | 背景图/字体全走外链且无兜底 | 本地资源 + 系统字体回退 |
| 拖入后页面猛跳 | 流程层走文档流而不是覆盖在 `.stage-slot` 里 | 流程层 `position:absolute; inset:0` |
| 16 格一次性铺满 | 没写 `#pipeline-timeline > .pl-pending{display:none}` | 补上；未来阶段不渲染 |
| 历史行集体闪烁 | 给 `.pl-done` 加了入场动画（列表每事件重建） | 动画只给 `.pl-running` |
| 流程样式不生效 | 选择器写成 `.pipeline-card.pl-running` | 时间线条目是 `li.pl-running` |
| 竖排字被裁掉 | 把字放进了 `clip-path` 面板内部 | 挪到面板的兄弟节点 |
