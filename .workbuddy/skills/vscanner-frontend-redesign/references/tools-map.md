# Skills / MCP 使用地图（本次前端改版专用）

## 0. 先弄清一件事

`skills/` 目录只是**下载下来的仓库集合**，不等于"已启用的技能"。
WorkBuddy 只会自动加载：

| 位置 | 范围 |
| --- | --- |
| `.workbuddy/skills/<name>/SKILL.md` | 本项目 |
| `~/.workbuddy/skills/<name>/SKILL.md`（Windows：`%USERPROFILE%\.workbuddy\skills\`） | 本机所有项目 |

所以：**要么显式 `Read` 源文件，要么复制到上面两个位置**。本文件里的路径都是相对项目根的。

> **`skills/<repo>/` 不在仓库里**（1.5 GB，被 `.gitignore` 排除）。新 clone 先按
> `skills/SKILLS.md` §2 只拉最小集（`anthropics-skills` + `lucide`），并用该节的两条
> `test -f` 校验；校验不过就别往下走，否则本文件里的路径全是空的。
> MCP 那两个（`playwright` / `chrome-devtools`）用 `npx` 启动，**不需要**克隆对应仓库。

本任务已内置一个项目级技能：

```
.workbuddy/skills/vscanner-frontend-redesign/
├── SKILL.md                      ← 工作流与红线
├── references/design-system.md   ← 视觉规范（唯一依据）
├── references/contract.md        ← DOM/API 契约
├── references/tools-map.md       ← 本文件
└── scripts/{check_contract.py, shoot.py}
```

---

## 1. 分层结论（先看这张表）

| 层级 | 资源 | 用途 |
| --- | --- | --- |
| **必用** | `anthropics-skills/skills/frontend-design` | 设计定调、反"AI 味"自评 |
| **必用** | `anthropics-skills/skills/webapp-testing` | 截图与功能回归（MCP 断了也能跑） |
| **必用** | `lucide/icons/*.svg` | 6 个导航图标 + 3 个功能图标的几何来源 |
| **首选** | `playwright-mcp` | 打开页面、截图、点击、看 console |
| **条件** | `chrome-devtools-mcp` | 只在需要看性能 trace / 网络瀑布时 |
| **备选** | `browser-use`、WorkBuddy 内置 `playwright-cli` / `agent-browser` | MCP 不可用时的浏览器自动化 |
| **参考** | `motion`、`animejs` | 只读动效原则；anime.js 仅在 CSS 做不出时 vendor |
| **禁用** | 其余全部（React/Vue/构建链） | 会把零构建页面带偏 |

---

## 2. 必用技能：怎么用

### 2.1 `frontend-design`（设计定调）

- 路径：`skills/anthropics-skills/skills/frontend-design/SKILL.md`
- 用在哪：**动手写 CSS 之前**与**截图自评时**各读一次。
- 怎么用：
  1. `Read` 全文（约 70 行，不要只读 frontmatter）。
  2. 按它的两遍法：先产出 `color / type / layout / principles` 四段式设计计划（本项目的计划已固化在
     `references/design-system.md`，直接对照，不要另起一套）。
  3. 用它列的 5 类"AI 生成感"特征逐条自查；命中就改。
  4. 它要求"spend your boldness in one place"——本项目的"一处"是**首页的巨型 V-SCANNER + 一束光**，
     其余全部压静。
- 不要做：不要用它的示例配色（米色 + 陶土色），那是它自己点名的 AI 味。

### 2.2 `webapp-testing`（验收）

- 路径：`skills/anthropics-skills/skills/webapp-testing/`
- 用在哪：第 6 步视觉与功能验收。
- 前置：若环境里没有 playwright，先装：

  ```bash
  python -m pip install playwright
  python -m playwright install chromium
  ```

- 怎么用：
  1. `Read` `SKILL.md`（决策树：静态 HTML 直接写选择器）。
  2. 先 `"$PY" skills/anthropics-skills/skills/webapp-testing/scripts/with_server.py --help`，
     按其用法托管 `http.server`；**不要**先读脚本源码（很长）。
  3. 本项目已提供更贴合的快照脚本，优先跑它：

     ```bash
     "$PY" .workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py
     ```

     它会起 8090 静态服务，截 `index` / `app` 的 1440×900 与 390×844，收集 console error，
     输出到 `output/frontend-shots/`。
  4. 参考它的 `examples/console_logging.py` 处理浏览器日志。
- 判定：截图中若出现文字溢出、元素重叠、首屏滚动条，直接返工。

### 2.3 `lucide`（图标几何）

- 路径：`skills/lucide/icons/`
- 用在哪：`app.html` 侧边栏 6 个 + 拖拽区/空态 3 个。
- 怎么用：
  1. 只取这几个文件：`zap.svg`、`code-xml.svg`、`scan-search.svg`、`activity.svg`、
     `sparkles.svg`、`file-text.svg`、`upload.svg`、`shield-check.svg`、`arrow-right.svg`。
  2. 打开后保留 `<svg viewBox="0 0 24 24">` 与内部 `<path>`，删掉 `width/height/class`。
  3. 统一改成：

     ```html
     <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="1.25" stroke-linecap="round" stroke-linejoin="round"
          aria-hidden="true"><path d="..."/></svg>
     ```

  4. **不要**引入 `lucide` npm 包或 CDN；不要用 emoji 代替。
- 许可：ISC，可商用，无需在页面署名。

---

## 3. MCP：配置与调用

### 3.1 Playwright MCP（首选）

配置文件：用户主目录下的 `.workbuddy/mcp.json`
（Windows：`%USERPROFILE%\.workbuddy\mcp.json`；macOS/Linux：`~/.workbuddy/mcp.json`。**不是** `.mcp.json`）。
把下面这段合并进已有的 `mcpServers`，不要覆盖其它服务器：

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@playwright/mcp@latest", "--viewport-size=1440,900"]
    }
  }
}
```

生效步骤（必须人工点一次）：

1. 保存 `mcp.json`；
2. 打开 WorkBuddy「连接器管理 → 自定义连接器」；
3. 对 `playwright` 点「信任」；
4. 重开会话。

调用序列（改版验收固定用这套）：

| 步骤 | 工具 | 参数 |
| --- | --- | --- |
| 1 | `browser_navigate` | `http://localhost:8090/index.html` |
| 2 | `browser_take_screenshot` | `fullPage=false`，存 `output/frontend-shots/index-1440.png` |
| 3 | `browser_resize` | `1440×900` → 再 `390×844` |
| 4 | `browser_navigate` | `http://localhost:8090/app.html` |
| 5 | `browser_console_messages` | 只看 `error`；`Failed to fetch` 若因后端未启动可忽略并注明 |
| 6 | `browser_click` | 依次点 6 个 `.nav-item`，每次截图 |
| 7 | `browser_file_upload` | 上传 `apk/mobile/*.apk` 验证时间线 |

> 工具名前缀以实际连接后为准；若只有 `browser_snapshot` 没有截图，就用快照 + 人工看。

### 3.2 Chrome DevTools MCP（条件启用）

只在两种情况下开：

- 首屏有明显卡顿 / 掉帧；
- console 有非网络类报错但定位不到。

```json
{
  "mcpServers": {
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest", "--no-usage-statistics"]
    }
  }
}
```

调用：

```
navigate_page → performance_start_trace(reload=true) → 操作 → performance_stop_trace
list_console_messages → get_network_request
```

判定：首屏 LCP < 1.8s（本地），无 long task > 200ms；背景图不得触发 layout shift。

### 3.3 降级链（按顺序）

1. MCP `playwright` 可用 → 用 MCP。
2. 不可用 → WorkBuddy 内置技能 `playwright-cli` 或 `agent-browser`。
3. 都不可用 → `python -m playwright`（需先 pip install，见 2.2）。
4. 全部不可用 → 人工在 Chrome 里看，并在交付说明中明确写"未做自动化截图验收"，
   **不许**声称"已验收"。

---

## 4. 其余技能：逐条判定

| 目录 | 实际能力 | 本次判定 | 理由 / 用法 |
| --- | --- | --- | --- |
| `anthropics-skills/.../theme-factory` | 10 套预设主题 | **禁用** | 会覆盖本项目定制色板，且预设偏"通用好看" |
| `anthropics-skills/.../brand-guidelines` | Anthropic 品牌规范 | **禁用** | 会把 Claude 的配色字体带进来 |
| `anthropics-skills/.../canvas-design` | 生成 PNG/PDF 海报 | **禁用** | 产物不是网页 |
| `anthropics-skills/.../web-artifacts-builder` | React + Tailwind + 打包成单 HTML | **禁用** | 与"零构建、纯 HTML/CSS/JS"直接冲突 |
| `anthropics-skills/.../mcp-builder` | 写 MCP Server | 不用 | 本任务不新增 MCP |
| `shadcn-ui-mcp-server` | 查 shadcn 组件源码/示例 | **不启用** | 组件是 React；只可人工看 a11y 约定，价值低 |
| `magic-mcp` | AI 生成 UI 组件 | **禁用** | 需 API key，产出 React/Tailwind |
| `shadcn-ui` | React 组件库 | 禁用 | 同上 |
| `daisyui` / `tailwindcss` / `unocss` | 需要构建的 CSS 方案 | 禁用 | 页面必须 `http.server` 直接打开 |
| `motion`（framer-motion） | React 动画库 | **仅参考** | 可读其 easing/时长原则；不引运行时 |
| `motion-primitives` / `magicui` / `react-bits` / `react-spring` / `auto-animate` / `sonner` / `vaul` | React 组件/动画 | 禁用 | 全部依赖 React |
| `vuejs-skills` / `antfu-skills` | Vue/Vite/Nuxt 技能 | 禁用 | 技术栈不符 |
| `pqoqubbw-icons` | 动画图标（React） | 可选 | 只可取其 SVG path 静态化，不引组件 |
| `animejs` | 原生 JS 动画库 v4.5 | **默认不用** | CSS 足够；确需编排时 vendor `dist/bundles/anime.umd.min.js` 到 `frontend/vendor/`，禁 CDN |
| `browser-use` | Python 浏览器框架 | 备选 | 需 `pip install browser-use`，本地模式可用 |
| `chrome-devtools-mcp` | Chrome 调试 MCP | 条件用 | 见 3.2 |
| `playwright-mcp` | 浏览器自动化 MCP | 首选 | 见 3.1 |
| `motionsites-ai` | **空目录**（只有 .git） | 不可用 | 不要浪费时间 |

---

## 5. 速查：改版六步该用什么

| 步骤 | 产出 | 用到的资源 |
| --- | --- | --- |
| 1 契约盘点 | 确认 17 个 id / 6 个页面 / 7 个端点 | `references/contract.md`、`scripts/check_contract.py` |
| 2 设计定调 | token 表 + 两张线框 | `frontend-design`、`references/design-system.md` |
| 3 背景图 | `assets/hero-bg.jpg` | ImageGen（先征得同意）或用户供图 |
| 4 首页重构 | `index.html` + `landing.css` | `frontend-design`、`lucide` |
| 5 工作台重构 | `app.html` + `app.css` | `references/design-system.md` §5、`lucide` |
| 6 验收 | 截图 + 回归日志 | `playwright-mcp` → `shoot.py` → `webapp-testing` |
