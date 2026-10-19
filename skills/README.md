# 前端辅助 Skills / MCP 工具集

从 GitHub 下载的开源工具集，用于增强 Agent 的前端开发、调试、测试与 UI 美化能力。
下载时间：2026-10-18（shallow clone 或 tarball；星标数为下载时约值）。

> **这些仓库副本不入库**（共 1.5 GB / 34,262 文件，见 `.gitignore`）。
> 别人 clone 本仓库后 `skills/` 下只有本文件与 [SKILLS.md](SKILLS.md)。
> **要真正下载，看 [SKILLS.md](SKILLS.md)**——那里有每个仓库的准确地址、最小集命令、
> 拉取后校验路径，以及「本项目到底用哪几个」的判定。
> 本文只解决「选哪个」的问题，不解决「怎么拿」。

## 目录总览（25 个仓库）

| 目录 | 来源 | 星标 | 类型 | 用途 |
| --- | --- | --- | --- | --- |
| `shadcn-ui/` | shadcn-ui/ui | ~112k | 组件库 | React 组件库事实标准，copy-paste 模式 |
| `tailwindcss/` | tailwindlabs/tailwindcss | ~95k | CSS 引擎 | 原子化 CSS，v4 纯 CSS `@theme` |
| `animejs/` | juliangarnier/anime | ~68k | 动画引擎 | 轻量全能 JS 动画（CSS/SVG/Canvas/WAAPI） |
| `daisyui/` | saadeghi/daisyui | ~35k | 组件层 | Tailwind 的语义化组件类 |
| `motion/` | motiondivision/motion | ~32k | 动画引擎 | Framer Motion 继任者，React 动画标准 |
| `react-spring/` | pmndrs/react-spring | ~29k | 动画引擎 | 弹簧物理动画，适合连续输入 |
| `lucide/` | lucide-icons/lucide | ~22k | 图标 | 1500+ 简洁图标，shadcn 默认 |
| `magicui/` | magicuidesign/magicui | ~18k | 组件库 | 150+ 动画组件（粒子/微光/光标轨迹） |
| `unocss/` | unocss/unocss | ~19k | CSS 引擎 | 即时原子化 CSS，Tailwind 兼容预设 |
| `auto-animate/` | formkit/auto-animate | ~14k | 动画 | 一行代码给列表加过渡动画 |
| `react-bits/` | DavidHDev/react-bits | ~25k | 组件库 | 110+ 动画组件，4 种技术栈变体 |
| `sonner/` | emilkowalski/sonner | ~10k | 组件 | Toast 通知 |
| `vaul/` | emilkowalski/vaul | ~9k | 组件 | 无依赖抽屉（Drawer） |
| `pqoqubbw-icons/` | pqoqubbw/icons | ~7.5k | 图标 | 会动的 SVG 图标 |
| `motion-primitives/` | ibelick/motion-primitives | ~5.5k | UI Kit | 设计感强的动效组件 |
| `aceternity-ui/` | manuarora700/ui.aceternity | - | 组件库 | 视觉特效组件（聚光/3D 卡片/光束） |
| `motionsites-ai/` | TheSatyam-Singh/motionsites.ai | - | Prompt 库 | 65 个 motionsites.ai 网页设计 Prompt |
| `anthropics-skills/` | anthropics/skills | - | Skills | 官方技能集（前端设计/测试/构建） |
| `vuejs-skills/` | vuejs-ai/skills | - | Skills | Vue 官方 8 个技能 |
| `antfu-skills/` | antfu/skills | - | Skills | Vite/Vitest/Nuxt/Pinia/UnoCSS 等 |
| `playwright-mcp/` | microsoft/playwright-mcp | - | MCP | 浏览器自动化 |
| `chrome-devtools-mcp/` | ChromeDevTools/chrome-devtools-mcp | - | MCP | Chrome 调试 |
| `shadcn-ui-mcp-server/` | uidesigntools/shadcn-ui-mcp-server | - | MCP | shadcn 组件检索 |
| `magic-mcp/` | 21st-dev/magic-mcp | - | MCP | AI 生成 UI（需 key） |
| `browser-use/` | browser-use/browser-use | - | 框架 | Python 浏览器自动化 |

---

## 一、组件库 / 美化（高星）

### shadcn-ui/ui（~112k★）
现代 React UI 的事实标准：基于 Radix + Tailwind，组件以源码形式复制进项目，
完全自主可控。安装：`npx shadcn@latest add button`。是 Magic UI / Aceternity /
React Bits 等所有扩展库的地基。

### react-bits（~25k★）
110+ 动画组件（文本动画/背景/按钮/卡片/加载态），提供 JS-CSS / JS-Tailwind /
TS-CSS / TS-Tailwind 四种变体。安装：`npx shadcn@latest add "https://reactbits.dev/r/split-text"`
或 `npx jsrepo add github/DavidHDev/react-bits/text-animations/split-text`。

### magicui（~18k★）
150+ 动画组件：animated beam、shimmer button、number ticker、bento grid 等。
`npx shadcn@latest add https://magicui.design/r/magic-card`。

### aceternity-ui
聚光灯、3D 卡片、背景光束等高冲击特效（Tailwind + Motion）。
注意：官方仓库已转私有/收费（All-Access），这里下载的是作者公开的站点源码
`manuarora700/ui.aceternity`；组件实际通过 shadcn registry 安装：
`npx shadcn@latest add https://ui.aceternity.com/registry/3d-card.json`。

### motion-primitives（~5.5k★）
比 Magic UI 更克制的动效 UI kit（ibelick 出品），适合精致内敛的界面。

### daisyui（~35k★）
给 Tailwind 加语义化组件类（`btn btn-primary` 这种），5 个主题开箱即用。

### sonner / vaul / pqoqubbw-icons / lucide
- `sonner`：React 生态最好用的 Toast；
- `vaul`：抽屉组件，无依赖；
- `pqoqubbw-icons`：带动画特效的 SVG 图标；
- `lucide`：shadcn/ui 默认图标库，tree-shakable + TS 类型。

## 二、动画引擎

| 目录 | 一句话选型 |
| --- | --- |
| `motion/` | React 首选；手势、滚动、退出动画、布局动画 |
| `animejs/` | 不挑框架，轻量全能，v4 模块化 ESM |
| `react-spring/` | 弹簧物理，拖拽/连续输入追踪 |
| `auto-animate/` | 零配置，一行代码给列表增删过渡 |

## 三、CSS 引擎

- `tailwindcss/`：v4 用纯 CSS `@theme`，无配置文件；
- `unocss/`：即时按需原子化，构建更快，有 Tailwind 兼容预设。

## 四、AI 设计 Prompt 库

### motionsites-ai
motionsites.ai（Viktor Oddy 的 AI 网页设计 Prompt 站）的社区导出版：
65 个高质量网页设计 Prompt（落地页/Hero/SaaS 界面），针对 React + Tailwind +
Motion 优化，可直接粘贴到 Cursor / Claude / v0 等工具生成页面。
每个 Prompt 带视频预览。原始站点为付费内容（$239/年或 $349 终身），
本仓库为社区整理，使用请自行确认授权边界。

## 五、Agent Skills（复制到技能目录激活）

| 目录 | 内容 |
| --- | --- |
| `anthropics-skills/` | `frontend-design`、`webapp-testing`（Playwright 测试）、`web-artifacts-builder`、`canvas-design`、`brand-guidelines`、`theme-factory`、`mcp-builder` 等 20 个 |
| `vuejs-skills/` | `vue-best-practices`、`vue-debug-guides`、`vue-pinia-best-practices`、`vue-testing-best-practices` 等 8 个 |
| `antfu-skills/` | `vite`、`vitest`、`nuxt`、`pinia`、`unocss`、`pnpm`、`vitepress` 等 10 个 |

激活：`cp -r skills/<仓库>/skills/<技能名> .workbuddy/skills/`（anthropics 的技能在
`anthropics-skills/skills/` 下，其余在 `<仓库>/skills/` 下）。

## 六、MCP 服务器（写入 `C:\Users\毛宇淇\.workbuddy\mcp.json`）

```json
{
  "mcpServers": {
    "playwright":     { "command": "npx", "args": ["@playwright/mcp@latest"] },
    "chrome-devtools":{ "command": "npx", "args": ["-y", "chrome-devtools-mcp@latest", "--no-usage-statistics"] },
    "shadcn-ui":      { "command": "npx", "args": ["-y", "shadcn-ui-mcp-server"] },
    "magic":          { "command": "npx", "args": ["-y", "@21st-dev/magic@latest"], "env": { "API_KEY": "你的 21st.dev key" } }
  }
}
```

写入后不会自动启用：打开「连接器管理 → 自定义连接器」，对新服务器点「信任」。
shadcn 官方 MCP 无独立仓库，内置于 CLI：`npx shadcn@latest mcp`。

## 七、浏览器自动化框架

### browser-use
Python 实现，Agent 可自主操作浏览器。安装：
`C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe -m pip install browser-use`
需要 LLM API key。

---

## 注意事项

1. **API key**：`magic-mcp`、`browser-use` 需要各自 key；其余零配置可用。
2. **Node**：本机已具备（22.22.2 / 24.14.0），所有 `npx` 命令可直接运行。
3. **版权**：各仓库版权归原组织（MIT/Apache 等）；`motionsites-ai` 是付费内容的
   社区整理版，商用前请确认授权；`aceternity-ui` 官方源已转私有，公开的是站点源码。
4. **代理**：本机代理访问 GitHub 偶发 502，克隆失败重试或改 codeload tarball 即可。
5. 本工具集仅用于授权开发与测试。
