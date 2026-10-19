# Skills 获取清单（唯一随仓库分发的 skills 文件）

> `skills/` 下的 25 个仓库副本共 **1.5 GB / 34,262 个文件**，已全部被 `.gitignore` 排除。
> 别人 clone 本仓库后**没有** `skills/<repo>/` 这些目录——本文件就是让他们按地址自取的索引。
> 人读的选型说明见 [README.md](README.md)；本文件面向 Agent，可直接照着执行。

**仅用于授权开发与测试。**

---

## 0. 给 Agent 的操作顺序

1. **只在真的要改 `frontend/` 时才拉取**，其余任务不需要这些仓库。
2. 跑 §2 的「最小集」（2 个仓库，约 67 MB），别全量克隆。
3. 按 §2.3 的路径清单**逐个校验**，不要假设 clone 成功。
4. 需要截图/回归再配 MCP（§4）；`playwright-mcp` 用 `npx` 即可，**不必克隆**。
5. 动手前先读 `frontend/README.md` 的「Skills / MCP 使用」与
   `.workbuddy/skills/vscanner-frontend-redesign/SKILL.md` 的四条红线。

**技术栈前提**：本仓库前端是**零构建**的纯 HTML/CSS/JS（`python -m http.server` 直接打开）。
所以 React / Vue / Tailwind / UnoCSS 类仓库在本项目**一律禁用**——装了只会把页面带偏。

---

## 1. 先弄清：`skills/` 不等于已启用的技能

下载下来只是"仓库副本"。WorkBuddy 只自动加载这两个位置：

| 位置 | 生效范围 |
| --- | --- |
| `.workbuddy/skills/<name>/SKILL.md` | 本项目（**已随仓库分发**，无需下载） |
| `%USERPROFILE%\.workbuddy\skills\<name>\SKILL.md`（macOS/Linux：`~/.workbuddy/skills/`） | 本机所有项目 |

所以要么**显式 `Read` 源文件**，要么把技能目录**复制**到上面两个位置之一。
`skills/<repo>/` 本身不会自动生效。

本项目已内置一个项目级技能，clone 后即可用，不需要联网：

```
.workbuddy/skills/vscanner-frontend-redesign/
├── SKILL.md                      ← 工作流与四条红线
├── references/design-system.md   ← 视觉规范（唯一依据）
├── references/contract.md        ← DOM/API 契约
├── references/tools-map.md       ← 哪个 skill/MCP 用在哪一步
└── scripts/{check_contract.py, shoot.py}
```

---

## 2. 最小集：真正需要的 2 个仓库

### 2.1 拉取（Bash / Git Bash / macOS / Linux）

```bash
cd "$(git rev-parse --show-toplevel)"   # 到仓库根（有 skills/ 的那一层）
mkdir -p skills
git clone --depth 1 https://github.com/anthropics/skills.git          skills/anthropics-skills
git clone --depth 1 https://github.com/lucide-icons/lucide.git        skills/lucide
```

### 2.2 拉取（PowerShell）

```powershell
Set-Location (git rev-parse --show-toplevel)
New-Item -ItemType Directory -Force skills | Out-Null
git clone --depth 1 https://github.com/anthropics/skills.git   skills/anthropics-skills
git clone --depth 1 https://github.com/lucide-icons/lucide.git skills/lucide
```

### 2.3 拉完必须校验（两条都 OK 才算成功）

```bash
test -f skills/anthropics-skills/skills/frontend-design/SKILL.md && echo OK-frontend-design
test -f skills/anthropics-skills/skills/webapp-testing/SKILL.md  && echo OK-webapp-testing
test -f skills/lucide/icons/zap.svg                             && echo OK-lucide
```

需要的图标只有这 9 个（全部在 `skills/lucide/icons/` 下）：
`zap.svg` `code-xml.svg` `scan-search.svg` `activity.svg` `sparkles.svg`
`file-text.svg` `upload.svg` `shield-check.svg` `arrow-right.svg`

### 2.4 这两个仓库用在哪

| 资源 | 用在哪 | 怎么用 |
| --- | --- | --- |
| `anthropics-skills/skills/frontend-design` | 写 CSS 之前定调、截图后自评 | 通读 `SKILL.md`（约 70 行）；按它的两遍法产出 color/type/layout/principles，再用它的「AI 味」清单自查 |
| `anthropics-skills/skills/webapp-testing` | 第 6 步验收 | 先跑 `scripts/with_server.py --help`；本项目优先用 `scripts/shoot.py`（见 SKILL.md） |
| `lucide/icons/*.svg` | 侧边栏 6 个 + 拖拽/空态 3 个图标 | 复制 `<path>`，统一成 `viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.25"`；**不要**引 npm 包或 CDN |

---

## 3. 全量地址表（25 个仓库 · 含本项目判定）

判定依据：`frontend/README.md` 与 `.workbuddy/skills/vscanner-frontend-redesign/references/tools-map.md`。
**标「禁用」的不是坏仓库，是和本项目「零构建 / 非 React」的技术前提冲突。**

| 目录 | 仓库地址 | 类型 | 本项目判定 | 用途 |
| --- | --- | --- | --- | --- |
| `anthropics-skills` | https://github.com/anthropics/skills | Skills | **必用** | `frontend-design`、`webapp-testing` 等 19 个技能 |
| `lucide` | https://github.com/lucide-icons/lucide | 图标 | **必用** | 1500+ 图标，取 SVG path 内联 |
| `playwright-mcp` | https://github.com/microsoft/playwright-mcp | MCP | 首选 | 浏览器自动化；用 `npx` 启动，**无需克隆** |
| `chrome-devtools-mcp` | https://github.com/ChromeDevTools/chrome-devtools-mcp | MCP | 条件用 | 只在查性能 trace / 网络瀑布时开 |
| `browser-use` | https://github.com/browser-use/browser-use | 框架 | 备选 | MCP 全不可用时的 Python 兜底（`pip install browser-use`） |
| `animejs` | https://github.com/juliangarnier/anime | 动画 | 默认不用 | CSS 做不出来才 vendor `dist/bundles/anime.umd.min.js` |
| `pqoqubbw-icons` | https://github.com/pqoqubbw/icons | 图标 | 可选 | 只取 SVG path 静态化，不引组件 |
| `motion` | https://github.com/motiondivision/motion | 动画 | 仅参考 | 只读 easing / 时长原则，不引运行时 |
| `shadcn-ui` | https://github.com/shadcn-ui/ui | 组件库 | 禁用 | React 组件；零构建页面用不上 |
| `shadcn-ui-mcp-server` | https://github.com/uidesigntools/shadcn-ui-mcp-server | MCP | 禁用 | 组件是 React；官方 MCP 已内置在 CLI（`npx shadcn@latest mcp`） |
| `magic-mcp` | https://github.com/21st-dev/magic-mcp | MCP | 禁用 | 需 API key，产出 React/Tailwind |
| `magicui` | https://github.com/magicuidesign/magicui | 组件库 | 禁用 | React + Tailwind |
| `aceternity-ui` | https://github.com/manuarora700/ui.aceternity | 组件库 | 禁用 | React + Tailwind（官方源已转私有） |
| `react-bits` | https://github.com/DavidHDev/react-bits | 组件库 | 禁用 | React 动画组件（本地副本 665 MB，最重） |
| `motion-primitives` | https://github.com/ibelick/motion-primitives | UI Kit | 禁用 | React + Motion |
| `react-spring` | https://github.com/pmndrs/react-spring | 动画 | 禁用 | React only |
| `auto-animate` | https://github.com/formkit/auto-animate | 动画 | 禁用 | 虽可裸 JS 用，但与 CSS 入场方案冲突 |
| `sonner` | https://github.com/emilkowalski/sonner | 组件 | 禁用 | React Toast |
| `vaul` | https://github.com/emilkowalski/vaul | 组件 | 禁用 | React Drawer |
| `tailwindcss` | https://github.com/tailwindlabs/tailwindcss | CSS 引擎 | 禁用 | 需要构建链 |
| `unocss` | https://github.com/unocss/unocss | CSS 引擎 | 禁用 | 需要构建链 |
| `daisyui` | https://github.com/saadeghi/daisyui | 组件层 | 禁用 | 依赖 Tailwind 构建 |
| `vuejs-skills` | https://github.com/vuejs-ai/skills | Skills | 禁用 | Vue 技能，技术栈不符 |
| `antfu-skills` | https://github.com/antfu/skills | Skills | 禁用 | Vite/Vitest/Nuxt，技术栈不符 |
| `motionsites-ai` | https://github.com/TheSatyam-Singh/motionsites.ai | Prompt 库 | 不可用 | 本地副本是**空仓库**（只有 `.git`），别浪费时间 |

> 需要某个标「禁用」的仓库做**离线参考**（比如查 shadcn 的 a11y 约定），
> 单独 `git clone --depth 1 <上表地址> skills/<目录>` 即可，但不要让它的产物进 `frontend/`。

---

## 4. MCP 配置（不克隆任何仓库）

配置写入 `%USERPROFILE%\.workbuddy\mcp.json`（macOS/Linux：`~/.workbuddy/mcp.json`，
注意**不是** `.mcp.json`）。合并进已有的 `mcpServers`，不要覆盖其它服务器：

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["@playwright/mcp@latest", "--viewport-size=1440,900"]
    },
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest", "--no-usage-statistics"]
    }
  }
}
```

写入后**不会自动启用**：打开 WorkBuddy「连接器管理 → 自定义连接器」，对新服务器点「信任」，再重开会话。

**降级链**（按顺序，不许跳步声称已验收）：

1. MCP `playwright` 可用 → 用它截图/点页面；
2. 不可用 → 内置技能 `playwright-cli` / `agent-browser`；
3. 仍不可用 → `pip install playwright && python -m playwright install chromium`，
   跑 `.workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py`；
4. 全不可用 → 人工看，并在交付说明里如实写「未做自动化截图验收」。

---

## 5. 激活一个下载来的技能（可选）

```bash
# 项目级（跟着仓库走，团队共享）
cp -r skills/anthropics-skills/skills/frontend-design .workbuddy/skills/
# 用户级（本机所有项目可用）
cp -r skills/anthropics-skills/skills/frontend-design "$HOME/.workbuddy/skills/"
```

`anthropics-skills` 的技能在 `anthropics-skills/skills/` 下，其余仓库在 `<repo>/skills/` 下。
只复制真正要用的那一个，不要整仓复制（会把 1.5 GB 塞进技能目录）。

---

## 6. 为什么不入库（维护者备注）

- **体积**：1.5 GB / 34,262 文件，其中 `react-bits` 665 MB、`motion` 532 MB；
  21 个仓库自带嵌套 `.git`，`git add` 时会被当成嵌入仓库，产生 submodule 警告。
- **可重现**：全部是公开仓库，按地址 `--depth 1` 重拉即可，锁定提交见 §7。
- **合规**：`motionsites-ai` 是**付费内容的社区整理版**（原站 $239/年），
  `aceternity-ui` 官方源已转私有——分发仓库副本有授权风险，只给地址最安全。
- `.gitignore` 的写法是 `skills/*` + `!skills/SKILLS.md` + `!skills/README.md`；
  必须用 `skills/*` 而非 `skills/`，否则父目录被整体排除后无法再反排除单个文件。

## 7. 拉取时的提交（复现用）

以下是 2026-10-18 首次下载时的 HEAD，需要完全一致的结果时用 `git checkout <sha>`：

| 仓库 | 提交 | 仓库 | 提交 |
| --- | --- | --- | --- |
| anthropics-skills | `dbd4588` | lucide | `1ef60af` |
| playwright-mcp | `b8b4183` | chrome-devtools-mcp | `ff5204a` |
| browser-use | `aa093a8` | motion | `2d27b04` |
| shadcn-ui | `d2fba50` | tailwindcss | 无 .git（tarball） |
| animejs | 无 .git（tarball） | aceternity-ui | 无 .git（tarball） |

其余仓库不涉及本项目使用，需要时再查。
