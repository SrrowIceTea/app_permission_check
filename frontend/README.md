# V-Scanner 前端界面

移动端「一键审计」工作台 + 落地页（零构建纯静态）。
**仅用于授权测试（自有设备与自有 APK）。**

> **后端变了（2026-10-16 起）**：`app.js` 对接的是 `mobile/pipeline`（`http://127.0.0.1:8771`），
> **不是** `vehicle/workbench`（8770）。本文件下面的文件结构注释与 `CONTRACT_AUDIT.md`
> 仍写着 8770 时期的情况，属于已知漂移；契约以
> [`.workbuddy/skills/vscanner-frontend-redesign/references/contract.md`](../.workbuddy/skills/vscanner-frontend-redesign/references/contract.md)
> 与 `app.js` 为准。车载看板仍在 `output/frontend-review/dashboard.html`。

## 文件结构

```
frontend/
├── index.html      # 首页（Landing Page）
├── landing.css     # 首页样式
├── landing.js      # 首页动画与交互（含 3s 兜底：GSAP 异常时强制显示入场元素）
├── assets/         # 首页背景视频（网络安全监视实拍，Mixkit 免费可商用，720p）
├── app.html        # 工作台主界面
├── app.css         # 工作台样式
├── app.js          # 工作台逻辑（对接 mobile/pipeline 一键审计后端，127.0.0.1:8771）
├── highlight.js    # 零依赖 Java/Kotlin 词法高亮器（自写，不引 CDN）
├── library.js      # 历史报告书架
└── pdfs/           # 审计报告 PDF 快照：车载 + 移动端（设备/回归/第三方）各一份
```

## 开发前：Skills / MCP 使用（Agent 必读）

改这一层之前，先读完本节，别直接开写。

**技术红线（不可协商）**：本前端是**零构建**的纯 HTML/CSS/JS。不新增 `package.json`、
不引 React/Vue/Tailwind/UnoCSS、不用 CDN 组件库；`python -m http.server` 打开必须能跑。
所以下面标「禁用」的仓库不是坏东西，是和这条红线冲突。

### 1. 项目级技能已随仓库分发，先读它

```
.workbuddy/skills/vscanner-frontend-redesign/SKILL.md
```

里面是工作流、四条红线、11 种失败模式。配套两份依据：`references/design-system.md`（视觉规范）
与 `references/contract.md`（17 个必需 id / 6 个页面 / API 端点）。**改版不许临场发挥。**

### 2. 外部 skills 不在仓库里，按地址自取

`skills/` 下 25 个上游仓库副本共 1.5 GB，已被 `.gitignore` 排除；
clone 本仓库后那里只有索引文件。需要时按 **[../skills/SKILLS.md](../skills/SKILLS.md)** 拉取，
它给的是最小集（2 个仓库，约 67 MB）而不是全量：

```bash
cd "$(git rev-parse --show-toplevel)"
git clone --depth 1 https://github.com/anthropics/skills.git   skills/anthropics-skills
git clone --depth 1 https://github.com/lucide-icons/lucide.git skills/lucide
# 校验（两条都 OK 才算成功）
test -f skills/anthropics-skills/skills/frontend-design/SKILL.md && echo OK
test -f skills/lucide/icons/zap.svg && echo OK
```

### 3. 哪个用在哪

| 资源 | 用在哪 | 说明 |
| --- | --- | --- |
| `anthropics-skills/skills/frontend-design` | 写 CSS 之前定调、截图后自评 | 用它反「AI 味」；本文档已锁定一套 token，别另起 |
| `anthropics-skills/skills/webapp-testing` | 验收 | 本项目优先跑 `.workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py` |
| `lucide/icons/*.svg` | 侧边栏 6 + 功能图标 3 | 只取 `<path>` 内联，**不引 npm/CDN** |
| `playwright` MCP | 截图、点页面、看 console | `npx @playwright/mcp@latest`，不必克隆仓库 |
| `chrome-devtools` MCP | 首屏卡顿 / 定位不到的 console 报错 | 条件启用 |
| `motion` / `animejs` | 只读动效原则 | 默认不用；CSS 做不出才 vendor 本地文件 |
| shadcn-ui / tailwind / magicui / react-bits / sonner / vaul 等 | — | **禁用**：React 或需要构建链 |
| `motionsites-ai` | — | 上游是**空仓库**，别下 |

MCP 配置写在 `%USERPROFILE%\.workbuddy\mcp.json`，写入后还需在「连接器管理 → 自定义连接器」
点一次「信任」。浏览器全不可用时，如实写「未做自动化截图验收」，**不许**声称已验收。

### 4. 改完必须跑的验收

```bash
node --check frontend/app.js && node --check frontend/landing.js
python .workbuddy/skills/vscanner-frontend-redesign/scripts/check_contract.py
python .workbuddy/skills/vscanner-frontend-redesign/scripts/shoot.py
```

`check_contract.py` 出现新的 FAIL 就是契约被改坏；`shoot.py` 的截图看五件事：
首屏无滚动、巨字不溢出、凹槽/切角看得出来、拖入后页面不跳动、书脊是扇形不是并排矩形。

## 功能页面

### 首页 (index.html)
- 高端大气的 Landing Page，进入工作台按钮跳转 `app.html`
- GSAP 滚动动画（CDN 不通时自动降级，不影响使用）

### 工作台 (app.html)
左侧导航包含五个功能页面：

1. **源码查看** - 反编译源码树（嵌套目录 + 路径过滤），点文件看代码
2. **静态审计** - 静态规则命中表（规则/类型/强度/等级/信号/依据）
3. **动态审计** - 静动交叉核对四象限（both / static_only / dynamic_only / none）
4. **AI 报告** - 综合审计报告（概览/权限/风险分布/缺口/建议）
5. **PDF 报告** - 审计报告 PDF 查看（车载 + 移动端快照，iframe 原生查看器）

## 使用方式

### 1. 启动后端服务（vehicle/workbench）

```bash
cd vehicle/workbench
python server.py --port 8770
# 可选：带采集会话做静动对照
python server.py --port 8770 \
    --session ../output/device-xxx \
    --findings ../output/delivery-xxx/findings.jsonl
```

### 2. 打开前端页面

```bash
cd frontend
python -m http.server 8080
# 访问 http://localhost:8080/app.html
```

> 前端通过 `127.0.0.1:8770` 调用后端 API，`server.py` 已加 CORS 头，
> 跨端口/跨域访问无需额外配置。

### 3. 上传 APK

- 拖拽 APK 到顶部上传区，或点击选择文件
- 后端后台分析（静态扫描秒级出结论，反编译分钟级），前端轮询进度
- 完成后自动跳转到静态审计页

## API 接口（vehicle/workbench/server.py）

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/apk?name=..` | POST | 上传 APK（原始字节，非 multipart），返回 `{digest, job, cached}` |
| `/api/jobs/{id}` | GET | 查询任务状态（`state`: queued/running/done/failed/cancelled） |
| `/api/jobs/{id}/cancel` | POST | 取消任务 |
| `/api/apk/{digest}/tree` | GET | 文件树（扁平 `{files:[{path,size}]}`） |
| `/api/apk/{digest}/source?path=..` | GET | 源码（`{path,size,truncated,text}`） |
| `/api/apk/{digest}/static` | GET | 静态结论（`findings` 等） |
| `/api/apk/{digest}/summary` | GET | 分析摘要（`apk/findings/decompile` 等） |
| `/api/apk/{digest}/crosscheck` | GET | 静动四象限对照（或 `comparable:false`） |
| `/api/tools` | GET | 工具链就绪情况（jadx/aapt2/dexdump） |

## 关键约定

- **PDF 页列的是手工快照，不是实时产物**：`pdfs/` 下四份 PDF 都没有脚本引用，
  要更新得重新拷。移动端报告的**正规产物**原本在 `output/mobile-*/`、`output/thirdparty-*/` 下
  （指针 `latest-mobile-device.txt` / `latest-mobile.txt` / `latest-thirdparty-batch.txt`）。
  > **2026-10-19**：`output/` 历史跑批产物与全部 `latest-*.txt` 已清理，上述路径与指针
  > **暂时不存在**。需要新报告时重跑设备/第三方批次，产物会重建并再用新指针替换这里的快照；
  > 在此之前，`pdfs/` 里的四份快照是唯一的现成报告。
  > 历史：2026-10-12 拆分时曾把移动端三份移出 `archive/`，以让前端「只服务车载」；
  > 2026-10-13 按用户要求恢复回下拉（前端是日常查看报告的入口，只列车载不够用）。
- **静态结论等级封顶 `candidate`**：代码里出现引用不证明运行时行为，违规仍需人工判定。
- **动态侧数据来自 `/crosscheck`**：需要后端启动时带 `--session`/`--findings`；
  缺失时前端如实显示"无法对照"，不硬凑数据。
- **源码渲染零 innerHTML**：反编译产物可能含任意字符串，统一走 `textContent`。

## 授权声明

**仅用于授权测试（自有设备与自有 APK）。**
所有抓包、Hook 操作均在白名单包名范围内进行，观察不改写，判定可追溯。
