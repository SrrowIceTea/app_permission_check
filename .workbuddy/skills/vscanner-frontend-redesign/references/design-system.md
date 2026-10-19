# V-Scanner 前端设计系统（v3 · 移动端 / 暗场 / 发丝线）

> 参考对象：`https://www.bmwf3.com/`（首页构图）× `https://kling4.org/`（工作台居中舞台）。
> 目标不是复刻，而是提取两者的**共同语法**：近黑底、单一高光、极大字号、极少 chrome、慢动效。
> 本文件是 `index.html` / `app.html` 改造的**唯一视觉依据**，实现时不得自行换色、换字体、加圆角。
> 任务书见 `prompts/frontend-redesign-prompt.md`；契约见 `contract.md`。

---

## 0. 一句话方向

**一间关了灯的移动安全实验室**：画面里只有一束冷白光、一块巨大的字、几根 1px 的线。
所有"科技感"来自**留白与对比**，不来自渐变、发光边框和玻璃卡片堆叠。

三个关键词：`暗场` · `发丝线` · `单点高光`

### 产品定位（写死）

- **只做移动端 APK 审计**。界面不出现 AAOS、车载、车机、IVI、座舱。
- 不出现"N 条规则"这类会过期的数字。要表达规模就用 `16 STAGES`。

### 明确禁止的"AI 味"（出现即返工）

- 紫蓝渐变背景、霓虹 glow、彩虹描边
- 每个区块都是同一种圆角玻璃卡片 + 同一种阴影
- 所有按钮都是胶囊形；所有卡片都 `border-radius: 16px`
- 彩色 KPI 大数字 + 图标色块
- emoji 当图标、Font Awesome、iconfont
- 全屏粒子/星空/矩阵雨（与"审计"语义无关）
- 标题里给某一个词单独换色或斜体
- "静态剖析 / 动态采集 / 关联研判"这类四字排比堆成一句正文

---

## 1. Design tokens

直接落地为 `frontend/landing.css` 与 `frontend/app.css` 顶部的 `:root`（两份保持一致）。

```css
:root {
  /* —— 表面 —— */
  --bg:          #05070A;
  --bg-soft:     #080B10;
  --panel:       rgba(12, 16, 22, 0.52);
  --panel-solid: #0B0F14;
  --panel-lift:  rgba(255, 255, 255, 0.035);

  /* —— 线：只允许 1px —— */
  --line:        rgba(255, 255, 255, 0.09);
  --line-2:      rgba(255, 255, 255, 0.16);
  --line-3:      rgba(255, 255, 255, 0.30);

  /* —— 字 —— */
  --paper:       #F2F4F6;
  --paper-2:     rgba(242, 244, 246, 0.66);
  --paper-3:     rgba(242, 244, 246, 0.42);
  --paper-4:     rgba(242, 244, 246, 0.24);

  /* —— 信号色：只用于"运行/结果"状态，绝不用于装饰 —— */
  --live:  #9BE7F5;
  --pass:  #7FE0AE;
  --warn:  #E8C583;
  --fail:  #FF8A8A;

  /* —— 字体 —— */
  --font-display: "Archivo", "Inter", "PingFang SC", "Microsoft YaHei", sans-serif;
  --font-ui:      "Inter", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
  --font-mono:    "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;

  /* —— 几何 —— */
  --r-0: 0px;      /* 首页 CTA / 舞台面板：直角 */
  --r-1: 2px;      /* 小控件、书脊 */
  --r-2: 10px;     /* 流程层 */
  --r-3: 12px;     /* 拖拽区 */
  --pad-x: clamp(24px, 4.6vw, 80px);
  --rail: 76px;
  --rail-open: 212px;
  --topbar: 64px;

  /* —— 动效 —— */
  --ease-out: cubic-bezier(.16, 1, .3, 1);
  --ease-io:  cubic-bezier(.65, 0, .35, 1);
  --dur-1: 160ms;
  --dur-2: 260ms;
  --dur-3: 900ms;
}
```

**用色纪律**

| 场景 | 用色 |
| --- | --- |
| 正文/标题 | `--paper` / `--paper-2` |
| 次要说明、单位、计数 | `--paper-3` |
| 分隔线、表格行线 | `--line` |
| hover 边框 | `--line-2` |
| 拖拽中 / focus | `--line-3` |
| 运行中 | `--live`（仅圆点、进度线、书签） |
| 通过 / 警告 / 失败 | `--pass` / `--warn` / `--fail`（仅状态点与徽标文字） |

> 全站彩色像素占比目标：**< 2%**。截图缩小到 25% 时，画面应几乎只有黑白灰。

---

## 2. 字体

| 角色 | 字体 | 用法 |
| --- | --- | --- |
| Display | **Archivo**（可变字宽 `wdth`） | 只用于 `V-SCANNER` 与页面大标题。`font-stretch: 112%`，`font-weight: 500` |
| UI | **Inter** | 正文、按钮、表格、表单。400 / 500 两档为主 |
| Mono | **JetBrains Mono** | 规则 ID、路径、字节数、阶段序号、状态码。`font-variant-numeric: tabular-nums` |
| CJK 回退 | PingFang SC / Microsoft YaHei | 不额外加载 Noto Sans SC（体积换不来质感） |

> v2 写的 Google Sans Flex **不在 Google Fonts 公开库**，那条链接会 404。改用 Archivo：
> 同样有可变宽度轴（`wdth 62..125`），SIL OFL 许可，可商用。

引入方式（`<head>`，保留 `preconnect`，合并成一条 request）：

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wdth,wght@62..125,100..900&family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@300;400;500&display=swap" rel="stylesheet">
```

**规则**

- `V-SCANNER` 必须**全大写**，字距 `-0.04em`，行高 `0.86`，不允许拆成两种颜色。
- `font-stretch` 只作用于拉丁字母；给中文容器单独写 `font-stretch: 100%`。
- 中文标题字重 500，字距 `0.01em`；正文 400，行高 1.7。
- 大标题与正文之间至少留 40px；全大写小标签全页最多 2 处。
- 数字一律 mono + `tabular-nums`，防止进度跳动时宽度抖动。

字号阶梯（写死，不要临时加档）：

```css
--fs-display: clamp(56px, 8.9vw, 132px); /* 仅首页 V-SCANNER */
--fs-brand:   56px;                      /* 工作台初始品牌 */
--fs-title:   24px;                      /* 内页标题 */
--fs-stage:   28px;                      /* 流程当前阶段 */
--fs-cover:   17px;                      /* 书封面标题 */
--fs-body:    13.5px;
--fs-sm:      11.5px;
--fs-micro:   10px;                      /* 全大写，字距 .18em */
```

---

## 3. 布局栅格

- 12 列，`gap: 24px`，左右安全边距 `--pad-x`。
- 首页不使用卡片栅格，只有**不规则舞台面板 + 凹槽竖排 + 页脚角标**三个锚点。
- 工作台：`rail 76px` + 主区；主区内容最大宽度 `880px`，水平居中。
- 所有分区分隔只用 `1px solid var(--line)`；不用阴影表达层级，用**亮度与模糊**。
- 允许的阴影只有一种：`0 24px 80px rgba(0,0,0,.45)`，仅用于浮层（书封面、结果卡）。

断点：

| 断点 | 变化 |
| --- | --- |
| `≤1180px` | 首页巨字 `8.2vw`；流程层吃满舞台；书脊 40×240 |
| `≤860px` | rail 变底部 64px tab bar；隐藏凹槽与竖排字；书架改可横滚 |
| `≤560px` | 巨字取下限 56px；拖拽区高 112px 且宽 100%；流程层贴边（radius 0） |

---

## 4. 首页 `index.html`

### 4.1 结构线框（1440×900）

```
      ┌──────────────────────────────────────────────────────┐╮   ← 面板 inset 20px
      │ ◈ V-SCANNER                          仅用于授权测试   ││
      │                                                      ││
      │  V-SCANNER                                           ││ ← 128px
      │                                                      ╎│╎  ← 凹槽（64×160）
      │  移动应用数据安全审计                                  ╎│╎    竖排落款
      │                                                      ││
      │  ┌────────────────┐                                  ││
      │  │ 进入工作台    → │                                  │╲    ← 右下 45° 切角
      │  └────────────────┘                                   ╲   ← 80px
      │ 2026 · 移动应用审计                                    │
      └──────────────────────────────────────────────────────┘
```

面板是一块**不规则形状**：整体内缩 20px（上下 44px），右侧在 `y 300–460` 处挖掉 64×160 的凹槽，
右下角 45° 切掉 80px。缺口里露出的是更黑的 `body` 底色 `#030507`，所以"缺了一块"看得见。

### 4.2 形状（clip-path，百分比）

```css
.stage-panel {
  position: fixed; inset: 0;
  clip-path: polygon(
     3.06%  4.90%,  96.94%  4.90%,
    98.61%  7.55%,
    98.61% 33.33%,
    94.17% 33.33%,
    94.17% 51.11%,
    98.61% 51.11%,
    98.61% 87.78%,
    93.06% 95.11%,
     3.06% 95.11%,
     1.39% 92.44%,
     1.39%  7.55%
  );
  background: url("assets/hero-bg.jpg") center right / cover no-repeat, var(--bg);
}
```

- **面板四角一律直角**：`clip-path` 与 `border-radius` 同时用会互相切。
- 凹槽宽度用 `clamp(48px, 4.4vw, 64px)`；`≤860px` 换成不带凹槽的六边形，竖排字隐藏。
- 缺口里**不能有内容**（会被裁掉）。竖排字是面板的**兄弟节点**：

```css
.notch-tag {
  position: fixed; right: 0; top: 33.33%; height: 17.78%; width: clamp(48px, 4.4vw, 64px);
  display: flex; align-items: center; justify-content: center;
  writing-mode: vertical-rl;             /* 拉丁字母会顺带旋转 90° */
  font: 500 9.5px/1 var(--font-mono);
  letter-spacing: .34em; color: var(--paper-3);
  background: #030507;                   /* 与 body 同色，像刻在底上 */
  pointer-events: none;
}
```

### 4.3 尺寸与位置

| 元素 | 规格 |
| --- | --- |
| `.masthead` | `position:fixed; top:0; height:88px; padding:0 56px`，两端对齐 |
| `.hero` | `min-height:100svh`，`padding:0 56px`，`display:flex; flex-direction:column; justify-content:center` |
| `.hero-mark` | 36×38 线性盾形 SVG，`opacity:.72`，距标题 40px |
| `h1.display` | `font-size:var(--fs-display)`，`line-height:.86`，`letter-spacing:-.04em`，`font-stretch:112%`，`white-space:nowrap` |
| `.lede` | 距标题 52px，15px/1.5，`color:var(--paper-2)`，**只有一行** |
| `.cta` | 距副标题 46px，196×52，`border-radius:0`，白底 `#F2F4F6`，字 `#06080B`，12.5px/500，字距 `.08em` |
| `.cta svg` | 16×16，距文字 22px；hover `translateX(4px)`，200ms |
| `.authorized` | 右上，11px `--paper-3`，左侧 `1px solid var(--line-2)` 竖线，`padding-left:14px` |
| `.corner-note` | `left:24px; bottom:16px`，9px mono，`--paper-4` |

### 4.4 文案（照抄，不要改写）

- 左上品牌：`V-SCANNER`（mono 10px，字距 .22em）
- 右上：`仅用于授权测试`
- 主标题：`V-SCANNER`
- 副标题：`移动应用数据安全审计`
- CTA：`进入工作台`
- 右侧竖排：`AUTHORIZED TESTING ONLY`
- 左下角标：`2026 · 移动应用审计`

**不许加**：规则条数、阶段数、AAOS、车载、KPI、状态栏、"静态剖析/动态采集"排比。

> v2 的底栏（`44 车载规则 / 223 移动规则 / 16 审计阶段`）与本版定位冲突，整条删除。

### 4.5 背景层（从上到下）

```html
<div class="bg">
  <div class="bg-image"></div>   <!-- 图片 + 缓慢缩放 -->
  <div class="bg-veil"></div>    <!-- 左侧压暗 + 暗角 -->
  <div class="bg-grain"></div>   <!-- 噪点 -->
</div>
```

```css
.bg { position: fixed; inset: 0; z-index: 0; overflow: hidden; background: var(--bg); }
.bg-image {
  position: absolute; inset: -2%;
  background: url("assets/hero-bg.jpg") center right / cover no-repeat;
  transform: scale(1.06);
  animation: bg-drift 28s var(--ease-io) infinite alternate;
  will-change: transform;
}
@keyframes bg-drift {
  from { transform: scale(1.06) translate3d(0, 0, 0); }
  to   { transform: scale(1.12) translate3d(-1.2%, -0.8%, 0); }
}
.bg-veil {
  position: absolute; inset: 0;
  background:
    linear-gradient(90deg, rgba(5,7,10,.94) 0%, rgba(5,7,10,.78) 34%, rgba(5,7,10,.30) 66%, rgba(5,7,10,.58) 100%),
    radial-gradient(120% 90% at 50% 45%, transparent 40%, rgba(5,7,10,.55) 100%),
    linear-gradient(180deg, rgba(5,7,10,.85) 0%, transparent 22%, transparent 78%, rgba(5,7,10,.92) 100%);
}
.bg-grain {
  position: absolute; inset: 0; opacity: .05; mix-blend-mode: overlay;
  background-image: url("data:image/svg+xml,...feTurbulence...");
}
```

`prefers-reduced-motion: reduce` 时停掉 `bg-drift`，保留静态帧。

### 4.6 入场动效（只做一次编排）

1. `h1` 外层 `overflow:hidden`，内层 `translateY(108%) → 0`，900ms `--ease-out`，延迟 100ms。
2. 副标题：`opacity 0→1` + `translateY(12px→0)`，700ms，延迟 320ms。
3. CTA：同上，520ms，延迟 460ms。
4. 角标与竖排字：仅 `opacity`，800ms，延迟 640ms。

禁止：逐元素 `fade-in-up` 扫过全页、视差滚动、鼠标跟随的 3D 倾斜。

**纯 CSS 实现，不依赖 GSAP**。`landing.js` 只保留 `enterDashboard()` / `enterPipeline()`，
删除 GSAP 引用与 3s 兜底。

---

## 5. 工作台 `app.html`

### 5.1 结构线框（1440×900）

```
┌──────┬──────────────────────────────────────────────────────────────┐
│  ◈   │ 当前样本  未选择                            ● 127.0.0.1:8771   │ 64
│──────┼──────────────────────────────────────────────────────────────┤
│  ⚡   │                                                              │
│ </>  │                        V-SCANNER                             │
│  ⌕   │                          一键审计                              │
│  ◔   │        ┌──────────────────────────────────────┐              │
│  ✦   │        │  ↑  拖入 APK              [ 选择 ]   │  640×128     │
│  ▤   │        └──────────────────────────────────────┘              │
│      │              16 STAGES · OBSERVE ONLY                        │
│ 授权 │                                                              │
└──────┴──────────────────────────────────────────────────────────────┘

拖入后（同一块舞台换内容，页面不长高）：
┌──────┬──────────────────────────────────────────────────────────────┐
│  ◈   │ 当前样本  com.example.apk                    ● 127.0.0.1:8771  │
│──────┼──────────────────────────────────────────────────────────────┤
│  ⚡   │                      V-SCANNER                               │
│ </>  │                   AUDIT IN PROGRESS                          │
│  ⌕   │   ┌────────────────────────────────────────────────────┐     │
│  ◔   │   │ AUDIT · 03 / 16                            00:41   │     │
│  ✦   │   │ 静态剖析                                            │     │
│  ▤   │   │ ▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬▬  16 段进度轨                       │     │
│      │   │ ┌──────────────────────────────────────────────┐   │     │
│ 授权 │   │ │ ● 正在反编译                                  │   │     │
│      │   │ │   1 284 / 4 844 classes                      │   │     │
│      │   │ └──────────────────────────────────────────────┘   │     │
│      │   │ ✓ 环境准备                                  0.4s  │     │
│      │   │ ✓ 模拟器就绪                                8.1s  │     │
│      │   └────────────────────────────────────────────────────┘     │
└──────┴──────────────────────────────────────────────────────────────┘
```

### 5.2 左侧 rail（核心要求：图标"尽量透明"）

| 项 | 规格 |
| --- | --- |
| 宽 | `76px`，hover 展开 `212px`，`transition: width 260ms var(--ease-out)`；`position:fixed; z-index:40`，展开时覆盖内容而不是挤压主区 |
| 背景 | `rgba(8,10,14,.52)` + `backdrop-filter: blur(24px) saturate(120%)` |
| 边框 | 只留右边 `1px solid var(--line)` |
| 图标 | 20×20，`stroke-width:1.25; fill:none`，默认 `opacity:.34` |
| hover | 图标 `opacity:1`，背景 `rgba(255,255,255,.03)`，160ms |
| active | 图标 `opacity:1` + 左侧 2px 白色竖条 + `radial-gradient` 微光 `.06`；文字转 `--paper` |
| 文字 | 12px `--paper-3`；收起时 `opacity:0; translateX(-6px)`，展开时出现 |
| 底部 | `仅用于授权测试`，10px `--paper-4` |

六个导航项（保持 `.nav-item[data-page]`，图标取自 `skills/lucide/icons/`）：

| data-page | 文案 | 图标文件 |
| --- | --- | --- |
| `pipeline` | 一键审计 | `zap.svg` |
| `source` | 源码查看 | `code-xml.svg` |
| `static` | 静态审计 | `scan-search.svg` |
| `dynamic` | 动态审计 | `activity.svg` |
| `ai-report` | AI 报告 | `sparkles.svg` |
| `pdf-report` | PDF 报告 | `file-text.svg` |

### 5.3 舞台三态（idle / running / done）

| 状态 | 品牌 | 拖拽区 | 流程层 | 结果 |
| --- | --- | --- | --- | --- |
| `idle` | 56px | 可见 640×128 | 被 JS `display:none` | 隐藏 |
| `running` | 18px + `AUDIT IN PROGRESS` | `opacity:0; scale(.985)` | `scale(.92)→1`，`opacity 0→1` | 隐藏 |
| `done` | 18px | 不可见 | `opacity:0`（200ms）后 `visibility:hidden` | `translateY(12px)→0` |

- 品牌切换用**两套节点交叉淡入**，不要用 `font-size` 过渡（会抖）。
- 流程层是 `.stage-slot` 里的绝对定位层（`inset:0`），而 `.stage-slot` 的高度**恒等于流程层高度**
  （`min-height: min(560px, calc(100svh - 240px))`），所以拖入前后页面高度一致、不重排、不跳滚动条。
- `done` 时不要清空 `#pipeline-timeline`，`app.js` 每次事件都会重建它；
  我们只让它淡出。

### 5.4 "做到哪里显示哪里"

`app.js` 给每条阶段加的类名是 `pl-pending / pl-running / pl-done / pl-failed / pl-skipped`
（**不是** `.pipeline-card`；`.pipeline-card` 只用于结果卡）。

```css
#pipeline-timeline > .pl-pending { display: none; }                 /* 未来：不渲染 */

#pipeline-timeline > .pl-done,
#pipeline-timeline > .pl-skipped {
  display: grid; grid-template-columns: 16px 1fr auto; align-items: center;
  gap: 10px; height: 34px; padding: 0 2px;
  border-bottom: 1px solid rgba(255,255,255,.05);
  font-size: 12.5px; color: var(--paper-3);
}
#pipeline-timeline > .pl-done .pl-msg { display: none; }            /* 旧消息不占地方 */

#pipeline-timeline > .pl-running {
  position: relative;                                        /* 高光线的定位基准 */
  display: block; margin: 14px 0 10px; padding: 22px 24px 24px;
  border: 1px solid var(--line-2); border-radius: 10px;
  background: rgba(255,255,255,.03);
  animation: stage-in 220ms var(--ease-out) both;
}
#pipeline-timeline > .pl-running .pl-label { font-size: 28px; line-height: 1.2; color: var(--paper); }
#pipeline-timeline > .pl-running .pl-msg   { margin-top: 10px; font: 400 12px/1.6 var(--font-mono); color: #7FB9C4; }
```

**因为 DOM 每次事件都整体重建，只能给 `.pl-running` 加入场动画**；给 `.pl-done` 加会导致
所有历史行每 300ms 集体闪一次——这是本版最容易踩的坑。

### 5.5 16 段进度轨

静态写 16 个 `<i>`，用 `--p` 驱动透明度（补丁只写一个变量）：

```html
<div class="stage-rail" data-rail aria-hidden="true">
  <i style="--i:0"></i> … 共 16 个 …
</div>
```

```css
.stage-rail { display:flex; gap:5px; }
.stage-rail i {
  flex:1; height:3px; background: rgba(255,255,255,.12);
  opacity: clamp(.12, calc((var(--p, 0) - var(--i)) * 6), 1);
  transition: opacity 200ms linear;
}
```

不要试图用 CSS 去数 16 个 `<li>`，数不出来。

### 5.6 右侧五个内页

统一骨架，**不许卡片套卡片**：

```html
<header class="page-head">
  <h2>静态审计</h2>
  <div class="page-meta"><span class="mono">com.example.apk</span><span>128 findings</span></div>
</header>
```

| 规则 | 值 |
| --- | --- |
| `.page-head` | 高 72，底部 1px `--line`；标题 24px；meta 11px mono `--paper-3` |
| 内容区 | `max-width:1080px; margin:0 auto; padding:40px var(--pad-x) 64px` |
| 卡片 | 全部拆掉，用 1px 行线 + 8px 行距分区 |
| 表格 | 无斑马纹；表头 10.5px 全大写 `--paper-3` 字距 `.12em`；单元格 12.5px，`padding:12px 14px` |
| 徽标 | 透明底 + 1px 同色边框 + 同色字，10.5px，radius 2（不要实心胶囊） |
| AI 报告 | 正文 `max-width:74ch`，14px/1.8；section 之间只一条发丝线 |
| 源码页 | `grid-template-columns:300px 1fr`；文件树行高 30；代码区 `#07090C`，12.5px/1.75 mono |

工作台背景：复用 `hero-bg.jpg`，`filter: brightness(.42) saturate(.85) blur(1.5px)`，
再叠 `radial-gradient(90% 70% at 50% 30%, transparent, rgba(5,7,10,.72))`。

---

## 6. 历史报告 · 扇形书架

### 6.1 三态

| `#page-pdf-report[data-state]` | 画面 | 交互 |
| --- | --- | --- |
| `browse` | 四本书脊立在搁板上，绕底部中心 `−21° / −7° / +7° / +21°` | hover 抬起 6px 且归正；`←/→` 移动；`Enter` 抽出 |
| `open` | 选中的那一册放大成 296×400 封面，其余变暗下沉 | `Esc` 回 `browse`；「打开 PDF」进 `reading` |
| `reading` | `#pdf-viewer-container` 占满舞台，左上「← 返回书架」 | 返回回 `open` |

### 6.2 几何

| 部件 | 规格 |
| --- | --- |
| 搁板 | 1.5px 渐变线（两端透明），下方 24px 深色带 |
| 书脊 | 44×280，`border-radius:2`，`1px #2A3540`，左侧 1px 竖向高光，顶部 14px 处 1.5px 青线 |
| 书签 | 最新一册：8×34 的 `--live` 竖条，`opacity:.75`，从书脊顶端探出 11px |
| 书脊文字 | `writing-mode: vertical-rl`，mono 8px `--paper-3`；文件名靠右、日期靠左 |
| 封面 | 296×400，radius 3，`1px #3A4753`，左侧 3px `--live` 竖条，右缘两条 5px 斜切做内页厚度 |
| 数量 | 有几份 PDF 就几本；> 7 本改横向滚动，**不要**缩到 30px 以下 |

### 6.3 数据来源（不许编）

只读现有 `#pdf-select` 的 option：一本书 = 一个 option。点击回写 `select.value` 并
`dispatchEvent(new Event('change'))`，之后交给 `loadPdf()`。

- 封面只允许写：报告名、文件名、两个动作。
- **不许**渲染风险数、页数、通过率——接口没返回，写了就是造假。

### 6.4 动效

```css
.shelf-book { transition: transform 280ms var(--ease-out), opacity 280ms var(--ease-out); }
.shelf-book:hover, .shelf-book:focus-visible { transform: rotate(0deg) translateY(-6px); }
[data-state="open"] .shelf-book:not(.is-active) { transform: translateY(8px) scale(.98); opacity: .30; }
```

要求是"从书架抽出"的**连续**感：不允许 `display:none` 硬切，不允许 `position:fixed` 的 modal 遮罩。

---

## 7. 自查清单（截图前逐条打勾）

- [ ] 首页面板右侧的凹槽与右下切角看得出来；缩到 25% 仍不是方角矩形
- [ ] 凹槽里的竖排字没被裁、没压边
- [ ] 首页可见文字块 ≤ 3 个；没有 AAOS / 车载 / 规则条数
- [ ] 标题单行；右边缘没越过 39%
- [ ] 拖入 APK 后页面没有纵向跳动；拖拽区确实消失
- [ ] 流程里未来阶段不可见；只有当前阶段是"卡"
- [ ] 阶段推进时没有历史行集体闪动
- [ ] 书架四册底边不在同一直线（是扇形）
- [ ] 点第 2 本加载的是第 2 个 option 的 value
- [ ] 全屏彩色像素 < 2%；没有紫蓝渐变残留
- [ ] 1440×900 与 390×844 都无意外滚动条
