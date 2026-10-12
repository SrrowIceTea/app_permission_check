# 审计复核工作台（vehicle/dashboard，原 Phase 6）

仅用于授权测试（自有设备与自有 APK）。展示 Phase 5 的落盘结论，不发网络请求、不修改证据、不产出违规判决。

## 打开与使用

当前前端：[审计复核工作台](../output/frontend-review/dashboard.html)。双击 HTML 可离线打开，需要启用 JavaScript。

- 搜索规则 ID、权限、属性、源码文件或方法，并组合规则类型与结论等级筛选。
- 展开“代码位置”查看读取处/外发处、事件级 dex 核对及定位缺口；带缺口的结论在折叠标题中提示。
- 展开“规则依据”查看原始判定依据与来源记录，未提供的依据明确标示缺失。
- 下方证据链与筛选同步，概览统计始终保留本轮总数。
- 支持深浅主题、键盘操作与窄屏横向表格。打印当前筛选视图时自动展开依据和代码位置，打印后恢复。
- 左侧导航定位概览、结论、证据链、规则覆盖、方法边界。

当前演示输入来自 `output/delivery-20260924-193039/`：16 条结论，5 已关联、5 已观测、6 候选，38 个 VERIFIED 定位徽章和 2 处定位缺口。不是新采集会话，也不是实时监控。

## 重新生成

在项目根执行：

```powershell
. .\environment.ps1
& $VScanPython vehicle/dashboard/dashboard.py `
  --findings output/delivery-20260924-193039/findings.jsonl `
  --summary output/delivery-20260924-193039/summary.json `
  --verify output/delivery-20260924-193039/dex-verification.json `
  --rules vehicle/rules/rules_library/rules.db `
  --out output/frontend-review/dashboard.html --force
```

更换输入即可生成其他会话的独立 HTML。省略 `--verify` 时不展示 dex 核对徽章；省略 `--rules` 时规则库元信息标示未提供。不要混用不同会话输入。

## 源文件职责

| 文件 | 作用 |
| --- | --- |
| dashboard.py | 读取审计文件、转义 JSON、内嵌样式与脚本 |
| template.html | 语义页面、导航、搜索控件 |
| style.css | 原有状态色、深浅主题与证据图形 |
| workspace.css | 操作型布局、响应式、交互与打印 |
| ui.js | 常量、DOM 工具与组合筛选条件 |
| render.js | 总览、等级分布、证据链、边界 |
| findings.js | 逐条结论、事件级定位、规则依据 |
| extras.js | 规则覆盖、时间基准、会话 |
| workspace.js | 搜索、类型、重置、导航与打印行为 |

源码单文件不超过 300 行；生成的自包含 HTML 是拼接产物。经典脚本 IIFE，无外部库和 CDN。

## 验证

```powershell
& $VScanPython tools/run_regressions.py
& $VScanPython tools/verify_frontend.py
node tools/verify_frontend_viewport.mjs
```

浏览器验证使用本机 Chrome 与独立测试 profile，不读取个人浏览数据。
`verify_frontend.py` 验证真实数据、组合筛选、空状态、展开、注入防护、主题、打印状态恢复；
`verify_frontend_viewport.mjs` 精确设置 390px 移动视口，避免 Chrome 命令行窗口最小宽度影响截图。
结果与截图位于 `output/frontend-review/`，通过状态见 `verification.json` 与 `viewport-verification.json`。

## 边界

静态事后视图；更新数据必须重新生成。时间相邻不证明外泄，内容匹配不证明具体属性值泄露，dex 行号不证明违规语义。
缺少证据不能推断安全；native TLS 和未解析协议没有明文能力。旧版实测记录见 DECISIONS.md。
