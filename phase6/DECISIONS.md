# Phase 6 设计决策

## D601 静态单文件，不是 WebSocket 实时服务

申报书（第 106 段）的 WebSocket 通道服务的是**采集时**回传事件——那段已经由
phase3 的 `send()` → run.py 落盘实现了。看板是**事后**视图：输入是 phase5 落盘的
findings/summary/verify，输出一份自包含 HTML。

静态页还躲开两条本环境的硬约束：

1. `dl.google.com` 不通 → 任何 CDN 图表库（Chart.js 等）都拉不下来，看板必须手绘；
2. `file://` 下浏览器禁止 `fetch()` → 数据必须**内嵌**，不能外置 JSON 再读。

代价明说：没有实时刷新（重跑 `dashboard.py` 即重新生成）、没有服务端聚合。
对"审计一轮 → 出看板 → 演示/复核"的用法，这个代价换来了双击即开、断网可用。

## D602 数据内嵌的转义：`</script>` 会静默击穿脚本块

结论里的 `note`、文件路径、异常消息是**不可信数据**（它们来自被测 APK 的运行时
栈与载荷）。若其中出现 `</script>`，内嵌的 JSON 会提前结束脚本块，之后的渲染
脚本全部失效——页面白屏，不报错。修法是 `json.dumps(...).replace("<", "\\u003c")`：
JSON 字符串里的 `<` 在 JS 解析时还原成 `<`，但永远不会形成字面 `</script>`。

`test_dashboard.py` 里钉死两件事：恶意载荷不出现字面 `</script>`，且还原后与原文字逐
字相等。这是看板唯一的注入面，其余数据流（模板标记替换）不含数据。

## D603 渲染全部走 textContent，零 innerHTML 赋值

`render.js` 里没有一处 `.innerHTML =`。包名、权限名、文件路径全部经
`createElement` + `textContent` 写入。与 D602 是同一原则的两道防线：
D602 防脚本块击穿，D603 防 DOM 注入。测试钉死的是**赋值用法**的缺席
（注释里出现这个词不算数——第一版测试就误报过一次）。

## D604 状态色板 = dataviz skill 参考实例；validator 的两项 FAIL 是设计如此

色板一字未改地取自 dataviz skill 的 `palette.md`（状态四色 + 蓝系顺序色 + 表面/墨色）。
用它自带的 validator 实测了看板实际用到的四个状态色：

```
light: [FAIL] Lightness band（#fab219 出带）· [FAIL] 相邻正常视觉 ΔE 13.6（warning↔serious）
       [WARN] 对比度 #ec835a=2.57 / #fab219=1.79
dark:  [FAIL] Lightness band（#ec835a / #fab219 出带）· [FAIL] 相邻 ΔE 13.6
```

两项 FAIL 的缓解在 palette.md 里就是写明了的：**状态色永不单独表意**，必须配
图标+文字标签。看板的落实：徽章永远带图标+中文标签；分布条相邻段之间有 2px
表面间隙 + 段内直接标签 + 图例 + aria-label + 悬浮提示 + 表格视图。

validator 顺带暴露了一个真问题，已修：分布条段内标签原先统一用黑字，而
`critical` 红段上黑字对比度只有约 2.5:1。palette.md 的唯一例外条款规定"段内标签
按填充亮度取白或黑"——现按等级取色（critical 白 / 其余黑）。

**已知缺口（不假装没有）**：纹理通道（CVD/打印/forced-colors 的备援填充）未实现。
当前的身份通道是图标+文字+表格，够用但不如纹理完备。

## D605 筛选是"强调"，不是"重计算"

筛选 chips 收窄逐条结论表；分布条、图例、KPI tile 对被筛掉的等级是**变灰
（ghost，opacity 0.25）而不是移除**。理由：强调（highlight one, gray the rest）
是 dataviz 方法里专门对付"单一序列才是重点"的形式，且避免了两个反模式——
筛掉后重排颜色会让读者已建立的"红=已关联"记忆失效（recolor-on-filter），
而移除后只剩单段时又退化成 one-bar chart。数值从头到尾不重算，天然一致。

## D606 排序按结论等级，不按严重度

PDF 报告（report.py）按严重度优先排序；看板按 `correlated > observed > candidate`
排。同一份数据两种排序**不是不一致**：报告是文档，读者从头读；看板是预警，
最强证据链（读取+外发+内容匹配）应该在最上面。此差异已在此注明，避免被当成 bug。

## 未验证 / 边界

- 看板只在 headless Chrome 上做过实渲染检视（浅色截图 + 两套计算样式探针），
  未在真实车机浏览器上打开过。CSS 用的是标准网格与 flex，风险低但非零。
- 事件级时间轴（读取/外发事件按绝对时刻排布）**未做**：需要把设备时钟与
  主机时钟对齐（summary 的 `clock_offset_ms`），而跨时钟拼时间轴是个已知的
  误导源（D306）。看板的证据链按 pairs 的 `delta_ms` 画相对比例，不碰绝对时间。
- 悬浮提示依赖 JS；禁用 JS 时看板仍是完整表格视图（所有值都在 DOM 里）。

## D607 按事件显示核对结果与主题作用域（2026-09-25）

同规则同role可能有多个事件，dex徽章还必须匹配event_id；不能拿第一条结果覆盖其余事件。
native回调无行号保留定位缺口，不展示虚假的VERIFIED。
颜色变量原来只定义在.viz-root，body与悬浮提示无法继承；改为:root并实测整页背景变化。
纹理需与.badge.s-*同等选择器优先级，否则background简写会覆盖background-image。
88项离线回归之外，新增真实headless Chrome深浅主题、筛选、38个事件级徽章、缺口与纹理检查。
PDF共12页、8张载荷图，页码与中文回读通过；仍需逐页视觉检查。
旧“禁用JS仍有完整表格”不准确：表格由JS渲染，禁用JS不支持。

## D608 审计复核工作台（2026-09-25）

用户选择优先结论检索、证据与代码定位。使用已安装 Impeccable 的 Operate 规范，继承既有色板与离线契约，新增侧栏、会话概览、组合筛选与可展开明细。
Taste v2 明确不面向数据看板，因此不套用营销页布局/动画；仅采用先读任务与遵从既有项目约束的原则。
Impeccable context 引擎因未缓存且缓存目录受限无法运行，依其 fallback 直接读取项目上下文。

结论表从 render.js 拆为 findings.js，工作台样式/交互独立为 workspace.css/workspace.js。
代码定位仍按 rule_id + role + event_id 匹配，依据逐条显示 basis_refs/source_refs 原始记录。
修复等级关闭两项或三项时分布不变灰的问题；分布条用 backgroundColor 保留纹理。
绿色核对徽章改用深色文字提高对比度。打印自动展开明细，避免来源内容因滚动容器截断。

使用原交付 16 条真实结论重新生成独立 output/frontend-review/dashboard.html，不覆盖旧交付。
全量离线回归通过；22 项浏览器行为检查在深浅主题及精确 390px 视口通过。
手机保留横向表格而非挤压七列，屏幕内正文不横向溢出。
