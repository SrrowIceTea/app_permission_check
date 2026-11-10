# Web 可视化预警看板（vehicle/dashboard，原 Phase 6）

**仅用于授权测试（自有设备与自有 APK）。** 看板只展示 Phase 5 的落盘结论，
不发任何网络请求、不改任何数据。**已完成。**
决策见 `DECISIONS.md`（D601–D606），全局约束见根 `CLAUDE.md`。

对应申报书第 125 / 138 段的「Web 端可视化预警看板」。读的是**事后**产物
（findings.jsonl + summary.json + codeloc-verify.json），不是实时采集通道——
实时回传在采集侧已由 vehicle/hooks 的 `send()` 实现（D601）。

## 目录

| 路径 | 作用 |
| --- | --- |
| `dashboard.py` | 生成器：读 vehicle/analyze 产物 + 规则库元信息，内嵌进模板（CLI） |
| `template.html` | 页面外壳与三个占位标记 |
| `style.css` | 全部样式：深浅两套色板**按角色声明**（取自 dataviz skill 参考实例） |
| `ui.js` | 常量表（等级/类型/严重度中文标签、dex 徽章映射）+ DOM 小工具 |
| `render.js` | 各区块渲染：KPI / 分布条 / 证据链 / 逐条结论表 / 边界 |
| `test_dashboard.py` | 离线回归，8 用例，**不需要浏览器** |
| `evidence/` | 实测轮生成物 + 浅色截图 |

## 怎么跑

```bash
cd vehicle/dashboard
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...
"$PY" dashboard.py --findings ../analyze/logs/findings.jsonl \
    --summary ../analyze/logs/findings.summary.json \
    --verify ../analyze/logs/codeloc-verify.json \
    --rules ../rules/rules_library/rules.db \
    --out dashboard.html          # 已存在会拒绝覆盖，重生成加 --force

"$PY" -m unittest test_dashboard  # 8 用例
node --check render.js ui.js      # 语法检查
```

产出 42 KB 单文件，**双击即开、断网可用**：样式、脚本、数据全部内嵌，页面顶部已声明不发网络请求。

## 本目录的坑

- **必须是静态单文件**（D601），三个约束同时成立：实时通道已由 vehicle/hooks 的 `send()` 实现，
  看板是事后视图；本网络 `dl.google.com` 不通（CDN 拉不下来）；Chrome 禁止从 `file://`
  发 `fetch()` 且禁止加载 ES module → 数据必须内嵌、脚本必须是经典 IIFE。
- **数据内嵌必须转义 `<`**（D602）：数据里出现 `</script>` 会提前结束脚本块并静默击穿。
  文件路径、异常消息这些**不可信数据**完全可能带 `<`。用
  `json.dumps(...).replace("<", "\\u003c")`。
- **渲染零 `.innerHTML` 赋值**（D603）：全部 `textContent`。测试查的是真正的赋值用法
  （`re.search(r"\.innerHTML\s*=")`），不是注释里出现的那个词。
- **`render.js` 曾贴着 300 行上限**，拆成 `ui.js`（配置与工具）+ `render.js`（区块渲染），
  经 `window.VSCAN_UI` 共享——因为 `file://` 下不能加载 module。
- **色板 validator 的两项 FAIL 是设计如此**（D604）：状态色 warning/serious 在浅色面上的
  对比度与相邻 ΔE 低于 validator 的**分类色**门槛。缓解＝图标 + 文字标签、2px 表面间隙、
  直接标签与表格视图——**状态色永不单独表意**。段内标签按填充亮度取白或黑
  （critical 红段必须白字，实测修过：暗色墨在 `#d03b3b` 上只有约 2.5:1）。
- **筛选是"强调"，不是"重计算"**（D605）：筛掉某级时该级的段、图例、tile 是**变灰 ghost**
  而不是消失——不重算颜色（recolor-on-filter 是反模式，颜色必须跟着实体走，不跟排名走）。
- **排序按结论等级**（correlated 最上），与 `report.py` 的严重度优先**故意不同**（D606）。
- **证据链只画 pairs 的 `delta_ms` 相对比例，不碰绝对时间轴**——跨时钟对齐是 D306 的坑。
- **深色主题用 CSS 变量双声明 + `data-theme` 显式切换**压过系统偏好。
  验证靠计算样式探针或 headless Chrome `--dump-dom` 查处渲染后的 DOM，
  **不要靠读截图**（图像回读曾间歇性失败，会让人误判成"深色模式坏了"）。

## 状态（2026-09-24）

自包含看板继续展示结论、证据链、dex核对和深浅主题。
新增会话/时间基准/无规则属性提示（extras.js），风险颜色补纹理与forced-colors边框。
展示数目及徽章取决于本轮输入，不硬编码旧的10条/6个位置。
任何新增区块应拆文件保持<=300行，不产生或暗示policy_violation。
