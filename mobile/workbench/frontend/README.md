# Permission Lab · 移动应用隐私审计工作台

新增的移动端产品入口，复用 core 静态内核与 MOB 规则。前端独立在 mobile/workbench/frontend/，
由工作台服务同源托管；**根 `frontend/` 是另一套「一键审计」前端**（对接 `mobile/pipeline`），
两者互不覆盖；默认端口已错开——工作台 **8772**，一键审计 **8771**，可以同时起。

## 启动（项目根目录，PowerShell）

```powershell
python mobile/workbench/server.py
```

在浏览器打开 `http://127.0.0.1:8772/app.html`。前端与 API 同源，无 CDN、远程字体或构建工具依赖。
静态扫描需要 Android SDK 的 `aapt2`、`dexdump`；源码反编译另需 JADX 与 Java。
缺少 JADX 时静态扫描仍可完成，界面明确展示反编译缺口。

## 工作流

1. **任务总览**：上传 APK，或导入 `mobile/ai/evidence_bundle.py` 生成的 JSON。依赖就绪状态来自本机服务。检测执行面板可显式枚举设备、选择设备并授权运行固定自有 Gadget 夹具；默认不探测、不采集。
2. **一键审计**：在任务页对已上传 APK 触发 `POST /api/tasks/{id}/audit`，服务端按
   `static → policy → capture → correlate → bundle → ai → report` 串联（阶段清单见
   `mobile/workbench/report_ai.py` 的 `STAGES`）；前提是 `workflow.can_audit=true` 且正控自检通过。
   视图逻辑在 `js/audit-view.js` + `js/audit-model.js`，契约回归 `test_audit_model.mjs`。
   后端能力与限制见 `../README.audit.md`。
3. **静态发现**：查看、搜索、筛选规则命中；展开原始证据。静态结论封顶候选，不等于实际收集或违规。
4. **动态证据**：浏览本任务采集或导入的敏感读取、权限/政策事件、网络流与钩子健康。空返回不计为取得数据；打开政策不视为接受政策。
5. **政策与研判**：展示政策原文及检查信息（含《用户协议》分册 `app_agreements`）；已有 AI 输出须通过本地阶段校验。失败阶段不显示为有效结论。
6. **报告中心**：基于当前任务证据包生成新 PDF、预览、独立打开。项目中已有的 PDF（若存在）明确标为历史快照，不是本轮产物；本提交不新增 PDF 或预览图片。
7. **基准实验**：只读视图，见下文「基准实验概览」。

### 证据导入

支持原始 bundle JSON，或 `{ "bundle": <证据包>, "ai": { "stages": { "stage1": ..., "stage2": ..., "stage3": ... } } }`。
导入数据原样留存，计数由实际条目重新计算；导入并不认证文件真实性。
设备采集需在“检测执行”面板选择设备、勾选安装运行授权并主动启动。支持服务端固定自有夹具，不支持任意第三方 APK 注入。上传 Debug 与实际采集 Gadget 是不同 APK，面板与产物分别展示 SHA256 和构建关系声明。

采集成功可自动生成本任务报告；已有导入证据也可单独生成报告，无需 AI Key。当前报告只包含工具证据，导入 AI 结果不冒充本轮模型调用。工作台不调用在线模型、不执行 Root、不装系统 CA。

取消采用合作停止：当前不可中断的命令返回后停止后续动作，并清理采集资源。重采集会撤销旧动态证据和报告的当前指针，旧文件归入尝试目录；失败、取消不显示旧报告为本轮成功。

## 前端结构

`app.html` 是同源壳；`app.js` 是入口，具体视图位于 `js/`；`app.css` 导入 `css/` 模块。
所有任务、源码、政策和证据内容均以 DOM `textContent` 渲染，不执行导入 HTML。
桌面双栏 / 移动端折叠导航，支持键盘焦点、真实空状态、失败提示。

API 契约与后端测试见 `mobile/workbench/README.md`。
运行产物默认保存在 `output/mobile-workbench/`，不提交至 Git。

前端离线检查（`tools/check_mobile_branch.py` 的 7 个 `ui_*` 组就是这七个）：
`test_workflow_model.mjs`、`test_job_model.mjs`、`test_runtime_model.mjs`、`test_evidence_model.mjs`、
`test_audit_model.mjs`、`test_benchmark_model.mjs`、`test_risk_model.mjs`；
浏览器验收需使用移动端同源服务。

> 这个前端由 `mobile/workbench/server.py` 托管（默认 8772）。根 `frontend/` 是**另一套**
> 「一键审计」前端，对接 `mobile/pipeline`（默认 8771）。两套默认端口不冲突，
> 见根 `README.md`「运行入口」。

## 基准实验概览

导航“基准实验”是独立只读视图（`app.html#benchmarks`），与某个上传任务的上下文分离。
数据来自同源 `GET /api/benchmarks`；仅展示服务发现的真实批次，没有批次时显示空状态。

- 展示批次环境、样本数、静态/安装/启动/触发/采集完成数、已报告事件数量。
- 阶段图和运行结果分布按 `samples` 重新计算，不使用批次自报汇总或论文标签。
- `observed` 表示目标事件已观察，不代表违规；`not_observed`、`unsupported`、`failed`、`not_run` 分开显示。
- 缺失事件数显示“—”，未知阶段显示未执行；不生成准确率或安全率。
- 样本支持搜索、结果筛选和证据 JSON 链接。原论文标签保留在明细，独立于运行结果。

前端契约回归：`node mobile/workbench/frontend/test_benchmark_model.mjs`。

## 风险与 AI 图表

基准实验页增加每 APK 风险分、五维覆盖、证据强度、风险分布和 AI 状态筛选。
AI 摘要仅在样本 status=ok 且 validation.passed=true 时显示；调用来源区分在线与导入。
图表按样本计数，不把 10 个样本的一次批量请求显示为 10 次模型调用。
未知维度采用未测试状态，不用零分补图。详细方法及复跑入口见 `mobile/lab/README.risk.md`。

国内真实应用静态批次与论文运行基准共用只读视图，但尚未执行的阶段仍显示未执行。
Web 页面本身不发起在线模型调用；此处展示通过命令行显式调用后保存并校验的真实结果。

前端风险契约检查：`node mobile/workbench/frontend/test_risk_model.mjs`。
