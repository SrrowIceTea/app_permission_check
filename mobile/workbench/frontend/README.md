# Permission Lab · 移动应用隐私审计工作台

新增的移动端产品入口，复用 core 静态内核与 MOB 规则。前端独立在 mobile/workbench/frontend/，不覆盖根 frontend/ 车载工作台；默认端口 8771。

## 启动（项目根目录，PowerShell）

```powershell
python mobile/workbench/server.py --port 8771
```

在浏览器打开 `http://127.0.0.1:8771/app.html`。前端与 API 同源，无 CDN、远程字体或构建工具依赖。
静态扫描需要 Android SDK 的 `aapt2`、`dexdump`；源码反编译另需 JADX 与 Java。
缺少 JADX 时静态扫描仍可完成，界面明确展示反编译缺口。

## 工作流

1. **任务总览**：上传 APK，或导入 `mobile/ai/evidence_bundle.py` 生成的 JSON。依赖就绪状态来自本机服务。检测执行面板可显式枚举设备、选择设备并授权运行固定自有 Gadget 夹具；默认不探测、不采集。
2. **静态发现**：查看、搜索、筛选规则命中；展开原始证据。静态结论封顶候选，不等于实际收集或违规。
3. **动态证据**：浏览本任务采集或导入的敏感读取、权限/政策事件、网络流与钩子健康。空返回不计为取得数据；打开政策不视为接受政策。
4. **政策与研判**：展示政策原文及检查信息；已有 AI 输出须通过本地阶段校验。失败阶段不显示为有效结论。
5. **报告中心**：基于当前任务证据包生成新 PDF、预览、独立打开。项目中已有的 PDF（若存在）明确标为历史快照，不是本轮产物；本提交不新增 PDF 或预览图片。

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

前端离线检查：`node mobile/workbench/frontend/test_workflow_model.mjs`、`node mobile/workbench/frontend/test_job_model.mjs`；浏览器验收需使用移动端同源服务。
