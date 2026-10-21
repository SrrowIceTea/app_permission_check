# 新版工作台：功能修复与界面优化（2026-10-19）

## 交付位置与入口

独立开发目录：`D:/AAA-Codex/shengsai_app/c1f6f4e`。
未覆盖 Downloads 原解压目录、原始 ZIP 或之前的 ch 工作目录。功能开发阶段未推送；本次按用户请求交付至远端 ch 分支。

当前预览：本机 8090 的 `/index.html` / `/app.html`，静态文件由此目录的 `frontend/` 提供。
8771 运行新版 `mobile/pipeline` 服务，不是旧 `mobile/workbench` 页面。

## 1. 功能修复

1. `mobile/lab/core_observer.py`：真实复现“Gadget hooks did not arm”，先用失败测试钉住；改为命名导入并在单一 Java bridge 中显式调用三个 `main()`。
2. `mobile/pipeline/formal_runner.py`：保持队友前端 API 与 16 阶段 SSE，适配共享 Runtime/正式核心。原始 APK 静态与政策身份绑定、本轮实际制备/安装/采集、真实模型响应与引用校验、PDF 门控全部复用，不造第二套判定引擎。
3. Root 与非 root 按真实正控分别配置。原 legacy runner 保留，不把它“有 PDF 即成功”的口径混入本轮正式模式。
4. `mobile/pipeline/history.py`：读取持久化完成任务；进程身份校验区分仍运行的其他服务与真正重启中断，防止误报完成/中断。源码树仍绑定原上传缓存。
5. 新前端 AI 页原来主要显示静态概览与通用建议，现在读取本轮已校验三阶段结果、模型请求数、引用字段和不确定性。规则风险分与 AI 评级独立显示。
6. 动态页展示实际读取、归因流量、同意/权限时序、存储/加密观察与原始证据；未知不画成 0 风险。
7. 增加“新建审计”，修复完成后无法再次上传；恢复历史任务；切换样本时同步结果；服务状态不再固定显示在线；失败不再标 AUDIT COMPLETE。
8. PDF 页新增本轮报告表，与历史示例快照分开；未通过完整门控不给成功下载入口。

## 2. 真实运行验收

| 发起方式 | 样本 | 模式 | 采集读取 / 归因流 | 真实 AI 请求（含修复） | PDF |
|---|---|---|---|---:|---:|
| 新流水线 API | LibChecker 2.5.4 | nonroot-gadget | 2 / 0 | 5 | 13 页 |
| 新流水线 API | Read You 0.16.2 | nonroot-gadget | 0 / 1 | 4 | 14 页 |
| 新流水线 API | LibChecker 2.5.4 原包 | root-emulator | 2 / 0 | 3 | 13 页 |
| 新前端选择 APK | LibChecker 2.5.4 | nonroot-gadget | 1 / 0 | 4 | 13 页 |

四轮共 16 次真实 DeepSeek 请求；两种模式真实夹具正控均通过。读取数量受有限交互窗口影响，不是恒定基准。
Read You 的 1 条流是实际加入的本地公开 RSS 测试源的 HTTP200，不冒充其生产后端业务或敏感信息泄露。
所有实际采集为本轮新生成；只复用工具、原始 APK 字节和已取得的官方政策快照，没有拿历史会话替代。

### 前端与 HTTP 验收

- 实际浏览器完成：新建审计 → 文件选择器上传 APK → SSE → 完成结果。
- 六个工作区可切换；真实源码路径过滤与 17396 字节 MainActivity.java 正文已加载。
- AI 原始结论与 5 维风险信号显示；动态页展示 R1 的应用安装列表读取，不把 0 流当作无外发。
- PDF 页显示 4 份本轮报告，同时保留 3 份明确标注“历史快照”的示例封面。
- 服务重启后四轮 `/static`、`/tree`、`/source`、`/ai`、`/bundle`、`/report`、SSE end 都通过；源码越界请求 HTTP403。
- PDF 实际下载并用 pypdf 解析页数；AI 三阶段均重新通过已有门控，不只是检查文件存在。
- 浏览器本轮 error 日志为空。

## 3. 前端优化与网络参考

保留原首页与原生零构建架构；不引 React、Vue、Tailwind、Bootstrap 运行时，也未增加 npm 依赖。

- [Tabler](https://github.com/tabler/tabler)：参考工具型导航与结果组织，不复制整套主题。
- [Lucide](https://github.com/lucide-icons/lucide)：参考统一线性图标语言，沿用现有内联图标，不加入字体图标/CDN。
- [Carbon 数据表规范](https://v10.carbondesignsystem.com/components/data-table/usage/)：参考结果表格层级、可读性与操作位置。

`frontend/workspace.css` 独立承载优化：桌面展开导航、压暗结果页背景、清晰证据表面、提高文字对比度、表格行交互/粘性表头、风险维度条、键盘焦点与减少动效支持。

截图在本机 `output/fix-20261019/frontend-ai.png`、`frontend-reports.png`。

## 4. 回归与证据

24 组离线回归通过（含新增流水线恢复与门控测试、风险未知值模型测试）；前端 DOM/CSS 契约 PASS21 / WARN0 / FAIL0；JS 语法检查通过。

证据根：`output/fix-20261019/`：
- `compile-before.log` / `compile-after.log`：同一个真实入口回归从红到绿。
- `fixture-positive/verification.json`、`root-fixture/verification.json`：真实正控。
- `http-verification.json`：四轮 REST / SSE / 源码 / AI / PDF 结果。
- `libchecker-result.json`、`readyou-result.json`、`root-libchecker-result.json`、`browser-result.json`。
- `regression-delivery.log` 与 `frontend-contract-final.log`。
- `source-changes.json` 与 `originals/`：文件清单及改前备份。
- 当前完整会话、原始模型响应和 PDF 在 `output/pipe/` 下，密钥配置在源码外。

## 5. 本轮不作出的能力声明

本轮非 root API/UI 测试未启用 VPN，所以不声称非 root 已监控所有包。Root 保留 PCAP，但并不等同所有协议已明文解密。
JADX 仍有部分类反编译失败（LibChecker83、Read You232），源码部分可用与全 DEX 方法引用扫描分别记录。
原有 native/QUIC/keylog 相关实验入口保留；不因为本轮正式模式成功就宣称这些实验能力全部通过端到端验收。
签名绑定/加固、Gadget 加载前与其他进程、登录后业务、完整磁盘持久化与通用协议解密仍有边界。

## 启动与合并

启动参数见根 README。配置两个端口服务不能同时抢占 8771；并行采集仍受共享审计队列约束。
后续合并以 `source-changes.json` 的源码与新增文件为准；不复制 `output/`、APK、模型配置、SDK、node_modules 或签名测试私钥。

## ch 分支提交基底

提交时保留 main 的 `a59584b`（端口与文档修正），只叠加本轮源码和说明。交付仓库与运行数据分离；原始四轮实际运行证据仍留在上文 c1f6f4e 目录。

本次独立提交目录：`D:/AAA-Codex/shengsai_app/ch-delivery-20261019`。打包仅取 Git 跟踪文件，不带本机运行证据、APK、模型配置或依赖。
