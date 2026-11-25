# V-Scanner 开发日志

从 2026-11-15 起记录每次开发。按日期追加，同日多轮写明任务。开始时登记范围，收尾时记录改动、验证、证据和待办。达到 300 行时将旧记录转入按日期命名的分卷，并在这里保留索引。验收记录只引用可复核、无测试凭据的产物。

- [2026-11-15 至 2026-11-18 分卷](DEVELOPMENT_LOG_20261115_20261118.md)
- [2026-11-19 至 2026-11-22 分卷](DEVELOPMENT_LOG_20261119_20261122.md)
- [2026-11-24 车载环境搭建分卷](DEVELOPMENT_LOG_20261124_SETUP.md)

## 2026-11-24 · 把分支与提交约定写进 AGENTS.md

- 范围：仅 `AGENTS.md`（全局约束新增第 10 条 + 新增「分支与提交流程」小节）。不改代码。
- 起因：2026-11-23 把 v2 移植的 3 个提交直接 `git push origin feature/...:main` 推到了 `main`，而用户要求的是
  推功能分支、由管理员审核合并。已用 `git push --force-with-lease=main:4a51546 origin cf5f3c7:main` 回退，
  `main` 回到 `cf5f3c7`，3 个提交保留在 `feature/vehicle-frontend-ui`（`4a51546`）。代码未丢，但 `main` 历史被改写过一次。
- 改动：约束第 10 条定为「只推功能分支，`main` 走 PR」；小节写明标准流程、PR 链接格式、三条禁止项
  （不 `push` 到 `main`、不对 `main` force、不用 `git add -A`）和推送后自检（`git rev-parse origin/main`）。
  同时点明「需要管理员审核」的前提是管理员把 `main` 设为保护分支，否则任何人都能直接推。
- 未做：保护分支是 Gitee 仓库设置，本地改不了，需管理员在网页端配置；未在仓库加 `CODEOWNERS` 之类的自动化拦截。

## 2026-11-23 · 旧工作台的流程引导与悬停预览移植到 v2 七页工作台

- 范围：`vehicle/frontend/v2/`。**不改**旧 `app.html` + `components.js` + `nav-flyout.js` + `page-identity.css` 体系——v2 是独立界面（暖纸白单主题、pill 顶栏、`section.view`），stash 里依赖 M3 角色变量与 `html[data-theme]` 亮暗分支的样式层（`page-identity.css` / `enhance.css`）与 `theme-toggle.js`、`nav-flyout.js` 在这套基线上没有落点，只移植功能本身。
- 改动：
  - 源码页从 `pages.js` 拆到新的 `v2/source.js`，并移植「悬停小窗」：260ms 防抖 + 按 `job.id|path` 缓存，只在悬浮行附近弹 5 行预览，**绝不改写右侧 `#codeView`**，点击才固定；左侧无空间时改贴锚点下方并与文件树列左对齐，避免压住右侧代码区；窄屏（≤860px）隐藏小窗。
  - 新增 `v2/flow.js`：七个功能页共用的流程条（`01–07` 序号 + 「← 上一步 / 下一步 →」），概览页隐藏；点步骤只调 `VS.go()`，与顶栏 pill 走同一导航，不碰业务逻辑。
  - `pages.js` 空态加「去概览选任务」按钮（静态/动态表格空态、AI 横幅），统一用 `[data-goto]` 委托，不各页重复绑事件。
- 验证：Playwright（Python 3.13）+ `page.route` mock 产物接口，1360×900 实测 17 项断言全通过、`pageerror` 与 console error 均为 0：`flow_hidden_on_overview=True`、`flow_on=source`、`prev_text=← 概览`、`next_text=静态 →`、`peek_shown=True`、`right_untouched=True`、`peek_clear_of_code=True`、`peek_attached=True`、`peek_lines=6`（5 行代码 + 省略号）、`code_fixed=True`、`peek_closed=True`、`next_page=page-static`、`empty_goto_btn=1`、`goto_target=page-overview`。临时脚本跑完已删。
- 存量红（**与本次改动无关**，`git show HEAD:` 的同名文件即如此）：`tools/engineering_guards.py` 报 `vehicle/frontend/vehicle.css = 426 行`、`vehicle/frontend/v2/app.js = 316 行`（合并 `origin/main` 后 317，超限仍在）未登记，且基线里的 `vehicle/targets/target-app/build/reports/problems/problems-report.html` 已不在原路径；`run_regressions.py` 的 `completion` 组因该守卫失败，`vehicle-pipeline` 1 failure/1 error（`test_capture_lifecycle` 的 `restore_proxy` 0 次调用）、`collector` 1 error（`FileNotFoundError`，本机缺外部可执行文件），`vehicle-ledger-ui`/`runtime`/`privacy-runtime` 三组需要 `node`（本机没有）使脚本在第 16 组中断。本次新增/修改的 5 个文件按守卫口径均 ≤300 行（`source.js` 176、`flow.js` 60、`pages.js` 234、`pages.css` 162、`index.html` 269）。
- 待办：`v2/app.js` 316 行按职责拆到 ≤300（与 `pages.js` 重复的 `levelOf/locOf` 可抽 `v2/util.js`）；`vehicle.css` 426 行同理；基线里的 `problems-report.html` 路径漂移需显式 `--update` 或改判据，不能靠放行新违规来洗白。

## 2026-11-23 · Car Stats Viewer 独立样本验证

- 范围为核验固定源码的 VHAL 车速到 HTTPS 正文路径，尝试在自有测试环境构建并验证独立样本。任何字段映射须有源码和证据依据，保持普通规则的现有匹配范围。
- 在 `output/b1-carstatsviewer-20261123/` 解包固定上游源码，校验 Gradle 9.5.1 官方分发 SHA-256。`:automotive:assembleStableLegacyDebug` 的原始构建和本地隔离 HTTPS 调试构建均成功，`apksigner verify` 通过。源码包 438 个文件原样，调试层只增加限定接收端的证书信任。
- 首个证书链缺少 AKI，补齐后 `test_receiver.py` 三项回环 HTTPS 自测通过。设备前两轮分别遇到 `stopservice` 和正常帮助命令的特殊退出码，日志保留。第三轮上传链路通过，单次注入未改变回调或正文的车速，6 条回执全为 0 m/s。
- 专用 AVD 用 `run.ps1 -RunName trial-04` 保存、设置并恢复 VHAL 车速。−7.25 和 13.5 m/s 读回正确，Hook 与服务端分别确认 `speed=7.25` 两条、`speed=13.5` 三条。采集健康 10/10，车速恢复 0，实验 APK 已卸载。证据摘要在 `trial-04/speed-observation.json`。同值回调存在多个可能来源，30 秒跨应用阈值待测。
- `py_compile` 和 B1 定向 unittest 25/25 通过。更新状态、设备结果和日志，未修改生产窗口或匹配器。

### Car Stats Viewer 断网行驶点补传（2026-11-23）

- 范围为复用已核验的调试 APK，在专用 AAOS 上执行在线对照、断网入队和恢复补传，核对设备本地行驶点与 HTTPS 原始正文的字段及时间，评估窗口计分资格。
- 使用 `output/b1-carstatsviewer-20261123/run_queue.ps1` 在专用 AVD 确认 4 条在线点和 5 条离线点。Wi-Fi 断开 56.563 秒，接收端期间 0 请求，恢复后同一 POST 补传全部 5 条且未重复。用 `verify_queue.py` 核对 SQLite 主文件及 WAL、原始正文与 SHA-256，离线点从记录到打包 55.748–64.011 秒。 [验收证据](../output/b1-carstatsviewer-20261123/queue-trial-01/queue-verification.json)
- 采集健康 10 项通过，挡位、车速及 Wi-Fi 恢复均读回验证，测试 APK 已卸载。区间聚合和派生字段没有单次读取标识，保持 `window_scored=false`。替代来源初筛暂未找到满足独立评分口径的路径。
- `tools/python313.ps1 -m py_compile` 核对本轮实验脚本，`tools/python313.ps1 -m unittest vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 25/25，`git diff --check` 通过。

## 2026-11-23 · 执行 11/23–11/29 周计划

- 范围为将补传证据复验固化为仓库入口，完成 B1 独立样本资格核对；若缺少单次读取级证据，交付 B2 最小基准、真实样本重放、回归和周结。
- 新增 `vehicle.bench.carstats_queue`，从临时 SQLite 和 WAL 副本、原始 HTTPS 正文与回执重验 4 条在线点、5 条离线点。独立候选缺少可唯一绑定单次 VHAL 读取的延迟证据，按计划选择 B2 备线。
- 新增 `vehicle.bench.vscanbench` 与冻结清单。两个自有 APK 的 90 个签核配对中有 25 个正例、50 个同值跨批反证和 5 个不同值负控。两次五档重放的报告 SHA-256 相同。错误规则摘要返回 2，未写成功报告。 [报告](../output/vscanbench-week-20261123/pilot-repeat.json)
- `tools/python313.ps1 -m unittest vehicle.bench.test_vscanbench vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 30/30。 `tools/python313.ps1 tools/run_regressions.py --out output/vscanbench-week-20261123/regression` 22/22，`git diff --check` 通过。已更新周结，独立应用阈值与 B2 完整场景矩阵待补。

## 2026-11-23 · VScanBench AAOS 只读负控与发送对照

- 范围为在同一个自有 APK 上执行两个独立 AAOS 会话，核对读取、上游接收和关联重放，将证据纳入 VScanBench 工作流验收。
- 初轮在只读动作后取得设备回执，接收端无请求。采集在 Frida 收尾阶段停滞，ADB 随后报告设备离线，未生成健康验收。保留 [失败日志](../output/vscanbench-read-send-20261123/run-01/read_only/capture.log)。重跑将代理限定到夹具显式使用的回环端口。
- `vehicle.lab.read_send_control` 复用专用 AAOS 35 user 10 与现有 debug 场景，两轮关闭 TLS 绕过，各通过 10 项采集健康检查和回环转发清理读回。只读轮成功读取车速 `0.0`，0 个请求、0 个外发配对。发送轮读取同值，接收端返回 HTTP 200，窗口重放 8 个候选中的 5 个配对由正文与主读取确认。 [对照证据](../output/vscanbench-read-send-20261123/run-02/control-verification.json)
- `tools/python313.ps1 -m vehicle.bench.read_send_control --source output/vscanbench-read-send-20261123/run-02 --out output/vscanbench-read-send-20261123/run-02/control-verification.json` 通过。默认 `vscanbench` 清单固定证据摘要，两个会话按一个既有 APK 计入工作流。 `tools/python313.ps1 -m vehicle.bench.vscanbench --out output/vscanbench-read-send-20261123/pilot-final.json` 重放通过，报告与前两次重放字节一致。 [基准报告](../output/vscanbench-read-send-20261123/pilot-final.json)
- `tools/python313.ps1 -m unittest vehicle.bench.test_vscanbench vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 32/32。初次完整回归发现收尾强制终止分支缺日志，已补齐。 [首次回归日志](../output/vscanbench-read-send-20261123/regression/completion.log)
- `tools/python313.ps1 tools/run_regressions.py --out output/vscanbench-read-send-20261123/regression-final` 22/22，`git diff --check` 通过。工作流证据已归档并更新当前状态。独立应用阈值仍待单次读取级证据。 [最终回归](../output/vscanbench-read-send-20261123/regression-final/verification.json)

## 2026-11-23 · VScanBench 配对模式回归与独立复核

- 范围为固化只读与发送对照的三模式验收，覆盖缺失、重复批次标识，重放已有 90 个签核配对，并由两个子代理独立复核差异。
- `read_send_control` 增加三种模式的逐事件验收，原封存报告重放逐字节一致。缺失与重复批次标识的反例均验证时间窗候选保持未确认。`vscanbench` 增加五档的已签核正例与同值跨批反证差异，第二夹具的两个令牌模式显式记录不适用。
- `tools/python313.ps1 -m vehicle.bench.vscanbench --out output/vscanbench-pairing-20261123/pilot-final.json` 通过，三次结果逐字节一致。只读为 0/0/0，发送为 8/5/5。其中三条额外窗口候选均为诊断复读。第一夹具组合模式五档均为 10 个签核正例、0 个额外候选。第二夹具完成五档时间窗重放。 [重放报告](../output/vscanbench-pairing-20261123/pilot-final.json)
- `tools/python313.ps1 -m unittest vehicle.analyze.test_vehicle_evidence vehicle.bench.test_vscanbench vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 54/54。 `tools/python313.ps1 tools/run_regressions.py --out output/vscanbench-pairing-20261123/regression` 22/22，`git diff --check` 通过。 [完整回归](../output/vscanbench-pairing-20261123/regression/verification.json)
- 两个隔离上下文的子代理各从封存证据重算。`tools/python313.ps1 output/vscanbench-pairing-20261123/verify-reviews.py` 通过，20 个计分档、10 个适用范围诊断档和 6 个对照档相符，无需仲裁。第一夹具五档均保留已命中的签核正例，5/10/30 秒各补回 5 对。独立应用校准仍待符合条件的证据。 [双人复核](../output/vscanbench-pairing-20261123/review-verification.json)

## 2026-11-23 · 运行依赖与环境清单

- 范围为新增 Windows 运行清单，覆盖车载静态与动态、移动端、夹具构建、离线回归及按需工具，并核对本机已备的关键组件。
- 新增 [运行依赖与环境清单](ENVIRONMENT_CHECKLIST.md)，按场景列出最小依赖、固定版本、端口、环境变量、首次启动及换机所需的大文件。
- 用 `tools/python313.ps1 --version`、`core.env_guard`、`core.static.toolchain.describe` 和 `python -m vehicle --help` 核对解释器、依赖前置、静态工具和启动入口，并确认 SDK、AAOS 镜像、AVD、frida-server 和默认 APK 路径。PowerShell 示例语法 4/4、本地链接 11/11、依赖固定版本 9/9、`git diff --check` 均通过。本轮为文档核对，设备验收可查 [已封存的 AAOS 对照](../output/vscanbench-read-send-20261123/run-02/control-verification.json)。

## 2026-11-23 · 车载 v2 工作台真实数据验收与静态结论接线

- 范围为用仓库自有 APK 在真实静态任务上验收 v2 七页，核对前端调用的接口与后端契约是否一致；不使用设备与外部样本。
- 真实任务 `v-d29d8ad8ed624470bd51655f9e893868`（`vehicle/targets/target-app` 的 debug APK，3.7 MB，`mode=static`）静态分析 2.2 秒、反编译 8.8 秒，终态 `static_only`，静态结论 22 条全为 `candidate`。
- 修复一：`static_only` 任务在概览页显示 0 条结论、「静态审计」页空表——前端只读 `/findings`，而该接口按契约要求 `state=done`。`presentation.decorate` 改为静态任务从 `static/static.json` 按 `conclusion_level` 计数，写入 `findings_count_source=static` 与专用说明；`/static` 复用动态结论的规则标题口径（中文映射优先）；v2 概览对非 `done` 任务改读 `/static`。
- 修复二：顶栏原写「已连接 · AAOS 35」，在无设备时会把服务在线读成设备已连；改为「服务已连接 · 目标 AAOS 35」。
- 验证：七页逐页渲染（Edge headless `--dump-dom` 与 1440×980 截图，均在 `output/v2-acceptance/`）：概览「22 条结论 / 候选 22」、静态「22 / 22 条」并显示中文标题、源码页取到 jadx 文件树与 `AuditConsentActivity.java` 正文、动态页五阶段（2 完成 / 3 跳过）、AI 页降级文案、PDF 页禁用提示、复核页「未发布本轮证据复核」。未完成任务的 `/report`、`/dashboard`、`/evidence.zip`、`/summary`、`/coverage` 均为 404 + `audit_not_completed`。
- `tools/python313.ps1 -m unittest vehicle.webapp.test_presentation vehicle.webapp.test_server vehicle.webapp.test_workflow vehicle.webapp.test_integration` 46/46；新增 4 例（静态计数只认 `conclusion_level`、`static_only` 标来源、`done` 仍用摘要、`/static` 带标题）。全量 `tools/run_regressions.py` 21/22，唯一红仍是 `completion`：`vehicle/frontend/vehicle.css` 426 行、`v2/app.js` 317 行，均为远程 main 带入且未登记基线。
- 待办：`completion` 要绿只能拆分这两个文件（守卫 `--update` 只允许收紧，不能新增条目）；v2 的采集/关联审计/看板三页需接设备跑 `live` 或 `replay` 任务；AI 页对静态任务可给出更准确的原因文案。

## 2026-11-25 · 车载流水线自动 UI 探索

- 范围为抽取移动端 UI 树解析能力，将可选的自动交互接入车载实时采集及 v2 工作台，按会话留存动作和停止原因。
- 两端共用控件树解析与父节点定位。车载端默认手动，可在自有模拟器开启自动探索。采集就绪后核对主屏焦点、包名和用户，再执行有界点击与滚动。停止原因和动作保存在采集验证文件、审计摘要与动态页。
- 首轮夹具停在页面底部，向下滚动未触发读取。修正后 Chrome 实测向上滚动两次并点击「读取 VHAL」，在同一会话记录 13 条读取事件，审计正常完成。关闭探索的实测任务同样完成。 [自动模式](../output/vehicle-ui-exploration-20261125/existing-1795575848388/verification.json) · [手动模式](../output/vehicle-ui-exploration-20261125/existing-1795575908249/verification.json)
- `node --check`、`git -c core.whitespace=cr-at-eol diff --check` 通过。根离线回归 `tools/python313.ps1 tools/run_regressions.py --out output/vehicle-ui-exploration-20261125/regression-verified` 22/22。移动离线回归 62/63，界面解析相关检查通过，`device_tools` 因本机缺少 tshark 失败。 [车载回归](../output/vehicle-ui-exploration-20261125/regression-verified/verification.json) · [移动回归](../output/mobile-regression-20261125-110230-2ileyxe1/verification.json)
- 8773 工作台已加载新版，保留原 AI 配置和任务记录。自动流程已在自有 AAOS 35 夹具上验收，通用导航策略的覆盖率和其他车载应用待实测。 [服务验证](../output/vehicle-ui-exploration-20261125/service-verification.json)

## 2026-11-25 · 车载会话自动回放与 Frida 转发收尾

- 范围为将已完成的车载实时采集接入工作台回放列表，并由车载采集生命周期管理独立的宿主 Frida 转发。
- 工作台自动登记本工作目录里已完成、健康、会话一致的实时任务。v2 切换回放模式时刷新，旧实时任务也可读取。车载采集用 ADB 分配独立宿主 Frida 端口，结束时按设备及端口归属释放，并把回读结果写入采集验证。
- Chrome 同页实时采集与回放通过。宿主端口 54484 在采集后释放，测试前已有的 27043 映射在两轮间保持。实时和回放均为 5 条已关联、5 条已观测及 6 条候选，两份 ZIP 各 22 项摘要校验通过。首轮回放已完成，测试脚本比对下载文件头时大小写处理不一致，修正后重新走完整链路。 [浏览器验证](../output/vehicle-replay-forward-20261125/live-1795579275095/verification.json) · [归档验证](../output/vehicle-replay-forward-20261125/live-1795579275095/archive-verification.json)
- `node --check vehicle/frontend/v2/upload.js`、`git -c core.whitespace=cr-at-eol diff --check` 通过。补齐回放目录异常诊断后，`tools/python313.ps1 tools/run_regressions.py --out output/vehicle-replay-forward-20261125/regression-final` 22/22。 [离线回归](../output/vehicle-replay-forward-20261125/regression-final/verification.json)
- 8773 已重启并核对旧会话登记和原 AI 配置。清理了本项目早期验收创建、当前闲置的 AAOS 固定转发。 [服务核对](../output/vehicle-replay-forward-20261125/service-verification.json)

## 2026-11-25 · 车载 v2 工作台主题切换

- 范围为在同一车载前端加入纸白与影院银两套主题，验证切换及刷新保持当前页面、审计状态与无构建入口。
- v2 顶栏提供纸白和影院银选项。沿用原有颜色变量和车身背景，浏览器本地保存主题；切换保持任务、路由、结论和筛选，390 像素下顶栏分两行，任务和阶段卡片改为两列。
- 初次窄屏检查发现历史和阶段卡片的最小宽度撑开页面，调整后 Chrome 复验七个页面、两套主题、刷新恢复、当前任务和筛选，以及 390 像素页面宽度通过。 [浏览器证据](../output/vehicle-v2-themes-20261125/browser-verification.json)
- `node --check vehicle/frontend/v2/theme.js`、`git diff --check`、`tools/python313.ps1 tools/run_regressions.py --out output/vehicle-v2-themes-20261125/regression` 通过，根回归 22/22。本次浏览器只读取现有任务。 [离线回归](../output/vehicle-v2-themes-20261125/regression/verification.json)

## 2026-11-25 · 车载 v2 失败日志与重试

- 范围为在概览和动态页读取当前失败任务日志，经重新授权创建独立重试任务，并验证旧失败与新任务的证据隔离。
- v2 复用现有日志和重试接口。确认授权后使用同一 APK 与原设置新建重试任务，沿用上传流程的任务轮询，并可从重试任务返回原失败。提交结果无法确认时，页面提示先检查任务列表。
- 隔离 Chrome 读取历史实采装机摘要不匹配的日志，并验证该历史副本缺少 APK 时的错误提示。真实 AAOS 采集副本临时移出一份输入，回放按预期失败；还原该文件后，浏览器重新授权，仅创建一条重试任务并完成回放。核对同一采集会话、相同 APK、原日志摘要及新证据 ZIP，390 像素下授权弹窗可操作。 [浏览器验收](../output/vehicle-v2-retry-20261125/browser-verification.json)
- `node --check`、`git -c core.whitespace=cr-at-eol diff --check` 通过。根回归首跑有 3 组被沙箱拦截本机回环，允许回环后 `tools/python313.ps1 tools/run_regressions.py --out output/vehicle-v2-retry-20261125/regression-final` 为 22/22。新一轮设备实采重试待验证。 [回归结果](../output/vehicle-v2-retry-20261125/regression-final/verification.json)

## 2026-11-25 · 车载 v2 补充证据与人工复核

- 范围为在动态审计任务上传政策和场景材料，在审计结论页对具备稳定结论标识的条目写入并回读人工复核。
- v2 与旧工作台共用附件编码和复核表单。动态任务保留附件相对路径，入队后清理本次选择。完成任务按 `finding_uid` 保存人工复核，状态、人员、时间与备注从服务端回读。
- Chrome 以已封存的自有 AAOS 35 采集回放，用合成政策、场景和两份子目录文件验收材料绑定。核对 4 个文件逐字节一致，政策提取状态为 `available`，场景标为 `synthetic_only`。录入一条「需补充证据」意见后，核对回读、刷新持久化、16 条结论等级、原审计文件摘要、ZIP 下载、静态任务隔离及旧工作台兼容。390 像素下表单通过。 [浏览器验收](../output/vehicle-v2-material-review-20261125/browser-verification.json)
- `node --check` 和 `git -c core.whitespace=cr-at-eol diff --check` 通过。`tools/python313.ps1 tools/run_regressions.py --out output/vehicle-v2-material-review-20261125/regression` 为 22/22。本轮执行了真实采集回放和真实 APK 静态审计，政策与场景输入为验收夹具。 [根回归](../output/vehicle-v2-material-review-20261125/regression/verification.json)

## 2026-11-25 · G1 车载 UI 探索覆盖率最小基准

- 范围为冻结两个自有 AAOS 夹具的手动标注范围，用同一判据比较手动和自动探索，以本轮实际 UI 和运行时事件复核覆盖率。
- 冻结两份 APK 的摘要、主 Activity、直接读取与订阅动作。新增自有设备对照入口和离线评分器。手动参考由 ADB 复现人工标注动作，自动轮使用现有探索器。评分核对同会话前台 Activity、点击和 Hook 事件，订阅须同时见到成功注册与后续回调。
- 专用 AAOS 35 / user 10 执行四次独立 36 秒采集，均通过 11/11 健康检查。四轮页面 1/1，手动动作均 2/2，自动第一夹具 1/2，第二夹具 0/2。两次离线评分结果逐字节一致。专用只读 AVD 已关闭。 [覆盖报告](../output/vehicle-g1-20261125/coverage.json) · [方法及复现](../vehicle/bench/UI_COVERAGE.md)
- `tools/python313.ps1 -m unittest vehicle.bench.test_ui_coverage -v` 3/3。缺少输入的命令退出 2。根回归首轮识别出评分入口的错误出口不透明，改为显式标准错误与退出码后，`tools/python313.ps1 tools/run_regressions.py --out output/vehicle-g1-20261125/regression-final` 22/22，`git diff --check` 通过。后续待验证普通车载应用的多页面范围。 [根回归](../output/vehicle-g1-20261125/regression-final/verification.json)

## 2026-11-25 · G1 双夹具自动动作覆盖

- 范围为按两个自有夹具的资源标识识别读取与订阅，复用冻结清单和 36 秒窗口实测动作覆盖。
- 车载探索按包、资源 ID 和按钮文案匹配两个已标注动作。UI 树将订阅按钮的 `2b` 转为 `2B`，因此文案匹配处理大小写。分别限制上下滚动，每个控件只发送一次。新动作保留资源 ID，旧会话仍可按原标签评分。 [控件观测](../output/vehicle-g1-actions-20261125/fixture-ui-diagnostics.jsonl)
- 初轮 ADB 收尾等待超时，首个独立 ADB 实例的采集停在 Frida 刷盘。保留失败目录，最终用经过既有 G1 验收的只读 AAOS 35 镜像与专用 ADB，关闭设备 Wi-Fi 和移动数据，保留原代理设置。 [初轮日志](../output/vehicle-g1-actions-20261125/trials/target-app-automatic/capture/reads.log) · [刷盘失败](../output/vehicle-g1-actions-20261125/trials-isolated/target-app-manual/capture/reads.log) · [网络条件](../output/vehicle-g1-actions-20261125/network-baseline.json)
- 四轮全通过采集健康检查，页面各为 1/1，自动动作由 1/2 和 0/2 提升到两个 2/2，手动均为 2/2。评分重算两次摘要一致，旧基准重算也一致。定向测试 8/8，前端状态检验 3/3，根回归 22/22。`node --check` 与 `git diff --check` 通过。 [覆盖率](../output/vehicle-g1-actions-20261125/coverage.json) · [根回归](../output/vehicle-g1-actions-20261125/regression/verification.json)
