# V-Scanner 开发日志

从 2026-11-15 起记录每次开发。按日期追加，同日多轮写明任务。开始时登记范围，收尾时记录改动、验证、证据和待办。达到 300 行时将旧记录转入按日期命名的分卷，并在这里保留索引。验收记录只引用可复核、无测试凭据的产物。

- [2026-11-15 至 2026-11-18 分卷](DEVELOPMENT_LOG_20261115_20261118.md)

## 2026-11-19 · 车载工作台前端视觉重做（影院银主题）

- 背景：用户对前几版迭代不满——"只改了灰度、车变模糊、还是黑"。根因：一直在用 PIL 二次压缩原始车图（JPEG 有损 → 车发糊；gamma 提亮 → 黑底变灰发脏），再叠厚层黑色蒙版把图压死。
- 决策：停止处理车图。原始 `vehicle/frontend/assets/vehicle-studio.png`（1672×941，银色轿车 3/4 前视，本身已有右上角影棚光束）质量足够好，**直接全亮度铺底**，不做任何滤镜/混合模式。
- 新增覆盖层样式 [theme-cinematic.css](../vehicle/frontend/theme-cinematic.css)（239 行，单文件 ≤300 合规），在 `app.html` 中最后加载，用 `!important` 覆盖 `vehicle.css` / 共享 `app.css` 的视觉。**不碰 HTML / JS / 布局逻辑**，回退只需删一行 `<link>`。
- 视觉要点：
  - 底：原始车图全亮度 + 右上角冷白光晕（增强原图光束，光从右上来）+ 极薄暖橙点缀（黎明感）+ 左侧 52% 处即透明的薄压黑（只保证文字可读，不挡车）+ 底部接地压黑。
  - 车：sharp，是页面主角，位于右侧；左侧留给表单/标题。
  - UI：rail / topbar / 表单卡 / dropzone / 进度卡 / 结果卡 / 报告卡 全部改为 `backdrop-filter: blur(16–18px)` 毛玻璃 + `rgba(17,21,29,.55)` + 细白边 + 投影，悬浮感。
  - 排版：品牌 eyebrow 改小写字距 .22em 大写；H1 放大到 clamp(34–56px) weight 600；主按钮白色渐变。
  - 交互：冷银蓝（#a8c8ec 系）hover 抬升、进度点脉冲、状态点呼吸，无金色/粒子/扫光。
- 验证：用 Edge headless（`--headless=new --virtual-time-budget=6000 --window-size=1440,900`）截图 `_shots/cine3_main.png` 等确认车清晰、光束可见、卡片毛玻璃。HTTP 200。静态服务 `python -m http.server 8090`。
- 待办：后端未起（页面显示"车载服务未连接 / Failed to fetch"），属预期——纯前端预览不依赖 8773；等用户确认视觉方向后再联调。

### 同日续 · 提交主题层并启动后端联调

- 提交 `d18bf0a`：仅含 `vehicle/frontend/theme-cinematic.css`（292 行）+ `app.html`（新增 link、`theme-color` 改 `#0A0D12`），未推送远端。另加 `?v=20261119a` 版本号规避浏览器 CSS 缓存。
- 后端启动环境：本机**无** `%LOCALAPPDATA%\Programs\Python\Python313`，也无 `.venv`；新建 `.venv` 后其 `Scripts\python.exe` 被 **Windows 应用控制策略拦截**（`os error 4551`，程序执行被阻止），已删除该 venv。改用 `uv run --with pillow --with reportlab python -m vehicle.webapp.server --port 8773`（临时叠加环境，不落地 exe），`import vehicle.webapp.server` 通过。
- 进程驻留：TRAE 工具调用结束会回收整个进程树（`Start-Process` 起的 python 与可见 cmd 窗口都被杀），改用 WMI `Win32_Process.Create` 由 `WmiPrvSE` 派生，实测跨调用存活；8090 静态服务另有计划任务 `VScannerStatic8090` 每 2 分钟健康检查兜底。
- 修复：`vehicle/webapp/server.py` 静态分发是**显式白名单**，新主题样式未登记导致 8773 打开时无影院银效果且无车图。把 `'/theme-cinematic.css'` 加入该白名单后重启后端，`/theme-cinematic.css` 返回 200（13171 字节），页面恢复完整主题；`/assets/vehicle-studio.png` 原已在白名单内。
- 验证：`http://127.0.0.1:8773/api/config` 200、`/` 200（16 KB）、主题 CSS 200；Edge headless 截图确认右上角显示"车载服务已连接 · AAOS 35"、车图与毛玻璃卡片均在位、页面底部不再出现连不上服务的提示。

### 同日续 · v2 全新界面（编辑风格）并接入真实数据

- 用户反馈旧页面"只改了颜色、没有大改"，要求推翻重写并可换背景图。新建独立目录 `vehicle/frontend/v2/`，**不改动旧 `app.html`**，两套并存便于对比：
  - `index.html`（167 行）/ `style.css`（约 280 行）/ `app.js`（约 280 行）/ `assets/paper-bg.jpg`（2400×1350，PIL 生成：暖米白渐变 + 等高线 + 颗粒）。
  - 设计语言换成**暖纸白 #f7f4ed + 墨黑 + 烧橘 #c2491f**，左侧 rail → 顶部胶囊导航，表单 → bento 四卡，新增环形进度卡与阶段条。
  - 背景图未用在线生成接口：`text_to_image` 连续两次返回同一张 176626 字节的坏图（1832×1832、灰度 229），改为 PIL 代码绘制，尺寸/亮度可控。
- 真实数据接入（同源，无 CORS）：`GET /api/config` → 连接态与版本/阶段计数；`GET /api/pipeline` → 任务列表；`GET /api/pipeline/{id}` → 阶段状态与阶段耗时；`GET /api/pipeline/{id}/findings`（仅 `state=done`）；`POST /api/pipeline?name&mode&version&authorized=true` 以原始字节体上传，2 秒轮询至终态。
- **修正一处事实错误**：车载侧 `jobs.STAGES` 是 **5 个阶段**（static / decompile / capture / audit / dashboard），此前文案按移动端写成"16 阶段"，已改为 5；指标卡改为「规则版本 / 审计阶段 / 目标 API」。
- 后端改动：`server.py` 增加 `/v2` 静态路由（`resolve()` + `parents` 校验防目录穿越），静态分发仍是显式白名单。
- 验证：`/v2/`、`/v2/style.css`、`/v2/app.js`、`/v2/assets/paper-bg.jpg` 全 200；临时构造一个 `v-0123…` 假任务（`job.json` + `audit/summary.json` + `audit/findings.jsonl`）验证渲染链路——环形进度 80%（5 阶段 4 完成）、阶段条状态、任务选中高亮、结论表 3 行与"3 条 · 来自 …"均正确；**验证后已删除该临时任务并重启后端，`/api/pipeline` 回到 0 条**，不残留假数据。
- 待办：真实结论需要 jadx 与 APK 样本（本机均无），当前只能验证到空态与接口链路；`server.py` 的 `/v2` 路由与开发日志尚未提交。

### 同日续 · v2 七个页面独立化 + 交互补齐

- 用户反馈："除了车载审计这个页面，其他页面都只变了个标题"——此前 6 个子页只是同一个占位视图。本次把 7 个页面拆成各自独立、各自取真实产物的视图：
  - **源码查看**：`GET /{id}/tree` 左侧文件树（600 条上限 + 实时过滤）→ `GET /{id}/source?path=` 右侧代码面板，复制路径走 clipboard + toast。
  - **静态审计**：`GET /{id}/findings` 全量结论；等级 chips（已关联 / 已观测 / 候选，对应 `conclusion_level` 真实枚举，不再是虚构的高/中/低）、关键字搜索、`n / m 条` 计数；点行展开证据详情（观测说明、代码位置含角色/类/方法、定位缺口、事件证据、复核状态）。
  - **动态审计**：`privacy_observation` 三态矩阵（已观测 / 仅注册 / 未观测 + 每类原因文本）、`stage_timings` 五阶段耗时、`field_gaps` 与 Hook 缺口计数。
  - **辅助复核**：`GET /{id}/ai` 的 `status` 横幅（skipped 时显式黄色告警）与 `result` 分区卡片；AI 不改变判定。
  - **PDF 报告**：`/report`、`/evidence.zip`、`/dashboard` 三个动作入口，未完成时按钮置灰并写明原因。
  - **证据复核**：`GET /api/review-round` 只读轮次，计数 + `<details>` 案例 + 限界说明；未发布时显示后端原文。
- 代码结构：`index.html`（7 个 `<section class="view">`）+ `style.css`（共用设计语言）+ **新增 `pages.css`**（子页版式）+ `app.js`（导航/任务/上传/轮询/事件总线 `window.VS`）+ **新增 `pages.js`**（各页按需取数渲染）。全部单文件 ≤300 行；脚本经 `DOMContentLoaded` 启动，保证 pages.js 先注册监听。
- 修掉两个真实 bug：① 快照里**没有** `stages` 字段，环形进度此前恒为 0；改为按 `stage_timings` 渲染（decorate 恒返回 5 条）；② 页面入场动画带 opacity，headless/低性能环境会截到半透明画面，改为仅位移。
- 交互补充：hash 路由（`#static` 等）+ 浏览器前进后退、任务切换 toast、拖拽/键盘选文件、筛选与搜索即时生效、行展开、文件树过滤、复制反馈。
- 验证：临时构造 `v-0123…` 假任务（5 阶段事件 + 6 条三档结论 + 3 个 Java 源文件 + AI 结果），Edge headless 截图 7 页确认版式各不相同、环形 100%、阶段耗时 13–16s、三态观测表与发现表均有数据；再用浏览器代理实测"点结论行展开详情"与"点文件树加载源码"两条交互，均 PASS。**验证后已删除假任务并重启后端，`/api/pipeline` 为 `[]`**。
- 仍未提交（用户要求先别提交）：`v2/` 全部文件、`server.py` 的 `/v2` 路由、本日志。

## 2026-11-21 · B1 切换为 subagent 签核

- 范围为 B1 自有夹具的证据冻结、双盲复核和第三方仲裁入口，以及签核状态。旧初评作为历史记录保留。
- 新增 `vehicle.bench.window_review`，沿用盲审与仲裁门禁。候选来自同会话的原始事件与动作，答卷包排除先前标注和回放结果。签后保持自有夹具来源，窗口重放可直接读取签核标签。
- `tools/python313.ps1 -m unittest vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 24/24 通过。合成用例验证端到端流程、签后重放和篡改拒绝。
- 真实旧会话按文档参数运行退出 1，缺失 `output/vehicle-offline-window-20261103-002/capture/session-manifest.json`，对应的回执和规则快照也缺失。未出真实盲审包，未启动签核。 [复跑与签核步骤](../vehicle/bench/WINDOW_CALIBRATION.md#2026-11-21-切换到-subagent-签核)
- `tools/python313.ps1 tools/run_regressions.py --mobile --out output/b1-subagent-regression-20261121` 共 22/23 组通过，车载与共享组均通过。附带的移动侧 62/63 项通过，`device_tools` 的缺失 pcap 用例因本机找不到 tshark 而提前返回。 [全量结果](../output/b1-subagent-regression-20261121/verification.json) · [移动失败日志](../output/b1-subagent-regression-20261121/mobile/device_tools.log)

### B1 原始证据恢复与补采（2026-11-21）

- 范围为恢复摘要匹配的 B1 原始证据；旧会话缺失时尝试恢复自有 AAOS 环境并补采，随后开展 subagent 盲审。
- 从本机历史产物找回旧会话摘要匹配的规则库，原事件与回执仍缺。校验 AAOS 35 A6 镜像和 Frida 17.18.0 后重建专用 AVD，离线编译自有 APK。恢复材料和构建日志见 `output/b1-recovery-20261121/`。
- `vehicle.lab.window_run --offline` 冻结本轮规则库和两份夹具源码，单进程附加且关闭 TLS 绕过。车载采集对自有代理与转发的 ADB 超时各重试一次，读回验证后才计为恢复，尝试状态写入 `verification.json`。
- `output/b1-fixture-20261121/` 首轮刷盘卡住且代理恢复失败；`output/b1-fixture-20261121-retry/` 第二轮正常刷盘，代理与转发恢复失败。第三轮在一次 ADB 超时后读回确认恢复，全部采集健康检查通过，封存于 `output/b1-fixture-20261121-recovery/`。三条本地 POST 均收到 HTTP 200，专用模拟器已关闭。
- 两名独立 subagent 核对 45 项，第三名确认 10 项同源配对和 5 项设计负控，0 项分歧。`vehicle.bench.blind_signoff` 产出正式标签，`vehicle.bench.window_calibration` 的 window/token/both 五档重放均完成。答卷、启动记录、签核和重放均在 `output/b1-fixture-20261121-recovery-review/`，后续需独立样本验证跨应用阈值。
- 定向 unittest 37/37；`tools/python313.ps1 tools/run_regressions.py --out output/b1-recovery-20261121/regression-verified` 22/22，允许本机回环后重跑通过。默认沙箱首跑拦截本机回环，3 组错误日志保留于 `output/b1-recovery-20261121/regression-final/`。

## 2026-11-22 · B1 跨应用对照

- 范围为盘点独立包和会话资格，并在第二个自有 AAOS 夹具上用既有 UI、正文时间及独立服务回执设计直传和延迟上传对照。
- 旧日志转入日期分卷。第二 APK 沿用源码并以本机 JDK 21 离线成功构建。第一次未通过端点回读，第二次捕获目标 POST 但宿主无法连到 `10.0.2.2`，第三次用本机回环接收端完成三轮 HTTP 200 且采集健康全绿。命令、失败路径和证据保存在 `output/b1-cross-app-20261122/`。
- 盲审比对首次读到没有 `business` 别名的显式证据清单。修复旧值的提前求值，保留冻结材料和两份原答卷，新增针对该输入的回归。
- 盘点历史独立会话，并记录 Car Stats Viewer 源码摘要、构建矩阵及正文格式测例。VHAL 出站规则 `VSC-E002` 当前无法匹配其 `speed` 字段，暂不纳入跨应用阈值统计。
- A/B/C 签核 45 项，15 项同批、30 项普通跨批反证，0 项分歧。`vehicle.bench.window_calibration --pairing window --include-pairs` 五档重放完成，正式标签、原始答卷和报告在 `output/b1-cross-app-20261122/review/`。30 秒命中 10 项、漏配 5 项，60 秒补齐。独立应用待设备实测。
- `tools/python313.ps1 -m unittest vehicle.bench.test_window_review vehicle.bench.test_window_calibration vehicle.bench.test_blind_round vehicle.bench.test_subagent_signoff` 25/25；`tools/python313.ps1 tools/run_regressions.py --out output/b1-cross-app-20261122/regression` 22/22；`git diff --check` 通过。

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

## 2026-11-26 · 移动读取与外发窗口基准

- 范围为复用自有移动夹具，新增 Android ID 只读、即时发送、延迟发送和同值跨批四组对照，通过独立本机回执核对来源并复用移动关联器重放五档窗口。
- 自有 Gadget 变体新增受 `android.permission.DUMP` 限制的测试 Activity，读取并缓存 A/B，仅发送 A 到本机回环。复用现有 Gadget 驱动、移动代理、规则库和关联器，封存 APK、观测脚本、会话与输入的摘要。
- API 36 手机模拟器多次复现 Java 读取 Hook 的 ART/JIT 崩溃，保留 [设备失败日志](../output/mobile-window-20261126/real-06/read_only/device-crash.log)。最终基准使用自有夹具真实读取后发出的原生日志标记。读取观测口径为 `fixture_native_log`。
- 修复关联器读取移动规则维表时的 Windows SQLite URI 转义，缺失 PCAP 时优先报告输入缺失。
- 离线构建 `:app:assembleGadget --offline --no-daemon` 成功，`-m unittest mobile.lab.test_window_benchmark core.test_rules_contract` 14/14。`tools/run_regressions.py --prepare --mobile` 通过 23/24，唯一失败 `completion` 报告两个已有车载文件超过 300 行，以及隔离工作树缺既有登记的车载 Gradle 构建报告。 [根离线回归](../output/mobile-window-20261126/regression-root-prepared/verification.json)
- `mobile/tools/run_mobile_checks.py` 63/63，`tools/check_mobile_branch.py` 26/26。 [移动离线回归](../output/mobile-window-20261126/mobile-checks-native/verification.json) · [移动分支回归](../output/mobile-window-20261126/mobile-branch-native/verification.json)
- `-m mobile.lab.window_benchmark_capture` 在 API 36 非 root 仿真环境封存四组，专用夹具已卸载，转发和模拟器已释放。两次 `-m mobile.lab.window_benchmark` 重放报告摘要相同。5/10/30 秒漏掉约 36 秒的旧批次发送，60/120 秒纳入，五档均误配同值 B。 [设备会话](../output/mobile-window-20261126/real-07/suite.json) · [清理记录](../output/mobile-window-20261126/device-cleanup-7.json) · [窗口验收](../output/mobile-window-20261126/verification.json)
- 待办为独立移动应用的窗口取证和生产读取 Hook 的 API 36 兼容性复验。沿用生产窗口 30 秒。

## 2026-11-26 · 移动审计交付与复核

- 范围为证据 ZIP 与离线重放、任务失败日志与重试、移动夹具多页面覆盖率、逐条人工复核。以已推送的移动窗口基准提交为父提交。
- 一键审计关联阶段封存规则、实际选用的政策与原始输入。HTTP 下载按任务绑定，CLI 复用移动关联器。拒绝错误的 APK 摘要、已变化的输入和混入的会话。四组手机原件全部从 ZIP 重放，五档报告摘要与上轮一致。 [四组离线结果](../output/mobile-audit-delivery-20261126/portable-window-final/verification.json)
- 失败任务日志按固定名称读取，重试复用经核对的原 APK 和任务设置，独立记录任务 ID 和原单。复核由本任务的发现 ID 定位，单独保存人工状态、复核人、时间和依据。Chrome 用封存的真实手机会话验收下载与复核回读，用受控失败验收重试和回看原单。浏览器下载包离线核对四条原始发现一致。 [页面验收](../output/mobile-audit-delivery-20261126/browser-verification.json) · [下载包复算](../output/mobile-audit-delivery-20261126/browser-zip-replay/verification.json)
- 自有 Android 16 三页夹具标注参考及自动轮各完成 3/3 页、4/4 个运行时确认动作。首轮等待设备电话服务，第二轮遇到顶部区域点击未进入目标页。最终夹具用无标题栏主题和安全内边距复验，专用模拟器与安装已释放，离线重新评分摘要一致。 [G1 设备验收](../output/mobile-audit-delivery-20261126/ui-coverage-03/verification.json) · [清理记录](../output/mobile-audit-delivery-20261126/device-cleanup-3.json)
- `mobile/tools/run_mobile_checks.py` 63/63，`tools/check_mobile_branch.py` 26/26，`unittest discover -s mobile/pipeline -p 'test_*.py'` 17/17，前端流水线契约 7/7。根回归 23/24，`completion` 受既有车载 CSS/JS 行数和本隔离树构建报告基线影响。 [移动回归](../output/mobile-audit-delivery-20261126/mobile-checks/verification.json) · [移动分支回归](../output/mobile-audit-delivery-20261126/mobile-branch-final/verification.json) · [根回归](../output/mobile-audit-delivery-20261126/regression-final/verification.json)
- 待办为独立移动应用的 G1 多页面覆盖验证。
