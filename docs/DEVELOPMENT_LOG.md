# V-Scanner 开发日志

从 2026-11-15 起记录每次开发。按日期追加，同日多轮写明任务。开始时登记范围，收尾时记录改动、验证、证据和待办。达到 300 行时将旧记录转入按日期命名的分卷，并在这里保留索引。验收记录只引用可复核、无测试凭据的产物。

- [2026-11-15 至 2026-11-18 分卷](DEVELOPMENT_LOG_20261115_20261118.md)

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
