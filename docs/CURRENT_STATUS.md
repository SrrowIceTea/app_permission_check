# V-Scanner 当前状态与本周工单（唯一入口）

> 更新：2026-11-23｜本轮以 `main` 的 `a71895b` 为基线；§1–2 保留 11-12 工程验收快照。
> 仅用于授权测试（自有设备与自有 APK）。本文只写**状态与工单**，不新增任何检测结论。
> `docs/` 下 16 份计划/方案类文档与根目录那份副本顶部都已标注「历史快照（2026-11-11 归档，
> 不作当前清单）」——它们保留证据与来龙去脉，但**不再互相替代**；要判断"现在做什么"只看本文。
> 交付/验收记录类（`DUO_WEEK1_INTEGRATION`、`ME_CAPTURE_WEEK1_DELIVERY` 等）不标注，它们本来
> 就是记录而不是清单。

---

## Android 13 车载编译权限级别标定（2026-11-24）

- 官方 AAOS 33 x86_64 r05（`TEA1.250515.001`）逐条确认 10/10 项权限的编译整数，已同步发布库和 Room 预置资产。Android 13、14、15 合计 170 条已标定，Android 16 的 10 条待取证。 [冻结证据](../vehicle/rules/device_calibration/protection-level-aaos33-r05.json) · [入库核对](../output/vehicle-permission-api33-20261124/publication-verification.json)
- AAOS 33 / user 10 的 Room DAO 回读与发布库 180 行逐项一致，Android 13 的 10 条整数全部匹配。根离线回归 22/22。 [Room 验收](../output/vehicle-permission-api33-20261124/room-verification.json) · [根回归](../output/vehicle-permission-api33-20261124/regression/verification.json)

## Android 14 车载编译权限级别标定（2026-11-24）

- 官方 AAOS 34 ext9 x86_64 r05（`UAA1.250512.001`）逐条核对 10/10 项权限，编译整数已进入发布库和 Room 预置资产，原有 AOSP 定义来源保留。 [冻结证据](../vehicle/rules/device_calibration/protection-level-aaos34-r05.json) · [入库核对](../output/vehicle-permission-api34-20261124/publication-verification.json)
- AAOS 34 / user 10 的 Room DAO 回读与发布库 180 行逐项一致，Android 14 的 10 条整数全部通过。根离线回归 22/22。 [Room 验收](../output/vehicle-permission-api34-20261124/room-verification.json) · [根回归](../output/vehicle-permission-api34-20261124/regression/verification.json)

## 11/23–11/29 周计划验收

| 计划项 | 本轮验收 |
| --- | --- |
| 11/23 补传复跑 | 仓库入口从原始 SQLite、WAL、HTTPS 正文和回执复现 4 条在线点、5 条离线点。 [补传报告](../output/vscanbench-week-20261123/carstats-replay.json) |
| 11/24 样本资格 | Car Stats Viewer 有离线批次回执，记录粒度是行驶点。Auto4Android 上游协议给出批量车辆字段，单次读取标识和延迟参考未证实。GeelyDiagnostics 上游公开的是本机报告导出。现有证据下走 B2 备线。 [补传证据](../vehicle/bench/WINDOW_CALIBRATION.md#car-stats-viewer-断网补传) · [Auto4Android 协议](https://github.com/DigitalDistraction/Auto4Android/blob/main/docs/protocol.md) · [GeelyDiagnostics](https://github.com/lisindima/GeelyDiagnostics) |
| 11/25–11/27 基准与报告 | 两个自有 APK、90 个已签核配对，重放 5、10、30、60、120 秒五档。同值跨批、不同值负控和范围外候选单列。 [冻结清单](../vehicle/bench/vscanbench-pilot.json) · [五档报告](../output/vscanbench-week-20261123/pilot-repeat.json) |
| 11/28–11/29 复跑与周结 | 两次真实原始证据重放的报告 SHA-256 一致，定向测试 30/30，根离线回归 22/22。 [复跑说明](../vehicle/bench/README.md#b2-vscanbench-最小基准) · [离线回归](../output/vscanbench-week-20261123/regression/verification.json) |

30 秒生产阈值沿用现有值。独立应用的窗口校准仍需可唯一对齐到一次读取的短延迟、长延迟和负控证据，当前两份夹具标签为工程复核层。

VScanBench 新增同一自有 APK 的只读负控与发送对照。两个 AAOS 会话各通过 10 项健康检查。只读轮 0 个请求、0 个外发配对。发送轮 1 个 HTTP 200 回执、5 个经正文核对的主读取配对。两轮计为一个夹具工作流，沿用两份已签核样本的统计。 [原始证据复验](../output/vscanbench-read-send-20261123/run-02/control-verification.json)

配对模式回归已覆盖只读 `0/0/0` 和发送 `8/5/5`。90 个签核配对重放经两个子代理独立复核一致。支持批次标识的夹具在五档组合模式下均命中 10 对正例、0 个额外候选，未丢失时间窗已命中的正例。第二夹具按时间窗重放。 [基准报告](../output/vscanbench-pairing-20261123/pilot-final.json) · [双人复核](../output/vscanbench-pairing-20261123/review-verification.json)

## 车载 v2 工作台真实数据验收（2026-11-23）

- 自有 APK 的静态任务（`mode=static`）跑通 v2 七页：概览 22 条候选、静态审计 22/22、源码页取到 jadx 文件树与正文；采集、关联审计、看板三页仍只有跳过态，未接设备。
- 修复静态任务只读 `/findings`（按契约要求 `state=done`）导致概览 0 条、静态页空表：投影层改从 `static/static.json` 计数并写 `findings_count_source=static`，`/static` 复用规则标题口径。证据在 `output/v2-acceptance/`（不入库）。
- 顶栏连接态改为「服务已连接 · 目标 AAOS 35」，不再用服务在线暗示设备已连。
- `vehicle-webapp` 组测试含新增 4 例，46/46；根回归 21/22，唯一红仍是 `completion` 的 `vehicle/frontend/vehicle.css`（426 行）与 `v2/app.js`（317 行），两文件来自远程 main 且未登记基线。

## 车载一键审计复验（2026-11-18）

- 使用自有 AAOS 35 模拟器、user 10 和仓库自有夹具，关闭 TLS 校验绕过。第一批三轮均有独立会话，采集校验 10/10，进程正常退出并生成 PDF 与看板。第三轮使用本机故障端点，AI 复核标为降级，任务状态为 `done`。
- 第一批默认 HTTP 地址未取得独立回执，会话绑定核验为 `incomplete`，已声明的会话、包、摘要与采集健康检查全部一致。证据见 [复验汇总](../output/vehicle-stability-20261118/verification.json)。
- 使用仓库自有 debug 场景和独立本机 HTTP 接收端补测三轮。每轮有一个独立会话和一条以唯一场景标记关联的服务端回执，原目录及报告证据包均核验为 `binding_consistent`，采集正常退出，PDF 与看板齐全。第三轮验证了 AI 不可用时的降级。见 [带回执的复验汇总](../output/vehicle-stability-bound-20261118/verification.json)。
- 旧失败记录最后一行是停止信号，无法区分刷盘、确认落盘或卸载阶段。现已增加刷盘各阶段的开始日志，本次复验未重现卡死，根因仍待确认。

## 车载复核（2026-11-14）

- 本机 AAOS 已恢复。使用已有 AVD 只读冷启动，独立保存 Android 工具状态。实测 Android 15 / API 35 / user 10，镜像 AAI5.260516.001.A6。隔离 HA 2026.10.4 已启动，测试账户通过 API 鉴权。证据根为 `output/vehicle-aaos-readiness-20261114-213908/`。
- HA 电量正文与订阅/控制各自建立了新 session。服务端确认电量 73% 和 61%，App 侧各有一条同值完整请求关联，电池模拟已恢复。订阅重连、旧连接消失和两次控制均通过。最终复验为 `ha-body-03/` 与 `ha-socket-02/`。两轮各封存两条当轮服务端回执，`binding-verification.json` 均为 `binding_consistent`，人工签核仍待完成。
- **YAABSA v1.17.0 AAOS x86_64** 已从 [官方发布资产](https://api.github.com/repos/Vito0912/yaabsa/releases/assets/724915285) 续传，签名及装机摘要 `5a00d096…f58873` 已核验。设备 Wi-Fi 已启用但未连接时，客户端将本地 Audiobookshelf 标为不可达。接回 `AndroidWifi` 后，原生车载媒体库加载合成音频，前后台各完成一次播放和暂停。独立服务端确认两次进度变化、累计听音分别增加 13.316 秒与 13.429 秒，暂停对照进度保持稳定。服务端进度与媒体会话暂停位置分别差 6.994 秒和 7.184 秒，未达到本轮 4 秒对齐判据。新通用采集健康，审计为 `no_target_general_reads`，业务回执保存在外部验收记录，采集会话绑定仍不完整。旧版专用发送契约仍只覆盖 v1.16.0。证据在 `yaabsa-v117-business/playback-03/verification.json`。
- 权限库共 180 行，Android 13/14/15/16 分别为 10/10/150/10 行。11-18 将 AAOS 35 A6 的 **150/150** 条编译整数作为独立设备来源纳入发布库和 Room 资产。A6 模拟器覆盖升级和应用进程重启后，Room 两次回读逐条匹配冻结证据。Android 13/14/16 的 30 条仍待对应版本取证。 [入库验证](../output/vehicle-permission-import-20261118/verification.json) · [运行验收](../output/vehicle-permission-room-20261118/device-003/verification.json)
- 基准、盲评、政策评估、SDK 调用栈归属、AAOS 35 覆盖表与进程生命周期监测均已有实现。仍缺独立参考与样本评测、SDK 库指纹侧车、扩展政策结构化、跨版本设备验收及晚启动/重启捕获。类加载归因、UI 探索覆盖率、分段自愈、独立设备侧连接对照和定位格式扩展仍无完整车载交付。普通第三方设备入口仍会拒绝 split APK，OEM 适配待实测。
- 车载账本按目标包和会话排除无归属的事件及回执。修复了 Windows 路径含 `#` 时无法只读加载显式规则快照的问题。新增 HA 专用验收在采集结束前封存独立 REST 回执。根离线回归 22/22 组通过，证据见 `output/vehicle-kickoff-host-final-20261114-214942/verification.json`。

### YAABSA 暂停同步复验（2026-11-15）

- 原生播放验收接入已有的 AAOS Wi-Fi 检查。仅在装机摘要匹配、设备为自有模拟器时执行重连。人为断开预设 Wi-Fi 后，实测恢复连线、DHCP 及默认网络。证据见 `yaabsa-v117-business/playback-04/wifi-recovery.json`。
- 同一份 v1.17.0 APK 复验中，前台与后台各在暂停后得到两条进度请求。带听音增量的第一条 `currentTime` 为 15.347366 秒和 35.521501 秒，与媒体会话 15.347 秒和 35.521 秒均在 1 毫秒内对齐。随后 52 和 122 毫秒各有一条 `timeListened=0` 请求，上报 15.437 秒和 39.146 秒，与最终服务端记录相同。后续请求引入本轮 0.090 秒和 3.625 秒的差值。这两段满足原 4 秒判据，重复提交仍存在，旧轮约 7 秒偏差继续保留。
- v1.17.0 源码同时包含播放状态变更触发的同步和 `pause()` 内的显式 `flush()`。目前依据为源码路径与隔离回环请求，尚未取得逐调用栈证据或验证上游补丁。设备验收与请求位置见 `yaabsa-v117-business/playback-04/verification.json`、`loopback-sync-requests.json`。根离线回归见 `output/vehicle-yaabsa-wifi-regression-20261114-235905/verification.json`。
- `playback-07` 完成新版隔离回环请求归属和两条业务回执封存。4 条已归属请求覆盖两次暂停，2 条周期请求保留归因缺口。客户端暂停后覆盖进度的问题继续跟踪。开发与复现入口见 [开发日志](DEVELOPMENT_LOG.md)。

## 1. 代码基线（2026-11-12 快照）

| 项 | 值 |
| --- | --- |
| 分支 / HEAD | `main` @ `81f14dc`（`Add vehicle frontend ledger panel and work_docimg AAOS charts…`） |
| 上一提交 | `172f613 Clarify acceptance baseline after syncing teammate updates` |
| 解释器 | 解析顺序 `VSCAN_PYTHON` > `.venv` > `%LOCALAPPDATA%\Programs\Python\Python313`（本机落到 3.13.9）；用户登录 shell 的默认 `python` 是 WindowsApps 3.15，缺 frida/mitmproxy/cryptography/jsonschema/pypdf |
| 回归产物根 | `output/`（不入库，`.gitignore:24`）；本轮三份见 §2 |
| 设备 | 本轮**未接任何设备**：三条入口全部离线，AAOS 模拟器与手机模拟器均未启动 |

### 1.1 工作区未提交改动（按主题，2026-11-12 00:20 `git status` 快照）

| 主题 | 文件 | 状态（据 `git diff` 观测，不替并发会话下结论） |
| --- | --- | --- |
| A1 回归可信化 | `core/regression_output.py`、`core/test_regression_output.py`、`mobile/ai/benchmark_review.py`、`mobile/ai/benchmark_review_attach.py`、`Jenkinsfile`、`.github/workflows/ci.yml`、`docs/REGRESSION_CI.md` | 已落：`atomic_write_text` 复用 `REPLACE_ATTEMPTS`、两处 AI 落盘点接入、两条 CI 设 `CODEBUDDY_SAFE_DELETE_ENABLED=0`、文档有「Windows 环境注入假红」小节；**缺口**：三入口各连跑 3 次的 `verification.json` 证据 |
| A2 组数口径 + CI 第三入口 | `tools/test_regression_manifest.py`（新增）、`docs/REGRESSION_CI.md` 机器标记、`Jenkinsfile`、`ci.yml` | 已落：组数由代码对拍文档，两条 CI 都跑 `check_mobile_branch.py` |
| A3 质量守卫 | `tools/engineering_guards.py`、`tools/engineering_guard_baseline.json`、`tools/test_engineering_guards.py`、`requirements-dev.txt`、两条 CI | 已落：三条规则（行数含 `.js/.css/.mjs`、授权声明、静默吞异常）+ `--update` 重建基线；**缺口**：baseline 只有数字，缺「登记日期 / 后续拆分标记」 |
| A4 静默异常 | `core/collector/{health,uid_sampler}.py`、`core/ai/llm_client.py`、`core/frida_host/{message_stream,run}.py`、`vehicle/workbench/server.py`、`vehicle/webapp/{server,http_io,finding_reviews}.py` | 进行中：改动处带 `# noqa: BLE001 + 理由`；12 处未逐条核完 |
| A5 `load_rules` 收敛 | `core/rules_contract.py`（新增 `load_rule_rows`）、`vehicle/analyze/correlate.py`、`mobile/analyze/correlate_mobile.py`、`core/test_rules_contract.py` | 已落：两线只剩转发壳与各自失败策略 |
| A6 环境/数据集口径 | `AGENTS.md` 环境表与数据集说明、`environment.ps1`、`.agents/README.md`、`core/env_guard.diagnose_apk_dir`、`mobile/tools/batch_thirdparty.py` | 已落：`missing/empty/filtered/ok` 四态诊断 |
| A7–A9 本次交付 | 见 §4.1 | 完成（未提交） |
| 前一轮车载前端 | `vehicle/frontend/{README.md,ledger.js,results.js,test_ledger_panel.mjs}` | 面板本体已在 `81f14dc`；工作区是后续微调 |

> 说明：A1–A6 由**并发会话**在同一工作区推进，上表是 00:20 的快照；判断某项是否完成，
> 以 `git diff` 与 §4 的验收命令为准，不以本文文字为准。

---

## 2. 三条回归（2026-11-12 00:2x 实测，全部离线）

| 入口 | 命令 | 组数/项数 | `verification.json` | 结论 |
| --- | --- | --- | --- | --- |
| 根回归 | `tools/run_regressions.py` | **22 组** | `output/a789b-root/verification.json` | 22/22 退出码 0 |
| 移动侧 | `mobile/tools/run_mobile_checks.py` | **63 项** | `output/a789b-mobile/verification.json` | `passed=true`、`failed=[]`（63/63） |
| 移动分支 | `tools/check_mobile_branch.py` | **26 组** | `output/a789b-branch/verification.json` | `passed=true`、`failed=[]`（26/26） |

运行环境约定（两类环境假红，改完先按这里设）：

```bash
# 1) Windows bulk-delete guard 会把 3 组分支回归打成 SystemExit(1)
CODEBUDDY_SAFE_DELETE_ENABLED=0
# 2) 必须用 Python 3.13（缺库时 env_guard 以退出码 3 结束，那不是测试失败）
.\tools\python313.ps1 <脚本>
```

组数口径：`22` 来自 `tools/run_regressions.py:CHECKS`（`--mobile` 23、`--prepare --mobile` 24），
`26` 来自 `tools/check_mobile_branch.py:CHECKS`，`63` 来自 `mobile/tools/run_mobile_checks.py`。
三处现在由 `tools/test_regression_manifest.py` 与文档机器标记对拍（A2），不要再手写数字。
注意 `docs/ENGINEERING_WEEK_TASKS_20261111.md` 里 A4 的验收标准仍写「根回归 21 组」——
那是建单时的口径，A8 加 `log-rotation` 组后是 22 组。

---

## 3. 未完成清单（6 + 4 + 4 = 14 条，去重与剔除后 11 项）

来源：`AGENTS.md`「仍**未做**」段（6 条）、`mobile/CLAUDE.md`「**未完成**」段（4 条）、
`docs/VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md`「仍未完成（不得写成已完成）」段（4 条）。
只写小节名不写行号——这三份文件都还在被编辑，行号会漂。

| # | 未完成项 | 来源 | 为什么不在本周 A 组 |
| --- | --- | --- | --- |
| 1 | 车载 B1 已签核两个自有 APK 的五档重放。Car Stats Viewer 已验收车速上传与 5 条断网行驶点补传 | [车载复核](../vehicle/bench/WINDOW_CALIBRATION.md) + mobile「未完成」 | 独立应用窗口仍缺可唯一对齐到单次 VHAL 读取的延迟证据，移动 30000ms 待实测 |
| 2 | `protection_level_value`：车载 Android 13/14/15 共 170 条已入库，Android 16 的 10 条待补。移动 40 条未断言 | 本文「Android 13 车载编译权限级别标定」+ mobile「未完成」 | 各版本使用各自来源 |
| 3 | B2 VScanBench 最小版已交付，完整场景矩阵待扩展 | [车载基准](../vehicle/bench/README.md#b2-vscanbench-最小基准) | 新场景仍需独立参考与负控 |
| 4 | F1 类加载归因（无 `hook_classload.js`） | AGENTS「未做」 | 需新钩子 + 设备验收 |
| 5 | G1 UI 探索覆盖率度量 | AGENTS「未做」 | 需设备与人工标注 |
| 6 | A4 分段自愈 | AGENTS「未做」 | 与 1/3 同类的设备专项 |
| 7 | AI 跨运行一致性 / 幻觉率无量化数据 | mobile「未完成」 | 需多次真实 key 调用，成本与口径未定 |
| 8 | 写入类 API（`ContentResolver.insert` 等）与覆写型服务（无障碍/通知监听）未覆盖 | mobile「未完成」 | 需夹具扩展，非本周范围 |
| 9 | 车载真实业务复测。定位夹具和 MG4 已有 11-11 真实验收，HA 两条链路已于 11-14 复测通过。YAABSA v1.17.0 的连接、前后台播放、暂停及服务端进度变化已验证 | 本文「车载复核」 | YAABSA 仍待核对约 7 秒位置差、封存业务回执和验证新版发送观测契约 |
| 10 | 对每个新的业务会话依次核验当前构建、新采集、会话绑定及审计产物 | VEHICLE_ONLY「未完成」2 | 每条业务独立留下验收证据 |
| 11 | 车载 §4 第二/三阶段：设备侧连接对照（PCAPdroid）、自然定位格式扩展、SDK 库指纹侧车、政策结构化、四版本能力矩阵、split APK/OEM 适配 | VEHICLE_ONLY「未完成」3 | 需真实 AAOS 输入与独立参考 |

**合并与剔除规则**（14 → 11）：

- 车载跨应用阈值验证与移动侧 30000ms 校准归在时间窗议题 → #1（-1）；
- AGENTS 的 protectionLevel 与 mobile 的 40 条是同一件事（级别映射）→ #2（-1）；
- VEHICLE_ONLY「未完成 4」写「前端未改」，但该文件 §7 已记录"本轮补齐"，HEAD `81f14dc`
  的提交标题就是车载前端面板 → **该项已交付、不是未完成项**，剔除（-1）；
- VEHICLE_ONLY 的「采集未执行」与「待执行顺序」是同一件事的现状与步骤，保留为 #9/#10 两步（不减）。

14 - 3 = 11。若后续发现 #11 里某条已闭，请直接改本表并在提交信息里说明。

---

## 4. 本周 A 组工单状态（`docs/ENGINEERING_WEEK_TASKS_20261111.md`）

| 项 | 优先级 | 状态 | 证据 / 缺口 |
| --- | --- | --- | --- |
| A1 回归可信化 | P0 | 基本完成 | 见 §1.1 行 A1；差「三入口各连跑 3 次」的证据 |
| A2 组数口径 + CI 第三入口 | P0 | 基本完成 | `tools/test_regression_manifest.py` 对拍文档与代码；两条 CI 已跑第三入口 |
| A3 质量守卫进 CI | P0 | 基本完成 | `tools/engineering_guards.py` + baseline + CI；差 baseline 的登记日期/拆分标记与 `ruff format --check` |
| A4 静默异常治理 | P1 | 进行中 | 目标文件有带理由的未提交改动；12 处未逐条核完 |
| A5 `load_rules` 收敛 | P1 | 基本完成 | 两线为转发壳；对拍与「不得出现第二个 SQL 读库者」守卫在 `core/test_rules_contract.py` |
| A6 环境/数据集口径 | P1 | 基本完成 | `diagnose_apk_dir` 四态 + 环境表统一；跑批入口已接 |
| **A7 补三处离线测试盲区** | P2·余量 | **本次完成** | `mobile/pipeline/test_runner_branches.py`（7 例）、`mobile/tools/test_batch_plan_resume.py`（10 例）、`frontend/test_pipeline_contract.mjs`（7 例）、`mobile/pipeline/test_stages_api.py`（2 例，服务端 `/api/stages`）；新回归组 `batch_plan`、`pipeline_frontend_contract`；`test_inventory_guard` 0 未登记 |
| **A8 `output/` 盘点 + 日志上限** | P2·余量 | **本次完成** | `tools/inspect_output.py`（首跑 6.9s / 37.7 GB / 263,305 文件 / 10 个链接；不遍历 junction、读不到计入 `unreadable`）+ `core/log_rotation.py`（20 MB 分卷、`O_EXCL` 占位不覆盖、新卷首行自描述）+ `core/test_log_rotation.py`（10 例）；接进 `batch_dynamic.run`、`supervise_batch` 三处，并把 `batch_plan._write_header` 改为**追加**（否则跨 `--resume` 的现场每轮被截断，分卷也永远不会触发） |
| **A9 唯一状态入口** | P2·余量 | **本次完成** | 本文 + 17 处「历史快照」标注（16 份 docs + 根目录副本）+ `AGENTS.md` 回归段按实测改写 + `DELIVERY_INDEX.md` 入口 |

### 4.1 本次新增/修改（A7–A9）

新增：

- `mobile/pipeline/test_runner_branches.py` —— 三条终态分支 + 阶段划分（13/4/17 硬编码期望）；
- `mobile/pipeline/test_stages_api.py` —— 起回环 HTTP 服务，断言 `GET /api/stages` 与 `stages.STAGES` 逐项一致；
- `mobile/tools/test_batch_plan_resume.py` —— `_finished` 反例、`collect(resume=True)` 重跑判定、表头追加不截断；
- `frontend/test_pipeline_contract.mjs` —— 时间线由 `/api/stages` 生成（17 阶段）、非数组不画假进度、动态阶段表 = 13 个设备阶段中的 10 个、二次渲染不重复追加；
- `core/log_rotation.py`、`core/test_log_rotation.py` —— 追加日志的 20 MB 分卷口径；
- `tools/inspect_output.py` —— `output/` 只读盘点（不删不移）；
- 本文。

修改：

- `tools/check_mobile_branch.py` —— 注册 `batch_plan`、`pipeline_frontend_contract`（24 → 26 组）；
- `tools/run_regressions.py` —— 注册 `log-rotation` 组（21 → 22 组）；
- `mobile/tools/batch_dynamic.py`、`mobile/tools/supervise_batch.py` —— 日志改走 `open_capped`；
- `mobile/tools/batch_plan.py` —— 样本 `run.log` 表头由截断改为追加（失败现场不再被下一轮抹掉）；
- `mobile/pipeline/runner.py` —— `badging`/`launchable_activity` 提到模块顶层（行为不变，
  但测试能打到真桩，不再依赖"函数体内延迟导入"这一实现细节）；
- `docs/REGRESSION_CI.md` —— 新增「output/ 盘点与新增日志上限（只读）」小节；
- `AGENTS.md` 回归段、`DELIVERY_INDEX.md`、17 处历史文档标注。

---

## 5. 结论可信度：七条已知缺口（必须继续守住）

**未观测 ≠ 安全。** 当前 `observed_findings` 恒为 0（round2 9 样本、breezy 12 条都只到 `candidate`），
所以本项目的结论**不能**说明"某 App 把某数据发出去了"。七条缺口按"会不会导致结论出错"排序，
原文与依据见 [PROJECT_STATUS_20261110.md §4「已知缺口」](PROJECT_STATUS_20261110.md)。

任何报表、页面、汇报口径都不得把 `candidate` 写成违规、不得把漏斗各层相加成"检测率"、
不得把"设备未验收"写成"已验收"。

---

## 6. 维护规则（避免下一个人再遇到口径漂移）

1. **组数只认代码**：`CHECKS` 变了就同步 `AGENTS.md` 与 §2，不要凭记忆写数字；判通过只看 `verification.json`。
2. **环境值只认 `env_guard` 退出码**：`0` 通过、`1` 测试失败、`3` 环境缺库。不要再在文档里写"依赖已齐/缺 jsonschema"这类无时点结论。
3. **新增守卫要能说出"改坏哪一行会红"**：写不出变异证据的断言，等于没有（本轮审查就抓到两条：
   期望值用被测常量自指、断言的对象由 fixture 自己创建）。
4. **本文只增状态，不写计划**：新计划另立文件并在此登记一行；旧计划一律加「历史快照」标注，不改正文。
5. **`output/` 只读**：盘点用 `tools/inspect_output.py`，不删除、不移动（`AGENTS.md`「待办」段的同款约束）。
