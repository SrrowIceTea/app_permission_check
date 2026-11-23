# AAOS 35 关联窗口初评

2026-11-03。仅用于授权测试。使用自有 AAOS 35 夹具和本机 HTTP 接收端。先缓存读取批次，等待约 36 秒，再执行一次读取并立即上传，最后上传缓存批次和不同值负控。参考配对由夹具的动作回执、批次语义和请求标记确定，人工签核待完成。

| 窗口 | 命中参考配对 | 额外候选 | 漏掉参考配对 |
| --- | ---: | ---: | ---: |
| 5 秒 | 14 | 14 | 14 |
| 10 秒 | 14 | 14 | 14 |
| 30 秒 | 14 | 14 | 14 |
| 60 秒 | 28 | 28 | 0 |
| 120 秒 | 28 | 28 | 0 |

同一个车辆属性值可能连续多次相同。短窗口会漏掉旧批次，同时让近期同值读取成为旧批次上传的候选。加长窗口补回延迟配对，也会产生更多跨批次候选。此表按规则、读取事件、流事件计数，一个应用调用可经过多层被观察的 API。额外候选表示与夹具已知来源批次不一致，不能用于推算第三方 App 的违规误报率。

报告在每条配对显示匹配读取候选数，并记录 `origin_proven=false`。默认 30 秒是当前观察基线。缓存、断网恢复等场景需要独立批次证据，才适合解释更长时间范围的相关性。

本地原始证据见 `output/vehicle-window-20261103-004/`。其中 `actions.json`、`reference-alignment.json`、`labels.json` 和 `window-calibration.json` 分别记录动作、对齐、初评来源与窗口结果。004 轮使用唯一动作令牌，复现 002 轮的统计结果，同时通过生效代理清理检查。失败日志保留。校准工具复用采集健康和摘要校验，窗口覆盖值只进入重放过程。

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.window_calibration --capture output/vehicle-offline-window-20261103-002/capture --labels output/vehicle-offline-window-20261103-002/labels.json --rules output/b1-window-review-20261118/rules.db --out output/window-replay.json
```

## 真实断网恢复对照

在专用 AAOS 35 模拟器上关闭 Wi-Fi 并将 `wlan0` 置为 down。夹具直接尝试连接同一自有接收服务，记录真实失败和一批缓存。恢复 Wi-Fi 后，先执行一次同值的新读取并直传，再上传旧批次。重传正文携带原缓存 `sourceBatchTokens`，与离线动作回执的令牌一致。Wi-Fi 与采集代理均通过收尾检查。

5、10、30、60、120 秒的参考配对和额外候选计数与上表一致。带令牌的旧批次可独立核验，60 秒补回它的参考配对。常规规则继续使用 30 秒。扩展窗口仅用于批次标记可对齐的复核或实验。

证据见 `output/vehicle-offline-window-20261103-002/`，包含断网与恢复状态、失败回执、带批次标记的上传和人工待签初评。002 轮冻结了夹具源码，后续改动工作区源码也能重放该轮标签。

## O2 主读取配对

旧标注按动作时间段包含 28 个运行时事件。其中 18 个来自 `readFloatCrossCheck` 的
诊断调用及其嵌套 Hook。夹具的 `VhalReader` 明确将该分支排除在上传载荷之外。
主读取参考沿用原始动作回执和两条目标流，按独立调用栈保留 10 条 `readOne` 观察。
原标注保留作窗口兼容基线。主读取初评仍待人工签核。

| 冻结断网 002，30 秒基线 | 主读取命中 | 额外候选 | 漏配 |
| --- | ---: | ---: | ---: |
| `window` | 5/10 | 23 | 5 |
| `token` | 10/10 | 0 | 0 |
| `both` | 10/10 | 0 | 0 |

5 条缓存主读取的上传间隔超过 30 秒。令牌模式要求封存的自有夹具证据，
同包、同会话、相同已知 UID、成功且明确归因的代理请求、唯一批次令牌与唯一主读取。
直传使用请求令牌，缓存上传要求恰好一个原始批次令牌。
正文属性 ID、属性名、结果和值必须一致，并在设备时钟下与主读取 Hook 相差 0–50 ms。
配对输出保留令牌摘要、事件引用与时间差。该结果描述夹具正文主张与独立 Hook 的一致性。
普通审计入口沿用 30 秒默认窗口。

两个旧在线会话的原始源码引用已通过相同 SHA-256 的快照恢复到复核副本。
原动作窗口的命中、额外候选和漏配数均可重放。
这两轮的缓存正文缺少原始批次令牌，严格模式各匹配 5/10 条直传主读取，额外候选为 0。
混合模式把未取得批次依据的流交回窗口逻辑，30 秒下各留下 14 个额外窗口候选。

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.bench.window_calibration --capture output/vehicle-offline-window-20261103-002/capture --labels output/o2-batch-pairing-20261103/primary-labels.json --rules output/b1-window-review-20261118/rules.db --pairing both --include-pairs --out output/o2-batch-pairing-20261103/replay.json
```

## 2026-11-18 离线复核

重放按会话摘要核对显式规则库快照，VHAL 和通用规则使用同一份文件。`--include-pairs` 输出逐窗口的规则与事件引用，供复核配对。使用当前发布库时，工具以摘要不匹配拒绝该历史会话。

用原始标签复现五档结果。用 10 条主读取标签时，5、10、30 秒各命中 5 条，产生 23 个额外候选，漏 5 条。60、120 秒各命中 10 条，产生 46 个额外候选。批次令牌和混合模式在这次封存会话的五档均为 10 条命中、0 个额外候选、0 条漏配。不同值负控涉及五个成功读取属性，各档均无配对。 [逐条验收证据](../../output/b1-window-review-20261118/verification.json)

本轮建议常规审计保留 30 秒，延迟上传复核优先使用可独立校验的批次证据。签核材料逐条列出动作回执、读事件、流事件及时间差，等待人工填写结论。 [待签核清单](../../output/b1-window-review-20261118/REVIEW.md)

## 2026-11-21 切换到 subagent 签核

11-18 的初评属于历史记录。新一轮使用两名全新上下文的 subagent 分别盲审，第三名 subagent 独立核对原始证据、确认负控并裁决分歧。组织者保留真实启动记录 `run.json`、三份原答卷及摘要。旧会话的规则库快照已按清单摘要恢复，原始采集和动作回执仍缺失。

采集健康检查通过后执行下列命令，新轮次使用空的输出目录。第一步校验会话、规则库、动作回执和冻结夹具源码的摘要。候选取各动作的主读取和三条请求的组合，审阅包只提供原始观测。A/B 收到各自的 ZIP，答卷分别保存为 `A.json`、`B.json`。比较完成后，C 使用原始证据及 `signoff-request.json` 独立填写 `C.json`。任一配对缺证据时保留待审状态。

```powershell
$run = 'output/b1-fixture-20261121-recovery'
$pack = 'output/b1-subagent-review-new'
$compared = "$pack/compared"
.\tools\python313.ps1 -m vehicle.bench.window_review `
  --source $run --reference "$run/labels.json" --rules "$run/rules.db" --out $pack
.\tools\python313.ps1 -m vehicle.bench.blind_round compare `
  --organizer "$pack/organizer-only" --review-a "$pack/A.json" --review-b "$pack/B.json" --out $compared
.\tools\python313.ps1 -m vehicle.bench.blind_signoff `
  --organizer "$pack/organizer-only" --review-a "$pack/A.json" --review-b "$pack/B.json" `
  --signoff "$pack/C.json" --out "$pack/signed"
```

签核后，可用 `window_calibration --labels "$pack/signed/labels-signed.json"` 重放。结果使用 `subagent_signoff=signed` 和 `human_signoff=not_applicable`，仅用于本轮夹具复核，不计作独立样本准确率的金标准。

## 2026-11-21 自有 AAOS 夹具补采

使用重建的 AAOS 35 A6 专用模拟器、自有 `com.vscanner.targetapp` 和冻结的当轮规则库，新采集会话为 `capture-1ae1d8ffe1bc49e69e570fd6ff6573da`。断网请求失败并缓存一批，恢复后的直传、旧批次上传和不同值负控均收到 HTTP 200。代理写回首次 ADB 调用超时，重试读回确认恢复，端口转发已移除。前两轮失败证据单独保留。 [采集健康](../../output/b1-fixture-20261121-recovery/capture/verification.json) · [动作与回执索引](../../output/b1-fixture-20261121-recovery/actions.json)

A、B 独立逐题复核，同意 10 项同源配对和 35 项有反证的配对，全部 45 项一致。C 独立核对并确认 5 项不同值负控。签核状态为 `subagent_signoff=signed`，标签仅适用于本次自有夹具会话。 [启动记录](../../output/b1-fixture-20261121-recovery-review/run.json) · [签核标签](../../output/b1-fixture-20261121-recovery-review/signed/labels-signed.json)

| 签后重放 | 窗口 | 命中 | 额外候选 | 漏配 | 负控命中 |
| --- | --- | ---: | ---: | ---: | ---: |
| 仅窗口 | 5、10、30 秒 | 5 | 11 | 5 | 0/5 |
| 仅窗口 | 60、120 秒 | 10 | 22 | 0 | 0/5 |
| 批次令牌及混合模式 | 五档各自 | 10 | 0 | 0 | 0/5 |

缓存批次的实测读取至上传间隔为 42.447 秒。常规审计仍使用 30 秒默认窗口。签核结果与健康校验均基于补采会话，跨应用阈值泛化仍待独立样本验证。 [窗口重放](../../output/b1-fixture-20261121-recovery-review/window-signed.json) · [批次令牌重放](../../output/b1-fixture-20261121-recovery-review/token-signed.json) · [混合模式重放](../../output/b1-fixture-20261121-recovery-review/both-signed.json)

## 2026-11-22 第二个自有 APK 对照

使用 `com.vscanner.targetapp2` 原有界面和 HTTP 发送路径，在专用 AAOS 35 A6 的三个分开的读取批次后触发上传。读取事件到请求的宿主时钟差分别为 **0.377、16.366、39.370 秒**，当轮全部 10 项采集健康检查通过。三份正文均无批次令牌，代理原始正文 SHA-256 与应用日志、接收端独立响应一致。 [采集健康](../../output/b1-cross-app-20261122/trial-03/capture/verification.json) · [动作与回执](../../output/b1-cross-app-20261122/trial-03/actions.json)

两名独立 subagent 判定一致，第三名独立仲裁后签核。45 项包含 15 项同批主读取和 30 项同值跨批反证，本轮无专设不同值负控。盲审包使用应用原始操作日志和宿主动作记录核对点击，UI 快照随原始采集保存。 [签核标签](../../output/b1-cross-app-20261122/review/signed/labels-signed.json) · [复核启动记录](../../output/b1-cross-app-20261122/review/run.json)

| 仅窗口重放 | 命中 | 漏配 | 额外候选 | 其中已复核跨批 |
| --- | ---: | ---: | ---: | ---: |
| 5、10 秒 | 5 | 10 | 3 | 0 |
| 30 秒 | 10 | 5 | 14 | 5 |
| 60 秒 | 15 | 0 | 25 | 10 |
| 120 秒 | 15 | 0 | 33 | 15 |

额外候选包含已证实的跨批组合与主读取复核范围以外的事件。常规 30 秒规则库未写入。该结果记录两个自有 APK 中的窗口现象，独立应用阈值仍待测量。 [签后逐对重放](../../output/b1-cross-app-20261122/review/window-signed.json)

已盘点历史独立样本清单。Home Assistant 电量回执归属 Android 设备电量读取。其他旧会话缺少原始可重放输入，本轮独立 VHAL 样本计数为 0。 [输入盘点](../../output/b1-cross-app-20261122/historical-inputs.json)

已固定上游 Car Stats Viewer 源码提交 `beda44c4b88cef97862023d529a9f61a337e0ff1`。源码包含 VHAL 回调与 HTTPS 遥测，协议支持离线队列。用同值合成正文调用本仓实际匹配器时，标准属性键 `PERF_VEHICLE_SPEED` 可匹配，应用键 `speed` 无法匹配。该版本另需要 Gradle 9.5.1、AGP 9.1.1 和 compileSdk 37，仍处于静态候选阶段。 [上游协议](https://github.com/Ixam97/CarStatsViewer/blob/beda44c4b88cef97862023d529a9f61a337e0ff1/docs/APIDOC.md) · [本机探测](../../output/b1-cross-app-20261122/carstatsviewer/static-readiness.json)

## 2026-11-23 Car Stats Viewer 独立样本

固定提交的上游源码和仅附加实验室信任锚的本地调试版本均已构建。源码包原有 438 个文件逐字节一致。调试版本信任锚只用于模拟器宿主 `10.0.2.2`，正常执行证书及主机名校验。实测关闭 TLS 绕过，接收端独立记录合法 POST 的车速、接收时间和正文 SHA-256。 [构建与签名身份](../../output/b1-carstatsviewer-20261123/source-build-verification.json) · [接收端测试](../../output/b1-carstatsviewer-20261123/receiver-selftest.json)

`PERF_VEHICLE_SPEED` 经 Car Stats Viewer 取绝对值后以 m/s 写入根字段 `speed`。正文 `timestamp` 是序列化时的设备时钟。首次完整设备轮的采集健康通过，收到 6 条 `speed=0` 的 HTTPS POST。服务命令回报了两次车速注入，但 Hook 和接收端都没有观察到注入值，这一轮只能确认上传链路。 [源码引用和摘要](../../output/b1-carstatsviewer-20261123/source-chain.json) · [首次设备观察](../../output/b1-carstatsviewer-20261123/trial-03/speed-observation.json)

后续会话 `capture-d11fd4f9dbc9493abcb579cf26d33852` 在专用 AAOS 35 A6 上依次设定并读回 −7.25 和 13.5 m/s。两个动作窗口内分别记录 139 和 140 条同值 VHAL 回调，并收到对应的 2 条 `speed=7.25` 和 3 条 `speed=13.5` 的 HTTPS 200 回执。全会话共 6 条回执，包含恢复后的 0 m/s。采集健康 10 项通过，原车速已读回恢复，实验 APK 已卸载。 [实际配对范围与摘要](../../output/b1-carstatsviewer-20261123/trial-04/speed-observation.json) · [恢复核验](../../output/b1-carstatsviewer-20261123/trial-04/vhal-after.json)

独立应用的车速转换及上传链路已验证。同值连续回调形成多个可能来源，正文缺少源读取标识，本轮 `window_scored=false`。30 秒跨应用校准仍需要可独立定位到单次读取的短延迟与延迟上传参考。 [复跑入口](../../output/b1-carstatsviewer-20261123/run.ps1)

### Car Stats Viewer 断网补传

专用 AAOS 35 上先进行了在线对照，4 条本地行驶点均在 HTTPS 正文中找到，设备时钟下从记录到打包为 16–62 ms。随后确认 Wi-Fi 关闭，读取应用 SQLite 主文件及 WAL 中新增的 5 条行驶点，再保持断网至少 45 秒。宿主计时断网区间为 **56.563 秒**，区间内接收端收到 0 条请求。 [时序与快照验收](../../output/b1-carstatsviewer-20261123/queue-trial-01/queue-verification.json)

恢复连接后的同一次 HTTPS POST 携带全部 5 条离线行驶点。以 SQLite 主键 `driving_point_epoch_time` 对照保留的原始正文，记录时间、距离、能耗、起止标记和电量比例逐项吻合，每个点仅出现一次。用同设备时钟计算，打包时这 5 条记录已有 **55.748–64.011 秒**。采集健康 10 项通过，挡位、车速和 Wi-Fi 恢复已读回，实验 APK 已卸载。 [原始正文](../../output/b1-carstatsviewer-20261123/queue-trial-01/request-bodies/3740ee609fa399b73427709f918e8ecc971ff62c58fbd3f8769d68aff249479b.json) · [复跑入口](../../output/b1-carstatsviewer-20261123/run_queue.ps1)

行驶点时间标识数据库记录，点内距离和能耗累积自一个区间，电量比例由电量与容量计算。本轮证据可定位到原始行驶点，单次 VHAL 读取仍缺独立标识，`window_scored=false`。现有候选初筛中，Auto4Android 的遥测协议使用批量车辆字段，GeelyDiagnostics 上游描述的是本机报告导出，尚未发现符合单次读取延迟取证要求的替代路径。 [Auto4Android 协议](https://github.com/DigitalDistraction/Auto4Android/blob/main/docs/protocol.md#app--bridge-vehicle_data) · [GeelyDiagnostics 项目说明](https://github.com/lisindima/GeelyDiagnostics)
