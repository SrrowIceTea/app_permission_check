# B1 独立应用窗口资格复核

2026-11-25。独立可计分案例为 **0**，生产窗口沿用 **30 秒**。在自有 AAOS 上封存的 Car Stats Viewer 会话可复现车速上传和离线补传。三个新增候选完成公开源码筛查，均缺可核验的单次车速读取到回执的对应关系。设备部分仅复用已授权采集的存档。

## 候选核对

| 应用与固定提交 | 观测到的数据路径 | 本轮资格 |
| --- | --- | --- |
| Car Stats Viewer `beda44c4` | 应用取车速绝对值后写入 HTTPS 正文 `speed`。`timestamp` 取自正文序列化时钟。5 条车速对照回执有 45、99、10、66、121 个先于请求的同值读取候选。断网 56.563 秒后收到 5 个可追溯到本地 SQLite 行的行驶点。 [上游协议](https://github.com/Ixam97/CarStatsViewer/blob/beda44c4b88cef97862023d529a9f61a337e0ff1/docs/APIDOC.md) | 两条业务链路均为 `workflow_only`，`window_scored=false`。 |
| Capy `e39777c1` | VHAL 回调保留属性时间戳。路线保存从当前快照取车速并使用路线采样时钟。同步的 `telemetryFrames` 携带持久化帧编号和帧时钟，车速字段未携带原回调时间戳。 [回调](https://github.com/Timoteohss/capy/blob/e39777c11c8eed28d1fd4af108d725525e270300/android/app/src/main/kotlin/com/timhss/capyenergy/telemetry/VhalSubscriptionManager.kt#L240-L280) · [路线采样](https://github.com/Timoteohss/capy/blob/e39777c11c8eed28d1fd4af108d725525e270300/android/app/src/main/kotlin/com/timhss/capyenergy/telemetry/FrameRepository.kt#L441-L487) · [同步帧字段](https://github.com/Timoteohss/capy/blob/e39777c11c8eed28d1fd4af108d725525e270300/android/app/src/main/kotlin/com/timhss/capyenergy/telemetry/db/TelemetryFrameEntity.kt#L118-L129) | 路线点或同步帧可标识自己的记录。已查车速路径缺少对原回调的引用。 |
| Drive Assist `5d6a14c9` | MQTT 将周期快照投递到可合并的状态消息。ABRP 将快照车速写为 `speed`，组包时生成 `utc`。 [状态分发](https://github.com/SuspiciousRepair/drive_assist/blob/5d6a14c9dffc03336e957cc6cea99ed7631320fd/drivemem/src/main/java/com/geely/drivemem/services/TelemetryService.java#L114-L125) · [MQTT 消息](https://github.com/SuspiciousRepair/drive_assist/blob/5d6a14c9dffc03336e957cc6cea99ed7631320fd/drivemem/src/main/java/com/geely/drivemem/net/MqttReporter.java#L371-L375) · [ABRP 正文](https://github.com/SuspiciousRepair/drive_assist/blob/5d6a14c9dffc03336e957cc6cea99ed7631320fd/drivemem/src/main/java/com/geely/drivemem/net/AbrpUploader.java#L436-L472) | 已查出站车速路径缺少每次读取的引用。 |
| Android-AAOS `da3811b4` | VHAL 仓库向工作台提供车辆状态。仪表盘的 NATS 计数和主题每秒随机更新。 [VHAL 仓库](https://github.com/vishnukumar94/Android-AAOS/blob/da3811b420b1f3bbfec6bd4d6830e2d59571d0bb/automotive/src/main/java/com/jgd/carapp/data/VehicleSignalRepository.kt) · [NATS 展示](https://github.com/vishnukumar94/Android-AAOS/blob/da3811b420b1f3bbfec6bd4d6830e2d59571d0bb/automotive/src/main/java/com/jgd/carapp/ui/dashboard/DashboardViewModel.kt#L97-L109) | 已查 NATS 展示路径缺少可核验的车速网络回执。 |

## 已封存证据重放

`output/b1-independent-qualification-20261125/verification.json` 汇总本轮结果，保存三个候选源码存档摘要及两份夹具签核标签和冻结规则库摘要。以下文件均在同一输出目录。

| 文件 | 结果 |
| --- | --- |
| `carstats-speed-replay.json` | `carstats_speed` 重放 6 条 HTTPS 200，结果与封存参考逐字段一致，保留 5 条对照回执的全部候选读取编号。该命令使用原工作树已有的 11/24 车速重放入口。 |
| `carstats-queue-replay.json` | `carstats_queue` 用原始 SQLite、WAL、正文和回执确认在线 4 点、离线补传 5 点，结果与封存参考逐字段一致。 |
| `fixture-1-five-window-replay.json`、`fixture-2-five-window-replay.json` | `window_calibration` 用两份原始会话、签核标签和当轮规则库重放 5、10、30、60、120 秒。每档命中、额外候选和漏配均复现。计分范围为两个自有夹具的 90 个签核配对。 |

## 下一份样本的验收条件

先在固定的授权构建中定位能跨缓存与发送保留的源标识，或取得能建立同等因果关系的独立记录。应用日志、持久队列与本机接收端的原始正文及摘要应能共同定位到同会话的一次读取。接收时间、同值与序列化时间用于筛选候选。

证据链成立后，在自有 AAOS 上各采一组短延迟（少于 30 秒）、长延迟（超过 30 秒）和同值不同批次负控，再按既有五档重放。保留合法接收端回执、冻结规则库和逐对参考。 [窗口方法](WINDOW_CALIBRATION.md)
