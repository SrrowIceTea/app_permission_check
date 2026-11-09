# 乙线测试集筛选：真实上传样本池

生成时间：2026-11-09T18:20:54+08:00。仅用于授权测试（自有设备与获授权 APK）。
本次交付是公开来源检索、候选清单与执行方案；未下载 APK、部署后台、登录账号或执行新会话。
机器清单见 [候选目录](VALIDATION_SAMPLE_POOL_20261109.json)，其 SHA-256 见同名 `.sha256` 文件。
该 JSON 是研究目录，不能直接传给 `samples --catalog`、`benchmark --suite` 或移动端跑批入口。

## 筛选结论与范围

建议组织成“原版 App + 自有服务端 + 专用测试账号 + 可核查上传动作”的测试集。
本次未找到能直接满足乙1至乙5全部条件、附真人标签且可重跑的现成公开数据集。
找到 8 个主选、2 个替补。官方文档支持其上传或同步功能，但本轮已验收数量仍为 **0 App / 0 会话**。
主选只有 HA 与 YAABSA 有明确的上游 AAOS 变体，其余 6 个先列手机 App / AAOS 侧载对照。
如果乙1要求“8 个原生 AAOS App”，这份清单尚未满足；不能将侧载成功改称原生适配。
同一 App 的 HTTP/MQTT、不同 ABI、minimal/full 变体和两个账号都不能重复计 App 数。

仓库现状也需校正：[历史样本复核](../vehicle/lab/SAMPLE_RUNTIME_REVIEW.md)记录前六个样本有四个无 INTERNET，
并记录后续 OwnTracks 两个新点的三侧对齐；[主线补测](VEHICLE_MAIN_CLOSEOUT_20261105.md)已有部分重连验收。
因此不重复宣称所有外发或重连都未做。既有两次动作也不自动等于乙1要求的两个独立会话。
本机只读检查未找到 `D:/数据集/数据集/F-Droid-60`；保留原路径约定，本轮未改环境、未要求用户探测。

## 主选：8 个独立 App

下表传输路径均为待设备核实的候选；官方产品能力不等于固定 APK 的实测结果。

| App / 原版 APK 来源 | 服务端与账号 | 明确上传动作 | 独立回执与评分边界 |
| --- | --- | --- | --- |
| [OwnTracks](https://github.com/owntracks/android/releases) | 自有 Recorder + 带认证的 HTTP 入口；扩展可用 Mosquitto 用户 | 发布新合成坐标和定位时间，先 HTTP POST | Recorder 条目与请求正文摘要；旧固定 APK 仍为 `workflow_only`，须验证本轮规则是否消费读取事件 |
| [GPSLogger](https://github.com/mendhak/gpslogger/releases) | 自有 HTTP 接收端 + Basic Auth 测试账号 | 配置 Custom URL 的 POST、正文模板，开始记录新点 | 独立接收日志中的坐标、时间与正文摘要；定位注册不等于取得坐标 |
| [Home Assistant Automotive](https://github.com/home-assistant/android/releases) | 自有 HA 实例 + 专用用户，固定 automotive-minimal 变体 | 启用支持的传感器、改变测试值并上报；控制动作另测 | 接收载荷及服务端状态/历史；电量、定位、VHAL 分列，minimal 不默认拥有 full 的传感器能力 |
| [YAABSA AAOS](https://github.com/Vito0912/yaabsa/releases) | 自有 Audiobookshelf + 专用用户 + 自有短音频 | 播放、跳到独特进度、同步、暂停 | 服务端播放会话、进度与接收记录；是业务外发样本，播放进度不自动适用隐私外发规则 |
| [DAVx⁵](https://f-droid.org/en/packages/at.bitfire.davdroid/) | 自有 Nextcloud + Contacts + 独立 DAV 用户/应用密码 | 在该 DAV 账号地址簿中新建合成联系人，手动同步 | 服务端 vCard、UID、ETag 和测试字段；AAOS ContactsProvider/账号支持须实测 |
| [Nextcloud Android](https://github.com/nextcloud/android/releases) | 同一自有 Nextcloud，不同测试账号/目录 | 先手动上传唯一小文件，再扩展照片自动上传 | 服务端下载原件核对 SHA-256，加上传日志；上传带坐标的图片不等于调用过定位 API |
| [Immich](https://github.com/immich-app/immich/releases) | 自有 Immich + 测试用户，固定兼容的服务端/客户端版本 | 选合成图片相册、启用备份，每轮新增不同文件 | 服务端 asset 记录、原图摘要；Flutter/native/multipart 解析能力独立登记 |
| [Element X Android](https://github.com/element-hq/element-x-android/releases) | 自有兼容 Matrix homeserver + 两个测试用户 | 给第二用户发送短合成语音消息，并做麦克风拒绝负控 | 接收用户导出/播放、media/event 标识和服务端密文回执；密文上传不能证明采集到了麦克风明文 |

功能依据：

- OwnTracks [自建后台与用户](https://owntracks.org/booklet/guide/quicksetup/)、[HTTP/MQTT 模式](https://owntracks.org/booklet/guide/scenarios/)。新带账号会话与仓库旧免认证 HTTP 实验分开。
- GPSLogger [Custom URL、Basic Auth 与离线队列](https://gpslogger.app/)。后台需接收真实 POST 并保存回执，不能只返回空 200。
- HA [AAOS 登录与传感器配置](https://companion.home-assistant.io/docs/android-auto/)、[传感器更新 API](https://contributors.home-assistant.io/companion/mobile-app-api/sensors/)、[WebSocket API](https://contributors.home-assistant.io/core/internals/websocket-api/)。传感器上报和 WebSocket 控制分开取证。
- YAABSA [上游平台与同步能力](https://github.com/Vito0912/yaabsa)；本仓库已有 [固定版本续验](../vehicle/lab/COMPANION_CLOSEOUT_20261106.md)，新版本不能继承旧版验收。
- DAVx⁵ [账号、集合与同步触发](https://manual.davx5.com/accounts_collections.html)。F-Droid 包由 F-Droid 签名，不能当成已核验上游发布方证书。
- Nextcloud [官方 Android 客户端源码与上传功能](https://github.com/nextcloud/android)。
- Immich [账号与手机客户端入门](https://docs.immich.app/overview/quick-start/)、[相册上传和去重](https://docs.immich.app/features/mobile-backup/)。第二轮使用不同内容，避免去重造成无上传。
- Element [语音消息说明](https://element.io/blog/element-x-now-with-embedded-voip/)、[当前客户端源码](https://github.com/element-hq/element-x-android)。自建 homeserver 的登录兼容性须先验证，不能沿用旧客户端假设。

## 替补与暂不选用项

| 替补 / APK 来源 | 适用动作 | 限制 |
| --- | --- | --- |
| [Joplin Android](https://github.com/laurent22/joplin-android/releases) | 用 Nextcloud 测试账号同步新笔记和附件，回收服务端资源、第二客户端内容与摘要 | [官方配置](https://joplinapp.org/help/apps/sync/nextcloud/)包含 WebDAV URL、用户名、密码；可复用后台，但笔记同步不自动补齐敏感 API 读取覆盖，E2EE 单列 |
| [Traccar Client](https://github.com/traccar/traccar-client-android/releases) | 自有 Traccar 服务端注册测试设备，上报位置，核对 positions 与设备 ID | [官方说明](https://www.traccar.org/client/)支持自建端点；客户端通常按设备标识接入，账号位于管理端。若必须 App 内登录，则不算乙1合格替补；不用公共 demo 接收测试数据 |

Trail Sense、离线录音机、Fossify Contacts、OpenTracks 继续用于“读取而不外发”的对照，不能凑外发阳性数。
固定流量语料只能辅助解析器离线回归，无法替代 APK、账号、设备动作与独立回执。

## 乙1：每个主选两次独立会话

1. 固定原版正式发布资产：记录版本/tag、不可变下载 URL、APK SHA-256、包名、ABI、min/target SDK、INTERNET 与相关权限、签名证书指纹及核验来源。不得仅引用 `latest`。下载失败、ABI 不符、无权限或业务不可用均留档。
2. 在自有服务端创建专用账号、目录和测试内容；保存脱敏配置与服务端版本。默认只监控实际白名单包名；观察代码只记录，不改写。密钥不进入 Git 或审阅包。
3. S1：独立 session ID、全新测试值，前台完成上传与回执。S2：重新建立采集会话与时间边界，使用不同测试值完成第二次上传；适合的 App 可在第二轮加入后台或重连段。不得把一轮两个请求拆成两个 session。
4. 每轮同时封存读取返回/回调、出站请求或可说明限制的密文、UID/user/进程归属、动作时间线、独立服务回执及采集健康。账号配置成功、200 响应和服务端旧缓存均不足以单独证明本轮上传。
5. 两轮均有新业务回执才算该 App 的乙1业务验收通过。读取未覆盖、正文未解析、身份未知、规则不适用分别登记；失败不记成“正常零条”。不足 8 个时启用合格替补，并报告仍缺多少。

建议顺序：先 OwnTracks、GPSLogger、HA、YAABSA，利用已有经验；再用一个 Nextcloud 后台支持 DAVx⁵ 与 Nextcloud，最后部署 Immich 与 Matrix。
这是降低配置成本的执行顺序，不表示后台已存在。同一后台服务多个客户端时按账号隔离，动态采集仍单设备串行。
两轮基线先固定相同协议；HTTP/MQTT、明文/E2EE 等额外变体另增会话，避免每格只有一次观测。

## 乙2、乙3：选择能被独立标注的样本

复用 [现有盲评和严格签核流程](VEHICLE_TEAM_HANDOFF.md)及 [bench 契约](../vehicle/bench/README.md)。
现有首轮 prepare 入口绑定历史案例，新增样本须先生成对应证据包和候选全集，不能直接复用历史包给新会话评分。
两名不同真人独立初评，第三名不同真人仲裁/确认负控并签核；本轮不代填真人身份或签名。
初评材料保留独立回执、原始读取与上传事实，隐藏工具预测；候选全集须含可能 FN 的正例、未发送/拒绝与错值负控。
规则 ID、适用依据和事件来源必须可追溯；不适用现有规则的 App 只计业务验收，不能临时发明规则让其成为 TP。

至少分别报告以下格子，各格只填真实观测：

| 数据源 | 传输路径 | 首选样本 | 未测时的口径 |
| --- | --- | --- | --- |
| 定位回调 | HTTP(S) POST | OwnTracks、GPSLogger | 标明回调缺失、规则适用或正文问题 |
| 定位回调 | MQTT/TLS | OwnTracks 扩展会话 | 未跑就是未测，不能借 HTTP 结果 |
| 联系人读取 | CardDAV / HTTP(S) | DAVx⁵ | 未取得查询返回值不计已取得数据 |
| 电量；定位/VHAL 按实际能力 | HTTP(S) webhook | HA | 电量与 VHAL 分开，不能互相替代 |
| 控制动作 | WebSocket | HA 单独实验 | 仅业务/协议覆盖；不填作定位 × WebSocket 的准确率 |
| 麦克风调用/可得数据 | Matrix HTTP(S) + E2EE | Element X | 调用、音频值和密文三层分开；无明文不宣称值级匹配 |
| 文件/媒体读取；播放进度 | WebDAV、Flutter/native HTTP 等实际路径 | Nextcloud、Immich、YAABSA | 业务观测与适用隐私规则指标分开 |

每层输出 TP/FP/FN、precision 分母 TP+FP、recall 分母 TP+FN、95% Wilson 区间、
独立 App 数、会话数、参考配对数及负控分母，并绑定规则、覆盖与标签摘要。
没有证据的“数据源 × 路径”格保留 `not_measured`，不补 0 或 1.0。
现有 metrics 按 `read_source/flow_path` 分层，须核实这些字段能区分数据类型和实际协议；
若只区分采集器来源，应另做可追溯映射，不能把同为 proxy 的 HTTP 与 WebSocket 合并解释。
同 App/会话内的配对存在相关性，Wilson 为配对单位区间，不能直接当作跨 App 泛化区间；报告中注明统计单位。

## 乙4：这份样本池如何支持场景补完

- 睡眠→点火→唤醒：优先 HA 与 YAABSA，要求设备电源/点火时序、进程生命周期及新服务端回执。模拟器锁屏不等于车机睡眠/点火；无适用设备条件时明确未测。
- 蜂窝重连：优先 OwnTracks/GPSLogger 的新点队列、HA 的恢复上报。记录蜂窝承载、断连和恢复时刻、排队与重传；当前环境事实只有 Wi-Fi，Wi-Fi 重连不能充当蜂窝验收。
- 多用户并发：优先 HA/YAABSA，在支持的两个 Android 用户中使用不同账号与唯一测试标记，记录 userId/UID/进程、各自回执和交叉归因。两个后台账号不等于两个 Android 用户；单前台串行切换不等于并发。

两周场景工作须在乙1已通过的固定样本上扩展。上述均为安排，未因本次检索标记设备通过。

## 乙5：新会话索引与汇总口径

每个会话记录 `generated_at`（带时区）及输入文件逐项 SHA-256：APK、会话清单、原始事件/流、
独立回执、动作日志、实际 Hook、规则库、覆盖表、标签及服务端配置的脱敏快照。
输入缺失写 `missing` 并说明影响；摘要绑定原文件字节，重新脱敏后保留转换关系，不混用摘要。
每条汇总明确证据类别、计数单位、生成时间和输入指纹：

- `observed`：直接运行时读取、请求、回执等事实；分别列读取数、请求数与独立回执数。
- `candidate`：待复核的读流关联；报候选配对数与适用规则，不当作已确认外发或违规。
- `static`：权限、组件、代码或端点线索；报静态线索数，不进入运行时外发计数。

本次候选目录仅为来源研究，`new_campaign_verified_apps/sessions=0`，指标保持空值。
乙1的 8 App / 16 会话是执行门槛，不是这次检索的已完成结论；乙2的人力签核与乙4设备实测仍须真实完成。
