# 独立第三方样本清单（O3 前置）— 2026-11-03

> **边界**：本清单只做“公开渠道下载 + 静态权限画像”。**未安装到模拟器、未执行 adb、未运行检测、未修改现有代码、未执行 git 操作。** 下载成功与静态画像不证明可安装、可运行或可采集；AAOS 35 运行时验证属后续设备阶段。

## 1. 结论

- **已下载 11 个**独立 App，**11/11** 的 SHA-256 与 F-Droid 官方索引记录完全一致，`apksigner` 校验全部通过；**仅登记未获取 0 个**，另有 **2 个类别缺口**（见 §4）。
- 全部为**原生 Android（DEX）**，逐个检查 ZIP 未发现 `libflutter.so`、`assets/flutter_assets/` 或 `assets/www/` 壳，符合“优先原生、避开纯 Flutter/WebView”的要求。
- 覆盖情况：定位 4、联系人 1、通话记录 1、广告/设备标识 2（部分）、麦克风 1、照片 1、文件 1；**车辆 VHAL 为 0**。
- 既有 3 个样本（Home Assistant Automotive、MG4 Browser、YAABSA）**未重复计入**本清单。

| 类别 | 数量 | 样本 | 状态 |
| --- | --- | --- | --- |
| 车辆 VHAL | 0 | — | **缺口**：无公开 APK（§4.1） |
| 定位 | 4 | GPSLogger、Trail Sense、OwnTracks、OpenTracks | 已下载；OwnTracks 需自建端点 |
| 联系人 | 1 | Fossify Contacts | 已下载 |
| 通话记录 | 1 | Fossify Phone | 已下载；**AAOS 无 telephony，高风险** |
| 广告标识 / 设备标识 | 2 | Exodus、GLPI Agent | 已下载；**仅部分覆盖**，均不读 GAID |
| 麦克风 | 1 | Audio Recorder | 已下载 |
| 照片 / 文件 | 2 | Fossify Gallery、Material Files | 已下载 |

## 2. 来源与校验口径

- 唯一来源：**F-Droid 官方仓库**（`https://f-droid.org/repo/<apkName>`），版本与哈希取自官方 `index-v1.json`；未使用任何第三方 APK 聚合站、破解版或重打包版本。
- 版本选择：取该包在 F-Droid 索引中的最高 `versionCode`（与 `suggestedVersionCode` 一致）。
- 静态画像工具：`aapt dump badging`、`aapt dump xmltree AndroidManifest.xml`、`apksigner verify --verbose --print-certs`、ZIP 条目检查；**未安装到设备**。
- 明文判定：Manifest 显式 `usesCleartextTraffic` 优先；未声明时按 `targetSdk>=28` 的平台默认值判为“否”。
- 可评估性来自 Manifest、官方说明与功能形态推断，**不是运行时结论**。

## 3. 样本清单（每样本一行）

| # | 名称 | 包名 | 版本 | 类别 | 许可 | 获取日期 | 下载 / SHA-256（前 16） | 敏感权限（全量见 manifest） | 明文 | 离线 | 登录 | 服务端 | 可评估性 | 为什么选 / 补哪个短板 | 已知风险 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | GPSLogger | `com.mendhak.gpslogger` | 138 | 定位（前台+后台） | GPL-2.0-only | 2026-11-03 | 已下载<br>`1d92fd8639dfc0ec` | 定位(前/后)×3、外部存储×3、其他×10 | 是 | 是 | 否 | 否 | 可不登录：是；触发：ACCESS_FINE/COARSE_LOCATION 前台读取 / ACCESS_BACKGROUND_LOCATION 后台定位；阻塞：后台定位需手动授权 | 原生 Java、维护活跃、F-Droid 官方分发；可前台/后台定位并本地落盘，能稳定产生定位读取事件 | Manifest 显式 usesCleartextTraffic=true（全局允许明文）；声明 MANAGE_EXTERNAL_STORAGE 与 ACCESS_MOCK_LOCATION |
| 2 | Trail Sense | `com.kylecorry.trail_sense` | 8.2.0 | 定位/传感器（离线） | MIT | 2026-11-03 | 已下载<br>`846249274a0e3006` | 定位(前/后)×3、相机×1、其他×13 | 否 | 是 | 否 | 否 | 可不登录：是；触发：导航/天气功能的定位读取 / CAMERA；阻塞：部分功能依赖气压计等模拟器不具备的传感器 | Kotlin 原生、离线优先、MIT；定位+气压/磁力等传感器组合，适合做离线对照 | 权限面较广（CAMERA/ACTIVITY_RECOGNITION/BACKGROUND_LOCATION）；无 INTERNET，外发路径不可测 |
| 3 | OwnTracks | `org.owntracks.android` | 2.5.9 | 定位（后台上报，需自建服务端） | EPL-1.0 | 2026-11-03 | 已下载<br>`b12ca46508b8f33e` | 定位(前/后)×3、外部存储×1、其他×11 | 否 | 否 | 否 | 是（需自建 MQTT broker 或 HTTP endpoint（无账号体系）） | 可不登录：是；触发：后台定位读取 / 定位经 HTTP/MQTT 外发；阻塞：无端点时只有本地界面，无法触发外发路径 | 原生 Java、长期维护；后台定位 + HTTP/MQTT 上报，是少数能覆盖定位外发链路的合规样本 | 必须有自有服务端，否则核心链路不可评估；含 networkSecurityConfig |
| 4 | Fossify Contacts | `org.fossify.contacts` | 1.6.0 | 联系人 | GPL-3.0-only | 2026-11-03 | 已下载<br>`6a89be96b5ec39f5` | 联系人×3、电话/通话×1、外部存储×2、其他×4 | 否 | 是 | 否 | 否 | 可不登录：是；触发：READ_CONTACTS / WRITE_CONTACTS；阻塞：需先预置联系人数据，否则读取为空 | Kotlin 原生、无广告/无网络权限、离线；打开即读联系人，触发路径最短 | CALL_PHONE 声明但 AAOS 无通话能力；WRITE_GLOBAL_SETTINGS 为 Fossify 自定义权限 |
| 5 | Fossify Phone | `org.fossify.phone` | 1.11.1 | 通话记录/联系人 | GPL-3.0-only | 2026-11-03 | 已下载<br>`d1ad08467034e513` | 联系人×2、通话记录×2、电话/通话×5、麦克风×1、其他×10 | 否 | 是 | 否 | 否 | 可不登录：是；触发：READ_CALL_LOG / READ_CONTACTS；阻塞：uses-feature android.hardware.telephony；AAOS 模拟器无通话栈 | Kotlin 原生；声明 READ/WRITE_CALL_LOG 与 READ_CONTACTS，是通话记录类最直接样本 | 依赖 telephony，AAOS 模拟器大概率不可用；CALL_PRIVILEGED 为系统权限，普通安装不授予 |
| 6 | Fossify Gallery | `org.fossify.gallery` | 1.14.1 | 照片/媒体（高敏感对照） | GPL-3.0-only | 2026-11-03 | 已下载<br>`9a9f2e06882abfda` | 照片媒体×6、外部存储×3、其他×5 | 否 | 是 | 否 | 否 | 可不登录：是；触发：READ_MEDIA_IMAGES/READ_MEDIA_VIDEO / ACCESS_MEDIA_LOCATION；阻塞：需预置图片/视频 | Kotlin 原生、无 INTERNET；启动即枚举媒体，并声明 ACCESS_MEDIA_LOCATION，可同时观察媒体读取与位置元数据 | MANAGE_EXTERNAL_STORAGE/MANAGE_MEDIA 属高权限，需单独授权；无 INTERNET，不能覆盖媒体外发 |
| 7 | Audio Recorder | `com.dimowner.audiorecorder` | 2.5.0 | 麦克风（高敏感对照） | Apache-2.0 | 2026-11-03 | 已下载<br>`b4076bf8f1c64ada` | 麦克风×1、外部存储×2、其他×11 | 否 | 是 | 否 | 否 | 可不登录：是；触发：RECORD_AUDIO / 前台服务麦克风；阻塞：模拟器需配置音频输入源 | Kotlin 原生、Apache-2.0、无 INTERNET；点按即录音，触发简单 | 声明 FOREGROUND_SERVICE_MEDIA_PROJECTION（屏幕采集相关，需用户同意）；无 INTERNET，不能覆盖录音外发 |
| 8 | Material Files | `me.zhanghai.android.files` | 1.7.5 | 文件/存储（高敏感对照） | GPL-3.0-or-later | 2026-11-03 | 已下载<br>`2fe900bf43d725b6` | 外部存储×3、全包枚举×1、其他×11 | 是 | 是 | 否 | 否 | 可不登录：是；触发：READ/WRITE_EXTERNAL_STORAGE / MANAGE_EXTERNAL_STORAGE；阻塞：MANAGE_EXTERNAL_STORAGE 需 app-op；可选 Shizuku | Kotlin 原生、GPL；本地文件管理 + FTP/SFTP/WebDAV，可覆盖存储读取与明文网络路径 | 显式 usesCleartextTraffic=true + INTERNET，可产生明文网络存储流量；声明 REQUEST_INSTALL_PACKAGES、QUERY_ALL_PACKAGES |
| 9 | Exodus | `org.eu.exodus_privacy.exodusprivacy` | 3.3.2 | 广告/设备标识（部分覆盖） | GPL-3.0-only | 2026-11-03 | 已下载<br>`7758d2c3189b2c7d` | 全包枚举×1、其他×4 | 否 | 部分 | 否 | 否 | 可不登录：是；触发：QUERY_ALL_PACKAGES 枚举已安装应用 / 按 tracker 签名库匹配广告 SDK；阻塞：本应用不调用 AdvertisingIdClient，不能证明 GAID 读取 | 原生 Kotlin；可枚举已安装应用并按签名库识别跟踪器/广告 SDK，作为“广告标识”类别的可评估替代 | 不能替代 GAID 读取样本，类别仅部分覆盖；首次报告/库更新依赖网络 |
| 10 | GLPI Agent | `org.glpi.inventory.agent` | 1.9.0 | 设备标识（需服务端） | GPL-3.0-only | 2026-11-03 | 已下载<br>`a8d353bf6dd1bb64` | 定位(前/后)×2、电话/通话×1、相机×1、外部存储×2、蓝牙×1、其他×17 | 是 | 否 | 否 | 是（需自建 GLPI 服务端与 inventory 端点/注册码） | 可不登录：是；触发：READ_PHONE_STATE/设备标识采集 / 系统与安装包清单采集；阻塞：必须先有 GLPI 服务端并完成注册 | 原生 Java；声明 READ_PHONE_STATE 等，能采集设备标识并向 GLPI 上报，是设备标识类少见的合规开源样本 | 必须有自有 GLPI 服务端；显式 usesCleartextTraffic=true，库存上报可能明文 |
| 11 | OpenTracks | `de.dennisguse.opentracks` | v4.29.0irreproducible | 定位/运动健康 | Apache-2.0 | 2026-11-03 | 已下载<br>`f63ed60e2a4f1b3d` | 定位(前/后)×2、蓝牙×4、其他×14 | 否 | 是 | 否 | 否 | 可不登录：是；触发：ACCESS_FINE_LOCATION/COARSE_LOCATION / 前台定位服务；阻塞：Health Connect 在 AAOS 镜像通常不存在，健康写入不可触发 | Kotlin 原生、Apache-2.0、无 INTERNET；开始记录即持续读取定位，适合做可重复的前台定位样本 | 版本串含 irreproducible 标记（F-Droid 可复现构建校验）；health 权限在无 Health Connect 环境无效 |

> 表中 SHA-256 只显示前 16 位便于阅读；完整值、下载 URL、字节数与签名证书见附录 A。`manifest.json` 为机器可读权威副本。

## 4. 缺口（未获取，未用不可信来源凑数）

### 4.1 车辆 VHAL：0 个

- 候选 `Ixam97/CarStatsViewer`（v0.29.0，126 stars）是明确的 AAOS VHAL 应用，但官方 README 写明**不在公开 Play Store 上架**，只通过限额 100 人的内部测试轨道分发；GitHub Releases **无 APK 资产**。
- 其他 VHAL 仓库（`VhalDemoApp`、`Akshay-Kumar-S/Automotive`、`KukhtoSlava/aaos-monitor`、`chandramouli369/VHAL_AAOS_Project`）均无公开 APK，或属于需平台签名的 privileged/system app；`Akshay-Kumar-S/Automotive`、`autoharness/CarToolForge`、`Wal33D/OBD-Droid` 的 Releases 页也未找到 `.apk`。
- **未做**：从源码构建 CarStatsViewer（超出“只下载”范围）。既有 Home Assistant Automotive 已覆盖 VHAL，但属旧样本，不计入本次独立样本数。

### 4.2 广告标识（GAID）：0 个直读样本

- F-Droid / GitHub 官方分发包以无广告应用为主，未找到调用 `AdvertisingIdClient` 的可合规下载样本；**不采用第三方聚合站或破解版**。
- 部分替代：`Exodus`（按签名库识别广告 SDK/跟踪器，不读 GAID）、`GLPI Agent`（设备标识/IMEI/序列号，需服务端）。
- 如必须覆盖 GAID，需要 Play 分发的公开测试版或企业账号；或改用 AAID 探针夹具，而不是第三方 App。

## 5. 需要用户决定 / 补充的点

1. **VHAL 样本**：是否允许后续从 CarStatsViewer 源码构建，或提供内部测试轨道安装包？当前按“只下载”边界记录为缺口。
2. **GAID 样本**：是否接受“Exodus + GLPI 部分覆盖”，或提供 Play 测试版/企业账号？
3. **通话记录样本**：Fossify Phone 依赖 `android.hardware.telephony`，AAOS 模拟器大概率装不上或记录为空；是否改用带 telephony 的 AOSP 镜像，或把该类别降为“仅静态覆盖”？
4. **服务端依赖**：OwnTracks 需自建 MQTT/HTTP 端点，GLPI Agent 需 GLPI 服务端；是否由项目提供最小端点，否则这两条链路只能做本地部分。
5. **特殊授权**：Gallery / Material Files / GPSLogger 的 `MANAGE_EXTERNAL_STORAGE`、后台定位等需设备阶段单独授权；需确认是否允许 adb app-op 授权（本任务未执行）。

## 6. 局限

- 下载成功与静态权限画像不证明可安装、可运行或可采集。
- AAOS 35 设备安装与运行时验证属于后续设备阶段，本清单未做。
- 可评估性基于 Manifest、官方文档与功能形态推断，未在设备上验证。
- Fossify Phone 依赖 telephony，在 AAOS 模拟器大概率不可用。
- GLPI Agent 与 OwnTracks 需要自有服务端，属条件可评估。
- 本清单**不声称任何样本“已验证可采集”**；`runtime_verified` 仍为 0，需设备阶段确认。

## 附录 A：下载与校验明细

| 名称 | 包名 | 下载 URL | 字节 | SHA-256（完整） | F-Droid 索引哈希一致 | 签名 | 签名证书 SHA-256 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GPSLogger | `com.mendhak.gpslogger` | https://f-droid.org/repo/com.mendhak.gpslogger_138.apk | 8050208 | `1d92fd8639dfc0ec210b013a81cc7dc85fc8c73ef521f71b2a08ffa165d4e265` | 是 | 通过（v1、v2、v3） | `dc3507919aad1c981423f7563ad699830518900f943632bc36eeb7250c390235` |
| Trail Sense | `com.kylecorry.trail_sense` | https://f-droid.org/repo/com.kylecorry.trail_sense_148.apk | 13271554 | `846249274a0e300622cc94815fd279d258738bfcaf60ee9e276edf74f5febc1c` | 是 | 通过（v1、v2、v3） | `afa319dce22c6a8fb3e4d852a2c0df6c07cf995dab2f78331e4bc5b5dd48bfaf` |
| OwnTracks | `org.owntracks.android` | https://f-droid.org/repo/org.owntracks.android_420509001.apk | 13574074 | `b12ca46508b8f33e6ddc03433be5600f7fec6b2c30adb8056368aa2e17129d0f` | 是 | 通过（v2、v3） | `8d8db68e4c582119c2d9f183c14a89777792918eba7b3de762e1c1f73475397b` |
| Fossify Contacts | `org.fossify.contacts` | https://f-droid.org/repo/org.fossify.contacts_13.apk | 8602985 | `6a89be96b5ec39f5e2b11bd61dc7031f4b88261b324ab13af5743fbc62f0cddb` | 是 | 通过（v2） | `affdb124d3f4720c2f98dbca9eacba0514fba4306e20a2786c861c3c0d6ff292` |
| Fossify Phone | `org.fossify.phone` | https://f-droid.org/repo/org.fossify.phone_22.apk | 9165050 | `d1ad08467034e5138a6e68f03b6e150f0bb010dfcbf490ff3d2bd4822b755728` | 是 | 通过（v2） | `affdb124d3f4720c2f98dbca9eacba0514fba4306e20a2786c861c3c0d6ff292` |
| Fossify Gallery | `org.fossify.gallery` | https://f-droid.org/repo/org.fossify.gallery_30.apk | 38538587 | `9a9f2e06882abfdae6f4c86aeaa83ae8102b2e081591df0eb2134a6f629657c7` | 是 | 通过（v2） | `affdb124d3f4720c2f98dbca9eacba0514fba4306e20a2786c861c3c0d6ff292` |
| Audio Recorder | `com.dimowner.audiorecorder` | https://f-droid.org/repo/com.dimowner.audiorecorder_951.apk | 4311248 | `b4076bf8f1c64ada10614acdd04968ae95e8a4f434bc3763d8f5680de697be4e` | 是 | 通过（v2、v3） | `a8d718965ffa5e7c2178d6635627d9753d0c59e7243395a7aedabe36f3db3500` |
| Material Files | `me.zhanghai.android.files` | https://f-droid.org/repo/me.zhanghai.android.files_40.apk | 10944578 | `2fe900bf43d725b655008d438f5ca46d0da0f301e3784403b5b96c3fc2df6e8a` | 是 | 通过（v1、v2、v3） | `9c22a742fa200c85bafbc9924a02ddc8f3a0b975d4d7b5a8da21d7cf34ce2b20` |
| Exodus | `org.eu.exodus_privacy.exodusprivacy` | https://f-droid.org/repo/org.eu.exodus_privacy.exodusprivacy_23.apk | 7281286 | `7758d2c3189b2c7deb1c3e3d76941ce21c1a1f2c3e95b94673c81514632c017b` | 是 | 通过（v1、v2、v3） | `6f44c54d127ce05b2bee4ab7c211ca5c3d175a88f352e631dac6d951501b487f` |
| GLPI Agent | `org.glpi.inventory.agent` | https://f-droid.org/repo/org.glpi.inventory.agent_39481.apk | 6342398 | `a8d353bf6dd1bb6478b7107a7993f0bdf35e84448b503578c1306765ba6d9657` | 是 | 通过（v1、v2、v3） | `1f46e7fa28a0c6e7ffb6cdc6b4d04afb7890e19ffd0a59bef76a50207142b875` |
| OpenTracks | `de.dennisguse.opentracks` | https://f-droid.org/repo/de.dennisguse.opentracks_6766.apk | 10934525 | `f63ed60e2a4f1b3d878671bfde2150ceaa89e484618b91390500e1a583694cc1` | 是 | 通过（v2、v3） | `4774e9917ce05a2071b5c339e8e6faa801bfc91b9dccc4804558cf8ae6555c74` |

## 附录 B：文件位置

- APK：`output/sample-acquisition-20261103/<包名>/sample.apk`（11 个目录，未覆盖既有 `output/vehicle-samples-*`）。
- 机器可读清单：`output/sample-acquisition-20261103/manifest.json`。
- 本文档：`docs/SAMPLE_CATALOG_20261103.md`。

运行记录的证据等级、网络权限复核和未覆盖路径见 [样本运行记录纠偏](../vehicle/lab/SAMPLE_RUNTIME_REVIEW.md)。

