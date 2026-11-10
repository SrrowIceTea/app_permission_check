# 普通第三方车载 App：范围与版本

核实日期：2026-11-03。仅用于授权测试（自有设备与已授权 APK）。

## 对象

本产品线审计**安装在车机上、以普通第三方身份运行的 App**。测试设备可以是自有 userdebug 模拟器，
被测 App 不因此获得系统/平台签名权限。拒绝读取是平台保护生效，不是已经采集。
Android Auto 是手机投屏应用体系，不等于车机原生 Android Automotive OS（AAOS）。
仅能侧载的手机 APK 单独列为兼容对照，不计入原生 AAOS 样本数量。

## 版本

“AAOS 35”是 API 35，即 Android 15，不是第 35 代 AAOS。compileSdk、targetSdk、设备 API、
SDK Extension、OEM 软件版本与 GAS/Google built-in 是不同字段，不能互相推断。

| Android | API | 本项目状态 | 扩展顺序 |
|---|---|---|---|
| 13 | 33 | AOSP `android-13.0.0_r1` 源码基线已入库；无本轮设备验收 | 优先补较老量产平台 |
| 14 | 34 | 四类通用来源已通过专用 AVD 正反例；VHAL 为源码基线 | 通用来源第二条设备基线 |
| 15 | 35 | 既有夹具基线；本轮验收产物必须另行读取 | 当前开发/回归主线 |
| 16 | 36 | AOSP `android-16.0.0_r1` 源码基线已入库；无本轮设备验收 | 核实新增第三方车辆数据能力后接入 |

旧系统 10/11/12/12L 可进入后续兼容研究，不把历史 API 名称直接当作已验证 Hook 签名。
全量车载审计入口拒绝未校准版本。API 34 使用 `--scope general`；`vehicle.ps1 profiles` 返回机器可读状态。扩展时必须同时具备：
对应版本定义与来源、权限/属性实际可用性、同步/订阅/异步 API 覆盖、正反例、设备运行证据。
已有 8 个属性不等于当前普通第三方可以读取 8 个；以实际授予、返回状态和覆盖链为准。

**离线流水线 vs 设备验收**：规则库登记四组行——`'13'`/`'14'`/`'16'` 为 AOSP 源码基线、
`'15'` 为设备观测行；每个平台解析到自己登记的行，不再借用相邻版本
（`ROW_VERSION`）。API 34 和 35 有通用来源夹具设备验收。API 33 和 36 目前覆盖离线解析、映射和规则加载。API 34 的 `general_dynamic_verified=true`，全量车载 `dynamic_verified=false`。

API 34 使用官方 Android 14 ext9 x86_64 r05 车载镜像。四类通用来源、查询未消费负控、错误键、拒绝和不同值对照全部通过。结果在 `output/vehicle-api34-20261103/general-001/verification.json`。API 36 本轮查询的 Google 官方车载镜像索引无对应 x86_64 条目。宿主机已有的 API 36.1 镜像属于手机变体。来源见 [Android 官方车载模拟器说明](https://developer.android.com/training/cars/testing/emulator)。

Android 16 的 AAOS 25Q2 官方说明新增了面向第三方的车辆属性访问能力，说明版本扩展确有价值；
16 版的常量与权限取自 `android-16.0.0_r1` 源码（`aidl_property/` 与 `CarSvcProps-Released.json`），
不新增未经证实的 ID。

## 代表性量产车型/车系

下表是有官方资料的实例，**不是市场占有率排名，也不是项目真车兼容名单**。

| 车型/车系 | 官方资料能证明的范围 | 不能据此推断 |
|---|---|---|
| Polestar 2 | 原生 AAOS；部分年款的软件更新明确升级到 Android 13 | 所有年款都为 API 35 |
| Volvo EX30 | 指定市场车型有 Google built-in 与原生车载应用生态 | 所有地区配置和 OTA 的底层 API 相同 |
| Renault Scenic E-Tech electric | 指定市场 openR 系统有 Google built-in 和应用生态 | 所有 Renault、所有地区均使用同一版本 |
| Honda Accord Touring Hybrid | 美国 2026 款指定配置有 Google built-in | 中国版雅阁或其他配置同样支持 |

对任何车型的兼容结论，最终仍须记录测试设备 API、指纹、年款/地区、软件版本、权限授予、
车辆属性可用性与实际测试结果。国内“Android 智能座舱”、Android Auto 或 CarPlay 标签都不能单独证明 AAOS。

## 官方来源

- [Android Auto 与 AAOS 的区别](https://developer.android.com/media/implement/surfaces/cars)
- [AAOS 发布列表](https://source.android.com/docs/automotive/start/releases)
- [AAOS 25Q2 / Android 16](https://source.android.com/docs/automotive/start/releases/aaos-25q2)
- [Polestar 2 更新说明](https://www.polestar.com/uk/manual/polestar-2/2021/software-updates)
- [Polestar 开发者模拟器](https://www.polestar.com/global/developer)
- [Volvo EX30 官方规格](https://www.volvocars.com/us/cars/ex30-electric/specifications/)
- [Renault Scenic 连接功能](https://www.renault.co.uk/electric-vehicles/scenic/connectivity-and-sound-experience.html)
- [Honda Accord 官方车型页](https://automobiles.honda.com/accord-sedan)
- [厂商属性与权限配置](https://source.android.com/docs/automotive/vhal/special-properties)

本轮官网下载的 AAOS 35 镜像是 `android-35-ext15 / android-automotive / x86_64 / r04`（本机存放在仓库
`output/vehicle-device-setup/image/x86_64/`，**没有**安装进 SDK `system-images/`，SDK Manager 里找不到）；
索引为 https://dl.google.com/android/repository/sys-img/android-automotive/sys-img2-1.xml 。
它与旧校准镜像属于同 API 的不同构建；新设备验收不能由旧记录替代。
