# O6 AAOS 35 设备验收

仅用于授权测试。使用 `emulator-5554` 的 AAOS 35 GMS 镜像，系统指纹为
`google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A6/16618942:userdebug/test-keys`。
所有读取均来自普通安装的自有 APK，设备结果限定于该镜像和夹具。

## AAID 四态

自有夹具使用 Google Maven 的 `play-services-ads-identifier:18.2.0`，targetSdk 35。
两份 APK 分别声明和省略 `com.google.android.gms.permission.AD_ID`。
安装摘要、合并后的实际权限清单、SDK 调用回执和 Hook 事件逐案封存。

| 状态 | 设备条件 | 结果 |
| --- | --- | --- |
| `obtained` | 原用户 10，声明并获得 AD_ID，GMS 可用 | `getId()` 返回非零 36 字符标识。只记录状态和长度 |
| `denied` | 原用户 10，未声明 AD_ID，GMS 可用 | SDK 正常返回全零，权限快照与回执均确认权限缺失 |
| `empty` | 一次性用户 11，在 Google 广告设置中删除标识，AD_ID 已授予 | SDK 返回全零，设置显示可生成新标识 |
| `unavailable` | 一次性用户 11，仅该用户移除 GMS | SDK 抛出 `IOException`，应用侧包查询证实 GMS 不可见 |

只有获得非零值触发 `VSC-GR-advertising_id`。获取 Info 只记调用，其他连接错误按 error 记录。
设备端回执、Hook 日志和规则报告不保存 AAID 原值或摘要。人工签核待完成。
[四态证据索引](../privacy/aaid-device-observation.json) ·
[系统删除操作](../../output/o6-aaid-isolated-20261104-135316/final-empty-action.json) ·
[GMS 缺失操作](../../output/o6-aaid-isolated-20261104-135316/no-gms-action.json) ·
[用户清理记录](../../output/o6-aaid-isolated-20261104-135316/cleanup.json)。
常规通用采集与审计入口已生成独立的 `observed` 读取结论。
[常规审计结果](../../output/o6-device-acceptance-20261104/aaid-audit/summary.json)。

## VHAL 属性与实际授予

同一采集会话绑定装机 APK、规则库、权限快照和运行时事件。以下权限列为项目策略中的候选，
授予状态取自本轮包快照，属性结果取自夹具的实际同步读取。

| 属性 | 权限候选 | 实际授予 | 同步读取 |
| --- | --- | --- | --- |
| INFO_VIN | CAR_IDENTIFICATION | 未授予 | denied |
| PERF_VEHICLE_SPEED | CAR_SPEED | 已授予 | ok |
| GEAR_SELECTION | CAR_POWERTRAIN | 已授予 | ok |
| CURRENT_GEAR | CAR_POWERTRAIN | 已授予 | ok |
| PERF_ODOMETER | CAR_MILEAGE | 未授予 | denied |
| ENGINE_RPM | CAR_ENGINE_DETAILED | 未授予 | denied |
| FUEL_LEVEL | CAR_ENERGY | 已授予 | ok |
| EV_BATTERY_LEVEL | CAR_ENERGY | 已授予 | ok |

`GEAR_SELECTION` 的两次模拟挡位变更分别命中实际 `onChangeEvent`，并验证原挡位已恢复。
各回调须在相应注入区间内匹配属性和值。设备结果不替代 OEM 或其他 API 版本的逐属性权限映射。
[八属性设备验收](../../output/o6-device-acceptance-20261104/vhal/verification.json) ·
[覆盖矩阵](../../output/o6-device-acceptance-20261104/coverage/COVERAGE.md)。

更新后的规则资产在同一模拟器通过 12 项 Room 设备测试，包括预置库摘要、条数和故障状态。
[Room 测试记录](../../output/o6-device-acceptance-20261104/room-device-test.log)。

## 复现

```powershell
. ./environment.ps1
./vehicle/targets/target-app/gradlew.bat -p vehicle/targets/target-app -PaaidFixture=true :aaid-fixture:assembleDeclaredDebug :aaid-fixture:assembleOmittedDebug
& $VScanPython -m vehicle.privacy.catalog
& $VScanPython -m core.frida_host.build --platform vehicle
& $VScanPython -m vehicle.lab.aaid_acceptance --help
& $VScanPython -m vehicle.lab.vhal_acceptance --out output/my-vhal --user 10
./vehicle.ps1 coverage --out output/my-coverage --vhal-capture output/my-vhal/capture
```

将夹具变体安装到待测用户后，使用 `aaid_acceptance` 指定 APK、用户与预期状态。
先跑获得和拒绝。对空值和不可用使用单独创建的一次性用户，确认用户身份后在 Google Ads 设置删除广告
标识或移除该用户的 GMS。验收完成后切回原用户并清理一次性用户。封存入口为
`vehicle.rules.python.aaid_observation`，接受四份通过的目录并校验其输入摘要。

SDK 参考见 [AdvertisingIdClient](https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient)
和 [AdvertisingIdClient.Info](https://developers.google.com/android/reference/com/google/android/gms/ads/identifier/AdvertisingIdClient.Info)，
固定 AAR 摘要和方法描述符见 [AAID 签名记录](../privacy/aaid-signatures.json)。
