# 车载通用隐私来源

仅用于授权测试。普通第三方 App 也会使用 Android 通用数据源，不能仅看 VHAL。
复用移动侧已验证的分类、异常、值摘要和返回值语义；平台规则与执行入口独立。

| 来源 | 当前读取证据 | 不当作读取的情况 | 外发关联 |
|---|---|---|---|
| 定位 | LocationManager.getLastKnownLocation 返回 Location | null、权限拒绝 | 暂未做坐标值级关联 |
| 麦克风 | AudioRecord.read 返回正数 | start/startRecording、0、负错误码 | 不保存音频，不做音频值关联 |
| 联系人 | 指定联系人 URI 返回的游标实际 getString 非空 | query、未消费游标、空字符串 | 至少 8 字符的原值摘要与完整 JSON 请求匹配 |
| Android ID | Settings.Secure.getString(android_id) 非空 | 其他键、null、拒绝 | 同 UID/用户/会话、30 秒内完整 JSON 字符串原值摘要匹配 |
| Google 广告标识（AAID） | AdvertisingIdClient.Info.getId() 返回非零标识，仅记录状态和长度 | Info 调用、全零、权限拒绝、GMS 不可用 | 暂未做 AAID 外发关联 |

14 个 Android SDK 目标、2 个 Google SDK 目标和运行时联系人游标 getString/close。
Google SDK 签名来自固定版本 AAR 的 javap 输出，见 [AAID 验收](../lab/O6_DEVICE_ACCEPTANCE.md)。
公开 API 文档记录可用性，不能代替旧版本 ROM 的实际方法存在和运行结果。
位置仅覆盖缓存路径，FLP/订阅、OAID、native 音频和其他数据类型仍列缺口。
联系人跟踪最多保留 256 个打开游标的身份，close 后移除；上限/接口缺失记录 PRIVACY_GAP。
不移动游标、不自行查询联系人、不改变应用返回值/异常；仅自有 debug Actor 创建并清理测试联系人。

## 版本与运行

- API 35：all 模式为 VHAL + 通用来源；general 模式只用通用来源。
- API 34：已通过通用来源夹具设备验收（`general_dynamic_verified=true`），可与 35 一样使用 general 模式。
- API 33/36：可使用 general 模式；方法逐个运行时核对，尚未完成这些版本的设备验收。
- 其他版本拒绝；all 模式仍要求已验证的 VHAL 版本，禁止使用邻近版本规则兜底。
- compileSdk/targetSdk 与设备 API 分别记录；权限声明不证明授予，更不等于取得数据或隐私同意。

```powershell
./vehicle.ps1 prepare
./vehicle.ps1 profiles
./vehicle.ps1 coverage --android-version 33 --out output/coverage-api33
./vehicle.ps1 capture --package 已授权包名 --user 10 --scope general --seconds 60 --out output/general-capture
./vehicle.ps1 audit --capture output/general-capture --package 已授权包名 --android-version 33 --out output/general-audit
./vehicle.ps1 scenarios --suite privacy
```

示例的版本必须与实际采集设备一致；API 35 常规完整范围可省略 --scope general。
审计绑定 APK、会话、实际 bundle 和通用规则摘要，并导出契约、政策与签名依据快照。
通用模式的 APK 静态阶段目前仅清单核对，明确标 manifest_only；不冒充完整 DEX 静态覆盖。
观察到空值/权限拒绝/零流量不构成隐私安全结论。规则、窗口与结论上限见 [POLICY.md](POLICY.md)。

## 本轮验收（2026-11-02）

真实 AAOS 35 自有夹具见 output/vehicle-privacy-device-unique-20261102/verification.json。
四类正控、query-only、其他键、不同值上传、定位/联系人拒绝均通过；采集进程正常退出、原 PID 存活。
定位用模拟坐标，音频仅样本计数，联系人是新建后删除的固定测试记录；不代表真实车辆或用户数据。
初轮定位总开关关闭导致空值，整轮失败保留；Actor 随后记录开关、启用、最终回读确认恢复。
权限撤回会杀死进程，因此拒绝场景使用独立采集/PID，不能在健康观察中途撤权再宣称进程存活。
每轮/每动作令牌唯一，避免旧回执和相同 capture 目录名混淆会话；时间窗仍受宿主接收批处理影响。

来源：[定位](https://developer.android.com/reference/android/location/LocationManager)、
[AudioRecord](https://developer.android.com/reference/android/media/AudioRecord)、
[联系人](https://developer.android.com/identity/providers/contacts-provider)、
[Android ID](https://developer.android.com/reference/android/provider/Settings.Secure#ANDROID_ID)。

通用规则的设备来源独立冻结在 device-observation.json，包含真实指纹、逐类型状态与采集摘要。
规则构建使用此快照；旧 VHAL device-facts 不代表这些来源的设备实测。生成入口：
`vehicle/rules/python/privacy_observation.py --capture <正控目录> --capture <拒绝目录> --out <快照路径>`。
