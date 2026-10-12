# 种子清单

AOSP android-14.0.0_r1 参考定义；全部新增平台事实【需实测校准】。

## 权限

| 名称 | 源码 protectionLevel | 设备存在性 |
| --- | --- | --- |
| android.car.permission.CAR_ENERGY | dangerous | 用户已确认名称存在 |
| android.car.permission.CAR_ENGINE_DETAILED | signature|privileged | 未校准 |
| android.car.permission.CAR_IDENTIFICATION | signature|privileged | 未校准 |
| android.car.permission.CAR_MILEAGE | signature|privileged | 未校准 |
| android.car.permission.CAR_POWERTRAIN | normal | 未校准 |
| android.car.permission.CAR_SPEED | dangerous | 用户已确认名称存在 |

## 属性

| 属性 | ID 十六进制 | 类型 | 单位 | 读取权限 |
| --- | --- | --- | --- | --- |
| CURRENT_GEAR | 0x11400401 | INT32 | 未声明/不适用 | CAR_POWERTRAIN |
| ENGINE_RPM | 0x11600305 | FLOAT | RPM | CAR_ENGINE_DETAILED |
| EV_BATTERY_LEVEL | 0x11600309 | FLOAT | WH | CAR_ENERGY |
| FUEL_LEVEL | 0x11600307 | FLOAT | MILLILITER | CAR_ENERGY |
| GEAR_SELECTION | 0x11400400 | INT32 | 未声明/不适用 | CAR_POWERTRAIN |
| INFO_VIN | 0x11100100 | STRING | 未声明/不适用 | CAR_IDENTIFICATION |
| PERF_ODOMETER | 0x11600204 | FLOAT | KILOMETER | CAR_MILEAGE |
| PERF_VEHICLE_SPEED | 0x11600207 | FLOAT | METER_PER_SEC | CAR_SPEED |

## API

以下为源码签名；未作为设备 Hook 签名实测确认。

| 方法 | JVM descriptor | 属性参数下标 |
| --- | --- | --- |
| getFloatProperty | `(II)F` | 0 |
| getProperty | `(II)Landroid/car/hardware/CarPropertyValue;` | 0 |
| getProperty | `(Ljava/lang/Class;II)Landroid/car/hardware/CarPropertyValue;` | 1 |

## 禁用的项目策略草案

| 规则 ID | 目标 | 类型 | 结论上限 | enabled |
| --- | --- | --- | --- | --- |
| VSC-E001 | property:INFO_VIN | data_egress | correlated | 0 |
| VSC-E002 | property:PERF_VEHICLE_SPEED | data_egress | correlated | 0 |
| VSC-E003 | property:GEAR_SELECTION | data_egress | correlated | 0 |
| VSC-P001 | android.car.permission.CAR_IDENTIFICATION | over_permission | candidate | 0 |
| VSC-P002 | android.car.permission.CAR_SPEED | over_permission | candidate | 0 |
| VSC-P003 | android.car.permission.CAR_POWERTRAIN | over_permission | candidate | 0 |
| VSC-R001 | property:INFO_VIN | sensitive_read | observed | 0 |
| VSC-R002 | property:PERF_VEHICLE_SPEED | sensitive_read | observed | 0 |
| VSC-R003 | property:GEAR_SELECTION | sensitive_read | observed | 0 |

平台事实与规则来源见数据库 source_refs_json；项目策略依据见 POLICY.md。
规则窗 3000ms 为项目实验参数【需实测校准】，时间相关性不直接证明泄露。
