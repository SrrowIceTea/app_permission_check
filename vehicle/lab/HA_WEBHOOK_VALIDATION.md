# HA Automotive 电量请求正文验收

2026-11-03。仅用于授权测试。AAOS 35 专用模拟器 user 10，Home Assistant Automotive minimal 2026.10.1，隔离 HA 2026.10.4。

| 数据类型 | 所需权限 | 读取 API | Hook 覆盖 | 判断规则 | 验收样例 | 未覆盖原因 |
| --- | --- | --- | --- | --- | --- | --- |
| Android 设备电量百分比 | HA 读取路径无需运行时权限 | `ACTION_BATTERY_CHANGED` 粘性广播与 `Intent.getIntExtra(level/scale)` | `--ha-webhook` 观察指定 APK 的 HA 电量读取、OkHttp 实际正文写入及同一次 HTTP 响应 | `VSC-LAB-ANDROID-POWER-001` 要求同一读取调用路径取得有效 level 和 scale=100。`VSC-LAB-HA-BATTERY-HTTP-001` 要求同一会话、设备、包、UID、PID，30 秒内写出完整的 `update_sensor_states` JSON，`unique_id=battery_level` 的 `state` 同值且响应 2xx | 模拟器电量分别设为 73% 和 61%，正文同值且返回 HTTP 200，隔离服务端实体两次更新为对应值 | 仅校准该 APK 的隔离 HTTP webhook。充电状态、动力电池、HA WebSocket、WebView 和 Flutter 路径各自保留缺口 |

请求与正文通过同一次 `CallServerInterceptor.intercept`、原 RequestBody 对象及实际 Sink 对象绑定。Hook 保留请求字节数、数据类型、电量字段和状态码，省略 webhook 标识、认证信息和其余字段。该采集模式保留原代理设置，运行时只观察。数据关联使用同进程设备时钟，以请求开始时刻计算间隔。相同值是内容关联证据，唯一来源与政策结论需人工复核。

本次新增规则登记在独立实验契约 `vehicle/privacy/ha_contract.py`。采集清单绑定契约和实际 bundle 摘要，审计生成 JSON 证据与 PDF。HTTP 2xx 由 App 侧观察，设备验收另查隔离服务端实体的 `last_changed`。离线对照覆盖移除正文、同数字异字段、不同值、错身份、截断、非 2xx 和超窗。人工签核为 `pending`。

最终模式连续三轮通过，每轮观察两次电量变化。读取到请求开始的实测间隔为 331–761 ms，移除正文和替换字段的对照均不产出关联结论。原进程存活，电池模拟复原。原始证据在 `output/ha-body-20261103/run-004` 至 `run-006`。首次报告缺少通用输入统计字段，另一轮复验发生 ART 原生崩溃。失败轮保留，最终模式移除了原通用出站 Hook。

后续复验 `output/ha-body-20261103/repair-001` 已通过，并在采集目录封存实际执行的 bundle。旧 `run-006` 的原 bundle 未找到，保留既有清单和报告。

~~~powershell
. ./environment.ps1
& $VScanPython -m core.frida_host.build --platform vehicle --only hook_vehicle_ha.js
& $VScanPython -m vehicle.lab.ha_body_run --out output/new-ha-body-run --apk output/vehicle-samples-20261102/home-assistant-automotive-minimal/sample.apk
~~~

复验需已有的隔离服务和授权装机样本。验收入口运行常规 `capture --scope general --preserve-system-proxy --ha-webhook` 和 `audit`，清理电池模拟并保存 `verification.json`。关联窗口对照见 [窗口校准](../bench/WINDOW_CALIBRATION.md)。

来源见 [Android BatteryManager](https://developer.android.com/reference/android/os/BatteryManager#EXTRA_LEVEL)、[HA Android 2026.10.1](https://github.com/home-assistant/android/tree/2026.10.1) 和 [HA 传感器协议](https://developers.home-assistant.io/docs/api/native-app-integration/sensors/)。
