# HA Android 电源状态变值验收

后续已将电量 HTTP 正文接入指定样本的常规审计扩展，见 [HA 电量请求正文验收](HA_WEBHOOK_VALIDATION.md)。下表为独立读取实验当时的覆盖。

2026-11-03。仅用于授权测试。AAOS 35 专用模拟器 user 10，普通安装的 Home Assistant Automotive minimal 2026.10.1，独立 HA 2026.10.4。

| 数据类型 | 所需权限 | 读取 API | Hook 覆盖 | 判断规则 | 验收样例 | 未覆盖原因 |
| --- | --- | --- | --- | --- | --- | --- |
| Android 设备电量 | HA 该路径无需运行时权限 | `ContextCompat.registerReceiver(..., null, IntentFilter(ACTION_BATTERY_CHANGED), ...)` 返回粘性 Intent，随后 `Intent.getIntExtra` 取 `level`、`scale` | 实验 Hook 只观察 `ACTION_BATTERY_CHANGED` 的返回值，按白名单和 UID 留证 | `VSC-LAB-ANDROID-POWER-001` 要求两次不同的设备输入均出现应用非默认返回和同值的新服务端状态 | 73% 和 61% 两次均通过，应用原 PID 存活，电池模拟已复原 | 常规审计尚未接入电源规则。实验以服务端状态核对上传结果，未采集上传正文，也未验收车载动力电池 |
| Android 充电状态与充电类型 | 同上 | 同一 Intent 的 `status` 和 `plugged` | 实验 Hook 已观察对应返回值 | 保留读取证据，服务端变值判定单列待验收 | 两次电量变值期间已保存读取事件 | 当前只对电量做完整变值验收 |

代码依据来自装机版本的 [BatterySensorManager.kt](https://github.com/home-assistant/android/blob/2026.10.1/common/src/main/java/io/homeassistant/companion/android/common/sensors/BatterySensorManager.kt)。运行时栈确认 `getBatteryPercentage → updateBatteryLevel → requestSensorUpdate`。原始回执、事件、设备状态和源文件摘要见 `output/vehicle-power-20261103/`。人工签核保留 `pending`。

```powershell
. ./environment.ps1
& $VScanPython -m vehicle.lab.power_run --out output/new-power-run
```
