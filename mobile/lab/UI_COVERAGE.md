# G1 移动三页夹具覆盖率

仅用于授权测试。自有 Debug APK 提供入口、设备标识、隐私偏好三页。标注路径事先固定为打开设备标识、取得 Android ID、打开偏好和保存偏好。

每轮分别留存真实 UI 树、发出的控件动作及应用运行时记录。评分区分页面到达、点击和经运行时确认的效果。动作需要同一轮中来自正确页面的控件点击、结果页面和时段内唯一的成功记录。读取仅记录成功状态。偏好写入后立即回读验收。

```powershell
. .\environment.ps1
.\mobile\fixture-app\gradlew.bat -p mobile/fixture-app :app:assembleDebug --offline
.\tools\python313.ps1 -m mobile.lab.ui_coverage_trial --serial emulator-5568 --apk mobile/fixture-app/app/build/outputs/apk/debug/app-debug.apk --out output/mobile-g1
.\tools\python313.ps1 -m mobile.lab.ui_coverage --source output/mobile-g1 --out output/mobile-g1/replay.json
```

参考轮按预定路线点击。自动轮复用移动端 UI 探索器，评分使用相同分母。结果适用于该自有夹具，独立移动应用的探索覆盖待后续实测。

2026-11-26 在 Android 16 手机模拟器上，参考轮与自动轮各到达 **3/3 页**，各完成 **4/4 个运行时确认动作**。重新评分的报告摘要一致。 [设备验收](../../output/mobile-audit-delivery-20261126/ui-coverage-03/verification.json) · [离线重算](../../output/mobile-audit-delivery-20261126/ui-coverage-03/replay.json)
