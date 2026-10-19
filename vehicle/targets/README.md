> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# 靶子 App（vehicle/targets，原 Phase 2）

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
本 App 是被审计的对象：它故意过度索权、读取 VHAL、外发 JSON，供 V-Scanner
（Phase 3/4）在自有 AAOS 模拟器上检测。不做任何规避、混淆或反分析 —— 一切行为必须可被直接观察。

## 是什么

- 包名 `com.vscanner.targetapp`，普通 Views + Kotlin，无 Compose、无 androidx、无第三方依赖。
- 三个按钮 = 三种**彼此独立、逐个触发**的行为，与审计规则一一对应：

| 按钮 | 行为 | 对应规则类型 |
| --- | --- | --- |
| 1. 索权演示 | 输出清单声明的权限、逐条 checkSelfPermission、对 dangerous 级发起运行时申请 | over_permission（VSC-P001～P003） |
| 2. 读取 VHAL | `Car.createCar(context)` → `getCarManager(Car.PROPERTY_SERVICE)`，用 `CarPropertyManager.getProperty(int,int)` 读 8 个属性，FLOAT 属性另加 `getFloatProperty` 交叉读取 | sensitive_read（VSC-R001～R003） |
| 3a. 外泄 HTTP | 把最近一次读取缓存 POST 为 JSON（明文） | data_egress（VSC-E001～E003） |
| 3b. 外泄 HTTPS | 同上，走 HTTPS | data_egress |

- 8 个属性与 6 条权限全部取自 `vehicle/rules/baseline_android14/rules.db`（source_verified），代码里未杜撰任何 `android.car` 常量。
- 外泄端点可编辑，默认 `http://10.0.2.2:8080/collect` 与 `https://10.0.2.2:8443/collect`
  （10.0.2.2 = 模拟器宿主机环回，Phase 4 的 Mitmproxy 监听处）。
- 所有事件同步写入三处：logcat（标签 `VSCTarget`）、界面日志面板、
  文件 `vscanner_events.log`（内部 files 目录 + 应用外部目录各一份）。

## 每个按钮预期产生什么（含“被平台拒绝”的预期）

1. **索权演示**：日志列出 8 条声明权限；6 条 `android.car.permission.*` 的 checkSelfPermission 状态；
   随后对 `CAR_SPEED`、`CAR_ENERGY`（dangerous）发起运行时申请。
   **预期拒绝**：`CAR_IDENTIFICATION`、`CAR_MILEAGE`、`CAR_ENGINE_DETAILED` 为
   `signature|privileged`（见 rules.db permissions 表），普通应用**永远不可能被授予**，
   这里不发起申请、只记录 DENIED 状态 —— 声明本身即是静态过度索权信号。
2. **读取 VHAL**：逐属性输出 `SUCCESS / DENIED / ERROR / UNAVAILABLE`。
   - `GEAR_SELECTION`、`CURRENT_GEAR`（需 `CAR_POWERTRAIN`，normal，自动授予）：预期可读。
   - `PERF_VEHICLE_SPEED`（`CAR_SPEED`）、`FUEL_LEVEL`、`EV_BATTERY_LEVEL`（`CAR_ENERGY`）：
     需先被授予（运行时申请或 `pm grant`），否则 **SecurityException —— 预期内**。
   - `INFO_VIN`（`CAR_IDENTIFICATION`）、`PERF_ODOMETER`（`CAR_MILEAGE`）、
     `ENGINE_RPM`（`CAR_ENGINE_DETAILED`）：**预期全部 SecurityException**。
     这是有价值的诚实结果：审计工具要能区分“读取成功 / 被 SecurityException 拒绝 / 崩溃”，
     本 App 逐条 try/catch 并记录异常类名与消息，不伪造成功。
   - `getFloatProperty` 交叉读取仅作日志参考：种子库警告单独调用可能回退 0，不进外泄载荷。
3a. **外泄 HTTP**：POST JSON（含属性名、数值 ID、类型、所需权限、结果、值/异常、读取时间戳）。
   端点未监听时得到 `ConnectException` —— 同样是诚实结果。先按 2 再按 3a（3 秒内）可命中规则
   VSC-E001～E003 的 3000 ms 关联窗（项目实验参数）。
3b. **外泄 HTTPS**：走系统默认信任、无证书固定（刻意保持“最平凡”的 TLS 客户端）。
   Mitmproxy CA 未安装为系统 CA 时**预期 `SSLHandshakeException`** —— 有效结果，不是缺陷；
   正是 Phase 4 CA 注入/绕过演练的靶点。

缓存为空时按 3a/3b 只记警告不发送，保证行为严格可分。

## 构建

```bash
# 版本矩阵：Gradle 8.13 · AGP 8.11.1 · Kotlin 2.2.0 · compileSdk 36 · minSdk 29 · targetSdk 35 · JDK 21 · JVM target 17
cd target-app
./gradlew :app:assembleDebug
# 产物：app/build/outputs/apk/debug/app-debug.apk（约 2.4 MB）
```

本机实测：`BUILD SUCCESSFUL`（Gradle 8.13 + AGP 8.11.1 + Kotlin 2.2.0，阿里云镜像；完整日志见 `target-app/build.log`）。
已用 `aapt2 dump permissions` 核对 APK 清单包含全部 6 条 car 权限与 INTERNET/ACCESS_NETWORK_STATE。
**设备运行尚未验证**（模拟器按协调约定未启动）。

## 安装与驱动（AAOS 模拟器 `Automotive_1408p_landscape`，API 35 / userdebug）

```bash
adb install -r target-app/app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.vscanner.targetapp/.MainActivity

# 授予两条 dangerous 级 car 权限（或点按钮 1 走运行时申请）
adb shell pm grant com.vscanner.targetapp android.car.permission.CAR_SPEED
adb shell pm grant com.vscanner.targetapp android.car.permission.CAR_ENERGY

# 观察：logcat 标签 VSCTarget
adb logcat -s VSCTarget:I

# 事件文件（两处）
adb shell run-as com.vscanner.targetapp cat files/vscanner_events.log
adb pull /sdcard/Android/data/com.vscanner.targetapp/files/vscanner_events.log .   # 应用外部目录，无需 root
```

## 已验证 / 未验证

| 项 | 状态 |
| --- | --- |
| 编译（assembleDebug） | ✅ 已实测通过 |
| APK 清单权限（aapt2） | ✅ 已核对 |
| 常量溯源（rules.db 三表） | ✅ 全部命中（见 DECISIONS.md D003） |
| 设备安装与三个按钮的真实输出 | ❌ 未运行（模拟器未启动），全部标【需实测校准】 |
| SecurityException 的具体文案 / VHAL 数值 | ❌ 同上 |
