# Phase 2 决策记录（靶子 App）

仅用于授权测试（自有设备与自有 APK）。本文件记录设计决策与**未能确认**的项。

## D001 交付边界与可观察性

- 全部工作在 `phase2/` 下完成；未创建、修改、删除 `phase1/android/` 下任何文件。
- 靶子 App 不做混淆、加固、反分析、规避。release 构建同样 `isMinifyEnabled = false`。
- 事件统一经 `EventLog`：logcat（tag `VSCTarget`）+ 界面面板 + 两个可 `adb pull` 的文件。

## D002 构建配置

- 版本矩阵固定：Gradle 8.13 · AGP 8.11.1 · Kotlin 2.2.0 · compileSdk 36 · minSdk 29 ·
  targetSdk 35 · JDK 21 · JVM target 17。compileSdk 必须 36：`android.car.jar` 只存在于
  android-36 / android-37.0 的 `optional/` 目录。
- 仓库用阿里云镜像（google / gradle-plugin / public），裸 `google()` 等仅作兜底（与 phase1/android 同策略）。
- 项目路径含非 ASCII（用户名 毛宇淇），沿用 `android.overridePathCheck=true`（AGP 官方豁免开关）。
- 包装器直接复制自 `D:\Anroid\program`（distributionUrl 已指向阿里云，勿重新生成）。
- 未引入 KSP：本夹具无 Room / 注解处理，矩阵中 KSP 版本仅约束用到它的模块。
- 构建实测：第一次 `BUILD FAILED`（Kotlin 无法对 `getProperty(int,int)` 的泛型 `E` 从星号投影推断），
  显式 `getProperty<Any?>(…)` 后第二次 `BUILD SUCCESSFUL in 1m 6s`（日志：`target-app/build.log`）。

## D003 常量溯源（规则一核对，Python 查 rules.db 完成）

全部命中 `baseline_android14/rules.db`：
- permissions 表 6 条：`CAR_IDENTIFICATION`、`CAR_SPEED`、`CAR_ENERGY`、`CAR_MILEAGE`、
  `CAR_ENGINE_DETAILED`、`CAR_POWERTRAIN`。
- vhal_properties 表 8 条：`INFO_VIN=286261504`、`PERF_VEHICLE_SPEED=291504647`、
  `GEAR_SELECTION=289408000`、`CURRENT_GEAR=289408001`、`PERF_ODOMETER=291504644`、
  `ENGINE_RPM=291504901`、`FUEL_LEVEL=291504903`、`EV_BATTERY_LEVEL=291504905`。
- dangerous_apis 表 3 条签名：`getProperty(II)`、`getProperty(Class,II)`、`getFloatProperty(II)`；
  主读取用的正是 risk_rules 引用的 `getProperty(II)Landroid/car/hardware/CarPropertyValue;`。

以下**不在**规则库中、按规则一不能声称种子来源，来源与处置如下（无遗漏）：
- `Car.createCar(Context)`、`Car.PROPERTY_SERVICE`、`getCarManager(String)`、`isConnected()`、
  `disconnect()`：任务书指定的获取方式；已用 javap 对 `platforms/android-36/optional/android.car.jar`
  逐一核实存在（编译期验证，非设备验证）。
- `CarPropertyValue.getStatus()`、`getValue()`、`STATUS_AVAILABLE`：同 jar 编译期核实。
- `INTERNET`、`ACCESS_NETWORK_STATE`：Android 框架标准权限（非 car 域）。
- `org.json`、`HttpURLConnection`：平台库。
- `AREA_GLOBAL = 0`：getProperty 的第二参数。种子库只给出 8 属性 `area_type=GLOBAL`，
  **未给出** areaId 数值常量；`VehicleAreaType` 类名也不在种子库，故按 0 传入并留 TODO，
  未引用任何未证实常量名。见【需实测校准】。

## D004 android.car 的接入方式

- 编译期 `useLibrary("android.car")`；manifest **不声明** `<uses-library android:name="android.car">`。
  理由：AAOS 设备 Car 服务恒存在，运行时必然可用；uses-library 声明只影响编译链接
  （对 optional 库可省），少写一个设备差异风险点（低风险优先，如任务书要求）。

## D005 getStatus() 与 getPropertyStatus() 的取舍

- API 36（编译 SDK 的 android.car.jar）把 `CarPropertyValue.getStatus()` 标记 deprecated，
  新增 `getPropertyStatus()`。目标设备是 API 35，`getPropertyStatus()` 在 35 上不存在，
  调用会在设备上抛 `NoSuchMethodError`。因此**保留 `getStatus()`**（该 API 自 CarPropertyValue
  引入起一直存在），接受编译期一条 deprecation 警告，注释已说明原因。
- 未能设备实测该结论 —— 列【需实测校准】。

## D006 三个行为严格可分

- 按钮 2 只读不发；按钮 3a/3b 只发不读：外泄仅使用最近一次读取的内存缓存，
  缓存为空时记警告、不发送。用户自行控制读与发的间隔，可与 3000 ms 关联窗（VSC-E001～E003）
  对齐。读取与外泄都在后台线程，不阻塞 UI。

## D007 外泄通道设计

- HTTP 变体：`usesCleartextTraffic="true"`（清单中明示），便于直接抓包观察。
- HTTPS 变体：系统默认信任链、无证书固定、无自定义 TrustManager —— 刻意“最平凡”，
  使 Phase 4 的 Mitmproxy CA 注入/绕过有真实靶点；CA 未装时预期 SSLHandshakeException 并如实记录。
- 端点可编辑（两个 EditText），默认指向宿主机环回 10.0.2.2。

## 未能确认的事项【需实测校准】

1. 设备端全部运行时行为：App 未安装、模拟器未启动（协调约束）。三个按钮的真实输出未验证。
2. `AREA_GLOBAL = 0` 与 GLOBAL 区域的对应（观察 getProperty 返回 status 校准）。
3. `getStatus()` 在 API 35 设备上的可用性与状态取值（D005）。
4. 各属性的真实可读性：预期 CAR_POWERTRAIN 组可读、dangerous 组授权后可读、
   signature|privileged 组 SecurityException —— 全部待设备确认，异常文案未采录。
5. AAOS 上对 `CAR_SPEED`/`CAR_ENERGY` 的运行时申请 UI 行为；必要时用 `adb shell pm grant` 代替。
6. `getFloatProperty` 单独调用回退 0 的种子库警告在设备上的表现。
7. HTTPS 变体成功条件（Mitmproxy CA 装为系统 CA 的步骤属 Phase 4）。
8. APK 的 dex 字符串级内容未复核（权限清单已由 aapt2 核对）。

## D208 新增夹具与横屏陷阱（2026-09-24）

两个夹具加入OkHttp4.12错误pin按钮、按device35签名订阅10秒的按钮。
新AAOS横屏布局高度小，新增按钮曾被挤出可见区域；现改为滚动布局，trigger按bounds查找。
订阅注册返回true与真实回调是两条证据，不能合并为“读取成功”。
OkHttp要先通过主机名校验才会进入Pinner；测试代理证书SAN显式含10.0.2.2，
仅用于自有夹具，不安装系统CA。实测见../output/device-20260924-133521/verification.json。
