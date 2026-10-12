> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# Phase 3：Frida 动态插桩层

**仅用于授权测试（自有设备与自有 APK）。** 观察模式：不阻断调用、不改写返回值、不篡改数据。
默认只记录白名单包名（`com.vscanner.targetapp`）。

## 先读这一条：Frida 17 不能用裸脚本

Frida 17 把 Java bridge 从 agent 运行时里移除了。任何以 `Java.perform(...)` 开头的脚本在这台设备上
都会立刻死在：

```
ReferenceError: 'Java' is not defined
```

本目录的四个钩子脚本最初就是这样写的，**因此从未能运行过**。修法是先用 `frida-compile` 把
`frida-java-bridge` 编译进 bundle：

```bash
npm install                      # 一次即可
python build.py                  # 产出 dist/*.bundle.js
```

`build.py` 在每个脚本前面注入一小段 shim（`import Java from 'frida-java-bridge'; globalThis.Java = Java;`），
所以 hook 源码本身保持为普通脚本，未被改写。**直接跑 `frida -l hook_vhal.js` 是不行的。**

## 目录

| 文件 | 作用 |
| --- | --- |
| `recon_cpm.js` | 侦察：CPM 方法面、VehiclePropertyIds 交叉核对、`getPropertyList` 桥接 quirk |
| `hook_vhal.js` | 观察 `CarPropertyManager` 的 8 个敏感属性读取 |
| `ssl_pinning_bypass.js` | 为审计流量捕获而绕过证书校验（进程内，白名单限定）——**入口**，只做白名单判断与装配 |
| `pinning_bypasses.js` | 上者的四条绕过手法本身（conscrypt / SSLContext / okhttp Pinner / HostnameVerifier） |
| `hook_egress.js` | 观察出站连接（`Socket.connect`），**Phase 4 包名归因的主来源** |
| `vscan_runtime.js` | **四个钩子共用**的观测运行时：事件记录格式、落盘双通道、进程名 |
| `test_runtime.mjs` | 上者的离线回归（`node test_runtime.mjs`），**不需要设备、不需要 Frida** |
| `analyze_log.py` | 解析 JSONL，统计与还原 |
| `build.py` | 注入 bridge shim + 调 frida-compile |
| `run.py` | 主机侧驱动：attach、接收 `send()`、写 JSONL |
| `dist/` | 构建产物（勿手工编辑） |
| `logs/` | 采集到的 JSONL |
| `tls-test/tls_listener.py` | Phase 4 用的最简 TLS 监听桩 |

**入口脚本现在是模块化的**：`import` 自 `vscan_runtime.js` / `pinning_bypasses.js`，
所以 `build.py` 把临时入口文件放在**源码同目录**（`.entry.<name>.js`）而不是子目录——
相对导入是按入口文件自身所在目录解析的，放子目录里会静默变成"模块找不到"。
`dist/*.bundle.js` 仍是单文件产物，设备侧不需要额外文件。

## 运行

```bash
export PATH="D:/Anroid/SDK/platform-tools:$PATH"
adb forward tcp:27043 tcp:27043          # 必需，见下
adb shell am start -n com.vscanner.targetapp/.MainActivity

PY313="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"   # 只有它装了 frida 模块
"$PY313" run.py --package com.vscanner.targetapp \
    --script dist/hook_vhal.bundle.js --seconds 45 --out logs/hook_vhal.jsonl
```

另开一个终端点击靶子 App 的「2. 读取 VHAL」按钮即可看到读取事件。
用 `vehicle/targets/trigger.py --package ... --button btnRead` 而不是写死坐标：
它会现读按钮 `bounds` 并回读 logcat 确认点中，写死的坐标在布局一变就会静默点到别处。

改完钩子源码后先跑离线回归，再上设备：

```bash
node test_runtime.mjs            # 10 个用例，不需要设备
python build.py                  # 重新打包，四个 bundle 都要重建
```

## 三个环境事实（实测，违反会失败或得到误导性结果）

**1. frida-server 监听在 27043，不是默认的 27042。**
设备上是 `/data/local/tmp/frida-server -l 127.0.0.1:27043`。
连 27042 会得到 `TransportError: connection closed`，看起来像 server 没跑，其实只是端口不对。
`run.py` 会自动补上转发。

**2. 必须 hook 应用进程，system_server 看不到读取。**
在 system_server 里建 Car 客户端会被拒绝：

```
SecurityException: Unable to find app for caller
  android.app.ActivityThread$ApplicationThread (pid=740)
  when binding service Intent { act=android.car.ICar pkg=com.android.car }
```

system_server 没有 app 身份，`bindService` 不成立。attach system_server 只适合类侦察；
要看"哪个 App 读了什么"，只能在应用进程里 hook。

**3. 日志写主机，不写 `/data/local/tmp`。**
`untrusted_app` 域被 SELinux 禁止写 `shell_data_file`，`chmod 777` 也没用：

```
avc: denied { append } for name="vscan.log"
  scontext=u:r:untrusted_app:s0:c250,... tcontext=u:object_r:shell_data_file:s0
  permissive=0
```

所以脚本用 `send()` 把事件推给主机，由 `run.py` 落 JSONL。脚本仍会尽力写一次设备端副本
（对 system_server / `com.android.car` 注入时有效），并在日志里标注 `DEVICE_WRITE_DENIED`。

另：`frida spawn` 在这台模拟器上会超时，但 `am start` 正常——应用本身没问题，所以 `run.py` 用 attach。

## 实测结果（2026-09-21，靶子 App `com.vscanner.targetapp`）

`recon_cpm.js`：

| 项 | 结果 |
| --- | --- |
| CPM 方法数 | **78**（与 Phase 0 记录一致） |
| VehiclePropertyIds 常量 | 254 个，8 个待核对属性 `missing=[] mismatch=[]` |
| 可见的 TLS 相关类 | `com.android.okhttp.CertificatePinner` 等 28 个 |

`hook_vhal.js`：点击一次读取按钮 → **46 条 `VHAL_READ`**，每条含属性 ID/名称、`outcome`、
线程名（`vsc-read`）、完整调用栈（归因到 `com.vscanner.targetapp`）。

`hook_egress.js`：挂钩 `Socket.connect` 两个重载，实测捕获到
`pkg=com.vscanner.targetapp -> 10.0.2.2:8888 outcome=ok`。
包名由应用进程自己给出，不是推断——Phase 4 的按包名分流就靠它（见 `vehicle/traffic/DECISIONS.md` D402）。

`ssl_pinning_bypass.js`：**绕过已实测生效**。靶子 App 的 HTTPS 外泄经中间人成功完成，
Phase 4 捕获到 `client_tls=True` 的明文流。修好之前它只"报告已挂载"却一次都没触发，
原因见 D307（三处静默缺陷叠加）。`okhttp3.CertificatePinner` 不在本进程
（靶子 App 未用 okhttp3，非缺陷）。

## 规则库预测运行时行为（本轮最有价值的结果）

把 hook 实测的 `outcome` 与规则库的 `protectionLevel` 对照：

| 属性 | 规则库权限 | 级别 | 预测 | 实测 |
| --- | --- | --- | --- | --- |
| INFO_VIN | `CAR_IDENTIFICATION` | `signature\|privileged` | 拒绝 | **error** ✓ |
| PERF_VEHICLE_SPEED | `CAR_SPEED` | `dangerous` | 拒绝* | **error** ✓ |
| GEAR_SELECTION | `CAR_POWERTRAIN` | `normal` | 可读 | **ok** ✓ |

\* `dangerous` 是**可**授权的，所以此处 `error` 意为"当前未授权"，不是"不可能授权"；
`signature|privileged` 才是普通应用永远拿不到的。

规则库覆盖的 3 个属性**全部命中**。另外 5 个（CURRENT_GEAR、PERF_ODOMETER、ENGINE_RPM、
FUEL_LEVEL、EV_BATTERY_LEVEL）**规则库里没有对应规则**——这是真实覆盖缺口，不是预测失败。

## 已修的缺陷

**重载匹配**：`ssl_pinning_bypass.js` 原先用 `cls[mName].overload.apply(null, 反射得到的类型名)`
匹配重载，匹配不上时 Frida 桥内部抛 `cannot read property '_o' of null`——
该消息既不含方法名也不含类型名，极难定位。改为遍历 `holder.overloads`。

**绕过失效**：修完上面的重载匹配后钩子能挂上了，但**依然没有绕过**——报告 ARMED
却一次都不触发。真因是钩错了类 + 异常类型匹配不全 + 返回空链，三处叠加。
详见 **D307**。这一条值得单独记住：**"钩子挂载成功"与"钩子被调用"是两回事**。

**观测失败会改到被测应用**（D310）：四个脚本各有一份 `vlog`，其中 `hook_vhal.js` /
`recon_cpm.js` 那两份**没有外层 try/catch**——`JSON.stringify(rec)` 一旦抛
（`extra` 里出现循环引用就会抛），异常就顺着 `implementation` 传回被挂钩的
`CarPropertyManager.getProperty`。**这直接违反"只观察不改写"**，而且一条日志都不会留下。
现已合成 `vscan_runtime.js` 一份，并加 `test_runtime.mjs` 把这条钉死。

## 边界

- 三个脚本都是**观察模式**，不阻断、不改值。
- `ssl_pinning_bypass.js` 只覆盖 Java 层（conscrypt、自定义 TrustManager、HostnameVerifier）；
  **不覆盖** native TLS（BoringSSL）、自绘加密协议、WebView 自身的校验路径。
- 靶子 App 未使用 okhttp3，所以 `CertificatePinner` 路径在本轮未被实际触发。
- 事件时间戳是设备 `Date.now()`，与主机时钟的对应关系尚未建立（Phase 5 的时间窗关联需要）。
