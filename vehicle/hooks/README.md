> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# Frida 动态插桩层（vehicle/hooks，原 Phase 3）

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
| `hook_native_ssl.js` | native TLS 明文（BoringSSL `SSL_read`/`SSL_write`），靠导出符号定位 |
| `hook_native_crypto.js` | 应用层加密明文：`SSL_write` 之前先 AES/EVP 了一次的情况（看入参/解密出参） |
| `hook_tls_meta.js` | TLS 元数据：SNI + 主动挂 keylog 回调（给 `tshark` 解包用），剥符号时的兜底 |
| `hook_flutter_ssl.js` | Flutter 静态 BoringSSL：按**代码形状**回扫序言定位，不依赖符号 |
| `hook_cipher.js` | JCE `Cipher.update/doFinal` 入参明文（自绘加密，不走 native） |
| `hook_classload.js` | **F1**：`BaseDexClassLoader.findClass` / `ClassLoader.defineClass` 记录运行时类加载并归因（host / third_party / unknown） |
| `classload_attribution.js` | 上者的纯归因模块：30 条 SDK 种子前缀、宿主包边界、数组/内部类归一化、调用方穿透反射帧 |
| `subscription_hooks.js` | 订阅回调观测（只读，不替换 callback） |
| `fixture_control.js` | 触发自有夹具按钮（`btnRead`/`btnEgressHttp`/`btnOkHttp`），不是审计 Hook |
| `scope.js` | 主机注入的显式包名白名单，禁止空白名单或默认全进程 |
| `stack_capture.js` | 共用 Java 栈采集：只挑应用自己的帧（行号定位唯一依据） |
| `vscan_runtime.js` | **各入口共用**的观测运行时：事件记录格式、落盘双通道、进程名 |
| `test_runtime.mjs` | 上者的离线回归（`node test_runtime.mjs`），**不需要设备、不需要 Frida** |
| `test_classload.mjs` | F1 归因口径 + 钩子透传/去重/批量的离线回归（`node test_classload.mjs`） |
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

## F1 类加载归因（2026-11-27）

**要回答的问题**：静态分析只知道 dex 里"引用了什么"，回答不了运行时"真正加载了什么"。
反射加载、动态 dex、加壳残留、第三方 SDK 是否真的被装载，只有运行时能给出证据。

**挂载点**：`dalvik.system.BaseDexClassLoader.findClass` 是所有 APK dex 类首次加载的必经点
（PathClassLoader / DexClassLoader / InMemoryDexClassLoader 都继承它，`Class.forName` 也走这里）；
父加载器里的 `java.*` / `android.*` 不经过它，正好挡掉平台类噪声。另挂
`ClassLoader.defineClass`，覆盖自定义加载器/加壳器直接定义字节码的路径。

**归因口径**（`classload_attribution.js`）：`origin` 只有三值——`host`、`third_party:<prefix>`、
`unknown`。前两者分别由宿主包边界（`host + '.'`，不是子串）与 30 条主流 SDK 种子前缀决定；
**没命中种子表的一律 `unknown`**，不按"看起来像"猜前缀。`class_kind`（platform /
support_library / sdk / other）只用于解释 unknown 的构成，不改变 origin。种子表是**有界**的，
报告必须同时给出 `uncovered_by_design`。

**事件**（`src=classload`）：`CLASSLOAD_START` / `CLASSLOAD_BATCH`（`items` 为
`[cls, origin, class_kind, sdk_prefix, loader_id, source]`，`source` 取 `find` 或 `define`）/
`CLASSLOAD_MISSING`（反射探测的失败样本）/ `CLASSLOAD_TRUNCATED`（默认 8000 类上限，
显式报 `dropped`，不静默截断）/ `ARMED`。按类名首次出现去重，按 200 条或 3 秒批量发送。

**同一套归因也用于隐私读取**：`PRIVACY_READ` / `PRIVACY_REGISTER` 新增 `origin`、
`origin_class`、`origin_sdk`。调用方取栈顶穿过反射/Binder 帧后的第一个真实帧；
取不到就是 `unknown`——**不从 `app_frames` 倒推**，那里按定义只有宿主帧。

**验证状态**：`node test_classload.mjs` 与 `node test_privacy.mjs` 离线通过，
`core/frida_host/build.py --platform vehicle` 可产出 `hook_classload.bundle.js` 并被两个入口引用。
**设备侧尚未验收**（当前无 AAOS 设备）：没有"已知含 SDK 的自有 APK 上稳定复现
`third_party` 前缀"的实测证据，设备条目只能标 pending。

## 运行

```bash
# 本机 SDK 在 %LOCALAPPDATA%\Android\Sdk（原开发机是 D:/Anroid/SDK）
export PATH="$(cygpath -u "$LOCALAPPDATA")/Android/Sdk/platform-tools:$PATH"
adb forward tcp:27043 tcp:27043          # 必需，见下
adb shell am start -n com.vscanner.targetapp/.MainActivity

PY313="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 只有它装了 frida 模块（原开发机是 C:/Users/毛宇淇/...）
"$PY313" run.py --package com.vscanner.targetapp \
    --script dist/hook_vhal.bundle.js --seconds 45 --out logs/hook_vhal.jsonl
```

另开一个终端点击靶子 App 的「2. 读取 VHAL」按钮即可看到读取事件。
用 `vehicle/targets/trigger.py --package ... --button btnRead` 而不是写死坐标：
它会现读按钮 `bounds` 并回读 logcat 确认点中，写死的坐标在布局一变就会静默点到别处。

改完钩子源码后先跑离线回归，再上设备：

```bash
node test_runtime.mjs            # 10 个用例，不需要设备
python build.py                  # 重新打包，8 个默认 bundle 都要重建
python build.py --only hook_flutter_ssl.js   # 该模块不在默认清单，按需单独构建
```

`build.py` 的默认清单是 `recon_cpm / hook_vhal / ssl_pinning_bypass / hook_egress /
hook_cipher / hook_native_ssl / hook_native_crypto / hook_tls_meta` 八个；
`hook_flutter_ssl.js` 只导出 `main()` 且不默认构建，用到时用 `--only` 显式加。
`ssl_pinning_bypass` 与 `hook_egress` 两个平台无关 bundle 同时输出到
`core/frida_host/dist/`，移动端直接复用，别只重建一边。

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

- 所有脚本都是**观察模式**，不阻断、不改值。
- 明文覆盖分四层，各管一段，别指望一个脚本通吃：
  `ssl_pinning_bypass`（Java 层放宽校验）、`hook_native_ssl`（BoringSSL 记录层）、
  `hook_native_crypto`（TLS 之前的应用层 AES/EVP）、`hook_cipher`（JCE 自绘加密）；
  `hook_tls_meta` 出 SNI + keylog，给 `tshark` 重组完整报文。
- 仍然**不覆盖**：WebView 自身的校验与网络栈、QUIC/HTTP3 载荷、加壳/反调试后的自定义协议、
  以及需要登录后才下发的加密配置。剥符号 BoringSSL 只有 Flutter 那条按代码形状回扫的路子，
  其它静态链接实现未见得能定位。
- 靶子 App 未使用 okhttp3，所以 `CertificatePinner` 路径在本轮未被实际触发。
- 事件时间戳是设备 `Date.now()`，与主机时钟的对应关系尚未建立（Phase 5 的时间窗关联需要）。
