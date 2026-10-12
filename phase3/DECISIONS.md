# Phase 3 设计决策

## D301 脚本必须打包，不能直接跑

Frida 17 移除了 agent 运行时的 Java bridge，裸 `Java.perform(...)` 抛
`ReferenceError: 'Java' is not defined`。本目录最初的三个脚本正是这样写的，所以从未运行过——
不是没来得及跑，是跑不了。改为用 `frida-compile` 把 `frida-java-bridge` 编译进 bundle。
`build.py` 注入 bridge shim，hook 源码本身保持为普通脚本，不被改写。
不选降级 Frida 16：那会推翻 Phase 0 已确立并记录的环境。

## D302 hook 目标是应用进程，不是 system_server

Phase 0 定的 system_server attach 方案**只能做类侦察**。实测在 system_server 内建 Car 客户端会被拒：

```
SecurityException: Unable to find app for caller
  android.app.ActivityThread$ApplicationThread (pid=740)
  when binding service Intent { act=android.car.ICar pkg=com.android.car }
```

没有 app 身份，`bindService` 不成立。而"哪个 App 读了什么"恰恰是本项目的核心问题，
所以读取观察必须在应用进程内进行。system_server 方案保留用于类侦察与
`com.android.car` 进程的全局观察。

附带确认：Phase 0 的 `ActivityThread.systemMain().getSystemContext()` 本身是对的，
但必须跑在有 Looper 的线程上（`Java.scheduleOnMainThread`），否则抛
`Can't create handler inside thread that has not called Looper.prepare()`。

## D303 JSONL 落在主机，不落 `/data/local/tmp`

SELinux 禁止 `untrusted_app` 追加写 `shell_data_file`，`chmod 777` 无效（`permissive=0`）：

```
avc: denied { append } for name="vscan.log"
  scontext=u:r:untrusted_app:s0:c250,... tcontext=u:object_r:shell_data_file:s0
```

这与 D302 直接冲突：既然只能 hook 应用进程，设备端那个日志路径就不可用。
改为脚本 `send()` 回传、`run.py` 在主机落 JSONL。脚本仍尽力写一次设备端副本
（对 system_server / `com.android.car` 注入有效），并如实标注 `DEVICE_WRITE_DENIED`，
不把"没写成功"伪装成成功。

## D304 观察模式，且必须能区分"没数据"与"崩了"

不阻断调用、不改写返回值、不篡改数据。默认只记录白名单包名（`com.vscanner.targetapp`）。
每条 hook 独立 try/catch，失败写入带 `where` 字段的 ERROR 记录——
`ssl_pinning_bypass.js` 的 conscrypt 缺陷正是靠这个机制定位的，而不是静默失效。
`outcome` 字段区分 `ok` 与 `error`：**"尝试读取被拒绝"本身就是审计发现**，
不能与"没发生读取"混为一谈。

## D305 修掉 conscrypt 重载匹配缺陷

原实现用 `cls[mName].overload.apply(null, 反射类型名)` 匹配重载。匹配不上时 Frida 桥内部抛
`cannot read property '_o' of null`，该消息既不含方法名也不含类型名，无法定位。
改为遍历 `holder.overloads`，不依赖类型名精确匹配。修后 conscrypt 三个方法全部挂载成功。

## D306 时间基准尚未建立

事件时间戳是设备 `Date.now()`。设备与主机的时钟对应关系、以及跨进程事件的排序，
都还没有建立。Phase 5 的时间窗关联（`window_ms=3000`）依赖这一点，**当前不可用**，
不得基于现在的日志做时间关联结论。

## D307 绕过曾经是坏的：三处缺陷，都是静默失败

第三轮实测发现 `ssl_pinning_bypass.js` **报告"已挂载"但一次都没触发**，
HTTPS 外泄始终以 `CertPathValidatorException: Trust anchor for certification path not found`
失败。三处缺陷叠加，每一处都只表现为"没生效"，不报错：

1. **钩错了类**。原代码 `tryUse('org.conscrypt.TrustManagerImpl') || tryUse('com.android.org.conscrypt.TrustManagerImpl')`
   用 `||` 短路。`Java.use` 只要能解析类引用就返回非空，与类是否被加载、被使用无关；
   而设备上真正在用的是 `com.android.org.conscrypt.TrustManagerImpl`
   （`enumerateLoadedClasses` 里根本没有 `org.conscrypt.*`）。于是钩子全挂到了一个死类上。
   改为**两个候选都钩，并分别报告各自挂到了什么**。
2. **异常类型匹配不全**。校验失败抛的是 `CertPathValidatorException`（经 `CertificateException` 包装），
   而原 `isBypassable` 只匹配 `CertificateException` 与 `SSLPeerUnverifiedException`。
   `CertPathValidatorException` 与 `CertificateException` **是兄弟**（同继承
   `GeneralSecurityException`），互不为 `isInstance`，于是异常被原样重抛、swallow 分支从未进入。
   改为同时匹配 `GeneralSecurityException`/`CertPathValidatorException` 并按类名兜底。
3. **返回空链**。`checkTrusted*` 返回"已验证的链"，返回空 `ArrayList` 会让 TLS 栈拿不到对端链
   而再次失败——吞了异常却仍然握手失败。改为返回**对端自己的证书**构成的链，这是 unpinning 的标准做法。

修后实测：`conscrypt.checkTrustedRecursive → swallowed ... Trust anchor not found`，
HTTPS 外泄成功，Phase 4 捕获到 `client_tls=True` 的明文流。

**教训**：这三处没有一处会报错。"钩子挂载成功"与"钩子真的被调用"是两回事，
"异常被吞掉"与"握手成功"也是两回事。诊断靠的是分别报告每个候选类的挂载结果，
而不是一个笼统的 ARMED。

## D308 栈不能"取前 N 帧"：应用帧恰好在截断点之外

`hook_egress.js` 第一版用 `maxStackFrames: 12` 取栈的**前 12 帧**。
实测这 12 帧**全是 okhttp 内部**：

```
java.net.Socket.connect(Native Method)
com.android.okhttp.internal.Platform.connectSocket(Platform.java:182)
com.android.okhttp.internal.io.RealConnection.connectSocket(RealConnection.java:145)
… 还有 9 帧同样在 com.android.okhttp.internal 里 …
```

应用自己的那一帧在更下面，**被整整齐齐地切掉了**。

**这个失败模式极难发现**：`stack` 字段不是空的，而是躺着 12 条真实、完整、
格式正确的 Java 帧。看日志的人只会觉得"栈采到了"。而"违规代码行号"要从应用帧里取——
也就是说，Phase 5 需要的**唯一**那一帧，恰好是唯一被丢掉的那一帧。

改为按**归属**取舍而不是按**位置**取舍：扫描整条栈，`context` 留框架帧
（够看清走的是哪条 HTTP 栈），`app_frames` 单独收应用自己的帧（上限 8 条，
超出就记 `app_frames_skipped`，**不静默截断**）。

判定"是不是应用自己的帧"用 `PKG + '.'` 前缀，不用子串包含——
`com.vscanner.targetapp` 是 `com.vscanner.targetapp2` 的前缀，
子串匹配会把另一个 App 的帧算进来（这个坑 Phase 4 的验收脚本已经踩过一次）。

修后实测：`app_frames` = `EgressSender.doSend(EgressSender.kt:46)` 起，共 4 帧，
其中 2 帧是 R8/D8 合成帧（无行号，已被 Phase 5 正确排除）。

## D309 钩子掉线与应用无动作，结果一模一样

`run.py` 采集时是一觉睡到底（`time.sleep(seconds)`）。**进程中途死掉的话钩子随之消失**，
此后一个事件也收不到——而"钩子掉了"与"应用什么都没做"的结果**完全相同**：
一个空 JSONL，日志干干净净，没有任何异常。

实测踩过：挂了两个钩子（vhal + egress），点完两个按钮回来是零条记录。
事后比对才发现钩子挂的是 pid 15505，而当时应用已经是 pid 15854。

改为轮询 + 存活检测：

- 每秒查一次 `/proc/<pid>` 还在不在，不在就**当场喊出来**（第几秒掉的、pid 是多少）。
  用 `/proc/<pid>` 而不是 `pidof`——**`pidof` 会返回一个同名的新 pid**，
  换过进程之后它照样有输出，看上去一切正常。要问的是"原来那个还在吗"。
- 超时打印里带上 `--package`，方便直接 `pidof` 复核。

**排查顺序**：设备侧零结果时，先确认钩子挂的 pid 还是不是当前 pid，再去怀疑代码。

## D310 事件记录合成一份：四份拷贝已经漂移，其中两份会改到被测应用

起因是单文件 300 行的约束（`ssl_pinning_bypass.js` 368 行、`recon_cpm.js` 316 行都超了），
但拆的过程中发现的问题比行数严重得多。

四个钩子各有一份 `vlog`，**已经漂移成四个版本**：

| 脚本 | 外层 try/catch | 日志路径 | console 行 |
| --- | --- | --- | --- |
| `hook_vhal.js` / `recon_cpm.js` | **没有** | `CFG.logPath` | 带 extras |
| `ssl_pinning_bypass.js` | 有 | `CFG.logPath` | 带 extras |
| `hook_egress.js` | 没有 | **写死字符串** | 不带 extras |

**没有外层 try/catch 那两份是缺陷，不是风格差异。** `JSON.stringify(rec)` 一旦抛
（`extra` 里出现循环引用就会抛），异常就顺着 `implementation` 传回被挂钩的
`CarPropertyManager.getProperty`——**观测失败改变了被测应用的行为**。
项目原则是"只观察不改写"，这条正好踩在上面。而它的失败方式是零日志：
应用那边多一个异常，审计这边什么都看不出来。

（`hook_egress.js` 那份没有外层 catch 但危害小些——`Socket.connect` 的回调里抛出
同样会传到应用，所以一样要修。）

改为 `vscan_runtime.js` 一份 `makeLogger(src, logPath)`，四个脚本都从这里取。
`src` 与路径做成参数是因为它们**本来就该不同**——共用的是"一条事件长什么样"，
不是"哪个钩子"。事件序号按 logger 各自计数：四个钩子是四个独立 Frida 会话，
本来就不共享 JS 上下文；即便将来同进程加载两个，各记各的也比串号好，
下游是按 `(src, evt_id)` 定位事件的。

顺带修掉一个**同样静默**的问题：原实现是保留字段先写、`extra` 后写，
于是 `vlog('X', {src: 'y'})` 会把 `src` 改掉，`evt_id` 同理——
等于让证据指向另一个事件。当前没有调用点这么做，但顺序不该由调用者的自觉来保证。
改成 extra 先写、保留字段后写。

**离线回归**：`test_runtime.mjs`（`node test_runtime.mjs`，10 个用例，不需要设备）。
它钉的是行为契约而不是实现：记录字段集、序号、`send`/`File` 抛异常时不外抛、
循环引用时不外抛、`DEVICE_WRITE_DENIED` / `SEND_FAIL` 如实标注、
四个 `src` 的记录形状逐字一致。这个缺陷**没有任何一条日志会显示出来**，只能靠测试钉住。

**拆分与验证**：`ssl_pinning_bypass.js` 拆成入口（白名单判断 + 装配）+ `pinning_bypasses.js`
（四条手法本身）。`build.py` 的临时入口文件改放**源码同目录**——相对导入按入口自身目录解析，
放 `.build/` 子目录里会失败。四个 bundle 重建后在设备上重跑了一整轮验证：

```
hook_vhal   23 条 VHAL_READ（与拆分前一致）
hook_egress 3 条 EGRESS_CONNECT，app_frames 完好（EgressSender.kt:46 + 2 合成帧）
ssl         PINNING_BYPASS 实际触发，TM_CLASS_HOOKED=6
→ Phase 5 关联出 10 条结论（6 candidate / 2 observed / 2 correlated）
→ dexlines 6/6 VERIFIED，位置与拆分前逐字相同
```

存档在 `phase5/evidence/refactor-check/`。

## 未验证 / 需实测校准

- `okhttp3.CertificatePinner` 路径未触发——靶子 App 未使用 okhttp3，因此该分支从未被执行。
- native TLS（BoringSSL）、自绘加密协议、WebView 自身校验路径**不在覆盖范围**。
- `subscribePropertyEvents` 相关路径未测试（靶子 App 只做主动读取）。
- 规则库的 8 个属性中只有 3 个有对应规则；其余 5 个的权限映射缺失，
  `CURRENT_GEAR` 实测可读但规则库里没有它。

## D311 订阅回调、Gadget与采集可靠性（2026-09-24）

回调参数静态类型为接口，Frida未暴露getClass；先cast到java.lang.Object再查运行类。
失败必须记录ERROR；不能把SUBSCRIPTION_REGISTER当VHAL_READ。
已实测callback.onChangeEvent、OkHttp CertificatePinner.check$okhttp及HTTPS明文。
Gadget在自有Application.attachBaseContext加载，回环27044等待；注入后恢复读取23条。
证据：../output/gadget-20260924-174538/verification.json；需要自有源码/安装权，不解决任意APK。
run.py为事件追加session与主机时刻、同步SQLite；捕获回调异常落CAPTURE_ERROR并非零退出。
frida-compile输出含UTF8字节长度头，不能直接向bundle前部拼JS；bundle_config重算模块长度。

## D312 内存 Hook 梯度一：JCE Cipher 明文截获（2026-10-11）

补齐申报书「内存 Hook 截获明文 Buffer」的能力缺口（此前 phase3 只有 Java 层绕过 + Socket.connect，
无任何明文能力）。梯度一 hook `javax.crypto.Cipher` 的 `update` / `doFinal`：

- **明文方向**：encrypt 时明文在**入参**（`firstByteArray` 取第一个 `byte[]`）；decrypt 时明文在
  `doFinal` 的**返回值**。两条都记 `CIPHER_PLAINTEXT`，用 `op`/`phase` 字段区分。
- **已知歧义（如实标注）**：`doFinal(byte[] output,int)` 这类「纯输出」重载里第一个 `byte[]`
  是 output 缓冲区而非明文，v1 不区分；夹具用单参 `doFinal(byte[])` 规避，注释已写明。
- **栈采集抽成 `stack_capture.js`**：hook_egress 里那份栈逻辑（按归属筛应用帧、`PKG+'.'` 前缀、
  app_frames_skipped 不静默截断）三个新入口都要用，抽出来避免再次漂移。hook_egress 本体不动
  （已实测，动它有回归风险）。

配套夹具：`phase2` 新增 `CipherSender`（AES/GCM 加密后原始 Socket 外发）+ 按钮 `4. 自绘加密外泄`。
`doFinal` 先于 `connect` 执行，故连接失败不影响「加密前明文被截获」这个验证点。

## D313 内存 Hook 梯度二：native TLS（BoringSSL）明文截获（2026-10-11）

梯度二用 `Interceptor.attach` 挂 BoringSSL 的 `SSL_write` / `SSL_read`，截获 native TLS 明文：

- `SSL_write(SSL*, const void*, int)`：onEnter 读 `args[1]`（明文），长度 `args[2].toInt32()`。
- `SSL_read(SSL*, void*, int)`：onLeave 读 `args[1]`（明文），长度 `retval.toInt32()`（>0 才读）。
- **只观察**：只读参数不改写、不 replace、不篡改返回值（与「观察不改写」铁律一致）。
- **符号/库名探测**：库名因 ROM 而异，候选 `libssl.so` 等逐个 `Module.findExportByName` +
  `enumerateModules` 兜底；找不到记 `SYMBOL_ABSENT`，**不编造**。
- **Java 栈在 native 上下文可能拿不到**：`withStack`（captureStack）本身 try/catch 兜底，
  另记 `native_backtrace`（模块+偏移）做调试线索。
- **边界**：静态链接自有 BoringSSL 且符号不导出的栈（Cronet 常见）覆盖不到，与 D312 的
  手工加密、手工 XOR 一起，仍是能力边界的下一层。**设备端实测待跑**。
