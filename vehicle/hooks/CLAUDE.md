# Phase 3 — Frida 动态插桩层

**仅用于授权测试（自有设备与自有 APK）。** 观察模式：不阻断调用、不改写返回值、不篡改数据。
默认只注入白名单包名。**已完成。** 决策见 `DECISIONS.md`（D301–D310），全局约束见根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `vscan_runtime.js` | **四个钩子共用**的观测运行时：事件记录格式、双通道落盘、进程名 |
| `test_runtime.mjs` | 上者的离线回归（`node test_runtime.mjs`，10 用例，不需要设备/Frida） |
| `hook_vhal.js` | 观察 `CarPropertyManager` 的 8 个敏感属性读取 |
| `hook_egress.js` | 观察出站连接（`Socket.connect`），**Phase 4 包名归因的主来源** |
| `ssl_pinning_bypass.js` | 绕过证书校验的**入口**：白名单判断 + 装配 |
| `pinning_bypasses.js` | 上者的四条手法（conscrypt / SSLContext / okhttp Pinner / HostnameVerifier） |
| `recon_cpm.js` | 侦察：CPM 方法面、VehiclePropertyIds 交叉核对 |
| `stack_capture.js` | 多个钩子共用的 Java 栈采集（按归属筛应用帧，见 hook_egress 的教训） |
| `hook_cipher.js` | 观察 `javax.crypto.Cipher` 自绘加密，截获加密前明文（内存 Hook，梯度一） |
| `hook_native_ssl.js` | 观察 native TLS（BoringSSL SSL_write/SSL_read），截获明文 buffer（内存 Hook，梯度二） |
| `build.py` | 注入 bridge shim + 调 frida-compile → `dist/*.bundle.js` |
| `run.py` | 主机侧驱动：attach、接收 `send()`、落 JSONL |
| `analyze_log.py` | 解析 JSONL，统计与还原 |
| `dist/` `logs/` | 构建产物（勿手改）、采集到的 JSONL |

## 怎么跑

```bash
export PATH="D:/Anroid/SDK/platform-tools:$PATH"
adb forward tcp:27043 tcp:27043              # 必需：端口不是默认的 27042
adb shell am start -n com.vscanner.targetapp/.MainActivity

PY313="C:/Users/OneKyubey/AppData/Local/Programs/Python/Python313/python.exe"   # 只有它装了 frida
"$PY313" run.py --package com.vscanner.targetapp \
    --script dist/hook_vhal.bundle.js --seconds 45 --out logs/hook_vhal.jsonl

# 改完钩子源码：先离线回归，再重新打包（四个 bundle 都要重建）
node test_runtime.mjs && "$PY313" build.py
```

点击按钮用 `vehicle/targets/trigger.py --package … --button btnRead`，不要写死坐标。
另需一个 TLS 监听桩给 Phase 4 用：`tls-test/tls_listener.py`。

## 本目录的坑

- **Frida 17 不能用裸脚本**：Java bridge 已从 agent 运行时移除，裸 `Java.perform(...)` 直接死在
  `ReferenceError: 'Java' is not defined`。必须先 `npm install && python build.py` 打包
  `frida-java-bridge`。`frida -l hook_vhal.js` 跑不了。
- **必须 hook 应用进程**：在 system_server 里建 Car 客户端会被
  `SecurityException: Unable to find app for caller … when binding service ICar` 拒掉
  （没有 app 身份）。system_server 只能做类侦察。
- **日志落主机**：SELinux 禁止 `untrusted_app` 写 `shell_data_file`，`chmod 777` 无效。
  脚本 `send()` 回传，`run.py` 落盘；同时尽力写设备端副本并标 `DEVICE_WRITE_DENIED`。
- **`build.py` 的临时入口必须放源码同目录**（`.entry.<name>.js`）：相对导入按入口文件自身
  目录解析，放 `.build/` 会变成静默的"模块找不到"。
- **`com.android.org.conscrypt.TrustManagerImpl` 与 `org.conscrypt.*` 必须都钩**：
  用 `||` 短路时 `Java.use` 只要能解析类引用就返回非空，钩子全挂到死类上（D307 之一）。
- **"钩子挂载成功"≠"钩子被调用"**：D307 是三处静默缺陷叠加（钩错类、异常类型匹配不全
  ——`CertPathValidatorException` 与 `CertificateException` 是兄弟、返回空链）。
- **观测失败会改到被测应用**（D310）：`vlog` 曾无外层 try/catch，`JSON.stringify` 一抛
  （extra 循环引用即抛）异常就顺着 `implementation` 传回 `CarPropertyManager.getProperty`，
  违反"只观察不改写"且一条日志都不留。现统一走 `makeLogger()`，保留字段**后写**
  （extra 先写会盖掉 `src`/`evt_id`，让证据指向别的事件——同样静默）。
- **栈不能"取前 N 帧"**（D308）：应用帧恰好在截断点之外。要按类名归属筛，并排除 R8/D8
  合成帧（行号为 0）。
- **钩子掉线与应用无动作结果一模一样**（D309）：`pidof` 为空、事件数 0 都可能是钩子没挂上。
- 设备时间保留原值；主机驱动追加 host_received_ts，下游默认不跨时钟比较。

## 状态（2026-09-24）

四钩子、打包、会话化主机驱动与SQLite双写已实现。
2026-09-24实测OkHttp CertificatePinner调用、订阅GEAR_SELECTION回调、HTTP/HTTPS载荷。
Gadget自有源码构建变体已实测：启动等待、注入后恢复、23条VHAL_READ。
默认只监控两个自有夹具；新增授权包须显式--allow-package，代理同步VSCAN_PACKAGES。
server attach不能追溯附加前行为；Gadget不能解决任意无源码APK的预置与签名问题。
不覆盖native TLS、Cronet与未解析协议。当前关联默认用host_received_ts，不用固定530ms。
订阅参数接口不一定暴露getClass，须先Java.cast到Object；注册成功不算读取。

## 状态（2026-10-11 增补：内存 Hook）

新增两条「内存 Hook 截获明文 Buffer」路径（申报书创新点 2，此前为能力缺口）：

- `hook_cipher.js`：hook JCE `Cipher.update/doFinal`，截获自绘加密**加密前明文**；配套夹具按钮 `4. 自绘加密外泄`（CipherSender，AES/GCM）。
- `hook_native_ssl.js`：`Interceptor.attach` 到 BoringSSL `SSL_write/SSL_read`，截获 native TLS 明文 buffer。

覆盖补齐了「自绘加密」与「native TLS」两类此前无明文能力的路径；边界仍在：
不覆盖静态链接自有 BoringSSL 且符号不导出的栈（Cronet 常见）、不经 JCE 的手工加密。
两脚本均已通过 `build.py` 编译；**设备端实测待跑**（AAOS 模拟器 + frida-server 27043）。
