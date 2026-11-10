# 靶子 App（vehicle/targets，原 Phase 2）

被审计的对象：两个故意过度索权、读取 VHAL、外发 JSON 的 App，供 Phase 3/4 在自有
AAOS 模拟器上检测。**不做任何规避、混淆或反分析——一切行为必须可被直接观察。**
**已完成。** 决策见 `DECISIONS.md`，全局约束见根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `target-app/` | 主靶子 `com.vscanner.targetapp`（普通 Views + Kotlin，含OkHttp 4.12测试依赖） |
| `target-app2/` | 第二靶子 `com.vscanner.targetapp2`（Phase 4 双应用并发归因用） |
| `trigger.py` | 点按钮的验收脚本：现读按钮 bounds 并回读 logcat 确认点中 |

三个按钮对应三类规则：索权演示→over_permission、读取 VHAL（8 属性）→sensitive_read、
外泄 HTTP/HTTPS（把读取缓存 POST 出去）→data_egress。8 个属性与 6 条权限全部取自
`vehicle/rules/baseline_android14/rules.db`，代码里**没有杜撰任何 android.car 常量**（D003）。

## 怎么跑

```bash
cd target-app
# 版本矩阵：Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / compileSdk 36 / minSdk 29 / targetSdk 35
# JAVA_HOME=D:\Android\JDK（原开发机是 D:\Anroid\JDK）；仓库阿里云优先（见 gradle 配置，与 vehicle/rules/android 同源）
./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk

# 点按钮：用 trigger.py 而不是写死坐标——坐标在布局一变就会静默点到别处
cd .. && PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...
"$PY" trigger.py --package com.vscanner.targetapp --button btnRead
"$PY" trigger.py --package com.vscanner.targetapp --button btnEgressHttp
"$PY" trigger.py --package com.vscanner.targetapp --button btnEgressHttps
```

事件同步写三处：logcat（标签 `VSCTarget`）、界面日志面板、`vscanner_events.log`。
预期行为（含"被平台拒绝"）见表：`signature|privileged` 权限永远拒、`normal` 可读、
`dangerous` 未授权时拒——这是夹具的**设计预期**，不是 bug。

## 本目录的坑

- **外发顺序不能反**：Phase 4 的时间窗关联要求先读后发（D404 在 vehicle/traffic 里）。
- 外泄端点默认 `10.0.2.2:8080/8443`（模拟器宿主机环回，Phase 4 的 Mitmproxy 监听处），
  换端口要在 App 界面里改，不要改死代码里的坐标。
- 设备网络只走 wifi 且会掉线；外发按钮点了没反应先查 `ip -brief addr show wlan0`。
- 两个 App 的包名是前缀关系（`targetapp` / `targetapp2`）——任何按子串包含匹配包名的
  代码都会把 A 判成 B，必须用 `pkg + '.'` 前缀比较（vehicle/hooks/4 都踩过）。

## 状态

已完成：双 App + 三按钮 + trigger.py，Phase 3–6 的全部实测都跑在这两个夹具上。
待办/可优化：

- **夹具不用 okhttp3** → `ssl_pinning_bypass.js` 的 `okhttp3.CertificatePinner` 分支
  **从未被实际触发**（vehicle/hooks 的已知未验证路径）。要覆盖它，给夹具加一个走 okhttp3
  的按钮即可，其余不动。
- `subscribePropertyEvents`（订阅式读取）路径无夹具，vehicle/hooks 同样未测试。

## 2026-09-24增补

两个夹具增加OkHttp错误pin按钮与10秒订阅按钮，主夹具提供Gadget构建变体。
横屏布局改为可滚动；trigger.py按界面bounds滚动定位，不硬编码按钮坐标。
订阅方法来自device35实测签名；只有收到有效回调才算读取。详见根COMPLETION.md。

## 2026-10-11增补

主夹具新增 `CipherSender` + 按钮 `4. 自绘加密外泄（AES/GCM 密文）`：把读取结果用
`javax.crypto.Cipher`（AES/GCM/NoPadding）加密后经原始 Socket 外发，作为 vehicle/hooks 内存 Hook
（`hook_cipher.js`）的靶子。密钥/nonce 固定且 nonce 前置，仅供夹具复现，非真实密钥管理。
`doFinal` 先于 `connect` 执行，连接失败不影响「加密前明文被截获」的验证点。
