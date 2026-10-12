> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# Phase 4：Mitmproxy 流量层

**仅用于授权测试（自有设备与自有 APK）。** 只抓取、只标注、不改写任何报文。

## 状态：四项全部已验证

| 规格项 | 状态 |
| --- | --- |
| 按包名分流 | ✅ **已验证**（含双应用并发），`attribution=app_process_hook` |
| 敏感字段打标 | ✅ **已验证**，命中规则库的属性名与属性 ID 指纹 |
| JSON 落盘 | ✅ **已验证**，统一 JSONL |
| HTTPS 明文 | ✅ **已验证**，`intercepted_tls=true` 的明文流已捕获 |

实测（单应用，两条流，一次 HTTP 一次 HTTPS）：

```
POST http  client_tls=False  package=com.vscanner.targetapp  delta=575ms
POST http  client_tls=True   package=com.vscanner.targetapp  delta=1128ms
tags=['vhal_property_name','vhal_property_id']  bytes=2463
```

双应用并发的验收见下面的「双应用并发归因」。

## 跑起来

```bash
# 1) 代理：反向模式。见 D401 为何不用正向代理
#    W=$(pwd -W) 而不是 $PWD —— 见下面第 5 个坑，这个差别会让整场归因静默失效
W="$(pwd -W)"
VSCAN_ATTRIB_SOURCES="$W/../hooks/logs/egress_events.jsonl" \
VSCAN_PACKAGES="com.vscanner.targetapp,com.vscanner.targetapp2" \
mitmdump -s addon.py --mode reverse:http://127.0.0.1:8080 \
         --listen-host 0.0.0.0 --listen-port 8888

# 2) 应用进程内观测出站连接（**归因的主来源**，与上一步并行）
#    另开一个终端，同时挂 SSL 绕过（HTTPS 明文需要）
cd ../vehicle/hooks
python build.py                                   # 首次需要（共享 bundle 会输出到 core/frida_host/dist）
cd ../core/frida_host
PY313="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
"$PY313" run.py --package com.vscanner.targetapp \
    --script dist/hook_egress.bundle.js --seconds 60 \
    --out ../../traffic/logs/egress_events.jsonl &
"$PY313" run.py --package com.vscanner.targetapp \
    --script dist/ssl_pinning_bypass.bundle.js --seconds 60 \
    --out ../../traffic/logs/integ_ssl.jsonl &

# 3) 靶子 App 先读 VHAL，再点外泄按钮（顺序不能反，见 D404）
#    用 vehicle/targets/trigger.py 而不是写死坐标：它会现读按钮 bounds 并回读 logcat 确认点中
cd ../vehicle/targets
python trigger.py --package com.vscanner.targetapp --button btnRead
python trigger.py --package com.vscanner.targetapp --button btnEgressHttp
```

`uid_sampler.py` 是兜底来源，当前抓不到应用连接（D402），一般不需要跑。

**必须用 Ctrl-C 正常退出**（`done()` 会排空挂起队列）。不过挂起重试还有一个 0.5s 的
daemon 冲刷线程兜底（见 D408），所以强杀最多丢掉宽限期内还没落盘的最后几条。

## 双应用并发归因

`verify_multi_app.py` 是这条的验收脚本：拿**载荷自报的包名**当基准，逐条比对 addon 的归因。
它的比较必须是**精确相等**——`com.vscanner.targetapp` 恰好是 `com.vscanner.targetapp2` 的前缀，
用子串包含会把 A 判成 B（我上一轮就这么误报过一次 `*** CROSSED ***`，出现在一条实际
归因正确的流上，delta 只有 2ms）。

```bash
python -m unittest test_attribution            # 归因逻辑的离线回归（不需要设备）
# 重放当轮的原始证据，不需要设备、不需要重新抓包：
python verify_multi_app.py --flows evidence/flows-multi-app.jsonl \
    --egress evidence/egress-multi-A.jsonl --egress evidence/egress-multi-B.jsonl
```

实测（两个 App 各挂一个钩子，先后 13s 外泄），证据存 `evidence/`：

```
 evt  attributed                 self-reported                delta  verdict
   1  com.vscanner.targetapp     com.vscanner.targetapp          24  MATCH
   2  com.vscanner.targetapp2    com.vscanner.targetapp2         15  MATCH
```

两条事件都**晚于**各自的流落盘——当场定案会全部扑空，靠挂起重试才对上（D408）。

## 落盘记录的样子

归因成功的一条（**实测**，字段有省略）：

```json
{"v":"1","src":"proxy","evt_id":2,"ts":1790172257934,
 "package":"com.vscanner.targetapp2",
 "attribution":"app_process_hook","attribution_source":"egress_hook",
 "attribution_delta_ms":15,"attribution_ambiguous":false,"attribution_runner_up":null,
 "method":"POST","scheme":"http","host":"127.0.0.1","path":"/collect",
 "status_code":404,"intercepted_tls":false,"request_bytes":2463,
 "request_tags":["vhal_property_name","vhal_property_id"],
 "request_tokens":["PERF_VEHICLE_SPEED","291504647"]}
```

`attribution` 是**置信度标签**（`app_process_hook` / `system_sample` / `ambiguous` / `unresolved`），
`attribution_source` 才是来源（`egress_hook` / `uid_sampler`）。两者分开是因为会不同步：
`ambiguous` 可能来自确定的应用进程内观测——来源可靠，但归属分不清。

归因不到但**载荷命中敏感指纹**的流照常落盘，`attribution: "unresolved"`（D403）。
载荷里是完整的 8 条 VHAL 读取结果，含 `requiredPermission` 与 `result`（`ok` / `denied`）。
`status_code:404` 是上游 httpd 对 `/collect` 的正常回应，不影响取证。

## 按包名分流：两次失败，第三次换对归因点才成

**mitmproxy 看不到包名。** 前两条路都失败了，原因值得记下来。

**第一版——按源端口回查 UID。实测不可行。** 模拟器的 SLIRP 是用户态 NAT，
不保留源端口，还把设备连接以宿主机本地连接的形式转发：

```
设备侧  10.0.2.16:54950 → 10.0.2.2:8888   uid 1010212
宿主侧  mitmproxy 看到 127.0.0.1:33012
```

两侧端口毫无对应关系。

**第二版——时间关联 + 系统层 `/proc/net/tcp` 采样。仍不可行。** 两个根因：
应用连接只存活几十毫秒，轮询抓不到 ESTABLISHED 行；TIME_WAIT 行**丢失 uid**（恒为 0），
事后也追溯不到。

**第三版——换归因点，把观测放到应用进程内。成了。**
Phase 3 新增 `hook_egress.js`，在应用进程内挂钩 `java.net.Socket.connect`，
记录 `(时间戳, 包名, 目标主机, 目标端口, 线程, 栈)`。包名是**确定的，不是推断的**——
应用进程本来就知道自己是哪个包。addon 再用时间就近把代理流对到这些事件上
（`delta` 实测 575ms / 1128ms，远小于 2000ms 容差；双应用那轮是 24ms / 15ms）。

这也印证了研究文档 §2.3 的判断："socket 须归属 UID 才能判定谁外发"——
而**应用进程内是唯一能确定归属的地方**。

**但换对归因点还不够，还得换对"什么时候问"。** egress 事件是 `Socket.connect`
**返回之后**才记录的，而 HTTP 请求紧跟着就到达代理——事件**结构上**必然晚于对应的流。
第一版在原地就把结果定成 `unresolved` 写盘：一次可恢复的时序问题被永久化。
实测同一轮里一条赶上（早 2ms）、一条扑空（晚 65ms），**65ms 远在 2000ms 容差之内**。
现在是挂起队列 + 3000ms 宽限期内重试（D408）。

`uid_sampler.py` 保留作为兜底来源，但已知在应用连接上抓不到。
`addon.py` 对白名单外的流，仅在"归因失败**且**载荷命中敏感指纹"时记录，
标 `attribution: "unresolved"`——宁可留一条待归因的可疑记录，也不要静默丢掉。

**白名单默认给两个包名，不是零个也不是一个**（`VSCAN_PACKAGES` 可覆盖）。
单包名白名单有个比归因失败更难发现的失败模式：归因**成功**到第二个 App 时，
"已归因且不在白名单"会让这条流被**静默丢弃**——归因失败至少还留一条 unresolved 记录，
这个是干净的、看起来毫无问题的结果。审计工具不该有这种失败模式。

## HTTPS 明文：先失败，修好后成功

第一轮它被 Phase 3 的绕过缺陷阻塞（`CertPathValidatorException: Trust anchor not found`，
钩子报告"已挂载"却一次不触发）。修掉 Phase 3 的三处静默缺陷后（见 `vehicle/hooks/DECISIONS.md` D307），
HTTPS 外泄完成，捕获到：

```json
{"method":"POST","host":"127.0.0.1","path":"/collect","status_code":404,
 "intercepted_tls":true,"request_bytes":2463,
 "request_tags":["vhal_property_name","vhal_property_id"]}
```

`intercepted_tls` 取的是**客户端连接**是否握手，不是 `req.scheme`。
反向模式下 `req.scheme` 反映的是上游协议，直接用它会把"客户端走 TLS、上游明文"
误报成没拦截——这是个会让人把成功看成失败的坑。

## 本环境踩到的五个坑（都会静默失败）

前四个是环境/设备的，第五个是**配置**的——而它最阴，因为它伪装成前四个的样子。

1. **AAOS 模拟器的网络走 wifi，不走 ethernet。** 这个镜像里 `Can't find service: ethernet`，
   `eth0` 永远停在 down，`ConnectivityService` 也就永远不注册网络，应用完全没有网络出口。
   修法是 `cmd wifi connect-network AndroidWifi open`。
2. **wifi 会周期性掉线。** 实测中途掉过一次（`wlan0 DOWN`、`default network: none`），
   之后所有设备侧操作静默失败——包括看起来像"代码 bug"的采样器 0 结果。
   排查任何设备侧异常前，先确认 `ip -brief addr show wlan0` 与 `dumpsys connectivity`。
3. **系统全局代理不会传播到 wifi 网络。** `settings put global http_proxy` 设了也白设，
   `dumpsys wifi` 恒为 `Proxy settings: NONE`，重连 wifi 也一样。
   所以审计代理只能由被测应用直接寻址（见 D401）。
4. **`adb shell` 从脚本里跑时，单个 `-t` 不分配 pty。** 没有 pty，设备上的 `grep`/`sed`
   会块缓冲，输出攒着不吐：实测 `-t` 收到 0 行，`-t -t` 收到 232 行/5s。
   adb 只在本地 stdin 是终端时才分配远程 pty，从脚本调用时 stdin 不是。
5. **`VSCAN_ATTRIB_SOURCES` 里的路径必须是 Windows 形式，且 `$PWD` 给的不是。**
   Git Bash 的 `$PWD` 是 POSIX 形式 `/c/Users/...`，写进 Windows 环境变量后被转成
   `\c\Users\...`——一个**根本不存在的路径**。而 `_refresh()` 里
   `if not path.exists(): continue` 是**静默跳过**的，于是"源配错了"和
   "今天没有出站流量"在结果上完全一样：每条流都是 `package=null`，
   日志里一条异常都没有。实测在这一条上绕了很久，一直以为是归因算法的问题。
   **用 `$(pwd -W)` 取 `C:/Users/...` 形式。** 启动日志里会打每个源的绝对路径与存在性，
   不存在用 `warn`——路径在启动时不存在是合法的（事件文件要等第一条事件才创建），
   所以只能警告不能报错，但必须喊得让人看见（D410）。

## 文件

| 文件 | 作用 |
| --- | --- |
| `addon.py` | Mitmproxy addon：流的生命周期、落盘、挂起重试式归因 |
| `attribution.py` | 时间归因与歧义判据（可离线测试，不依赖 mitmproxy） |
| `tagging.py` | 敏感载荷指纹与打标（可离线测试，不依赖 mitmproxy） |
| `test_attribution.py` | 归因的离线回归，10 个用例，**不需要设备** |
| `test_tagging.py` | 指纹的离线回归，10 个用例，**不需要设备** |
| `verify_multi_app.py` | 双应用并发归因的验收脚本（拿载荷自报包名当基准） |
| `uid_sampler.py` | 设备侧 UID 采样器（**当前抓不到应用连接，原因见上**） |
| `DECISIONS.md` | 设计决策 D401–D410 |
| `logs/flows.jsonl` | 抓到的流（可用 `VSCAN_FLOW_LOG` 改路径，见下） |
| `logs/uid_events.jsonl` | 兜底来源事件（当前为空） |
| `evidence/` | 双应用验收的原始证据：流、mitm 日志、两路 egress、判定结果 |

**跑验证轮之前先设 `VSCAN_FLOW_LOG`。** 本 addon 是**追加**写 flows.jsonl 的，
不设的话新一轮数据会直接混进既有证据里，而那份文件是审计结论的原始凭据——
混进去就再也分不开哪条是哪轮的了。默认路径不变，老命令照常工作。

`addon.py` 曾经贴着单文件 300 行的上限（超出 4 行）。`attribution.py` 和 `tagging.py`
两次拆分都是同一个理由：**流的一生**与**归因怎么看**/**报文里有什么**本来就无关，
拆开后各自能脱离 mitmproxy 单独测。不拆的话，指纹表写错一条正则这类错误
只能靠抓真流量去碰，而它的表现是"少打一个标签"——不报错，只是静默失真。

## 边界

**归因是统计性的，不是确定性的**——这一条必须写进论文的"适用范围"，不能含糊：

- 容差 2000ms 对"两个 App 在 2 秒内先后外发"**本身是不敏感的**。能分开靠的是
  "最近匹配 + 亚军距离判据"，而不是容差。分不清时标
  `attribution_ambiguous` 而不是猜——**错误归因比没有归因更糟**，
  它会把无辜的 App 写进报告。双应用并发已实测（`verify_multi_app.py`，证据在 `evidence/`）。
- `hook_egress.js` 只注入白名单包名，**未在白名单外的第三方应用上验证过**。
  真实车机上装的第三方 App 不能预先注入钩子，这是本方案最大的落地缺口。

其余沿用研究文档的结论：

- **真正的盲区不是证书锁定，而是非 HTTP 协议**：MQTT / gRPC / QUIC 解不了内容，
  只能按"主机 + 时序 + 属性值指纹"弱匹配。这是预期，不是意外。
- native 锁定（BoringSSL / Cronet / gRPC）需逐个定位，Java 层绕过覆盖不到。
- 双向 TLS 需要抽取客户端证书。
- HSTS 不构成实质障碍。
- 上游 httpd 对 `/collect` 返回 404，不影响取证，但意味着"响应内容"这一路证据不完整。
- **环境不稳定**：wifi 会周期性掉线，掉线后设备侧操作全部静默失败。
