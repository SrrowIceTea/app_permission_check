# Phase 4 设计决策

## D401 用反向代理，不用正向代理

规格原本假定"模拟器设全局代理 10.0.2.2:8080，App 流量自然进代理"。**在本环境不成立**：
`settings put global http_proxy` 设了也没用，`dumpsys wifi` 恒为 `Proxy settings: NONE`，
断开重连 wifi 也一样——这个 AAOS 构建不把全局代理应用到 wifi 网络。

因此改为 **mitmproxy 反向模式**（`--mode reverse:http://127.0.0.1:8080`），
由被测应用**直接寻址**代理端口。代价是偏离了真实车载网络形态：真机上应用会走系统代理或直连
TLS，不会主动连审计端口。这一条必须写进论文的"适用范围"，不能含糊过去。

配套改动：靶子 App 的默认端点从 `8080/8443` 改为 `8888`（`vehicle/targets/target-app/.../strings.xml`）。
靶子 App 是我们自己的夹具，指向审计代理正是它的用途。

## D402 包名归因：归因点在应用进程内，不在系统层

**第一版（按源端口回查 UID）失败。** 模拟器的 SLIRP 是用户态 NAT，不保留源端口：

```
设备侧  10.0.2.16:54950 → 10.0.2.2:8888   uid 1010212
宿主侧  mitmproxy 看到 127.0.0.1:33012
```

**第二版（系统层时间关联）也失败**，两个根因：应用连接只存活几十毫秒，
`/proc/net/tcp` 轮询抓不到 ESTABLISHED 行；TIME_WAIT 行丢失 uid（恒为 0），事后也追溯不到。

**第三版（应用进程内观测）成功。** Phase 3 的 `hook_egress.js` 挂钩 `java.net.Socket.connect`，
记录 `(时间戳, 包名, 目标主机/端口, 线程, 栈)`。包名是确定的——应用进程本来就知道自己是哪个包。
addon 用时间就近把代理流对到这些事件上，实测 `delta` 575ms / 1128ms，远小于 2000ms 容差。

**结论：能确定归属的只有应用进程内部。** 这印证了研究文档 §2.3 的"socket 须归属 UID
才能判定谁外发"——系统层做这件事在本环境做不到，应用层做是直接且可靠的。
`uid_sampler.py` 降级为兜底来源保留。

~~设备与主机 epoch 一致（偏差稳定约 0.53s），时间关联的前提成立~~ —— **这句是错的**，
后来实测偏移会漂移（从"设备快 530ms"到"设备慢 1731ms"）。因此改用**主机时钟**：
`run.py` 在主机落盘时给每条事件打 `host_received_ts`，流的时间戳也取主机时钟，
两边同源，不再做任何跨时钟比较。

## D402b 挂钩 Java 对象的参数必须先 Java.cast

`hook_egress.js` 第一版拿到 `Socket.connect(SocketAddress)` 的参数后直接调
`addr.getHostString()`，结果 `host=null、port=-1`——**方法调用静默失败，不报错**，
日志里全是 `-> None:-1`，看起来像"连了个没有地址的目标"。
改为 `Java.cast(addr, Java.use('java.net.InetSocketAddress'))` 后正常。
Frida 里 Java 对象参数是弱类型引用，不 cast 就调不出方法；这类失败没有任何提示。

## D403 归因不到的流，只要命中敏感指纹就照常落盘

否则一个归因失败就意味着一条可疑外发被静默丢掉——对审计工具而言这是最坏的失败模式。
`addon.py` 因此对白名单内一律记录，对白名单外仅在"归因失败 **且** 载荷命中敏感指纹"时记录，
标 `attribution: "unresolved"`。宁可留一条待归因的可疑记录。

## D404 靶子 App 必须先读后发

靶子 App 的两个行为刻意解耦：外泄按钮要求先有读取缓存，否则只打一条 WARN 不发送。
这是它的设计（"两个行为保持可分"），不是缺陷。重启 App 或重启模拟器后缓存即失效，
**自动化脚本必须按「读 VHAL → 外泄」的顺序点击**，否则会看到"点击无效、无流量"的假象。

## D405 日志落主机

设备侧 `untrusted_app` 写不了 `/data/local/tmp`（见 vehicle/hooks D303），
`uid_sampler` 的设备侧脚本输出改用 `adb shell -t -t` 取回主机。
**必须两个 `-t`**：从脚本里跑时本地 stdin 不是终端，单个 `-t` 不分配远程 pty，
设备上的 `grep`/`sed` 就会块缓冲，表现为"记录器在跑、主机一条也收不到"。

## D406 HTTPS 拦截：记录客户端侧握手，不是 req.scheme

反向模式下 `flow.request.scheme` 是**上游**协议（这里是 http），不是客户端侧。
第一版 addon 用它填 `intercepted_tls`，于是"客户端走了 TLS、上游是明文"被记成 `false`，
**把成功拦截误报成没拦截**。改为读 `flow.client_conn.tls_established`。
修掉 Phase 3 的绕过缺陷后，实测捕获到 `client_tls=true` 的明文流。

## D408 归因失败要挂起重试，不能当场定案

**egress 事件结构上必然晚于它所对应的那条流**：`hook_egress.js` 在 `Socket.connect`
返回**之后**才记录，而 HTTP 请求紧跟着就到达代理。所以"请求到达时事件还没落盘"是常态，不是偶发。

实测两条并发流：一条的事件比流早 2ms（当场就对上了），另一条晚 65ms（当场扑空）。
**65ms 远在 2000ms 容差之内——算法没错，是问得太早。**
（`host_received_ts` 还是在 `json.dumps`/`open`/`write` **之前**取的，所以真实落盘只会更晚。）

第一版在原地就把结果定成 `unresolved` 写盘，等于把这个可恢复的时序问题永久化。
改为**挂起队列 + 宽限期（3000ms）重试**：`request()`、`response()`、以及一个 0.5s 的
daemon 冲刷线程都会重试归因，宽限期内仍对不上才按 `unresolved` 落盘。

**不能只靠 `done()`**：那是 mitmproxy 正常退出才跑的钩子，`taskkill /F`、崩溃、
被 OOM 干掉都不会走到它——表现为最后几条本来能归因的流凭空消失。
mitmproxy 12 **没有 `tick` 钩子**（已核对源码），所以自己起线程。

副作用：`evt_id` 是**写入顺序**而非收到顺序（晚收到的流可能先落盘）。下游按 `ts` 排序。

## D409 事件文件的半截行绝不能吞掉

事件文件由 `run.py` 在**另一个进程**里边跑边追加，addon 与它并发读。
如果读取恰好落在"写了一半"的瞬间，最后一行是半截的。

第一版用 `for line in handle` 然后 `handle.tell()`：读到半截行时 `tell()` **已经越过它**，
下轮 `seek()` 从那半截的中间开始，读出来的两半都解析失败——
**这条记录就再也找不回来了**。症状极具误导性：文件里那条记录明明完整，
addon 却永远看不到，flow 一直是 `package=null`，看起来像归因算法失灵。

改为 `readline()` 逐行读，**行尾没有换行符就停在那里、不推进偏移**，下次从头再读。
离线测试 `test_half_written_line_is_not_lost` 钉死这条，并已用旧算法复现过丢失。

## D410 事件源路径配错会静默失败

`_refresh()` 里 `if not path.exists(): continue` 是**静默跳过**的。于是"源配错了"与
"今天没有出站流量"在结果上完全一样：每条流都是 `package=null`，日志里没有任何异常。

实测踩过：Git Bash 里 `$PWD` 是 POSIX 形式 `/c/Users/...`，写进 Windows 环境变量后
被转成 `\c\Users\...`——一个**根本不存在的路径**被当成配好的源，整场归因全废。

对策两条：

1. `load()` 时把**绝对路径 + 存在性**打出来，不存在用 `warn`。路径不存在在启动时是合法的
   （文件要等第一个事件才创建），所以只能警告不能报错，但必须喊得让人看见。
   同时在归因超时的警告里带上各源的存在性与大小——**"为什么没归因上"要能一眼看出来**。
2. Git Bash 下取 Windows 形式路径要用 `$(pwd -W)`，不要用 `$PWD`。

讽刺的是 `VSCAN_ATTRIB_SOURCES` 这个环境变量本来就是为了修 D402 那次的路径错配而加的，
结果从另一个入口又把同一类错误引了回来。

## D407 未验证 / 边界

- 四项规格均已验证，见 README。剩余边界见下。
- 归因依赖时间配对（容差 2000ms）。**双应用并发已实测**（`verify_multi_app.py`，
  证据在 `evidence/`：两条流 delta 24ms / 15ms，均 MATCH）。时间上分不清时靠
  `attribution_ambiguous` 标记而不是猜——**错误归因比没有归因更糟**，
  它会把无辜的 App 写进报告。但要注意：容差 2000ms 对"两个 App 在 2 秒内先后外发"
  这件事本身是**不敏感**的，靠的是最近匹配 + 亚军距离判据。
- `hook_egress.js` 只注入白名单包名，未在白名单外的第三方应用上验证过。
- 非 HTTP 协议（MQTT / gRPC / QUIC）解不了内容，只能按"主机 + 时序 + 属性值指纹"弱匹配。
- native 锁定（BoringSSL / Cronet / gRPC）不在 Java 层绕过的覆盖范围。
- 双向 TLS 需抽取客户端证书，未处理。
- 上游 httpd 对 `/collect` 返回 404，不影响取证，但意味着"响应内容"这一路证据不完整。
- **环境不稳定**：wifi 会周期性掉线，掉线后所有设备侧操作静默失败（表现为 0 结果，
  看起来像代码 bug）。排查任何设备侧异常前先确认 `ip -brief addr show wlan0`。

## D408 后到竞争者、明文存储与接收端（2026-09-24）

已有候选也要等满3000ms再定案，否则后到的另一个App事件无法参与亚军比较。
仅成功连接可作为候选，START/ARMED和失败连接排除；队列变更在同一锁内。
原始请求/响应捕获1MiB并保留原始长度、截断标志和SHA256，SQLite与JSONL双写。
多个采集器同时首次建库时PRAGMA journal_mode=WAL可立即BUSY；显式有界重试。
collector_server的/collect返回200和字节摘要，取代历史httpd的404。
双App在SLIRP多轮连接超时，失败证据保留；改用ADB回环验证同一Java Socket路径，
600ms错峰两流MATCH(2/3ms)，50ms近同时两流AMBIGUOUS(1/1ms)。
证据：../output/multi-20260924-183952/verification.json。该结果不等同SLIRP完全同时发送已通过。

## D411 无响应请求、扫描完整性（2026-09-28）

`addon.py` 原先只有 `request()` / `response()`，没有 `error()`。请求被代理观察到、
但上游连接失败或超时的场景因此**整条不在证据里**——而"未收到响应"与"没有发送请求"
对审计是完全不同的两件事，前者证明这个应用确实尝试把数据发出去。
新增 `error()`，记录写**独立文件** `flows-unanswered.jsonl`（`flows.jsonl` 的字段集
与加固前逐字一致，它是对外证据契约）。

**为什么不混进 `flows.jsonl`**（每条都是实测过的连锁后果）：`device_acceptance` 断言
`all(status_code == 200)`，多一条无状态码的记录会确定性打断整条交付链；
`multi_acceptance` 用直接下标 `f['status_code']`，会变成 KeyError；
最要紧的是 `vehicle/analyze/evaluation.py` 的外发判定**不看 `status_code`**——一条带
`request_tokens` 的失败流若被归因到白名单包，会生成 `content_match=True` 的外发结论，
报告里写成"确实出现了被读取的属性"，那是凭空造出来的关联。故失败流 `tokens` 一律为空。

**只写文件而没人看等于换个地方静默丢弃**：两套验收脚本都加了 `no_unanswered_requests`，
`build_delivery` 把条数写进 `provenance.json`，`load()` 打出该文件路径（路径配错与
"真的没有失败"在结果上完全一样，同 D410 的陷阱），`done()` 有记录时打 warn。

`body_of` 会在两处悄悄打折：解码失败返回空串、超过 `MAX_BODY_SCAN`(256KB) 截断。
两者都让"没打上标签"与"内容根本没被完整看过"无法区分。新增 `scan_body()` 返回
(text, status)，`addon` 把状态与标签**一起**缓存进 metadata（分开缓存会导致
用请求侧的扫描状态去描述响应），汇总进 `summary.inputs.bodies_truncated` /
`bodies_undecodable`——只躺在 JSONL 里评审看不到。

**覆盖范围是实测出来的，不是从源码推的**（三种情形逐一跑过，mitmproxy 12.2.3 反向模式）：

| 上游 | 触发的 hook | 客户端看到 |
| --- | --- | --- |
| 存活 | `request` + `response` | 200 |
| **连接被拒**（没东西监听） | **只有 `load`** | 连接被直接丢弃 |
| 接受后断开 | `request` + `error` | HTTP 错误 |

所以 `error()` 覆盖的是"**连上了、然后失败**"这一类。**上游连接被拒这条路径本版本
根本观测不到**——它连 `request` 都不调，`http_connect_error` 也不调（那是 CONNECT
方法专用的）。不要在报告或边界说明里声称覆盖了"上游不可达"。

真实 addon 的端到端验证（上游接受后断开）：`flows.jsonl` 0 条、
`flows-unanswered.jsonl` 1 条，package 正确归因、`status_code=None`、
`failure="server closed connection"`、tokens 为空。
证据：../output/device-20260928-015125/verification.json、../output/multi-20260928-015306/。

## D412 归因常数的适用范围（2026-09-28 量化）

D403 的 `MATCH_TOLERANCE_MS=2000` / `AMBIGUITY_MS=500` 与 D408 的 3000ms 宽限期，
此前只有**两个夹具**的校准。新增 `vehicle/traffic/experiment_attribution.py` 把时序变成可扫描的
参数，用真实 `TimeAttribution` 跑混淆矩阵（脚本内的解析预测与实测在 228/228 格一致）。
详见 ../../archive/EXPERIMENTS.md。

结论要点：
- **容差与歧义窗按设计工作**：孤立包在 ±2000ms 内 `correct`、之外 `unresolved`，从不出错。
- **歧义保护只覆盖 ±500ms 一条窄带**。本包事件离流较远（仍在容差内）而另一个 App 更近时，
  归属被**整条拿走且不标记**——`wrong`。这是"错误归因比没有归因更糟"最可能被违反处。
- **夹具坐在安全区里**：实测锚点（本包早 2ms）下从不出错，所以单靠夹具校准看不出该风险区。
  以后新增夹具也要报告它落在哪个区间。
- **宽限期是权衡不是白拿**：无竞争者时把 `unresolved` 救回 `correct`；有竞争者时把
  `wrong` **降级**为 `ambiguous`；但竞争者在窗口内落盘时，会把本来 `correct` 的变成
  `ambiguous`。报告里 `ambiguous` 的条数受采集时序影响。

**这些是构造时序下的规则语义，不是真实误判率。** 真实比率取决于事件迟到与
读取→外发间隔的分布，需要长时间真机采集。

## D413 / D414 / D415 归因决策已迁至 core/collector（2026-10-13）

`attribution.py` 已迁到 `core/collector/`（平台拆分），后续归因决策记录在
**`core/collector/DECISIONS.md`**（续 D413 起）：目标地址校验（第二信号）、
归因置信信息进结论层、保守弃权开关与错峰采样误归因率。改归因逻辑前先读那里。
