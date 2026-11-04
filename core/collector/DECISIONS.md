# core/collector 决策记录（归因 / 流量采集内核）

仅用于授权测试（自有设备与自有 APK）。

`attribution.py` 在平台拆分时从 `vehicle/traffic/` 迁到这里，它的历史决策仍在
`vehicle/traffic/DECISIONS.md`（D402–D412）。本文件从 **D413** 续写，是归因决策的新家。

## D413 目标地址校验：时间归因盲区的第二信号（2026-10-13）

### 问题

时间归因有一个**信息层面**的固有盲区，不是参数没调好：当"本包事件离流的距离 −
竞争者事件离流的距离 > AMBIGUITY_MS(500ms)"且竞争者是更近的那个时，归属会被整条
**静默抢走且不标记**（`wrong`）。因为"真主迟到 600ms + 竞争者 65ms"与"真主就是 65ms
那个"在**纯时间证据上完全同形**——任何只依赖候选距离的规则都无法同时保住理想锚点
（本包早 2ms）并消灭那条带。量化见 `experiment_attribution.py`（wrong 28/33）与
`archive/EXPERIMENTS.md:19`。

移动端还多一种更现实的形态：第三方样本走**常规代理模式**（`emulator -http-proxy` 是
SLIRP 层强制，全机流量都进代理），白名单只有一个包。此时**别的 App 的一条流**落进
被审计包某次 connect 的 ±2000ms 内且没有更近候选，就会被记成 `package=被审计包,
attribution=app_process_hook`，零标记；若载荷含与被审计包某次读取同哈希的设备标识值，
会被升级成移动端最强的 `value_hash_in_payload`——**误告被审计 App**。

### 解法：目标匹配作为第二信号

常规代理模式下 mitmproxy 看得见真实目标 host:port；egress 事件里也有
`target_host` / `target_port` / `target_ip`（`hook_egress.js:91-106`）。规则：

> 候选必须"目标匹配"才能归属；不匹配 → unresolved（宁缺勿错）。

真主的事件迟早会到（宽限期兜着），不会误伤。这直接杀掉移动端最现实的"误认领"形态，
且零成本。

### 三个必须遵守的坑（已写进 `target_match`）

1. **绝不要在 reverse 模式开**。reverse 下所有 App 都寻址同一代理端口，目标校验会把
   整场归因**静默变 unresolved**——正是本项目最恨的那类失败。因此做成**显式开关**
   `VSCAN_ATTRIB_TARGET_CHECK`，默认关；只有常规代理模式（`thirdparty_env.py`）置 1。
2. **Android 侧 getHostString() 对 OkHttp 常返回解析后 IP**（钩子注释已说明它不解析
   域名）。所以匹配是 **host/IP/peername 三选一**：`event.host==flow.host` 或
   `event.ip==flow.host` 或 `event.host==flow.ip` 或 `event.ip==flow.ip`，任一命中即可。
3. **两端解析域名可能拿到不同 CDN IP**。匹配失败时落到 unresolved，而不是随便选一个。
   此时 host 仍是同一个 hostname，靠 `event.host==flow.host` 兜住。

### 故意不 gate 端口

端口已被采集（`target_port` / `target_port`），但**不用于拒绝**。理由：端口不是身份
信号（同一 host 的不同端口可能是同一 App 的不同服务，反之同一 CDN 同端口可能服务多个
App），加入它会引入一条新的静默失败面，而收益远小于 host/IP 身份匹配。留作未来取证。

### 已知边界

- uid_sampler 事件无 target，目标校验开启时一律被排除（它本来就抓不到应用连接，D402）。
- 目标校验**只**消掉"误认领"，不消掉"真主迟到且无第二信号"的 silent wrong——那要靠
  P2 的确定性归属，或下面的显式开关（见 D414 末尾）。

## D414 把归因置信信息接进结论层（2026-10-13）

### 问题

`attribution_delta_ms` / `attribution_runner_up` 已经采到并写进流，但下游没有任何消费者
（analyze / 报告 / 看板全不读）。于是"接近但可疑"的归因信息没有进入结论层，一条被抢走
的流会被**自动升级成 `correlated`** 写进报告——真正伤人的是"wrong 被升级成强结论"这个
放大效应，不是 wrong 本身。

### 改动（三处）

1. **Top-K 候选**：`Attribution` 增加 `candidates`（前 5 个，含 package/delta/source），
   `flow_entry` 落盘 `attribution_candidates`。只存亚军取证不够。
2. **松归因封顶**：新增 `ATTRIB_LOOSE_MS = 1500`（MATCH_TOLERANCE_MS 的 3/4）。
   流有 `attribution_delta_ms` 且 ≥ 该值时，`evaluate_*` 把该 (read, flow) 配对的结论
   **封顶 candidate**，并标注 `attribution_delta_ms` / `attribution_runner_up` /
   `attribution_candidates` / `attribution_loose`，报告可见"归因距离 Xms"。
   **缺 delta 的流不判松**——否则旧证据结论会被无差别压到 candidate。
3. **移动端补 unresolved 跳过**：`evaluation_mobile.py` 原先只排除
   `attribution_ambiguous`，不排除"归因未解析"（unresolved 的流 package=None，可能是
   别的 App 的流）。三个流类谓词（read_then_egress / plaintext / third_party_domain）
   统一走 `_flow_unusable()`，同时排除 ambiguous 与 unresolved。

### 这条不消掉 silent wrong，只消掉放大效应

封顶只作用于"delta 接近容差"的松匹配。真主迟到 600ms、竞争者 65ms 命中的"抢走"案例里
冠军 delta 只有 65ms（看着很紧），`attribution_loose` 判不出。**那不归这条管**：移动端
靠 D413 的目标校验在前端拦掉；车载没有第二信号时，唯一保证"绝不静默出错"的办法是——

### 显式开关（已落成 D415，默认关）

"只要存在另一个包的竞争候选就弃权"能保证车载场景也绝不静默出错，但代价是 D407 已交付
的"双应用并发 MATCH（24ms/15ms）"全部退化成 ambiguous。已落成 `conservative` 开关
（D415），**默认关**——决策依据与代价曲线见下。

## D415 保守弃权开关 + 错峰采样误归因率（2026-10-13）

### 保守弃权开关：默认关

`TimeAttribution` 增加 `conservative` 参数；addon 读 `VSCAN_ATTRIB_CONSERVATIVE=1`
显式开启。开启后，容差窗口内**只要存在另一个包名的候选**就标 ambiguous（宁可错杀，
不可静默串包）。

**默认值的决策**：默认关。理由：

1. D407 的"双应用并发 MATCH"是已交付的验收能力，默认开会把它**静默退回** ambiguous
   ——等于悄悄回退一个已验收能力，正是本项目最忌讳的那类静默失败。
2. 保守语义适合"提交答辩/论文结论、要求零静默误报"的特定场景，应由使用者在该场景
   显式打开，而不是让所有审计默认牺牲确定性。
3. 报告的评估结论也是"做成显式开关 + 写进报告边界，而不是悄悄改默认值"。

**代价曲线**（`experiment_attribution_montecarlo.py` 的 `duo_concurrency_cost`，
D407 锚点 24ms/15ms，σ=20ms 抖动）：

- 默认：两条流间距 ≥750ms 即 `both_correct=1.0`（不串包、不弃权）。
- 保守：间距 750~1750ms 的 correct **全部**退化成 ambiguous；仅间距 ≥2250ms（对方事件
  落出自己 2000ms 窗口）才恢复 correct。

结论：车载审计若并发流间距常在 0.75~2 秒（D407 实测 24ms/15ms 说明两流可以很近），
保守模式会大面积弃权；间距稳定 >2 秒则可近乎无代价地开启。

### 错峰采样误归因率（P1 的离线部分）

`experiment_attribution_montecarlo.py` 把迟到分布做成**可配置参数**，用真实的
`TimeAttribution`（events 注入，resolve 逻辑不变）跑 Monte Carlo，回答"迟到分布下
误归因率是 X%"——把 28/33 的构造时序语义转成分布下的比率。

假设分布（A 迟到 N(-2,400)、B 迟到 N(65,150)、竞争者 50% 在场、宽限 3000ms）下：

| 模式 | wrong | ambiguous | correct |
|------|-------|-----------|---------|
| 默认 | 6.2%  | 44.3%     | 49.5%   |
| 保守 | 0%    | 50.5%     | 49.5%   |

即默认有 6.2% 的静默误归因；保守模式把它归零，代价是 ambiguous 升 6.2pp（correct 几乎
不变——"B 在场"场景默认本就几乎全是 ambiguous/wrong，只有极少数 correct 被转走）。

**关键边界**：这是**假设分布**下的基准，不是真机数字。真机迟到分布要靠
`verify_multi_app.py` 设备采集（下条待办），拿到后替换 `--mu-a/--sigma-a/--mu-b/...`
重跑即可得真机误归因率。

## 待办（需要设备或基础设施搬迁，未做）

- **P1 真机迟到分布采集**：离线采样器 `experiment_attribution_montecarlo.py` 已就位
  （分布参数可配），**缺的是真机实测迟到分布**。用 `verify_multi_app.py` 在设备上跑
  夹具多轮随机错峰，把实测"事件迟到"分布喂回采样器，得到真机误归因率，并校准
  MATCH_TOLERANCE_MS / AMBIGUITY_MS / 3000ms 宽限期三个常数。答辩要的是这个数字。
- **P2 确定性归属**：设备侧代理 + per-uid iptables REDIRECT + SO_ORIGINAL_DST
  （`mobile/traffic/transparent.py:84-100` 已留接口），唯一能给"确定性归属"的路线。
  车载可用双夹具独立监听端口（8888/8889）当验证基准，但不是产品能力。

## D416 普通第三方严格范围与回调健康（2026-11-02）

新版 vehicle capture 显式启用目标核对、保守归因与 VSCAN_STRICT_PACKAGE_SCOPE。
严格模式禁止单包兜底：一个包在白名单里不能证明设备中每条流都属于它。非白名单、缺 UID 或歧义
请求的正文不持久化，只留丢弃计数；既有移动默认策略保持兼容。严格模式不承诺确定性归属。
车载场景夹具也显式启用相同三项约束，防止新用户初始化的系统 CONNECT 被时间邻近误归给夹具。
health 模块包装采集回调和延迟 flush；异常保留结构化 failed 状态并重抛，done 不得洗掉先前失败。
本轮曾误删 response 的有效 request_tokens/request_scan 初始化，导致上游 200 而无流量落盘；
失败设备轮保留。补真实 request-response-flush 测试及元数据断言，修复后重跑设备验收。

## D417 reverse 模式目标锚定：用 pretty_host，不关 target_check（2026-11-02）

### 问题

车载场景夹具用 **reverse** 模式（`--mode reverse:http://127.0.0.1:<ephemeral>` +
`keep_host_header=true` + `adb reverse tcp:8888`）。mitmproxy 会把 `request.host`
改写成上游地址，客户端实际寻址的 host 只剩在 Host 头（`pretty_host`）里。
`flow_entry.target()` 原先取 `request.host`，于是：

- 夹具寻址 `10.0.2.2:8888`（离线重连场景），流的目标锚点是 `127.0.0.1`；
- egress 事件的目标是 `10.0.2.2`；
- `target_match` 失败 → unresolved → `VSCAN_STRICT_PACKAGE_SCOPE` 丢弃正文
  → `flows.jsonl` 0 字节；mitm.log 报「归因超时 … 已知事件 3 条」。

临时把 `VSCAN_ATTRIB_TARGET_CHECK` 关掉能跑通，但那是**用时间邻近掩盖目标失配**：
检查结束后系统连通性探测（`connectivitycheck.gstatic.com` 等）会被归给夹具，
与 D416「场景夹具也启用相同三项约束」直接冲突。不采用。

### 解法（两处，平台无关内核）

1. `flow_entry.target()` 优先取 `pretty_host`（Host 头，即客户端寻址目标），
   缺失时回退 `request.host`。
2. `addon._flush()` 的延迟重试同步改用 `entry["host"]`（pretty_host），
   不再用 `target_host`（reverse 下是上游地址）。

初版没有按实际代理模式区分；regular 自定义 Host 时也会错误使用 pretty_host，
并可能匹配另一个应用。该边界已在 D418 修复，不能沿用初版的“只会 unresolved”判断。

### 验证

`core/collector/test_unanswered.py` 新增 `FlowTargetTest`（pretty_host 优先 / 回退）；
`tools/vehicle_scenario_acceptance.py` 恢复 `VSCAN_ATTRIB_TARGET_CHECK=1` 并复跑
6 个场景。结果与证据路径记入 `vehicle/P0_P1_DELIVERY.md` 与 `vehicle/scenarios/CATALOG.md`。

## D418 按真实代理模式固定目标，延迟重试保持一致（2026-11-02）

从 client_conn.proxy_mode.type_name 判 reverse；不根据 Host 与 URL 是否相同推断。
regular 保留 request.host 与实际 peer IP；reverse 才用 pretty_host，并排除上游 peer IP。
每条记录保存 attribution_target，_flush 直接复用，避免第一次和延迟重试使用不同目标。
真实 mitmproxy Request 的自定义 Host 正反例、两模式回调及延迟落盘已加入离线回归。
