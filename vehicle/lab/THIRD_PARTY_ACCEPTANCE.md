# 第三方样本三条路径验收与人工签核登记

## O3 复核包

本轮复核包 `output/o5-o3-review-20261103-224003/review-packet.json` 收录七个授权业务案例和
一组 O2 自有夹具，逐项绑定证据摘要，人工签核均为待审。下文保留此前轮次的验收记录。

- HA 控制正例改用新注册后的 `output/o3-ha-post-rotation-20261103-223919/verification.json`。
  HTTP 控制、独立服务端状态和新 WebSocket 连接上的订阅均已复验。HTTP 503 保留为独立历史负例。
- MG4 自有表单改用 `output/vehicle-browser-o1-redaction-20261103-215419/business.json`。
  应用内请求与服务端正文对齐，代理逐流包名归因仍缺失。
- YAABSA 分列播放进度回执和 native 发送证据。O2 夹具的十条主读取与独立应用分开。

2026-11-03。仅用于授权测试（专用 AAOS 35 模拟器 + 隔离 Home Assistant / Audiobookshelf + 自有测试页）。
本轮不输出 `policy_violation`，只登记证据分级。三个样本均无独立标注，**precision / recall 保持不计算**。

## 判定口径

| 等级 | 含义 | 本轮是否达到 |
| --- | --- | --- |
| 控制闭环 | 控制请求 2xx + 同连接消息 ID 成功响应 + 订阅状态事件 + 独立服务端状态，四者齐全 | HA r4 达到 |
| 正文对齐 | 请求正文、样本身份、独立服务端记录三者对齐，并有暂停或失败对照 | YAABSA -006 达到（设备回环 tcpdump） |
| 仅服务端回执 | 服务端收到请求，但采集端无法把 flow 绑定到目标 App | MG4 -004 属此级，**不通过** |
| 仅握手 | 只有连接建立，没有成功响应或后续状态 | 一律不计 |

只有服务端回执、只有握手、错消息 ID、失败响应，均不得写成“采集成功”或安全结论。

## 1. Home Assistant Automotive minimal 2026.10.1

真机轮次 `output/ha-socket-20261103-r4`，session `capture-07ded7f46dd142728013b99de6aa9f15`，
包名 `io.homeassistant.companion.android.minimal`，测试实体 `input_boolean.audit_test_light`。

### 正例（四类证据齐全）

| 证据类 | 内容 | 原始位置 |
| --- | --- | --- |
| 控制请求 | `input_boolean.turn_on` / `input_boolean.turn_off`，`POST` 隔离 webhook，HTTP 200 | `capture/reads.jsonl`，`src=ha_transport`，evt 2 / 3 |
| 同连接响应 | `connection_id=1`、`message_id=242`、`subscribe_entities`，`success=true`，5 ms | `capture/reads.jsonl`，`src=ha_socket`，evt 2 / 3 |
| 订阅状态事件 | 同一 message ID 返回 `on` / `off` | 同上，evt 4 / 5 |
| 独立服务端状态 | HA REST 直读 `on` → `off`，`last_changed` 随两次操作推进 | `verification.json` 的 `steps[].server` |

控制请求到 HTTP 回执 45 ms / 21 ms；WS 请求到成功响应 5 ms。延迟单独记录，
不并入 30 秒归因窗口（`verification.json` 的 `latency`）。

### 负例（对同一轮真实事件做字段变异）

`verification.json` 的 `negative_controls` 九项全为 true：

| 变异 | 期望 |
| --- | --- |
| WS `message_id` 改为其他值 | 不配对 |
| WS `connection_id` 改为其他值 | 不配对 |
| WS `success=false` | 不配对（`server_rejected`） |
| 只有 `HA_WS_SEND`、无 `HA_WS_RESULT` | 不配对（`result_not_observed`） |
| 空证据 | 无 pair |
| 控制 `entity_id` 换成其他实体 | 不入控制证据（`outside_test_entity`） |
| 控制 `status=500` | 不入控制证据（`http_response_not_successful`） |
| 控制 `body_complete=false` | 不入控制证据（`body_not_complete`） |
| 控制 `operation=light.turn_on` | 不入控制证据（`outside_test_entity`） |

### 漏采 / 未覆盖

- HTTP webhook 没有消息 ID，控制侧只能用“事件 ID + 时间戳 + 测试实体”关联；
  与 WS 的 `message_id` 配对不是同一机制。
- `evt_id` 按 `src` 各自计数：控制 evt 2 与 WS 发送 evt 2 是两条不同事件，复核时必须带 `src`。
- r4 的负例是字段变异，设备端故障单独复验。
- 后续在隔离 HA 对测试实体注入 HTTP 503。审计与 PDF 均显示失败状态，成功控制数为零。服务端源文件已按摘要复原。证据见 `output/ha-control-503-repair-002/verification.json`。超时与错实体仍保留为离线对照。
- 只覆盖 attach 后的白名单进程；HA 引导期间进程退出、以及其他实体/其他服务调用不在采集面。
- 延迟只有两次控制、一次订阅响应，不足以做分位数或场景化窗口。

### 归因不确定

- 控制与状态是**两条独立链路**：HTTP 2xx 证明 App 发出控制，订阅事件证明 App 收到变化；
  两者时间接近不等于因果，需要独立服务端状态补第三点。
- 本轮 `states_linked_to_subscription=true` 依赖 `--reconnect` 断开的回环连接只属于该 PID。

## 2. MG4 WebBrowser 1.0.2

真机轮次 `output/vehicle-browser-20261103-004`，session `capture-f61662fd04fe46f9addc8e060e29e2fc`，
包名 `com.tommasov.mg4browser`。GET 导航与随机标记 POST 分开验收。

### 正例（仅服务端侧成立）

| 项 | 值 |
| --- | --- |
| GET 回执 | `/`、`/second`，HTTP 200 |
| POST 回执 | `/submit`，marker `3dac900d1f4d8188`，HTTP 200 |
| POST 正文摘要 | `ad290111e897a252bb0b721947d7c2d7297943300f57441d85b678a4d14fa467` |
| 代理层 | `mitm.log` 记录 `POST http://198.18.0.1:18124/submit` |
| 采集健康 | 7 项 capture checks 全真，`worker_exit=0`，观测 37.035 s |
| UI 证据 | `ui/01..10` XML/PNG/evidence，含 `06-post` |

### 负例（证明“只有回执不算通过”）

- 同一场景 `output/vehicle-browser-20261103-003` 只有 `post_flow_count=0`，无法区分
  “代理没看到”与“看到但丢弃”；因此本轮新增 `mitm.log` 与 `scope-discarded.json` 读取，
  结论改为“代理看到 POST、但未归因”。
- `post_marker_matched=true` 但 `post_flow_attributed=0`：按缺口语义判为
  `post_body_attribution_gap`，**不判通过**。
- 后续复跑 `output/vehicle-browser-repair-001` 仍为同一缺口。通过条件额外要求同次 POST 的目标、应用身份和完整正文摘要一致。
- 专用 `--webview-probe` 在 `output/vehicle-mg4-webview-003` 对齐了宿主 UID、WebView 主框架 POST、完整随机标记及服务端正文。常规代理逐流归因数量仍为零，结果以自有表单口径单列。

### 漏采 / 未覆盖

- `flows.jsonl` 无目标 App 的可归因 flow，WebView 网络进程到目标包的映射待逐连接核验。
- `scope-discarded.counts.outside_allowlist_or_unresolved=10`：GET 与 POST 都被丢弃。
- 只覆盖自有 HTTP 页面；HTTPS/证书固定、下载、跨域请求未验证。

### 归因不确定

- 服务端回执能证明“某请求到达自有页面”，不能证明由 `com.tommasov.mg4browser` 发出；
  本轮不能把该 POST 写成 MG4 的外发证据。
- GET 与 POST 的归因缺口相同，不能用 GET 未归因反推 POST 已归因。

## 3. YAABSA（Flutter）1.16.0

真机轮次 `output/vehicle-yaabsa-20261103-006`，包名 `de.vito0912.yaabsa`，uid 1010253，
装机 APK SHA-256 与样本一致（`3860d297...`）。证据来自设备 loopback 明文 HTTP，
**不是常规代理链路**。

### 正例（三向对齐 + 暂停对照）

| 项 | 值 |
| --- | --- |
| 实际路由 | `POST /api/session/4316585c-4193-47f7-a392-7f119f589844/sync` |
| 请求字段 | `currentTime`、`timeListened`、`duration`（5 次 sync，共 14 条 HTTP） |
| 服务端映射 | 请求 `timeListened` → 服务端 session `timeListening` |
| 服务端听音增量 | 12.117588，与请求 `timeListened` 总和 12.117588 一致 |
| 进度对齐 | 最新 sync `currentTime=16.478322`；服务端 progress `16.344`（夹具重置到 5 s 后起算） |
| 暂停对照 | 暂停后两次直读相隔 6 s，`currentTime` 保持 10.259 不变 |
| 样本身份 | `installed_matches_sample=true`，`libapp.so` SHA-256 已记录 |
| 实现定位 | Flutter AOT `lib/x86_64/libapp.so`；字符串含 `/api/session/`、`SyncSessionRequest`、`timeListening`、`just_audio` |

### 负例 / 对照

- 暂停后 `currentTime` 必须停止推进；本轮两次读值相同，`pause_stops_progress=true`。
- 字段缺失（`currentTime` / `timeListened` / `duration` 任一）→ `sync_fields_confirmed` 失败。
- 服务端增量或进度偏差超过容差（进度 2.0 s、累计 2.0 s）→ 对应 check 失败。
- 只拿到服务端听音记录、没有请求路由/字段/身份，不能达到 `playback_progress_aligned`。

### 漏采 / 未覆盖

- 常规代理链路仍无 Flutter 正文和可归因 flow；本轮证据是实验性的设备回环 tcpdump。
- 未覆盖 TLS、媒体流本身、其他 ABS 路由和后台长时同步。
- 会话累计值跨轮累积，已用 `PATCH /api/me/progress/:id` 重置到 5 s，
  并用“本轮增量”而不是历史累计做断言。

### 归因不确定

- tcpdump 是 loopback 聚合视图，绑定到 YAABSA 依赖“装机身份 + 时间窗 + ABS 服务端 session”，
  不是按 UID 的逐 flow 归因。
- 服务端 `mediaPlayer="Yaabsa just_audio"` 与 `clientVersion=1.16.0` 可交叉印证身份，
  但仍不能替代代理层 UID 归因。
- 后续修复将抓包原文限制在内存，保存的 `sync-requests.json` 仅包含路径内 session ID、设备时间及三项数值字段。验收要求该 ID 对应同一条服务端听音记录。
- 新轮次 `output/vehicle-yaabsa-repair-001` 验收通过。五次请求使用同一服务端 session ID，请求累计听音与服务端增量均为 12.056679 秒，暂停前后读值均为 12.484 秒。产物只保存脱敏字段和验收结果。
- `--socket-attribution` 增加实验性回环 TCP 端口与所有者采样。两轮播放业务通过。`-002` 四条请求的首个同 PID/socket inode 快照比发送晚 8–192 ms，逐流归因继续保留缺口。见 `output/vehicle-yaabsa-socket-001` 和 `-002`。
- `--send-attribution` 设备实测由 Cronet 调用 `sendto`。`output/vehicle-yaabsa-native-send-003` 四条请求均以正文摘要、端点和设备时钟对齐成功写入，含两条复用连接。独立发送端 HTTP 404 未被归给样本，失败返回的负例为离线变异重放。
- 常规 `capture --abs-send` 轮次 `output/vehicle-yaabsa-audit-send-001` 的两条样本请求进入封存证据，另一个发送端的请求被丢弃。普通 `audit` 重新关联写入证据，并在 PDF 展示计数。范围限定为固定 APK、AAOS 35 和隔离 ABS 的回环 HTTP。
- 历史三轮原文已脱敏，设备端旧原文已清理。隔离 ABS 轮换 JWT 签名密钥后，四个历史测试令牌均被拒绝。原始与脱敏摘要登记在 `output/p1p2-runtime/abs-credential-remediation.json`。

## 人工签核登记

状态统一为 `pending`。复核人逐条对照原始事件与独立回执后再填 `reviewer` / `reviewed_at`，
不得由 agent 代签。第三方样本没有独立标注前，`precision` / `recall` 保持 `null`。

| 路径 | 正例复核对象 | 独立回执 | 负例 / 漏采复核 | 状态 | reviewer | reviewed_at |
| --- | --- | --- | --- | --- | --- | --- |
| HA | `reads.jsonl` ha_transport evt 2/3；ha_socket evt 2/3/4/5 | `verification.json` `steps[].server`；`audit/summary.json` `ha_websocket` | `negative_controls` 九项；`control_gaps=[]`；延迟独立 | pending | | |
| MG4 | `business.json` POST marker；`mitm.log` POST 行 | 自有页面 `server_receipts` POST `/submit` | `scope-discarded.json` 10 条未归因；`post_flow_attributed=0` | pending | | |
| YAABSA | `playback-acceptance.json` `observed_routes` / `sync_fields` | 同文件 `server_session` / `server_progress_*` | `pause_stops_progress`；字段与增量容差；tcpdump 口径 | pending | | |

证据摘要（复核时重新计算并比对）：

| 文件 | SHA-256 |
| --- | --- |
| `output/ha-socket-20261103-r4/verification.json` | `bfb66e9a89062c9c712b9635ac32d4646f1eff50785459de71c464dd01230b02` |
| `output/ha-socket-20261103-r4/audit/summary.json` | `58e49369dc6535b71007ec29c1333708d59765d6b998db96ee96dabefcac79bb` |
| `output/ha-socket-20261103-r4/audit/vehicle-audit.pdf` | `ee1013923c759d947c98548fa81a575c04760218e931dbd0604ec2dd44e9ae9c` |
| `output/vehicle-yaabsa-20261103-006/playback-acceptance.json` | `38a3356ca5db7e8a625cbb2af4efce02bee03bf137bb4b7786da0c604f89e2c5` |
| `output/vehicle-yaabsa-20261103-006/loopback-http.txt`（脱敏后） | `5e3ebca9453b0613d2c85f62642294bf89afaed35e7be1a1caf69d21d0a35255` |
| `output/vehicle-browser-20261103-004/business.json` | `0cb5ffcfa061902c4bcd857a30946fe75ad9c63033c16f014cb772b099ef52c0` |
| `output/vehicle-browser-20261103-004/capture/scope-discarded.json` | `a8c59c2d87496241e4f48cd2a71b315654dbfdf809cd9855bcb0e208b6d59785` |
| `output/vehicle-browser-20261103-004/capture/verification.json` | `59b8cef227360202e9832cd54797ce74cff0a698debe1a176052d81e0c971d96` |

## 复核执行顺序

1. 先核对 APK SHA-256 与 session ID，再看事件；不得用结论反推原始事件。
2. HA：确认控制事件带 `src=ha_transport`、WS 事件带 `src=ha_socket`，再比对 message ID 与 `steps[].server`。
3. MG4：确认 POST marker 与 `body_sha256` 一致，再确认 `post_flow_attributed` 仍为 0。
4. YAABSA：确认 tcpdump 时间窗、`fixture_reset` 与两次暂停读值，再对比服务端增量。
5. 三条路径的 `precision` / `recall` 不因本轮通过而计算；需要独立标注后才进入指标。
