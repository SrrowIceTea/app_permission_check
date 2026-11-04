# HA WebSocket 订阅与控制链路验收

2026-11-03。仅用于授权测试（专用 AAOS 35 模拟器 + 隔离 Home Assistant）。本轮只观测白名单进程
`io.homeassistant.companion.android.minimal`，测试实体固定为 `input_boolean.audit_test_light`。

## 结论

- **控制侧**：车机点击开关实际发出 `POST /api/webhook/<id>`，正文为
  `{"type":"call_service","data":{"domain":"input_boolean","service":"turn_on|turn_off",
  "service_data":{"entity_id":"input_boolean.audit_test_light"}}}`。Hook 只保留
  `payload_type / operation / entity_id`，不保留 webhook 令牌、其余 `service_data` 或其他实体。
- **订阅侧**：重连后 App 发出 `subscribe_entities`（`id=242`），同一连接 `connection_id=1`
  收到 `success=true` 响应；两次开关变化都沿该消息 ID 返回状态事件。
- **独立核对**：每次操作后用 HA REST 直接读取实体状态，两次分别得到 `on` / `off`，与
  WebSocket 状态事件一致。
- **判定口径**：只有控制请求 2xx + 同连接消息 ID 成功响应 + 订阅状态事件 + 独立服务端状态
  四者齐全才计为通过；只有握手、只有服务端回执、错 ID、失败响应均不计。

## 本轮真机结果

轮次：`output/ha-socket-20261103-r4`，session `capture-07ded7f46dd142728013b99de6aa9f15`。

| 项 | 值 |
| --- | --- |
| 控制请求 | `input_boolean.turn_on` / `input_boolean.turn_off`，HTTP 200 |
| 控制事件 ID | 2 / 3 |
| WebSocket 连接 | `connection_id=1`，`message_id=242`，命令 `subscribe_entities` |
| 发送/响应事件 ID | 2 / 3（订阅请求与结果） |
| 状态事件 ID | 4 (`on`) / 5 (`off`) |
| 独立服务端状态 | `on` → `off`，`last_changed` 与步进时间对应 |
| 采集健康 | 7 项 capture checks 全真，`worker_exit=0`，重连 App socket 2 个 |

延迟单独记录，不并入 30 秒归因窗口：

| 指标 | 观测值 |
| --- | --- |
| 控制请求→HTTP 回执 | 45 ms / 21 ms |
| WS 请求→成功响应 | 5 ms |
| 归因窗口 | 30000 ms（保持不变） |

## 负例

设备端暂未注入失败的控制响应，以下负例是对同一轮真实事件做字段变异后的离线判定，
用于证明“错误证据不会被判成成功”：

| 变异 | 结果 |
| --- | --- |
| WS `message_id` 改为另一个值 | 不配对，`result_not_observed` |
| WS `connection_id` 改为另一个值 | 不配对，`result_not_observed` |
| WS 响应 `success=false` | 不配对，`server_rejected` |
| 只有 `HA_WS_SEND`、没有 `HA_WS_RESULT` | 不配对，`result_not_observed` |
| 重复消息 ID | 不配对，`duplicate_message_identity` |
| 控制 `entity_id` 换成其他实体 | 不入控制证据，`outside_test_entity` |
| 控制 `status=500` | 不入控制证据，`http_response_not_successful` |
| 控制 `body_complete=false` | 不入控制证据，`body_not_complete` |
| 控制 `operation=light.turn_on` | 不入控制证据，`outside_test_entity` |

变异结果由 `output/ha-socket-20261103-r4/verification.json` 的
`negative_controls` 逐项记录，全部为 true。

## 接入常规审计入口

- 采集开关：`python -m vehicle.pipeline.capture --ha-websocket ...`，bundle
  为 `vehicle/hooks/dist/hook_vehicle_ha_socket.bundle.js`，预检要求
  `ha_socket` 与 `ha_transport` 两个 ARMED。
- 审计汇总：`summary['ha_websocket']` 内含 `pairs / state_events / gaps / controls /
  control_gaps`，规则 ID 为 `VSC-LAB-HA-WS-RESULT-001`、`VSC-LAB-HA-WS-STATE-001`、
  `VSC-LAB-HA-CONTROL-001`。
- 报告：PDF 中同时输出 WebSocket 配对数量和 HTTP 控制条数；本轮 PDF 已确认包含两段文字。
- 回归：新增 `vehicle/privacy/test_ha_socket_evidence.py`，覆盖上述正/负例，已并入
  `tools/run_regressions.py` 的 `vehicle-pipeline` 组。
- 证据文件：
  - `output/ha-socket-20261103-r4/capture/reads.jsonl`（sha256 `4a3a441d2dfdfdd7...`）
  - `output/ha-socket-20261103-r4/audit/summary.json`
  - `output/ha-socket-20261103-r4/audit/vehicle-audit.pdf`
  - `output/ha-socket-20261103-r4/verification.json`（sha256 `bfb66e9a89062c9c...`）

## 仍未覆盖

- HTTP webhook 没有消息 ID 字段，控制侧的相关键是“事件 ID + 时间戳 + 测试实体”；
  只有 WebSocket 侧使用同连接 `message_id` 配对。
- 设备端未注入 5xx、超时、错实体的真实失败控制；负例目前是字段变异，不是端到端注入。
- 延迟样本只有两次控制、一次订阅响应，尚不足以做分位数或按场景调整窗口。
- 未验证其他实体、其他服务调用或非 `call_service` webhook；按约束这些不进入采集面。
