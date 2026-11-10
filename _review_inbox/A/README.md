# O3 首轮独立标注

只用本包内的材料判断。先读 evidence.md，再填写 review.json，保留每个问题编号。
请独立作答，提交前不要与另一位审阅者交换判断，也不要打开旧的审计报告或初评记录。

- present 表示本题命题得到证据支持。
- absent 表示证据足以否定本题命题。
- insufficient 表示证据不足或有歧义。说明缺什么，保留为待补证。

每题填写 decision 和 reason。reason 可引用证据中的来源与事件编号。
reviewer 填实际复核者，reviewer_kind 按本轮填写 human 或 subagent；ai 仅供旧初评。
subagent 另填实际 agent_id、context_mode=fresh 和独立 UUID review_session_id；不得冒充真人。
reviewed_at 填带时区的 ISO 8601 时间。同模型可能有共同错误，独立上下文不保证结论正确。
两位审阅者分别把填写完的 review.json 交回组织者。

电量题逐对判断同一次读取与请求是否能对齐。可核对 level、scale、实际请求字段、
请求时序、进程身份和独立服务端状态。同一个 evt_id 在不同来源下可能重复。
ts 和 request_started_ts 属设备时钟，host_received_ts 和外部动作记录属宿主时钟。
跨时钟请分别核对，外部动作的记录点本身不能证明设备读取的先后。业务复核题按题意作答。
浏览器题分开核对代理是否看见 POST、服务端标记是否匹配、以及是否有能归属到目标应用的流。
代理观察和归属后的落盘计数是不同的证据。
