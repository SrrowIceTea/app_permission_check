# 车载通用隐私分析决策

## L001 定位实验的表示、进程和清单范围（2026-11-10）

仅用于授权测试。位置内容匹配保持实验输出，不新增规则、不输出违规、不改变默认 findings。
持久化 request text 与 wire 是不同证据实体：分别核验摘要，不能用原始网络字节摘要否决合法解压/脱敏文本。
legacy 转换文本无独立摘要时记录 legacy_text_requires_capture_input_binding；CLI 仍校验原 JSONL 摘要。
读取引用必须有有效 PID，去重和候选计数均带 PID；同 PID 的同引用冲突拒绝，不跨进程合并本地序号。
重放先验证清单结构、user_id、包/会话、版本和摘要表，再验证记录用户；相互一致的错误用户也拒绝。
合法 JSON 但结构错误是诊断性失败，保存 failure.json；分析前后继续核对清单和输入未变。
不承诺 PID 重用生命周期、真实 APK 检出率或完整采集健康。研究依据、反例和验证见
[四项修复](../../docs/LOCATION_REVIEW_FIXES_20261110.md)。

## L002 双人计划B侧封存交接验收（2026-11-11）

只在新输出目录复制摘要绑定的采集输入、APK/规则和归档bundle；不修改A的采集器或设备。
重放结构/用户校验与原pipeline/preflight共同约束输入，动作/回执另绑定session和manifest摘要。
正例需匹配候选及完整正文接收摘要；异值/单坐标负控必须有同身份/时间窗可比组合，
不能因跨UID、超窗或全空输入而通过。实验新增compatible_comparisons作为该层分母，候选规则不变。
来源重复保留歧义；设备控制组和第三方尝试分别验收。synthetic永远不升级设备通过。
动作、设备来源及capture_commit均为交接声明，不作独立专家金标准；人工检查表不自动签核。
缺A本轮输入时总验收保持incomplete；不复用历史签核、不启用VSC-GE-location。
接口、失败处理及已发现的TLS开关/就绪接口风险见[交接说明](../../docs/DUO_LOCATION_HANDOFF.md)。

## L004 通用外发求值的进程引用与单一就绪契约（2026-11-11）

L001 只修了定位实验；通用 `VSC-GE-*` 仍用裸 evt_id，合成反例（PID100/101 各发
evt_id=1）会被报告为 `source_ambiguous_flows=0` 且两对均唯一来源。现统一由
`vehicle/analyze/event_ref.py` 提供引用，pairs 带 read_pid/flow_pid/session，
命中的 reads 按完整引用选取；`observed_rows`/`event_refs` 也带 PID 与会话。

TLS 开关与预检就绪集合收敛到 `vehicle/pipeline/readiness.py`：关闭校验收宽是合法对照，
需要 `TLS_BYPASS_DISABLED` 加同会话 `TLS_SWITCH{false}` 的正向证据，但不得免除
egress/privacy/VHAL/样本就绪；专用样本 bundle 不含 TLS 脚本，该例外在契约里显式声明。
新采集把当前 bundle 身份、开关、健康与业务动作回执封进 `session-binding.json`，
不继承旧签核；设备新会话与真实回执仍需另行执行，本轮未做设备采集。

## L005 会话绑定不得采信自述（2026-11-11 review 后）

子代理红队证明：manifest 不写 `session_binding_sha256` 时原 digest 校验被跳过，
伪造一份 `session-binding.json` 即可在零采集、零回执下拿到 `passed` 并抬高业务触达计数。
现摘要必填且必须匹配 64 位 hex、所有 checks 不得因字段缺失短路、`verify_binding`
重读 `business-actions.jsonl` 与每个回执并逐字段比对自述；状态改名 `binding_consistent`，
恒带 `device_acceptance=pending`。`passed`（preflight）只表示证据满足审计前门禁，
不等于设备已验收。合成交接夹具补 `TLS_SWITCH` 以符合新就绪契约。

## L003 批次否决与落盘一致（2026-11-11）

重复session或交接计划变更导致批次否决后，逐案acceptance.json同步保存最终blocked状态。
第三方尝试未通过门禁时supported_matches为null，不发布失败行的候选总和；原始计数仍留诊断。
