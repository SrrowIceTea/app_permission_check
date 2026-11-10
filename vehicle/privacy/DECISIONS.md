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
