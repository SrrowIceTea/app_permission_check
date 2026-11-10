# 车载端更新梳理与当前缺陷核对

日期：2026-11-10。仅用于授权测试。

范围：Git 提交历史、当前工作区、更新日志、冻结实验及设备验收 JSON。
HEAD 为 `372fd57`；大量新增方法代码尚未提交。同一开发目的的提交合并为一轮，合并提交和纯文档修订不重复计成功能。
10 月 12 日以前只有整体快照，不能据此还原每一次源码修改。
本次只写总结，不修业务代码、不运行新的设备场景、不替任何人签核。
核对期间其他工作仍在修改文件，以下结论对应本次读取与反例运行的快照。

## 1. 已提交的发展阶段

| 时间/提交 | 本轮做了什么 | 实际意义与边界 |
|---|---|---|
| 10-12，ce1859d | 建库保存完整系统快照 | 更早的采集、规则、报告能力已存在；该提交不能当作这些能力全部在当天新增 |
| 10-12，2de6a49、9428de7、db48229、2d73d53 | 抽取事件库、采集内核、证据定位、规则契约 | 车载/移动复用公共实现，按 VSC/MOB 区分规则 |
| 10-12，c27efec、efb7d79、17ec1d2 | 抽取 Frida 驱动、静态内核；phase1–7 改名 vehicle/* | 两条产品线分离，避免移动反向依赖车载 |
| 10-12～13，4a86373、d7ab425、dbd73c2 | 修 Windows 长路径、APK 分目录、Hook 路径守卫；恢复移动 PDF 入口 | 解决拆分造成的运行和交付回归 |
| 10-14～16，27a2869、a3c3a30、bda21c7 等 | 修取值/采集语义、覆盖守护、CA 信任及插桩问题 | 主要发生于 mobile；不能将其全部算作车载已接入能力 |
| 10-17～18，53fb22f、4dac4a7、c463c87 | 移动风险模型 v1→v1.3：必要性、衰减、单调性与标定 | 提供复核排序机制；并非车载评分已被验证 |
| 10-19～21，ba59b72、ae30b7f、93b0dba、4116d83 | 移动批处理/流水线、政策分册、TLS 元数据、证据链及 SARIF | 属于移动线与共享基础；原生 AAOS 支持须单独验收 |
| 10-24，787777c | 移动 ES 权重优化及真实静态样本链路 | 标签为规则预标注初稿，不是独立专家金标准 |
| 11-01，dd0b30f | 车载值级/派生值关联、UID/用户隔离、场景、政策与排序 | 从属性名线索推进到更明确的行为证据；仍不证明因果传播或违规成立 |
| 11-04，a201a71、03c525d | 公共解析/脱敏/policy/privacy 内核；车载通用隐私来源、覆盖链、基准、实验室验收 | 车载范围扩到通用隐私来源；各数据类型的读取与外发能力不同 |
| 11-05，c9971a3、a6709d8、a4a8b77、57de015 等 | HA/MG4/OwnTracks 等业务证据与身份归因；规则升级、CI 隔离回归 | 独立样本业务链与运行证据增加；专用样本路径不能当作通用检测能力 |
| 11-06，1c7372e、3728ad1、074e815 | 升级中断恢复、跨进程规则租约、撤权恢复、原生媒体后台同步 | 系统可靠性、收尾和业务场景增强；不等于增加跨进程 Hook 采集 |
| 11-08，0f0b811、f6e3f8e、b70384b、f315250 | 8773 车载前后端工作台、扩展复核轮次、回归接入 | 车载有独立操作入口；业务复核与正式配对计分分开 |
| 11-09～10，56ec8bb、e3336a6、244a25e | 规则扩为 Android 13/14/15/16 | 116 条、启用 96 条；13/16 外发规则登记未启用，四版本不等于四版本设备验证 |
| 11-10，69cfa13 | 采集盲区解析、WebSocket 帧与响应观测 | 丰富可见证据；响应内容不应被当成 App 请求外发证据 |
| 11-10，6f8ce43 | 移动 DEX 调用图、入口、wrapper、可达性四桶 | 主要是移动静态候选归因；unknown 不是不可达 |
| 11-10，f1bb1ed、39d4d13 | 工作台字段投影、复核入口、汇总与证据卡片、阶段耗时 | 完善证据阅读；不改变底层结论强度 |
| 11-10，5c75831、cf0f505、ad8c2b8、372fd57 | TLS 开关/固定证书夹具、流水线透传、解释器守卫与文档同步 | 让测试配置和失败可追溯；新增夹具不代表全部固定证书 App 已验证 |

## 2. 当前工作区新增轮次（尚未完整入 Git）

依据：`.workbuddy/memory/2026-11-10.md`、实际源码和 output 产物。日志是线索，以下状态经过代码或 JSON 核对。

| 轮次 | 新增/修改 | 当前能证明什么 |
|---|---|---|
| 方法层第一轮 | decidability、ambiguity、observation_conditions、source_candidates、coverage_layers、method_evidence | 有统一判定契约、候选集合和六层覆盖说明；首版曾有本次对话上一轮指出的 9 项缺陷 |
| 审查修复轮 | 候选完整性、marker_only 状态、policy availability、读取证据来源、静态接线、正确属性名基线、重放完整性 | 多数旧问题已经补上；不再使用 pairs−unique 作为过度声明减少量 |
| 评价治理轮 | label_gate、strata_report、人工审阅包 | 初评/subagent/人工来源分开，夹具与第三方指标不合并；当前冻结标签仍是 initial_review |
| 调度与优化轮 | gap_scheduler、triage_optimizer | 有预算计划、合成控制实验和 ES 入口；没有实测调度增益，也没有可发布的训练权重 |
| 新设备实验轮 | 多设备诊断修复、七场景设备验收 | AAOS 模拟器上 5/7 通过，后台/拒权两项超时；不是量产真车验收 |
| 批次联合对齐轮 | batch_alignment，随后接入候选集合 | 可找到窗口外批次形态，但重复批次仍不唯一；新合并实现还有跨属性污染，见下文 |
| 采集补洞轮 | registerCallback、PRIVACY_REGISTER、定位规范形态 | 源码和默认合并 bundle 都已包含；异步注册不算取得数据，定位外发求值器仍未接入 |
| 构建与展示轮 | freshness 门禁、bundle 摘要/源码闭包、PDF/前端隐私观测矩阵 | 可拒绝旧构建并展示 dirty 状态；构建依赖覆盖和真实行为验收仍有范围限制 |

## 3. 本次确认的事实

- 只读 SQL：规则 13/14/15/16 各 29 条，启用 19/29/29/19；权限原始级别 180/180，数值映射 0/180。
- freshness 检查：hook_vehicle_all、hook_vhal、hook_privacy 均为 warn_dirty，源码指纹匹配，没有 stale；构建时间为 15:00 左右。
- 默认 hook_vehicle_all bundle 中同时存在 CALLBACK_REGISTER 与 PRIVACY_REGISTER。
- 因此覆盖文档末尾“合并 bundle 尚未重建”和开发日志“registerCallback 未覆盖”均已过时。
- `output/vehicle-scenarios-20261110-143006/verification.json`：read-only、plain、different-value、derived、delayed 通过；background、permission-denied 超时，整体 passed=false。
- 重放 ablation.run()：方法与值匹配基线 P≈0.179、R=0.5；answerable_ratio=0.4、abstain_ratio=0.6、歧义率=0.6；不启用批次时唯一声明 4/4、delta=0。
- 批次部分：2 个 flow 对齐到窗口外；合并后 unique 从 4 到 0、10 个集合冲突。该变化受下述跨属性缺陷影响，不能全部解释为真实重复批次冲突。
- 标签仍为 agent_review / human_signoff=pending，不是独立人工参考；这些数字不代表真实第三方总体准确率。

## 4. 仍存在的实现缺陷（本次运行反例确认）

### D1：批次证据跨属性污染候选（优先修）

位置：`vehicle/analyze/source_candidates.py::_apply_batch`。
批次 read_event_ids 是整批所有属性，当前 cset 却是单 flow+rule 的单属性集合；二者直接求集合差。
反例：车速读取 1、挡位读取 2，批次为 [1,2]，两条规则原本各唯一。
合并后车速候选变成 [vhal:1,batch:2]，挡位变成 [vhal:2,batch:1]，两者都被降为 multiple_candidates。
应先按属性与完整事件引用投影批次记录；同时保留全部可行批次，不能只取第一种对齐。

### D2：方法摘要与 AI/评分能力状态不一致（优先修）

位置：`vehicle/pipeline/audit.py`、`vehicle/ai/evidence_capability.py`。
attach 只生成 summary，没有把修正后的候选能力接入后续 review(records,...) / rank_findings(records)。
冻结重放中 summary_unique=0，但 AI 能力仍把 VSC-E003、VSC-E004 标为 source_located=True。
应使用同一套最终证据能力契约；保留原 findings 不等于允许其他消费者继续使用旧能力状态。

### D3：AI 否定识别可掩盖后续肯定断言

位置：`vehicle/ai/evidence_capability.py::_negated`。
正确的否定句现在能通过，但“证据不足，但已传输具体车速。”在 value_match=False 时也通过。
“不是猜测，已传输具体车速。”同样通过。句首和六字符否定窗口不能代表整句语义。
应分句、逐处检查，并优先约束结构化声明；短语黑名单只能是辅助检查。

### D4：读取问题仍被无关流量拖成不可判

位置：`vehicle/analyze/observation_conditions.py::probe_conditions`。
成功读取本来 decidable，加入一条无关 attribution=unresolved 流后，Q_VALUE_OBTAINED 变为 not_applicable。
原因是共享 identity_ok 检查所有 flows。读取身份、对应请求身份和时序应按问题/事件分开检查。

### D5：覆盖差集仍有属性键与状态矛盾

位置：`vehicle/analyze/coverage_layers.py`。
同一属性的数值 ID 和名称会被计成两个属性；static findings 为空时，汇总 static_count=0，
by_property.static_reference 却因能力定义回退为 True。应规范属性键并分开 APK 引用与库内能力。

### D6：新标签门禁没有验证完整独立性契约

位置：`vehicle/bench/label_gate.py::_independent`。
两份 reviews 和 adjudication 全填同一个 reviewer，只要具名、时间带时区并声明签核，就被识别为 human_signed / usable_as_gold=True。
新门禁应复用既有 adjudicated_labels/签核来源与证据绑定检查，至少拒绝重复人员；程序仍不能替代对真实执行的核验。
当前没有真实训练成果，因此这是训练入口的潜在放行缺陷，不应表述为已经发生数据污染。

### D7：ES 目标名为 recall@K，但计算分母不同

位置：`vehicle/bench/triage_optimizer.py::recall_at_k`。
当前分母是 min(K,正例数)。10 个应复核项中仅前 2 项被选中，K=2，函数返回 1.0；标准 recall@2 应为 0.2。
可以保留“预算内归一化命中率”，但必须重命名，或修正为总正例分母，避免将来夸大效果。

## 5. 能力缺口与验收缺口（不等同于代码 bug）

- VHAL 主线 watch 仅 8 个属性；254 个设备常量只是候选面分母，不代表 254 个都是敏感且普通第三方可读，不能据 8/254 推算漏检率。
- registerCallback 已补；getPropertiesAsync、getIntArrayProperty 及若干元数据接口仍未覆盖。元数据查询不应冒充实际属性值读取。
- 默认合并入口没有接入全部 native SSL/JCE/Flutter 明文 Hook；现有代理可解密的 HTTP(S) 仍可做值匹配，不能笼统写成“所有加密流量只能属性名匹配”。
- resolve_pid 只选择一个主进程，没有完整监控 :remote 等子进程。规则数据库的跨进程租约测试不证明多进程 Hook 覆盖。
- 通用外发求值器仅消费 android_id、contacts；定位新代码补了 value_len/规范形态，但数值叶子、降精度、坐标转换、轨迹及通用 GE-location 仍未接线。
- 麦克风仅保留读取状态/字节计数，没有音频内容传播证据，这是当前明确的数据最小化边界。
- 第三方业务回执/专用样本验证存在，但新方法的第三方被动观测分层仍 not_measured，不能说“全项目从无第三方证据”，也不能说“通用方法已在第三方验证”。
- 本轮七场景整体失败。重建 bundle 解决了启动前置问题，也仍需要把后台/拒权重跑到验证完成。
- Android 13/16 无本轮动态验收；API 34 的通用来源验证不等于完整 VHAL 验证；没有量产 OEM 真车兼容结论。
- 权限级别数值映射仍缺，不能直接用 NULL 列推导保护等级。
- 调度仅有启发式/合成控制，不是经过真实设备对照验证的自动探索系统；ES 仍待可用独立标签与留出评估。

## 6. 验证与收口建议

本次首轮根回归：`output/regression-20261110-150214-ryuxspyp/verification.json`，18/19 通过。
失败为 privacy-runtime：新 locationEvidence 未注入旧测试 VM。
核对期间该测试被并行修正，随后单独执行 `node vehicle/hooks/test_privacy.mjs` 已通过。
最终整批复跑使用独立目录 `output/update-review-final-20261110/`，19/19 组通过；以该目录 verification.json 为准。
历史 14:54 的全绿不能证明后续所有改动都已回归；latest 指针会被并行任务更新，应引用固定目录。

建议顺序：先修 D1/D2 与证据状态统一，再修 D3～D7；随后补异步/子进程/实际协议采集、完成后台/拒权设备验收；
最后补原生 AAOS 第三方样本、独立标注、同预算调度对照与评分留出实验。
当前可主张的是证据范围、缺口解释与审计可追溯性的进展；检测率提升和跨应用泛化仍需证明。

## 7. 主要复核入口

- `vehicle/COMPATIBILITY.md`
- `docs/VEHICLE_RULE_COVERAGE_20261110.md`
- `docs/VEHICLE_PRIVACY_EGRESS_FEASIBILITY_20261110.md`（定位采集部分已被后续源码更新，需分层阅读）
- `vehicle/bench/ablation.py`、`ablation_integrity.py`
- `vehicle/analyze/method_evidence.py`、`batch_alignment.py`、`source_candidates.py`
- `vehicle/pipeline/audit.py`、`vehicle/ai/evidence_capability.py`
- `core/frida_host/freshness.py`、`device_target.py`
- `output/vehicle-scenarios-20261110-143006/verification.json`
