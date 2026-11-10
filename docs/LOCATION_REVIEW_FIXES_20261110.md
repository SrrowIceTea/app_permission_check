# 定位实验四项 Review 修复：论文依据与验收

日期：2026-11-10。修复对象为 135cfce；[原审查记录](LOCATION_WEEK1_REVIEW_20261110.md)保留历史发现。
仅用于授权测试（自有设备与自有 APK）。以下是代码缺陷修复，不新增定位外发规则，不把实验匹配升级成违规。

## 1. 研究依据及采用范围

| 原始论文 | 对本次修复的启示（工程推导） | 本项目落实 |
|---|---|---|
| Pourali 等，**Hidden in Plain Sight: Exploring Encrypted Channels in Android apps**，CCS 2022，[作者原文](https://users.encs.concordia.ca/~mmannan/publications/ThirdEye-CCS2022.pdf)，DOI 10.1145/3548606.3560665 | 论文区分多层加密/压缩处理及其观测数据；第 5 页讨论嵌套明文压缩时考察解压值。转换后的可见内容应保留与原表示的关系 | wire 与持久化 text 各自摘要，不能跨表示比较；gzip、脱敏及组合转换均用真实 collector 测试 |
| Gehani、Tariq，**SPADE: Support for Provenance Auditing in Distributed Environments**，Middleware 2012，[作者原文](https://www.csl.sri.com/users/gehani/papers/MW-2012.SPADE.pdf) | 论文以来源图组织实体、过程及关系；事件标识须带所属来源上下文。具体 PID 键方案是本仓库工程选择 | 读取的本地 evt_id 与 PID 一起定位，输出和候选计数一致使用进程上下文 |
| Ratazzi 等，**A Systematic Security Evaluation of Android’s Multi-User Framework**，MoST 2014，[作者原文](https://seedsecuritylabs.org/wenliangdu/Research/paper/multi_user_most2014.pdf) | 多用户与 App 隔离是不同维度，不能用两个记录“彼此一致”代替属于指定用户 | 清单 user_id 是重放约束，显式用户及 UID 推导用户均须与之相符 |
| Sassaman 等，**Security Applications of Formal Language Theory**，Dartmouth 技术报告 TR2011-709，2011，[机构原文入口](https://digitalcommons.dartmouth.edu/cs_tr/335/) | 形式语言视角强调输入识别与验证；JSON 可解析不等于业务结构有效 | 先验证清单对象、包/会话、用户、版本及摘要表，再执行匹配；结构错误成为可落盘的 ValueError |

论文提供方法依据，不直接证明本项目修复正确。通过与 collector/驱动真实契约一致的反例和测试验证具体实现；没有复制论文成绩作为项目准确率。

## 2. 四项修复

### F1：wire/text 摘要分离

core/collector/payloads.py 继续将 raw_sha256/raw_bytes 定义为原始传输字节，新增 text_sha256/text_bytes，描述**脱敏后实际持久化的文本**。
location_payload.py 从 location_match.py 拆出：完整未转换正文仍校验 wire/text 等价；转换文本只校验独立文本摘要，不再误用压缩前后的不同字节数。
legacy decoded_text_only/redacted 没有文本摘要时不改写旧文件，候选记录 legacy_text_requires_capture_input_binding；CLI 的 JSONL 摘要绑定和分析后复核仍强制执行。
这不是把旧文本摘要“补成已验证”：直接调用纯函数不证明文件来源，完整证据约束仍在重放入口。输出保留表示、retention、文本摘要和校验依据。
已脱敏掉的坐标不会恢复或匹配；其他字段脱敏而完整坐标仍存在时可以给内容候选。截断、解码失败、错误摘要及未知保留状态继续拒绝。

### F2：完整进程引用

location_match.py 去重使用 (src,pid,evt_id)，读取必须具备有效 PID；缺失时给诊断，不猜进程身份。
配对输出 read_pid/flow_pid；pair_ambiguity.py 的可选 PID 进入流分组及读取候选标识。旧调用方缺 PID 时保留原分组行为。
两个 PID 各自 evt_id=1 时，保留两条候选、1 个歧义流、source_read_unique=false；同 PID 重复记录只计一次，同 PID 同引用冲突仍拒绝。
PID 复用/进程生命周期编号不在此次数据契约内，不能仅凭 PID 宣称跨重启来源唯一。

### F3：绑定清单用户

location_inputs.py 在 CLI 边界验证 user_id 为非负整数，随后逐条核对目标包/会话记录的显式用户及 UID 推导用户。
清单 user 10、读写双方 user 11 即使彼此一致、文件摘要正确，也返回诊断性失败；不产出成功实验结果。
有效报告保留清单 user_id 和 identity_binding。其他来源的记录不会被当作目标会话证据。

### F4：先验证结构再处理

拒绝非对象清单、重复 JSON 字段、错误 packages/session、用户/版本和摘要表类型、缺失输入摘要，以及非对象 JSONL 记录。
结构错误主动抛出 ValueError，由原失败路径写 failure.json，返回失败；不通过捕获所有异常来掩盖程序缺陷。
分析前/后继续比较输入及清单字节摘要；测试分别在分析过程中追加 manifest、reads、flows，三种都失败且不发布 result.json。

## 3. 测试与复核

新增 vehicle/privacy/test_location_review_fixes.py 覆盖四项问题，已登记 tools/run_regressions.py，避免成为未被执行的测试。
本轮定向测试 76 个全部通过，包括旧定位/通用求值、真实 collector、方法层及新增修复反例。

```powershell
.\tools\python313.ps1 -m unittest vehicle.privacy.test_location_review_fixes vehicle.privacy.test_location_match vehicle.privacy.test_evaluation core.collector.test_redaction vehicle.analyze.test_method_evidence
.\tools\python313.ps1 tools/run_regressions.py --out output/location-fixes-new-regression
```

| 场景 | 修复后预期及实测 |
|---|---|
| 普通、gzip、脱敏、gzip+脱敏的同一坐标对 | 均 1 对；wire/text 各自校验，不出现伪摘要损坏 |
| 文本摘要/字节数被改、原文摘要被改、截断/未知 retention | 均拒绝，不因修复放宽完整性边界 |
| legacy 转换文本 | 可匹配且明确限制；修改捕获文件导致摘要不符时拒绝 |
| 不同 PID 同号读取 | 2 候选、1 歧义流，非唯一来源 |
| 不同 PID 同号流量 | 独立分组，候选数不串流 |
| 同 PID 重复/冲突、读取缺 PID | 去重/拒绝，均不制造进程唯一性 |
| 清单用户与记录用户不一致 | failure.json，拒绝成功结果 |
| 非对象/错误字段清单、非对象 JSONL、重复键 | failure.json，拒绝成功结果 |
| 分析过程中输入变化 | failure.json，原清单/文件摘要绑定保持 |

原两位 subagent 已只读复核：匹配侧验证真实 mitmproxy Request→capture() 的四种表示、多 PID 候选及 legacy 限制；CLI 侧验证用户/结构门禁和运行中篡改拒绝。均未发现本次范围的新确认问题。
根回归 19 组和移动分支 24 组通过，后者包含上游移动 63 项。移动检查使用当前进程的 UTF-8 javac 参数及 ASCII 临时目录，规避已记录的宿主编码/中文路径问题，未改移动业务代码。
最终日志与实验结果在 output/location-review-fixes-20261110/；旧失败轮和旧审查报告不覆盖。

## 4. 适用范围

默认规则库、Hook 业务行为、前端和规则启用不变；没有登记 VSC-GE-location，也不输出 policy_violation。
本机仍无连接的 AAOS 设备，历史 OwnTracks 会话缺少通用定位读取摘要。修复后的真实 APK 正例能力仍未验证，不能由离线通过推导总体检出率。
此次承诺是四项可复现代码问题及其回归已关闭；后续完整定位外发规则、窗口标定、实机和广泛协议覆盖仍按原边界另行验收。
