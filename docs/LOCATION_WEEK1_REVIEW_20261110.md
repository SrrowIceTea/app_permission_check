# 定位实验提交 135cfce 独立 Review

2026-11-10。按用户要求由两个只读 subagent 分别审查匹配/数据契约和重放 CLI，主 agent 复现核对；本轮不修改该提交代码。
两个 subagent 均复现了压缩正文问题；其他发现合并去重后如下。已有 13 个新增测试仍通过，说明其未覆盖这些真实数据/边界路径。

## 必须优先修复

1. **[P1] 原始网络字节和解压/脱敏正文摘要混用。** `vehicle/privacy/location_match.py:91–94` 将 `text.encode('utf-8')` 与 raw_sha256/raw_bytes 比较；但 collector 的 raw 是传输原文，text 可能已解压或脱敏。用真实 `core.collector.payloads.capture()` 产物复现：普通 JSON 1 对；同坐标 gzip JSON 为 0 对且误报 digest_or_length_mismatch；带被脱敏 token/password 的完整 JSON 同样 0 对。应分别核验 wire 和持久化文本的完整性，覆盖 decoded_text_only/redacted；不能简单删除所有完整性校验。
2. **[P1] 多进程事件引用缺少 PID。** `vehicle/privacy/location_match.py:122` 只按 (src,evt_id) 去重，而每个进程的 makeLogger 有独立 evtSeq，多进程共用输入流。`read(pid=100)`、`read(pid=101)` 同 evt_id 时得到 0 对、conflicting_event_reference=2。需要让去重、输出引用和候选计数同时识别进程，否则仅改去重后仍会在 annotate_candidates 中把两来源算唯一。

## 其他确认问题

3. **[P2] 重放未绑定清单 user_id。** `vehicle/privacy/location_experiment.py:27–29` 只绑定 packages/session。清单 user 10，读取及流量均为 user 11、摘要一致时，仍产出 uid_verified 候选和 supported_content_observed。彼此一致不代表属于清单目标用户；需显式绑定、检查并输出 manifest 用户。
4. **[P2] 错误清单结构未进入失败落盘。** 清单为合法 JSON `[]` 时，`location_experiment.py:27` 调用 .get 产生 AttributeError，当前捕获列表（:100）不含此异常；CLI 已建输出目录但不写 failure.json。input_sha256 非对象也有同类情况。应在入口验证结构，产生声明过的诊断性失败。

## 审查边界

未发现此次实验会修改默认规则、前端或原始会话；它仍明确标为 experimental_only，不输出规则 findings。以上问题意味着“现有测试通过”不足以验收真实定位链，不能因此宣称可合并为默认检测能力。
审查未做设备采集，也未修改代码。建议后续按四项分别修复并补真实 collector 产物、多进程引用、清单用户冲突和畸形清单回归。
