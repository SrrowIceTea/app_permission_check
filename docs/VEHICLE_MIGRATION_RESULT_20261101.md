# 车载迁移与验证结果

日期：2026-11-01，Asia/Shanghai。仅用于授权测试（自有 AAOS 与自有 APK）。
本次完成第一批核心迁移和车载适配，不宣称覆盖所有车型或证明软件绝无缺陷。

## 功能迁移清单

| 移动端能力 | 车载处理 | 当前状态 |
| --- | --- | --- |
| APK 清单/DEX 静态分析 | 共用 core/static，装机 APK 哈希核对，加载 VSC 规则 | 已验证 |
| 抓包、事件存储、运行时代码定位 | 共用 core/collector、event_store、evidence | 已验证 |
| 原值及派生值关联 | 按车辆属性绑定 JSON 值，避免短数字全文误匹配 | 已验证 |
| 模型调用、调用日志、密钥脱敏 | 通用客户端移到 core/ai，mobile 保留原兼容入口 | 已验证 |
| AI 研判 | 车载独立证据封装与门控，复用用户配置的 DeepSeek 服务 | 真实调用通过 |
| 场景/风险与报告框架 | 新增场景、观察频率、实验性复核排序与 PDF 附录 | 已验证 |
| 一键审计编排 | vehicle/pipeline/audit.py 串联现有采集产物、静态核对、关联、AI、报告 | 已验证 CLI；尚未接入现有前端 |
| 隐私政策解析、业务必要性分类 | 可复用 mobile 框架，需增加车载数据/用途与政策规则 | 尚未完成车载接入 |
| 手机专用规则与 UI 探索 | 需按 AAOS 权限、厂商接口、驾驶状态和多用户重新设计 | 仅完成本次列出的场景 |

## 最终验收

所有设备采集串行运行，失败轮次保留。最后通过的结果如下：

| 验收 | 结果 | 本机证据 |
| --- | --- | --- |
| 完整回归，含移动端 28 项检查 | 15 组全部通过（当时口径；现行为 18 组根回归、带 `--mobile` 19 组） | output/regression-20261101-224022/verification.json |
| 移动分支兼容及前端契约 | 24 组全部通过 | output/mobile-branch-20261101-222807/verification.json |
| 车载订阅、HTTP/HTTPS、OkHttp、收尾 | 8 项通过 | output/device-20261101-222703/verification.json |
| 7 类车载场景 | 全部通过；原 PID 存活 | output/vehicle-scenarios-20261101-224007/verification.json |
| 实际用户切换隔离与临时用户清理 | 8 项通过 | output/vehicle-users-20261101-223751/verification.json |
| AI 研判 | 10 条，引用/字段/人工复核门控通过 | output/vehicle-delivery-analysis/ai/review.json |
| 静态与动态版本一致性 | 装机 SHA-256 相同；22 静态候选、10 运行时发现 | output/vehicle-delivery-analysis/summary.json |
| PDF | 10 页，渲染检查无空白页、无裁切 | output/pdf/vehicle-audit-20261101.pdf |

7 类场景为只读不发、正常上传、同名不同值、SHA-256 摘要上传、延迟上传、后台、拒绝权限。
权限拒绝场景同时断言读取为 denied、无车速外发结论，其他可读属性提供正控。
同名不同值的报文确实到达接收端，但不建立值级关联。
用户隔离测试去除身份后的对照会建立关联，保留真实 UID/userId 后拒绝跨用户配对。

AI 最初把低风险项的 needs_human_review 改成 false，被门控拒收；补固定值语义及最多一次
格式纠正后，真实请求通过。发送的是用户明确批准的脱敏证据，不含原值、载荷、UID 或密钥。
最新设备会话的脱敏证据与已批准请求逐字段相同，复用真实模型响应；summary 中保留此来源，
没有冒充对新原始会话再次联网调用。原始调用和首轮拒收记录均保留。

## 修复的实际故障

1. AAOS 冷启动 Wi-Fi 未连接，导致 ENETUNREACH：增加实际连接/DHCP 就绪判定。
2. pending 延迟重试漏写 UID：统一刷新完整归因字段，同包不同用户纳入歧义判定。
3. 多 Java bridge 正常 detach 后 DeleteGlobalRef abort：合并单 agent、停止哨兵，验原 PID 存活。
4. Frida 将 Java SecurityException 包装为 JS Error：保留实际权限拒绝类型。
5. AAOS 前台字段与手机不同：兼容实际 topResumedActivity 等字段，核验场景建立。
6. 用户切换清理的瞬态失败：有界重试切回原用户，实际验证临时用户消失。
7. SARIF 校验缺 jsonschema、Windows 8.3 TEMP 夹具路径混用、既有 NO_STACK 白名单漂移：
   补依赖、规范测试临时目录并记录真实平台差异；完整移动兼容回归通过。
8. PDF 尾部 Spacer 与新附录 PageBreak 共同生成空白页：去除无证据的尾间距并重新渲染。

## 范围与下一阶段

- 当前设备是 AAOS 35 模拟器、userdebug，自有 debug APK；不等于真车或所有 OEM。
- 当前完成用户切换隔离；未验证并发多用户显示、前用户私人缓存残留或真实同意 UI。
- 驾驶状态模拟、位置轨迹链、座舱音视频、厂商私有接口和 ICC 完整污点分析仍未完成。
- JSON 属性绑定匹配不覆盖所有二进制/自定义加密协议；相等内容不证明因果传播或违规成立。
- 复核排序的权重尚未用独立专家样本校准，不输出风险概率或未经验证的准确率。
- 车载政策解析与业务必要性模块、现有前端接入，是下一批最值得迁移的功能。

研究原文和方法对应见 [研究依据](VEHICLE_RESEARCH_PLAN.md)，复现见 [车载 README](../vehicle/README.md)。
output/ 与模型本机配置不入 Git。提交与发布状态以 Git 记录为准。
