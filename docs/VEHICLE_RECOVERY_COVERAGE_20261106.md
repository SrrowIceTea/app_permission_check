# 规则库恢复与 OwnTracks 权限场景交付

2026-11-05 开始，11-06 完成实测。仅用于授权测试，限自有 AAOS 模拟器、规则库夹具及获授权固定 APK。
本轮文件变更保留在工作区，未提交或推送，未触发新的 Jenkins 构建。

## 规则库升级中断恢复

安装器写入、刷盘并校验新库，保留完整旧库及元数据，持久化切换意图后执行同目录 rename。
启动时按实际内容完成提交或恢复；无可信副本时停止，不能由 Room 创建空库掩盖安装失败。
同一租约覆盖安装、读取和关闭，包含协程互斥及协作进程文件锁。
锁获取失败也返回结构化错误，不在未上锁时读取当前文件或重复调用业务代码。
机制和复跑方法见 [RECOVERY.md](../vehicle/rules/RECOVERY.md)。

[最终设备验收](../output/rules-recovery-20261105-231119/device-final/verification.json)严格核对 raw instrumentation
的预期方法集合，26 项全部通过，覆盖写入错误、首装意图恢复、有效头损坏、corruption callback、
锁失败、并发安装、读取互斥以及既有升级/schema/来源测试。

| 实际中断 | 已验收阶段 |
| --- | --- |
| 杀掉夹具进程，另起新进程恢复 | 暂存写入、暂存完成、备份完成、意图落盘、库已切换、元数据已提交 |
| 模拟器整机重启 | 意图落盘后、库已切换后 |

逐轮记录故障与恢复 PID、boot ID、生效摘要、四表内容、schema、实际数据库副本。
8 个阶段均通过。原用户数据库逐字节不变，原 APK 恢复，临时测试用户移除。
进程内并发和读租约已经测试；跨进程竞争压力、物理断电和磁盘硬件失效不在本轮实测范围。

device-001 的主机轮询错误保留，device-002 是早期 22 用例轮次；最终以 device-final 为准。
corruption-repro 的有效头损坏反例在添加自定义 handler 前也通过；因此没有宣称在本机复现默认删除。

## OwnTracks 撤权与恢复

仍为固定 SHA-256 `b12ca46508b8f33e6ddc03433be5600f7fec6b2c30adb8056368aa2e17129d0f` 的普通第三方安装。
自有 HTTP 接收端、合成位置、user 10，每段使用独立采集 session。

| 阶段 | 验收口径 |
| --- | --- |
| 授权 | coarse/fine/background 实授，新位置读取、归属请求、独立回执同值 |
| 撤权 | 三项均撤销，约 15 秒内未取得或发送本轮新测试值 |
| 恢复 | 恢复授权，另一个新位置形成读取、请求与独立回执 |

[006](../output/rules-recovery-20261105-231119/owntracks-permissions-006/verification.json)与
[007](../output/rules-recovery-20261105-231119/owntracks-permissions-007/verification.json)连续三段健康通过。
两轮均恢复原权限及标记，各会话恢复代理和本轮转发；每段的卸载、detach、回调释放、事件库和 manager 关闭均正常。
仍只计 workflow_only：撤权观察不是“所有外发停止”，未收到回调也不等于观测到 API 拒绝异常。

001/003/004 的驱动收尾失败、005 的重复坐标超时保留。
重复坐标与样本 minUpdateDistance=1m 相遇会正确抑制更新，现先注入独立预热点，再注入本轮测量点，
设备位置时间仍须晚于注入时间，不能用旧缓存填正控。

## 主机采集收尾

补齐显式脚本卸载和 Frida manager 关闭，部分初始化失败也进入资源释放。
每步输出 FRIDA_CLEANUP；超时或错误保持不健康。采集子进程有有界 terminate/kill 兜底，日志始终关闭。
父进程留出 flush/ack 和有界释放步骤的时间，未放宽退出码、强制退出或健康判据。
参考 [Frida 官方工具的资源收尾](https://github.com/frida/frida-tools/blob/main/frida_tools/application.py)。
连续六个最终采集会话未再出现旧故障，不等于解决 Frida 所有平台的所有原生崩溃。

## 回归和签核

[最终回归](../output/rules-recovery-20261105-231119/regressions-final/verification.json)：prepare + 17 组全部通过；
vehicle-pipeline 190 项用例、其中新增的异常路径反例通过；移动侧 29 项通过。
（当时口径；现行为 18 组根回归、带 `--mobile` 19 组、移动侧 31 项。）
所有新增/修改源文件均控制在 300 行内。

签核采用用户指定的 subagent 流程。初轮发现的问题及答卷保留，不把 changes_requested 改成成功。
修订后的 A/B 独立复核及第三个 subagent 的最终签核、来源摘要以
[本轮总验收](../output/rules-recovery-20261105-231119/verification.json)为准。
subagent 评审不记为真人参考真值，也不产生本轮新增的整体准确率结论。
