# 跨进程复验与本地交付基线

2026-11-06。仅用于授权测试。
按 [本轮计划](VEHICLE_NEXT_ITERATION_20261106.md) 开始后，先将前轮 44 个文件封存为本地提交
`1c7372e`，分支 codex/vehicle-recovery-coverage。未推送远端，也未触发新的 Jenkins 构建。

新增工作与复跑命令见 [同库跨进程实测](../vehicle/rules/CROSS_PROCESS.md)。

## 已取得的证据

- AAOS 35，两个实际不同 PID，共同 UID、用户与目标数据库。
- 四项内核锁竞争与进程终止场景全部通过。
- 四份取回数据库的完整性、schema、内容及生效资产一致。
- 26 个既有设备测试方法逐项通过，四轮 seed/inspect 完成状态分别核验。
- 原用户数据库逐字节不变，原 APK 恢复，临时测试用户移除。
- debug 的两个入口受 DUMP 保护，release 合并清单不含这些入口。
- prepare + 17 组回归全部通过，vehicle-pipeline 192 个用例、移动侧 29 项通过。
  （当时口径；现行为 18 组根回归、带 `--mobile` 19 组、移动侧 31 项。）

[设备汇总](../output/rules-crossprocess-20261106-095505/device-003/verification.json)、
[回归汇总](../output/rules-crossprocess-20261106-095505/regressions/verification.json)、
[清单隔离验证](../output/rules-crossprocess-20261106-095505/manifest-verification.json)。

## 交付与边界

按用户指定的 A/B 独立 subagent 复核及 C 最终签核执行；
完整签核、源码和证据摘要以[本轮总验收](../output/rules-crossprocess-20261106-095505/verification.json)为准。
初轮文件轮询错误与连接故障保留，不能据失败轮次宣称通过。

本轮新增实证限该设备、该 APK 和同 UID 的两个协作进程；未执行跨应用、持续压力、跨设备或物理断电验证。
旧轮次仍保留各自的限制。基准准确率和真人参考状态不因本轮工程签核改变。
远端推送、新的 Jenkins 构建及下一条 HTTPS 业务路径为后续工作。
