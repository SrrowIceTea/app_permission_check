# 共享 Frida 驱动决策

## F001 子进程发现必须从进程表取名并核对主进程 UID（2026-11-10）

仅用于授权测试（自有设备与自有 APK）。`pidof package` 只查询精确进程名，不能把它当作
`package:remote`、`package:webview` 等进程的枚举器。原 resolve_pids 虽支持多 PID 和 user
过滤，实际仍只查 pidof，故多进程入口可报告附加成功但遗漏普通冒号子进程。

resolve_pid 保持原来的精确单进程契约。resolve_pids 以当前运行的主进程为身份锚，读取
`ps -A -o PID,NAME` 快照，仅选精确 `package:` 前缀、且 /proc/<pid>/status 的 UID 与所选
用户主进程一致的子进程；相似包名前缀、其他用户/UID、孤立 UID 进程不自动附加。
主进程始终排在子进程之前，再应用 MAX_PROCESSES 上限；超限 PID 保留 skipped。

进程表失败、未知表头/格式/重复 PID、UID 无法核验都抛出诊断性失败，不能静默降成“没有
子进程”。仅发现当时存在的命名子进程，不承诺晚起进程监控、任意自定义进程名或孤立
WebView 身份覆盖。多 PID 事件各有本地序号，下游仍须识别 PID，不得凭本修复声称关联已完整。

验证：core.frida_host.test_device_target 的真实命令形态模拟、异包/UID/user、上限、非法
进程表和进程消失反例。此轮没有连接 AAOS 设备，结论是离线复现与修复，不是设备实测。
