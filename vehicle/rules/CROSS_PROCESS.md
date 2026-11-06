# 同库跨进程竞争实测

2026-11-06。仅用于授权测试，使用自有 AAOS 35 和 com.vscanner.rules 调试夹具。
本轮基线为本地提交 `1c7372e`，后续产物位于 output/rules-crossprocess-20261106-095505/。

## 方法与结果

debug APK 中两个 Service 分别运行于 :rulesLeaseA 与 :rulesLeaseB，PID 不同、UID 与用户相同。
入口要求 android.permission.DUMP；release 合并清单中没有这两个入口。
使用临时测试用户和专用 lease-crossprocess.db，原用户数据库不参与写入。

| 场景 | 实测结果 |
| --- | --- |
| 读取租约阻止升级 | A 保持 Room 读取且内容不变，B 的升级在内核中等待；A 关闭/释放后 B 完成 |
| 两个升级请求竞争 | 第一个升级器在锁内受控暂停，第二个进入内核等待；最终一个 UPGRADED、另一个 UNCHANGED |
| 持锁者被杀 | A 被实际 kill -9，确认进程不存在；等待中的 B 完成升级，未依赖 A 的 finally |
| 等待者被杀后重试 | B 被实际 kill -9，A 继续读取且内容不变；重新启动同一 B Service 得到新 PID，完成升级 |

四项均通过。每项保存原始 /proc/locks，核对 POSIX WRITE 持锁行与带 -> 的等待行，
按精确 PID、同 UID/用户、同 boot ID、相同库路径以及实际 .lock 文件 inode 绑定。
时序使用设备单调时钟，不把宿主机动作时间直接与设备时间相减。

每项从设备取回数据库，核对完整性、schema、生效资产摘要、四表内容与元数据。
26 个既有 Android 测试方法仍逐项通过；seed/inspect 的每次调用也核对具体方法完成状态。
原 APK 已恢复，原用户数据库逐字节不变，临时测试用户已移除。

## 复跑

在项目根目录 PowerShell 中执行：

```powershell
. ./environment.ps1
& $VScanGradle -p vehicle/rules/android --offline :app:assembleDebug :app:assembleDebugAndroidTest :app:processReleaseMainManifest
adb -s emulator-5554 root
adb -s emulator-5554 wait-for-device
& $VScanPython -m vehicle.rules.android.tools.crossprocess_acceptance --out <新目录>
```

设备须为自有 userdebug AAOS 35。root shell 仅用于诊断和终止自有夹具进程；
普通第三方业务采集仍按原白名单和安装身份执行。
服务返回 START_NOT_STICKY，死亡后需显式重启；等待与调试暂停均有界。
调用方异常时尝试停止自有夹具、恢复 APK/用户并核对原用户库，失败项逐项保留。

## 失败记录与边界

- device-001：exec-out 读取尚不存在的 JSON 时返回错误文本、退出码却为 0。已用同一缺失文件实测复现，
  修订后事件轮询使用 shell 的退出状态；畸形成功响应仍报错并保留原文。
- device-002：宿主 ADB 连接中断，测试尚未进入四个场景；清理成功。连接/root 检查已移到创建测试用户之前。
- device-003：四项、26 方法及清理通过，为本轮设备证据。

本轮只证明同一 APK、同一 UID/用户的两个协作进程在该设备和该库上的行为，
不等于任意应用都遵守文件锁，也不是持续高负载、跨设备或物理断电验证。
父进程被强杀时的子进程树及设备设置恢复仍未纳入保证。

参考：[Android Service](https://developer.android.com/reference/android/app/Service)、
[Service 清单的进程及权限配置](https://developer.android.com/guide/topics/manifest/service-element)。
