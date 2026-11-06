# 规则库升级中断恢复

仅用于授权测试。2026-11-05，续 D014–D016。

当前实现不再先删除旧库。步骤为：写入并刷盘暂存库 → 摘要/SQLite/Room schema 校验 →
检查旧 WAL 并生成完整备份及其元数据 → 刷盘切换意图 → 同目录 rename →
核对新库、提交生效元数据 → 清除意图。每次文件替换后同步目录。

启动时优先按切换意图核验新库；未切换时保留匹配的旧库；当前副本不完整时恢复已核验备份。
首次安装无旧库，但有完整暂存库和持久化意图时，可以完成新库安装。
当前库、意图与备份均无法核验时，保留现场并停止读取，不能创建空库或报告零发现。

## 应用入口与并发

RulesVerifier 在 RulesDbInstaller.withInstalled 的租约内完成安装、读取和关闭。
租约使用进程内协程 Mutex 和文件锁，协作进程需使用同一入口；不能绕过入口持有旧 Room 连接再替换文件。
RulesDatabase.open 已改为模块内底层接口，使用 TRUNCATE 日志。探测库与设备测试可直接调用底层接口。
新的调用方也必须持有对应租约，文件锁不能强制未协作的 SQLite 读写者遵守约定。

## 结果

- UNCHANGED / UPGRADED / FIRST_INSTALL：按正常流程完成，仍需 contentMatch=true。
- RECOVERED：升级异常后核验到完整目标库，recovery 记录恢复动作。
- UPGRADE_FAILED_KEEPING_OLD：新源不可用或未提交，保留经过核验的库。
- FIRST_INSTALL_FAILED / INSTALL_ERROR：readable=false，验证器停止打开目标库。

effectiveSha256 标识安装来源；Room 添加内部表后的 live 文件摘要可能变化。
规则一致性按四表内容摘要和 schema 判定，原始文件摘要单列为 activeFileSha256。
元数据写入使用完整暂存与 rename，摘要字段格式不合法时拒绝使用。

## 复跑

在项目根 PowerShell 中加载环境并编译：

```powershell
. ./environment.ps1
& $VScanGradle -p vehicle/rules/android --offline :app:assembleDebug :app:assembleDebugAndroidTest
& $VScanPython vehicle/rules/android/tools/recovery_acceptance.py --serial emulator-5554 --out <新目录>
```

需使用项目自有 AAOS 35 模拟器。脚本只操作自有 com.vscanner.rules 夹具，
自动创建测试用户，备份并恢复原 APK，核对原用户数据库逐字节不变。
每个故障点记录输入、故障进程、恢复进程、boot ID、四表校验与实际数据库副本。
进程终止与重启轮次属于预期中断，不能把 instrumentation 提前结束当成正常测试成功；
需以恢复后新进程证据和总 verification.json 为准。

本轮根目录：output/rules-recovery-20261105-231119/。
device-final 严格逐方法确认 26 项用例、6 个终止进程点和 2 个重启点；失败 device-001 及早期轮次保留。
两次重启是模拟器整机重启；物理断电、磁盘硬件失效、跨进程竞争压力不在本轮实测结论内。

实现依据：[Android Os](https://developer.android.com/reference/android/system/Os)。
[AtomicFile 文档](https://developer.android.com/reference/android/util/AtomicFile)明确要求调用方自行提供并发保护；
本实现另加覆盖完整读取周期的租约，不能把单文件替换等同于多文件状态已经一致。
