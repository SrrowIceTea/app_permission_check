# V-Scanner 设计决策

## D001 本轮交付边界

首次交付：已确认 schema，用户暂无 AOSP 源码，先交付骨架和明确标注的合成测试。
不重复 Phase 0，不自动连接设备，不将项目书中的其他设想视为本轮执行指令。
最新种子进展见 D007。完整映射和 Android 集成验证仍待完成，不得标记整个 Phase 1 已完成。

## D002 两项唯一索引等价调整

将属性 ID 与 API 签名的表内 UNIQUE 约束替换为显式具名 UNIQUE INDEX，供 Room @Index 映射。
没有改变列、键、唯一性语义；当前仍处于 schema v1 的首次发布前。
旧草稿数据库应在新路径重建，不假设 CREATE TABLE 能升级已有数据库。

## D003 未知值与来源

源码引用保存字段覆盖范围、SHA-256、调用者提供的修订标签、符号和可确定的行号。
修订标签尚不等于经过验证的仓库提交；正式发布需补充仓库与确切 commit。
source_verified 仅说明已抽取的源码字段，不证明设备支持或其他空字段已确认。
属性仍有未抽取字段，因此统一保持 pending；已解析的名称/ID 在来源 fields 中单独标注。
CAR_SPEED/CAR_ENERGY 的存在性由用户实测确认；本轮未猜测保护级别，也未重复采集。

## D004 解析失败可诊断

采用受限 AST 整数计算，不使用 eval；不支持的常量表达式保存 TODO 和 NULL。
源文件整体格式错误、重复约束冲突导致构建失败，移除本次创建的失败数据库。
合成演示测试 HIDL/AIDL/Java、前向引用、未解析值、危险表达式和拒绝覆盖行为。
当前正则/枚举解析属于骨架，不声称覆盖任意 Java、AIDL 或 HIDL 语法。

## D005 规则和结果隔离

当前不生成启用规则；未来报告必须附规则 ID、revision、数据库摘要与证据来源。
时间相关性不直接证明数据外发；申请权限不直接证明过度索权。
只查询 Room DAO 提供逻辑只读；运行副本的强制只读与资产升级待工程集成阶段落实。

## D006 后续动态阶段固定约束

仅用于授权测试，默认只监控白名单包名；观察模式不修改返回值或拦截请求。
Frida 17.18.0，android-x86_64，按会话确认的 system_server attach 方案推进。
system_server Context 使用 ActivityThread.systemMain().getSystemContext()。
CPM 使用 android.car.hardware.property.CarPropertyManager；getPropertyList 显式绑定调用。
这些约束是后续实现输入，本轮不生成或运行 Hook、抓包或证书绕过代码。

## D007 固定版本的参考种子

用户运行合成演示通过后，继续抽取 AOSP android-14.0.0_r1，形成 17 条事实及 9 条禁用项目策略，共 26 条。
设备版本仍未知，源码 android_version=14 不得自动解释为设备版本14。
CAR_SPEED/CAR_ENERGY 只保留用户确认的存在性，源码级别另存，不补猜设备级别。
主要权限定义入口实际为 service/AndroidManifest.xml，car-lib Manifest 仅有1条；不固守原先单入口假设。
FUEL_LEVEL 文档冲突采用服务端权限映射，冲突留在 notes。
来源路径使用仓库相对路径，禁止写入随机临时路径，确保种子重建可复现。
源码原文件通过镜像的固定 AOSP commit 获取；完整源文件哈希与摘录行号均锁定。
本轮没有环境探测、Hook、抓包或启用任何设备审计规则。

## D008 真实 Android 工程与设备验证

工程落地在 `vehicle/rules/android/`，此前的 `android/RuleEntities.kt` 与 `RulesDatabase.kt` 已移入
`app/src/main/java/com/vscanner/rules/`，全项目单一副本，不再保留骨架副本。
`android/dependencies.gradle` 是设计期片段，已被真实的 `app/build.gradle.kts` 取代，保留仅作历史记录。

两个构建阻塞及其处理，均须写进部署文档：

1. `dl.google.com` 与 `android.googlesource.com` 在本网络不可达，AGP/AndroidX/Room 全部托管于
   Google Maven，裸 `google()` 配置必然失败。改用阿里云镜像优先，上游仅作兜底。
2. 工程路径含非 ASCII 字符（Windows 用户名），AGP 默认拒绝。已启用
   `android.overridePathCheck=true`（AGP 官方开关），但这是真实风险而非形式：若 aapt2 或 NDK
   出错，应把构建迁到纯 ASCII 路径，而不是继续加开关。

Room 预置库校验：经真实构建与设备运行验证通过，`schema.sql`、`rules.db`、Room 导出的
`1.json` 三方零差异。但 Room 的运行时校验只看列/索引/外键，**看不到 CHECK 约束、索引名和
主键顺序**，而这三项正是本项目数据完整性主张的依托，故新增 `tools/verify_schema_parity.py`
独立覆盖，不复用 Room 的结论。

损坏的 `assets/rules.db` **不会**让 Room 报错，这一点设备实测比预想更彻底：
0 字节、头部非法的垃圾字节、真库被截断到 2048 字节，**三种形态全都静默通过**——
Room 按空 schema 自建表，所有查询返回 0 行。因此验证器必须显式比对期望条数；
仅靠捕获异常会把任意一种损坏都误判为"读取成功、四表 0 行"，这是本项目最容易漏判的一处。

实测中真正会抛异常的只有两种：资产缺失（cause 链含 `FileNotFoundException`）与
schema 漂移（`IllegalStateException`）。`classify()` 保留损坏异常分支作为未观测形态的防线。

设备实测（`emulator_car64_x86_64`，Android 15 / API 35 / userdebug）：`state=OK`，
SHA-256 匹配，四表 6/8/3/9、合计 26，与当时的 `rules.db.summary.json` 一致
（启用数后来由 D010 改为 3）。
设备 API 35 与源码基线 14 的差异在页面显式标注，结论仍为【需实测校准】。

两条运维约束：预置库复制到设备后是粘性的，更换资产**必须**先清掉设备上的旧副本；
AAOS 上应用运行于 **user 10**，内部文件在 `/data/user/10/<pkg>/`，`adb shell` 需先 `adb root`。

上述两条是同一个坑的两面，且实测中真的踩到了：`adb shell pm clear <pkg>` **不带 `--user` 时
会打印 `Success` 却只清 user 0 的数据**，而应用在 user 10，于是旧库纹丝不动。
正确写法是 `adb shell pm clear --user 10 <pkg>`。误用后的表现极具误导性：
验证页报 `SCHEMA_MISMATCH`，但 SHA-256 显示**匹配**——因为哈希校验的是 APK 里的资产，
读的却是设备上那份陈旧副本，于是"哈希对得上、新版本数据 0 行"。
排查时对照 `databases/vscanner-rules.db` 的大小与 mtime 最快。

本轮仍未启用任何审计规则，未写 Hook、抓包或证书绕过代码。

## D009 双版本规则库：android-15 走设备实测

android-15 的源码抽取路径已确认为不可用：`android.googlesource.com` 不可达；
`LineageOS/android_packages_services_Car` 只有 `lineage-22.x` 分支，而项目规则禁止使用
LineageOS 分支上的修改内容；`aosp-mirror-neo/platform_hardware_interfaces` 无 `android-15*` tag；
GitHub 上不存在官方的 `aosp-mirror/platform_packages_services_car`。
因此 android-15 全部按**设备实测**建立，来源写进 `device_calibration_json`，
`definition_status` 保持 `pending`，**不得**标成 `source_verified`。

**Phase 0 那句"仅出现 2 个权限，说明当前镜像裁剪严重"是误判。** 真实原因是
`pm list permissions -d -g` 的 `-d` 只列 dangerous 组。改用 `-f` 后同一设备列出
**146 个** `android.car.permission.*`，其中 129 个是 `signature|privileged`——
它们一直都在，只是不属于 dangerous 组。危险的确实只有 2 个：`CAR_SPEED` 与 `CAR_ENERGY`。

设备实测同时**反向印证了源码抽取**：android-14 抽出的 6 条 protectionLevel 与设备 API 35
完全一致（含 `CAR_SPEED=dangerous`、`CAR_IDENTIFICATION=signature|privileged`），
8 个 VHAL 属性 ID 与设备 dex 常量表逐个相符，3 个 CPM 读取签名在设备上均存在。
这说明 14→15 之间这批常量未变，也说明当初的抽取没有编造。

VHAL 常量与 CPM 签名的设备来源是设备自带的 `/system/framework/android.car.jar`，
用 build-tools 的 `dexdump` 解析其中的 `classes.dex` 得到，不是靠猜或从别的版本套用。
附带修正：CPM 在 API 35 上有 **96 个**方法（Phase 0 记的是 78）；
`subscribePropertyEvents` 的真实返回类型是 `Z` 而非 `CarPropertyConfig`，共 5 个重载——
基线文档此前声明"未包含该签名"，现在有设备实证可补。

**android-15 的 9 条 risk_rules 是镜像过来的，但溯源被拆开处理**，这是本轮最容易做错的一处：

- `basis_refs_json` **原样保留**。它指向 `POLICY.md`，说的是 V-Scanner 选择把什么判为违规——
  这是项目策略，与 AOSP 版本无关，"必要性审查"这个谓词在两个版本上含义相同。
- `source_refs_json` **不保留**。它引用的是 AOSP android-14 的 commit 与行号，
  描述的是属性与签名的定义来源。把它沿用给 15 版本，等于给 android-15 的规则安上
  android-14 的出处。改为记录设备实测：设备指纹、观测到的 protectionLevel / property ID /
  CPM 签名，并显式注明"未沿用 android-14 来源引用"。

`enabled` 仍恒为 0（D005 未变：没有求值器，就不启用规则）。
这条不变式由设备侧测试 `android15RulesCarryDeviceProvenanceNotAndroid14SourceRefs` 锁定，
不靠人工检查——一次粗心的重建正是它悄悄退化的方式。

规则库产物：`rules_library/rules.db`，'14' 26 条 + '15' 166 条。
同输入重建可得到相同 SHA-256；该文件被复制进 `android/app/src/main/assets/rules.db` 并随之发布。

## D010 启用 12 条规则，data_egress 暂缓（用户决定）

`enabled = 1` 的含义是**"这条规则适合产出审计结论"**，不是"这条规则存在"。
D005 当初设的门槛是"没有求值器就不启用"，Phase 5 提供了求值器，门槛已跨过；
但还要看规则本身站不站得住，于是按谓词分开处理：

| 谓词 | 条数 | 启用 | 理由 |
| --- | ---: | ---: | --- |
| `over_permission` | 6 | ✅ | 只比对清单权限，无已知缺陷 |
| `sensitive_read` | 6 | ✅ | 只判 `outcome=ok`，无已知缺陷 |
| `data_egress` | 6 | ❌ | 依赖 `window_ms`，而该参数**实测偏小一个数量级** |

**不启用 data_egress 的理由不是保守，是它现在确实是坏的**：规则写 3000ms，
而靶子 App 实测的读取→外发间隔是 10634ms / 20292ms——用它跑，**真实外发一条都抓不到**。
启用一条已知会漏报的规则，等于对外声明它可用。**窗口校准后再启用。**

校准旋钮放在分析侧而不是规则侧：`vehicle/analyze/correlate.py --window-override-ms`。
理由见 vehicle/analyze/DECISIONS.md D502——`window_ms` 是政策参数（多近算相关），该由人改并留下记录。

`schema.sql` 对 `enabled=1` 的 CHECK 约束（必须具备完整出处）**经实测确认有效**：
故意把一条已启用规则的 `source_refs_json` 清空，SQLite 直接以
`CHECK constraint failed` 拒绝写入。这道闸不是摆设。

构建器加了 `--enable-types` 参数，启用状态随库一起重建，可复现。

## D011 规则覆盖从 3 个属性扩到全部 8 个；P 规则按权限去重

`seed_policy.py` 原先只覆盖 INFO_VIN / PERF_VEHICLE_SPEED / GEAR_SELECTION 三个属性。
Phase 5 实测暴露了后果：CURRENT_GEAR 可读却无规则，**已知漏报**。

扩到 `vhal_properties` 的全部 8 个属性，severity 沿用既有判据（标识能力）：
INFO_VIN=high；PERF_VEHICLE_SPEED / GEAR_SELECTION / CURRENT_GEAR / PERF_ODOMETER=medium；
ENGINE_RPM / FUEL_LEVEL / EV_BATTERY_LEVEL=low。
分级表写进 POLICY.md（它是项目策略的载体），并把更新后的 SHA-256 同步进
`sources.lock.json` 的 artifacts 锁定——POLICY.md 变了，锁必须跟着变。

**R 与 E 按属性生成，P 按去重后的权限生成。** 这是扩覆盖时暴露的一个质量问题：
P 的谓词是"清单请求了该权限"，与属性无关；按属性生成会让共享同一权限的属性
（GEAR_SELECTION 与 CURRENT_GEAR 同受 CAR_POWERTRAIN 管辖、FUEL_LEVEL 与
EV_BATTERY_LEVEL 同受 CAR_ENERGY 管辖）产生**两条一模一样的结论**——
那是噪声，不是信息。去重后 P 为 6 条（8 属性对应 6 个不同权限），
每版本规则总数 22（P6 + R8 + E8），启用 14（P6 + R8）。

数字链：baseline 41 条记录 → 双版本库 v14/v15 各 22 规则、启用 14。
规则编号兼容：原 P001-P003 / R001-R003 / E001-E003 不变，新规则追加在末尾。

## D011 外发窗口正式启用与当前设备验证（2026-09-24）

用户要求补齐缺口，据此启用每版8条外发规则，30000ms、revision=2。（静态反编译当时排除，2026-09-28 由用户解除并作为 vehicle/workbench 加入。）
双版本44条规则全部启用；规则库与Android资产摘要一致，设备Room返回state=OK。
完整结果：../output/completion/room-verification.json。校准依据见EGRESS_CALIBRATION.md。
核对修改前备份assets-before.db，R001–R008已经存在且启用，CURRENT_GEAR=R004；
旧的“仅3属性有规则”描述不适用于本次实际工作区，不能据此另造重复规则。

## D012 通用隐私来源独立冻结实测依据（2026-11-02）

通用 VSC-G* 规则不得复用旧 VHAL device-facts 的指纹。privacy_observation.py 从已通过的
正控/拒绝会话提取真实指纹和逐类型 read_state 计数；核对输入摘要、会话、API 与 Hook 契约。
固化到 vehicle/privacy/device-observation.json，带 manifest/reads/verification 摘要，支持离线重建。
构建器使用 --privacy-observation（默认此快照）；旧 --device-facts 仅供原 VHAL 校准。
本次仅 6 条 Android15 通用规则的 source_refs_json 改变；所有 VHAL 行及其他字段逐项核对不变。
同步库、Android 资产与 RulesVerifier SHA；14 版仅引用 SDK，仍不冒充设备实测。

## D013 AAID 独立读取规则（2026-11-04）

两版本分别登记 VSC-GR-advertising_id。API 35 行引用同镜像、同 Hook 的四态封存记录；
Android 14 行引用 Google SDK 依据。逐表核对既有行一致，规则库与 Room 资产同步。

## D014 规则库升级以摘要判定（2026-11-05）

**缺陷（设备实测复现）**：Room `createFromAsset` 只在运行副本缺失时复制。APK 升级换了
同 schema 的 `rules.db`（只改一条 notes，counts 不变）后，设备仍加载旧副本：
运行时文件 SHA-256 保持旧值，验证页 `sha256.actual` 却是新资产摘要，状态落到
`SCHEMA_MISMATCH`（"条数符合"），足以误导排查。复现证据在
`output/rules-db-upgrade-20261105/repro/`。

**修复**：新增 `RulesDbInstaller`，以资产原始 SHA-256 + schema 版本 + 四表内容摘要判定
是否重建，不再看 schema 版本单一信号。升级先写暂存文件，校验摘要、四表内容与 Room schema
（用一次性库名打开），再备份旧库并替换；新资产校验失败保留旧库，报告
`UPGRADE_FAILED_KEEPING_OLD`。返回的 `InstallReport` 含生效库摘要（安装字节的原始
SHA-256）与内容摘要，写入验证页 JSON 的 `install` 节点。

集成复核纠正边界：当前替换先删除再重命名，不能称为原子切换。磁盘写入异常、升级中断和并发安装
不在本次验收范围；正常升级后的重启不证明切换中断安全，替换异常会报告 `INSTALL_ERROR`。

**为何不用原始文件摘要判定**：Room 首次打开会追加 `room_master_table`/`android_metadata`，
运行文件摘要从 `4bf51b…` 变为 `e0ce73…`，而规则内容不变。因此"是否仍是同一份规则"必须
用四表内容摘要（`vscanner-rules-content-v2`，含 `PRAGMA user_version`）；原始摘要只作为
"这一版是哪份资产"的身份标识。

**验收**：设备侧 `RulesDbUpgradeTest` 四例全过（首次安装=包内摘要、同 schema 内容变更升级、
升级失败沿用旧库且仍可读、重启不回退旧库）；E2E 证据见
`output/rules-db-upgrade-20261105/acceptance/`，该轮使用 API 37 手机模拟器和 App 重启。既有 `RulesVerifierStateTest` /
`RulesSchemaValidationTest` 断言未改动、全部通过。

## D015 AAOS 35 规则库升级与整机重启复验（2026-11-05）

项目专用 `VScanner_AAOS_35_P1` 的 AVD 与镜像在 `output/vehicle-device-setup/`。
临时将 `ANDROID_AVD_HOME` 指向其中的 `avd`，使用现有 SDK 模拟器启动。设备指纹与 11 月 4 日
封存会话一致，API 35。测试在单独创建的用户 11 中执行，原用户 10 的夹具 APK 与运行库摘要在收尾时核对。

三份封存 APK 分别验证首次安装、同 schema 升级和损坏资产回退。升级成功后及损坏资产回退后各执行一次
`adb reboot`，分别等到新的内核 boot ID、系统启动完成及测试用户解锁，再启动 App 读取新生成的验证 JSON。
五个阶段均从设备取回实际运行库，并核对 SQLite 完整性、schema、条数、标记和生效摘要。
成功升级后重启为 `UNCHANGED`，损坏资产下重启仍为 `UPGRADE_FAILED_KEEPING_OLD`，均读取同一份已升级规则。
原用户 APK 恢复且运行库字节不变，测试用户已移除。证据见
[`verification.json`](../../output/rules-db-upgrade-aaos35-20261105-120531/verification.json)。
本轮范围为指定 AAOS 35 模拟器和自有规则库夹具。

## D016 升级中断恢复与读取互斥（2026-11-05）

切换改为同目录 rename，不再删除生效库后回退到覆盖复制。新库、备份、元数据和切换意图分别刷盘，
切换后核对内容再提交元数据，最后清除意图。下次启动依据实际内容、目标意图和已校验备份完成或恢复。
旧 WAL 在备份前 checkpoint；正常应用入口在同一协程互斥与文件锁租约内完成安装、DAO 读取和关闭。
没有可信副本时停止，不能让 Room 在目标路径自建空库掩盖安装失败。详情见 RECOVERY.md。

AAOS 35 的 device-002 已完成 22 项设备用例、6 个阶段真实终止进程、2 个阶段整机重启。
新进程 PID 与前进程不同，重启前后 boot ID 不同，恢复后四表内容、schema 与生效摘要一致。
测试用户移除、原用户数据库逐字节不变。device-001 的验收脚本轮询错误保留，修正后新目录复验。
首装提交意图后恢复另增用例；最新完整用例数与证据以本轮总验收文件为准。
不宣称物理断电、任意磁盘硬件故障或未执行的跨进程竞争已实测。

2026-11-06 最终修订：锁获取失败返回不读取未上锁文件的 INSTALL_ERROR；原始 SQLite 探测使用保留现场的
corruption handler。有效头损坏反例在本机修复前也未触发删除，此项按防御性改进登记，不声称已复现删除。
验收逐方法核对 raw instrumentation，不再接受任意 OK(N)；各项清理独立尝试。device-final 严格确认
26 项用例和 8 个真实中断点，原用户库逐字节不变、测试用户已移除。见 docs 本轮交付与总 verification.json。

## D017 同 UID 独立进程竞争复验（2026-11-06）

debug 专用双 Service 使用不同进程，共享同一测试用户的专用库。以 /proc/locks 的精确持锁/等待 PID
和实际 .lock inode 确认竞争，不把进程存活或短暂无结果当成阻塞证明。
读取阻塞升级、两升级器竞争、杀持锁者后继续、杀等待者再启动四项在 AAOS 35 通过；
一轮 26 方法及每次 seed/inspect 逐方法核对，原用户库不变、APK 恢复、测试用户移除。
调试入口要求 DUMP，release 合并清单无该入口。详见 [CROSS_PROCESS.md](CROSS_PROCESS.md)。
exec-out 缺失文件假成功与 ADB 连接中断各保留失败轮次，最终证据为本轮 device-003。
只补充本轮同 APK/UID 协作进程的已测范围，D016 的旧证据和未测硬件断电结论不追溯改写。
