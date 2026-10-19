> 2026-09-24 当前增补与复现见 [根 COMPLETION.md](../../COMPLETION.md)。以下旧实测条数、时间与未实现描述属于历史轮次，以当前交付说明和对应 verification.json 为准。

# V-Scanner 车载规则库（vehicle/rules，原 Phase 1）

当前内容：四表 SQL、Room Entity、只查询 DAO、源码解析、离线校准和合成演示。
android-14 部分是从 AOSP `android-14.0.0_r1` 抽取的 41 条（24 规则覆盖全部 8 个 VHAL 属性，P 按权限去重），见 [种子库说明](baseline_android14/README.md)。
android-15 部分是**设备实测**的 179 条，见 [设备校准说明](device_calibration/README.md)。
`android/` 已是可编译的 Gradle 工程，双版本规则库已在真实 AAOS 设备上验证加载成功（见下）。
每版本启用 14 条规则（over_permission 6 条 + sensitive_read 8 条）；`data_egress` 8 条因 `window_ms`
待校准而未启用，见 D010。
测试样例全部使用 TEST_ONLY 标识，不代表 AOSP 常量，也不能部署用于正式审计。

```text
vehicle/rules/
  schema.sql                    四表契约
  baseline_android14/           android-14 源码抽取基线（41 条，已锁定）
  device_calibration/           android-15 设备实测证据（146 权限 / 254 属性 / 96 签名）
  rules_library/rules.db        双版本规则库产物（'14' 39 条 + '15' 179 条）
  android/                      可编译的 Gradle 工程
    settings.gradle.kts         仓库源：阿里云优先
    gradle/libs.versions.toml   版本目录
    tools/verify_schema_parity.py
    app/
      build.gradle.kts          useLibrary("android.car") + Room + KSP
      schemas/…/1.json          Room 导出的 schema，需提交
      src/main/assets/rules.db  预置规则库（= rules_library/rules.db）
      src/main/java/com/vscanner/rules/
        RuleEntities.kt         四表实体
        RulesDatabase.kt        只查询 DAO + 计数
        RulesDbSource.kt        资产/字节/缺失三来源接缝
        RulesVerifier.kt        三态判定与期望常量
        MainActivity.kt         验证页
      src/androidTest/…         设备侧 schema 与失败路径测试
    dependencies.gradle         设计期片段，已被 app/build.gradle.kts 取代
  python/
    parse_sources.py
    build_rules.py
    calibrate_permissions.py
    extract_device_calibration.py
    build_multiversion_rules.py
    device_rows.py              设备观测行构造（自 build_multiversion_rules 拆出）
    demo.py
  README.md
  DECISIONS.md
```

## 关键接口

路径：`python/parse_sources.py`，Python。

```python
parse_permissions(path, android_version, revision) -> list[dict]
parse_properties(path, android_version, revision) -> tuple[list[dict], list[dict]]
```

路径：`python/build_rules.py`，Python。

```python
build(manifest, properties, android_version, revision, output, schema=None) -> dict
```

路径：`python/calibrate_permissions.py`，Python。

```python
compare(database, pm_output, android_version, coverage) -> dict
```

路径：`android/RulesDatabase.kt`，Kotlin。

```kotlin
RulesDatabase.open(context).rules().permissions(version)
RulesDatabase.open(context).rules().properties(version)
RulesDatabase.open(context).rules().apis(version)
RulesDatabase.open(context).rules().activeRules(version)
```

四个 DAO 方法是 suspend 函数，应从协程调用；此处不生成 UI 调度代码。

## 一条不连接设备的最小路径

依赖：电脑端 Python 3.10+，仅标准库，无需 pip 安装。
在电脑上的终端中进入本 vehicle/rules 文件夹后执行；以下为 bash 代码块，命令也可用于已有 python 命令的 PowerShell。

```bash
python python/demo.py --out demo/demo-rules.db
```

结果：生成 `demo/demo-rules.db` 和 `demo/demo-rules.db.summary.json`。
终端出现 `"demo_checks": "PASS"` 即表示演示检查通过。
预期四表行数为 permissions=1、vhal_properties=3、dangerous_apis=0、risk_rules=0。
其中一个属性 ID 为 NULL，有明确诊断信息。
重复运行时请换输出文件名；脚本拒绝覆盖已有数据库和摘要。
演示使用临时合成源码，结束后删除临时源码；源码内容保存在 demo.py 中可复现。

## 未来使用真实源码

目前没有指定源码，因此以下仅为接口示例，不要求现在执行。
在电脑执行，路径和版本标记都必须换成真实值，源码不由脚本自动下载。

```bash
python python/build_rules.py --manifest /path/to/car-lib/AndroidManifest.xml --properties /path/to/types.hal --android-version ACTUAL_VERSION --source-revision EXACT_TAG_OR_COMMIT --out draft/rules.db
```

properties 每次传一份：HIDL `types.hal`、AIDL `VehicleProperty.aidl` 或 `VehiclePropertyIds.java`。
源版本标签由调用者提供，脚本不能证明标签与本地文件一致；实际文件 SHA-256 会写入来源记录。
不同仓库使用同一 release tag 时，要在正式发布阶段记录各仓库确切 commit。

支持范围：

- Manifest 仅抽 `<permission>`，不会把 `<uses-permission>` 当成权限定义。
- 保留 protectionLevel 原始文本；仅纯数值可写入数值列，不硬编码 flag 数值。
- 解析字面量、加减、位运算和已解析的枚举/常量引用，不执行源码表达式。
- 未知引用、方法调用、未显式赋值枚举保持 NULL、pending，并出现在摘要诊断中。
- 属性类型、访问模式、单位、读写权限映射均为 TODO，禁止从名字猜测。
- 通用解析器仍未抽 API；固定种子的 extract_seed.py 另行抽取 3 个源码签名，见种子库说明。
- 同版本属性 ID 的别名会触发唯一约束；骨架明确失败，后续再增加有来源的规范名选择策略。

源码定义不代表当前设备支持。所有未在目标设备校准的属性 ID、权限级别及映射均为【需实测校准】。
构建摘要状态固定为 `draft_not_for_audit`，不产生启用的审计规则。

## 离线校准接口

只比较已保存的 pm 输出，不执行 adb，不重复 Phase 0，不修改 rules.db。
你此前经过 `-d -g` 与 grep 筛选的结果应标记 `filtered`。
“没有出现在输出里”只记为未观测到，不记为设备不存在。

未来在电脑执行，替换为已有文件路径：

```bash
python python/calibrate_permissions.py --db draft/rules.db --pm-output /path/to/saved-permissions.txt --android-version ACTUAL_VERSION --coverage filtered --out draft/calibration.json
```

结果分为 observed_and_declared、observed_only、source_only_not_observed。
原始文件应保存 UTF-8；空文件或未解析到权限行会明确报错。

## Room 集成与依赖变更

`RuleEntities.kt` 的四个类逐列映射 SQL，JSON 使用 String，未知值使用可空类型。
复合主键、唯一索引和外键均显式声明；SQL 默认值使用 @ColumnInfo(defaultValue=...) 对齐。
保留预置数据库中的 CHECK 约束。Room 自动建表不应替代正式数据库发布流程。

将两个 Kotlin 文件放入未来工程 `app/src/main/java/com/vscanner/rules/`。
正式发布的数据库放 `app/src/main/assets/rules.db`，不要使用 demo-rules.db。
`createFromAsset("rules.db")` 创建运行副本；只读 DAO 是应用层约束，并非文件系统强制只读。
扫描结果必须用另一个数据库。本骨架没有原始 SQL 写入口或破坏性迁移回退。
同 schema 版本更新资产不会自动刷新已有副本，规则发布更新策略待后续实现。

依赖变更单列：

- Python：零第三方依赖。
- Android：Room runtime/compiler 固定为 2.8.5；minSdk 至少 23，Kotlin 语言版本至少 2.0。
- 使用工程兼容的 KSP2 插件；本轮没有完整 Gradle 工程，不臆定 Kotlin/AGP/KSP 版本组合。
- `android/dependencies.gradle` 是合并片段，包含 `useLibrary 'android.car'` 和 Room schema 导出目录。
- 继续使用 Empty Views Activity；本轮不引入 Compose。

Room schema 校验已在真实工程中构建并装机通过，见下节。
参考：[Room Entity](https://developer.android.com/training/data-storage/room/defining-data)、
[预置数据库](https://developer.android.com/training/data-storage/room/prepopulate)、
[Room 发布说明](https://developer.android.com/jetpack/androidx/releases/room)。

## 在真实设备上构建与验证

已实测环境：SDK `D:\Anroid\SDK`（拼写如此），JDK 21（`JAVA_HOME=D:\Anroid\JDK`），
Gradle 8.13 / AGP 8.11.1 / Kotlin 2.2.0 / KSP 2.2.0-2.0.2 / Room 2.8.5，
`compileSdk 36`（唯一带 `android.car.jar` 的已装平台）、`minSdk 23`、`targetSdk 35`。

**本网络下 `dl.google.com` 不可达**，而 AGP、AndroidX、Room 全在 Google Maven 上，
因此 `settings.gradle.kts` 以阿里云镜像优先，上游仅作兜底；不要改回裸 `google()`。
工程路径含非 ASCII 字符，AGP 默认拒绝，已启用 `android.overridePathCheck=true`。
这是真实风险：若 aapt2 或 NDK 报错，应把构建迁到纯 ASCII 路径，而不是继续加开关。

```bash
cd vehicle/rules/android
./gradlew :app:assembleDebug          # 首次会从阿里云拉 Room 与 KSP
python tools/verify_schema_parity.py  # 比对 schema.sql / rules.db / Room 导出的 1.json
```

parity 脚本**覆盖 Room 运行时看不到的东西**：CHECK 约束、索引名、主键顺序。
Room 只比较列、索引列与外键；这三项恰好是本项目完整性主张的依托，因此不能只依赖它的结论。

设备侧（AAOS 模拟器 `emulator_car64_x86_64`，Android 15 / API 35 / userdebug）：

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell pm clear --user 10 com.vscanner.rules   # 注意 --user 10，见下
adb shell am start -n com.vscanner.rules/.MainActivity
adb root && adb pull /data/user/10/com.vscanner.rules/files/verification.json
```

三条运维约束，违反会得到误导性结果：

1. **预置库是粘性的，且 `pm clear` 不加 `--user` 是个假成功。**
   Room 发现目标文件已是同一版本就直接返回，重新安装或升级 APK 都不会替换它
   （`PrePackagedCopyOpenHelper` 只比版本号，不比内容）。
   更麻烦的是：应用跑在 user 10 而 `adb shell` 默认在 user 0 上下文，
   于是 `pm clear com.vscanner.rules` 会**打印 `Success` 却只清掉 user 0 那份不存在的副本**，
   user 10 的 `databases/` 原封不动。实测已确认：
   不带 `--user 10` 时 `databases/vscanner-rules.db` 仍在，加上之后才消失。
   换过 `assets/rules.db` 后**必须**用 `pm clear --user 10`，否则会一直看到旧库，
   而且界面上的 SHA-256 是**新**资产的（校验的是 APK 里的资产），
   于是表现为"哈希对得上但 15 版数据是 0 行"，极具误导性。
2. **应用运行在 user 10**（AAOS 多用户），内部文件在 `/data/user/10/<pkg>/`，
   `adb shell` 需要先 `adb root` 才读得到；`/sdcard/Android/data/...` 是 user 0 的视图，那里没有。
3. 首次成功打开后文件会多出 `room_master_table`，此后校验走 identity hash 分支，
   报错文案不同但仍属 schema 不匹配。

三种状态的判定依据（`RulesVerifier`）：

| 状态 | 依据 |
| --- | --- |
| 读取成功 | SHA-256 匹配**且**四表条数符合期望 |
| schema 不匹配 | Room 抛 `IllegalStateException`（含 "invalid schema" 或 "data integrity"） |
| 数据库缺失或损坏 | 资产缺失（cause 链含 `FileNotFoundException`）、真库被截断（`SQLiteDatabaseCorruptException`）、**或四表全为 0** |

最后一项是关键，且**覆盖的情形比最初预想的多得多**。设备实测（`RulesVerifierStateTest`）：

| 输入 | 实测行为 |
| --- | --- |
| 0 字节 | **不报错**。Room 按空 schema 自建表，查询返回 0 行 |
| 头部非法的垃圾字节 | **不报错**。同上 |
| 真库被截断到 2048 字节 | **不报错**。同上—— 有效库被空库取代，计数归零 |
| 资产缺失 | 抛 `RuntimeException`，cause 链含 `FileNotFoundException` |
| 真库被加了一个索引（schema 漂移） | 抛 `IllegalStateException` |

**三种损坏形态全都不抛异常**，只能靠显式比对期望条数发现。
能走到 counts 查询本身就说明表被建出来了——该 SQL 引用四张表，表不存在必然抛异常。
若没有这一步比对，验证页会把任意一种损坏都报成"读取成功、四表 0 行"。

`classify()` 里仍保留 `SQLiteDatabaseCorruptException` / `SQLiteException` 分支，
作为尚未观测到的形态的防线，但它不是这几种情况的判据。

实测结果：`state=OK`，SHA-256 匹配，双版本条数均符合预期，每个版本启用规则 14/22
（over_permission 6 条 + sensitive_read 8 条；data_egress 8 条因 `window_ms` 待校准而未启用，见 D010）：

| android_version | 权限 | 属性 | API | 规则 | 启用 | 合计 | 来源 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 14 | 6 | 8 | 3 | 22 | 14 | 39 | AOSP `android-14.0.0_r1` 源码抽取 |
| 15 | 146 | 8 | 3 | 22 | 14 | 179 | 设备实测（API 35） |

两版本来源不同，这是**刻意的**：`definition_status` 只有源码抽取才配 `source_verified`，
设备观测一律 `pending`，出处记在 `device_calibration_json`。

android-15 的 9 条规则是镜像的，但**溯源被拆开**（D009）：
`basis_refs_json`（POLICY.md，项目策略，与版本无关）原样保留；
`source_refs_json`（AOSP android-14 的 commit 与行号）**不保留**，改为设备实测记录——
否则就是给 android-15 的规则安上 android-14 的出处。
这条不变式由设备侧测试锁定，不靠人工检查。

设备为 API 35，页面会指出它与哪个版本对齐；未校准部分结论仍为【需实测校准】。

## 诊断

| 信息 | 含义和处理 |
| --- | --- |
| No android.car.* permission declarations found | 检查权限定义 Manifest；Android 14 的主要入口是 service/AndroidManifest.xml |
| No supported property declarations found | 格式不在骨架支持范围；保留文件供扩展解析器 |
| unresolved_properties 非空 | 某些 ID 未解析；查看符号、行号、表达式，不是零读取事件 |
| Refusing to overwrite | 使用新的输出路径，原数据库不受影响 |
| UNIQUE constraint failed | 有重复定义/别名，核对源码后确定规范记录 |
| ParseError | XML 格式错误，标准错误流输出结构化失败信息 |
| Room schema 校验失败 | 对照编译器导出 schema 与 SQL；禁止用清库回退掩盖问题 |

成功 CLI 输出 JSON；构建/校准失败返回非零退出码及 JSON 错误。
该阶段没有 Hook，因此不使用 /data/local/tmp/vscan.log；后续 Frida 阶段实现设备日志。
