# 规则库与 Android 工程（vehicle/rules，原 Phase 1）

车载隐私特征数据库：双版本规则库（android-14 = AOSP 源码抽取，android-15 = 设备实测）
+ 一个在真实设备上验证过 Room 预置库加载的 Android 工程。**已完成。**
约束与决策见 `DECISIONS.md`（D001–D011），全局约束见根 `CLAUDE.md`。

## 目录

| 路径 | 作用 |
| --- | --- |
| `schema.sql` | 四表契约（permissions / vhal_properties / dangerous_apis / risk_rules），**不要动** |
| `baseline_android14/` | android-14 源码抽取基线（已锁定，41 条，`source_verified`） |
| `device_calibration/` | android-15 设备实测证据（146 权限 / 254 属性 / 96 签名） |
| `rules_library/rules.db` | 双版本产物（'14' 39 条 + '15' 179 条，每版启用 14/22） |
| `android/` | Gradle 工程：Room 实体/DAO、RulesVerifier、验证页、设备侧测试 |
| `python/` | 抽取/校准/构建流水线（全部零第三方依赖） |
| `archive/research/RELATED_WORK.md` | 研究文档（已归档到 archive/，改算法前先读） |

## 怎么跑

```bash
PY="C:/Users/毛宇淇/AppData/Local/Programs/Python/Python313/python.exe"
# 离线演示（最小路径，零依赖）
"$PY" python/demo.py --out demo/demo-rules.db

# 重建双版本 rules.db（会拒绝覆盖已存在的输出；四表行内容必须逐字一致才算安全改动）
"$PY" python/build_multiversion_rules.py \
  --base baseline_android14/rules.db \
  --calibration device_calibration/permissions-car-android15.jsonl \
  --property-ids device_calibration/vhal-property-ids-device35.json \
  --cpm-signatures device_calibration/cpm-signatures-device35.json \
  --device-facts device_calibration/device-facts.json \
  --enable-types over_permission,sensitive_read \
  --out rules_library/rules.db

# Android 工程（JAVA_HOME 必须是 D:\Anroid\JDK；首次构建联网走阿里云）
cd android && ./gradlew :app:assembleDebug
"$PY" tools/verify_schema_parity.py          # schema.sql ↔ rules.db ↔ Room 1.json

# 设备侧（应用跑在 user 10！）
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell pm clear --user 10 com.vscanner.rules   # 换过资产必须执行，且必须带 --user 10
adb shell am start -n com.vscanner.rules/.MainActivity
```

## 本目录的坑（全部实测，细节见 README「在真实设备上构建与验证」）

- **预置库是粘性的，`pm clear` 不加 `--user 10` 是假成功**：`adb shell` 默认 user 0 上下文，
  会打印 `Success` 却只清掉不存在的那份；应用跑在 user 10，旧库原封不动。
- **0 字节/垃圾字节/截断的 rules.db，Room 全部不报错**：走 onCreate 自建空表，
  查询返回 0 行。所以 RulesVerifier 必须**显式比对期望条数**，不能只靠捕获异常。
- **android-15 行是设备实测，`definition_status` 只能是 `pending`**，严禁标 `source_verified`
  ——android-15 源码镜像在本网络不可达，给设备观测安源码出处就是伪造来源（D009）。
- **15 版风险规则溯源被拆开**：`basis_refs_json`（项目策略）原样保留，
  `source_refs_json`（AOSP 14 commit 引用）替换成设备观测记录。设备侧测试锁定这条不变式。
- 编译环境：compileSdk 只能取 36（已装平台里唯一带 `android.car.jar` 的）；
  Gradle 仓库**阿里云优先**（`dl.google.com` 不通）；非 ASCII 工程路径需 `android.overridePathCheck=true`。

## 状态（2026-09-24）

已完成双版本规则库、Room验证与schema parity。当前资产SHA256与RulesVerifier同步。
2026-09-24启用每版8条data_egress规则，window_ms=30000、revision=2；见EGRESS_CALIBRATION.md。
核对修改前备份库，8个属性已有读取规则（CURRENT_GEAR=R004）；旧的3/8描述不准确。
报告/看板按输入规则动态计算覆盖缺口，不预设存在或不存在。
不得将Android15设备观测的pending来源改成源码已核实。
