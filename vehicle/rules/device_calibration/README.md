# android-15 设备实测校准

本目录是从**测试设备**采集的原始证据，用于建立规则库的 android-15 部分。
这些是**设备观测**，不是源码抽取：`definition_status` 一律保持 `pending`，
来源写进 `device_calibration_json`，**不得**标成 `source_verified`。

之所以走设备而不是源码：`android.googlesource.com` 不可达，镜像仓库没有可用的
`android-15.0.0_r1` 参照（详见 `../DECISIONS.md` D009）。

## 设备

| 项 | 值 |
| --- | --- |
| 实例 | `emulator_car64_x86_64`（AVD `Automotive_1408p_landscape`） |
| fingerprint | `google/sdk_gcar_x86_64/emulator_car64_x86_64:15/AAI5.260516.001.A1/15446886:userdebug/test-keys` |
| 版本 | Android 15 / API 35 / userdebug |
| 安全补丁 | 2025-12-05 |
| 应用运行用户 | **user 10** |

## 内容

| 文件 | 是什么 |
| --- | --- |
| `permissions-full.txt` | `adb shell pm list permissions -f -g` 的原始输出（1495 个权限块） |
| `permissions-car-android15.jsonl` | 抽出的 146 条 `android.car.*`，含 protectionLevel |
| `permissions-car-android15.summary.json` | 抽取摘要：条数、缺 protectionLevel 的、重名冲突 |
| `permissions-general-android15.jsonl` | 同一份 pm 输出白名单抽出的 4 条通用权限（定位×2 / 录音 / 通讯录） |
| `vhal-property-ids-device35.json` | 设备 `VehiclePropertyIds` 全部 254 个常量 |
| `cpm-signatures-device35.json` | 设备 `CarPropertyManager` 全部 96 个方法签名 |
| `android.car.jar` | 设备 `/system/framework/android.car.jar`（1.4 MB，内含 `classes.dex`） |
| `device-facts.json` | 上述设备身份属性 |

## 重新采集

电脑执行，设备需在线。`-f` 是关键，`-d` 只会列出 dangerous 组。

```bash
# 本机 SDK 在 %LOCALAPPDATA%\Android\Sdk（原开发机是 D:/Anroid/SDK）
export PATH="$(cygpath -u "$LOCALAPPDATA")/Android/Sdk/platform-tools:$PATH"; export MSYS_NO_PATHCONV=1
cd vehicle/rules/device_calibration
adb shell pm list permissions -f -g > permissions-full.txt
adb pull /system/framework/android.car.jar ./android.car.jar
```

重新解析 dex（中间文件不入库，可随时重建）：

```bash
python -c "import zipfile;open('classes.dex','wb').write(zipfile.ZipFile('android.car.jar').read('classes.dex'))"
"$(cygpath -m "$LOCALAPPDATA")/Android/Sdk/build-tools/36.0.0/dexdump.exe" -d classes.dex > dexdump.txt
# 再从 dexdump.txt 里解析：
#   类 'Landroid/car/VehiclePropertyIds;' 的静态字段 value : <int>
#   类 'Landroid/car/hardware/property/CarPropertyManager;' 的方法 name/type 对
```

抽取脚本：`python python/extract_device_calibration.py --pm-output … --device-facts … --out … --summary …`
（不调用 adb，只解析已保存的输出；拒绝覆盖已有文件。）

## 两个值得记住的结论

**1. Phase 0 那句"仅出现 2 个权限、镜像裁剪严重"是误判。**
`pm list permissions -d -g` 的 `-d` 只列 dangerous 组。同一设备改用 `-f` 后列出
**146 个** `android.car.permission.*`：129 个 `signature|privileged`、8 个 `normal`、
4 个 `signature`、3 个 `signature|privileged|vendorPrivileged`，危险的确实只有
**2 个**——`CAR_SPEED` 与 `CAR_ENERGY`。其余的一直都在，只是不属于 dangerous 组。

**2. 设备实测反向印证了源码抽取。**
android-14 抽出的 6 条 protectionLevel 与设备 API 35 **完全一致**
（`CAR_SPEED=dangerous`、`CAR_ENERGY=dangerous`、`CAR_IDENTIFICATION=signature|privileged`、
`CAR_MILEAGE=signature|privileged`、`CAR_ENGINE_DETAILED=signature|privileged`、
`CAR_POWERTRAIN=normal`），8 个 VHAL 属性 ID 与设备 dex 常量逐个相符，
3 个 CPM 读取签名在设备上均存在。说明这批常量在 14→15 之间未变。

附带修正了两处基线记录：CPM 在 API 35 上有 **96 个**方法（Phase 0 记的是 78）；
`subscribePropertyEvents` 的真实返回类型是 `Z`（boolean）而非 `CarPropertyConfig`，
共 5 个重载——基线文档此前声明"未包含该签名"，现在有设备实证可补。

## 使用

```bash
cd vehicle/rules
python python/build_multiversion_rules.py \
  --base baseline_android14/rules.db \
  --calibration device_calibration/permissions-car-android15.jsonl \
  --general-permissions device_calibration/permissions-general-android15.jsonl \
  --property-ids device_calibration/vhal-property-ids-device35.json \
  --cpm-signatures device_calibration/cpm-signatures-device35.json \
  --device-facts device_calibration/device-facts.json \
  --enable-types over_permission,sensitive_read,data_egress \
  --egress-window-ms 30000 \
  --out rules_library/rules.db --summary rules_library/rules.db.summary.json
```

产物 `rules_library/rules.db`：'14' 50 条、'15' 190 条，每版本启用规则 29/29
（6 over_permission + 13 sensitive_read + 10 data_egress）。通用隐私 `VSC-G*` 共 7 条，
包含 O6 新增的 AAID 读取规则。

'15' 的 VHAL 规则沿用 android-14 的策略并独立登记设备来源（DECISIONS D009）：
`basis_refs_json`（POLICY.md，项目策略，与版本无关）原样保留；
`source_refs_json`（AOSP android-14 的 commit 与行号）**不保留**，改为记录本目录采集到的
设备实测值——否则等于给 android-15 的规则安上 android-14 的出处。
不变式由设备侧测试 `android15RulesCarryDeviceProvenanceNotAndroid14SourceRefs` 锁定。

复制进 `android/app/src/main/assets/rules.db` 后，`RulesVerifier.BaselineExpectation`
的条数与 SHA-256 必须同步更新，否则验证页会如实报 schema 不匹配。

2026-11-02 修正：本目录 device-facts 只用于原 VHAL 校准。通用隐私 VSC-G* 来源独立取自
`vehicle/privacy/device-observation.json`，通过 `python/privacy_observation.py` 从真实通过且
输入摘要匹配的采集冻结，指纹和状态逐类型记录，不能沿用本目录旧镜像的信息。
