# calibration/ —— 设备实测标定（可选输入）

仅用于授权测试（已获授权的样本与设备）。

`build_mobile_rules.py` 会在构建时读本目录下的 **`permissions-device.jsonl`**（若存在），
把设备实测到的 `protectionLevel` 写进 `permissions.protection_level_raw` /
`protection_level_value`。没有标定文件时，这两列保持 NULL。

2026-11-27 已冻结 Android 16 / API 36 自有模拟器的 40 条权限观测。设备指纹见
`device-api36.json`，原始输出见 `permissions-api36-pm.txt`，逐条解析与摘要见
`permissions-device.jsonl` 和 `permissions-device.summary.json`。发布库 40 条原文与
整数均已核对。结果适用于该构建，其他系统版本需要各自标定。

## 为什么需要它

`over_permission` 规则要判「清单里声明的隐私权限是否超出必要范围」，
权限的**保护级别**（normal / dangerous / signature / privileged …）是关键维度：
`dangerous` 才是用户可见可拒的隐私权限，`signature` 只给系统同签名应用。
本次设备观测覆盖了 40 条移动隐私权限种子。

**注意**：设备实测**不等于**源码事实。schema 规定 `definition_status` 只能是
`source_verified`（= 从可核对的权威来源抽取，本库即 `javap` 输出）或 `pending`，
而设备观测一律记 `pending`。本文件提供的是 `protection_level_raw` 的值，不是分级依据。

## 怎么产出

`vehicle/rules/python/extract_device_calibration.py` 是平台无关的解析器（默认前缀
`android.car.`，改参数即可用于手机权限）。**它自己从不调用 adb**，只吃已保存的文本输出：

```bash
# 1) 在已授权的设备上抓 pm 输出（-f 才会带 protectionLevel，-d 只给 dangerous 组，不要用）
adb shell pm list permissions -f -g > permissions-phone-android36.txt

# 2) 在本轮 device-api36.json 记录 android_sdk 和 build_fingerprint，再解析
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...
"$PY" vehicle/rules/python/extract_device_calibration.py \
      --pm-output permissions-phone-android36.txt \
      --prefix android.permission. --device-facts device-api36.json \
      --out output/phone-api36/permissions-device.jsonl \
      --summary output/phone-api36/permissions-device.summary.json

# 3) 核验新记录与设备事实后，提供标定目录并重建规则库
export VSCAN_MOBILE_CALIB="$PWD/output/phone-api36"
cd mobile/rules && "$PY" build_mobile_rules.py --force
```

> 不要把 `vehicle/rules/python/calibrate_permissions.py` 当作本步的工具：
> 它只**比对权限名**（并明确写着 "No protection levels inferred"），不抽取保护级别。
> 抽取保护级别的是 `extract_device_calibration.py`。

## 字段

每行一个 JSON，本构建器读两个字段：

| 字段 | 必需 | 说明 |
| --- | --- | --- |
| `permission_name` | 是 | 如 `android.permission.CAMERA` |
| `protection_level_raw` | 是 | 原样字符串，如 `dangerous` / `signature\|privileged`；另兼容 `protection_level` |
| `observation` | 否 | 其它设备观测，原样进 `device_calibration_json` |

提取器生成且包含设备事实的 `provenance` 也会进入 `device_calibration_json`。

`protection_level_value` 由 `build_mobile_rules.py` 按 AOSP 位值表（normal=0、
dangerous=1、signature=2、privileged=0x10、instant=0x1000 …）自动按位或算出；
出现认不出的级别词时该列留 NULL（**不编造**），原始串仍保留在 `protection_level_raw`。
本轮位值逐项对照 SDK 36 的 `data/res/values/attrs_manifest.xml`，该文件 SHA-256 为
`8164b282928162d32dbe775c7fb956adbd724076d8fbe5217a4e3584f5d7f441`。
有 `observation.android_sdk` 的记录只用于同版本规则库。

## 不可越过的边界

- 「未观测到」不等于「不存在」；`-f` 输出覆盖不全时会缺项，缺项**不得**当成无此权限。
- 设备指纹（机型/构建指纹）必须随标定文件一起留存，否则实测值的适用范围无法回溯。
