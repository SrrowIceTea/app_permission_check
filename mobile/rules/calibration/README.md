# calibration/ —— 设备实测标定（可选输入）

仅用于授权测试（已获授权的样本与设备）。

`build_mobile_rules.py` 会在构建时读本目录下的 **`permissions-device.jsonl`**（若存在），
把设备实测到的 `protectionLevel` 写进 `permissions.protection_level_raw` /
`protection_level_value`。没有这个文件时，这两列保持 NULL，构建摘要里会写明
`permissions_protection_level.asserted = 0/N` —— **这是当前状态，不是「已完成」**。

## 为什么需要它

`over_permission` 规则要判「清单里声明的隐私权限是否超出必要范围」，
权限的**保护级别**（normal / dangerous / signature / privileged …）是关键维度：
`dangerous` 才是用户可见可拒的隐私权限，`signature` 只给系统同签名应用。
目前 40 条移动隐私权限种子的保护级别全部未断言，所以该维度是空的。

**注意**：设备实测**不等于**源码事实。schema 规定 `definition_status` 只能是
`source_verified`（= 从可核对的权威来源抽取，本库即 `javap` 输出）或 `pending`，
而设备观测一律记 `pending`。本文件提供的是 `protection_level_raw` 的值，不是分级依据。

## 怎么产出

`vehicle/rules/python/extract_device_calibration.py` 是平台无关的解析器（默认前缀
`android.car.`，改参数即可用于手机权限）。**它自己从不调用 adb**，只吃已保存的文本输出：

```bash
# 1) 在已授权的设备上抓 pm 输出（-f 才会带 protectionLevel，-d 只给 dangerous 组，不要用）
adb shell pm list permissions -f -g > permissions-phone-android35.txt

# 2) 解析成标定文件（复用车载那份解析器，只换前缀）
PY="$LOCALAPPDATA/Programs/Python/Python313/python.exe"   # 原开发机是 C:/Users/毛宇淇/...
"$PY" vehicle/rules/python/extract_device_calibration.py \
      --pm-output permissions-phone-android35.txt \
      --prefix android.permission. \
      --out mobile/rules/calibration/permissions-device.jsonl \
      --summary mobile/rules/calibration/permissions-device.summary.json

# 3) 重建规则库（会读上面的 jsonl）
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

`protection_level_value` 由 `build_mobile_rules.py` 按 AOSP 位值表（normal=0、
dangerous=1、signature=2、privileged=4、instant=0x1000 …）自动按位或算出；
出现认不出的级别词时该列留 NULL（**不编造**），原始串仍保留在 `protection_level_raw`。

## 不可越过的边界

- 「未观测到」不等于「不存在」；`-f` 输出覆盖不全时会缺项，缺项**不得**当成无此权限。
- 设备指纹（机型/构建指纹）必须随标定文件一起留存，否则实测值的适用范围无法回溯。
