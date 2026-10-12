# Android 14 参考种子库

本包从 AOSP android-14.0.0_r1 抽取 17 条平台事实，配合 24 条禁用的项目策略草案（8 属性 × 3 谓词，P 按权限去重后 22 条——见 DECISIONS D011），共 41 条种子记录。
源码基线与设备版本是两个概念：用户设备版本尚未建立对应关系，所有新增平台事实均【需实测校准】。
rules.db 可用于离线查看和后续 Room 预置验证，不能据此直接输出设备违规结论。

## 内容

| 表 | 条数 | 范围 |
| --- | ---: | --- |
| permissions | 6 | VIN、车速、能源、里程、发动机详情、动力系统 |
| vhal_properties | 8 | VIN、车速、选定挡位、当前挡位、里程、RPM、燃油、电池电量 |
| dangerous_apis | 3 | CPM 两个 getProperty 重载与 getFloatProperty |
| risk_rules | 22 | 全部 8 个属性：over_permission 6 条（按权限去重）+ sensitive_read 8 条 + data_egress 8 条 |

CAR_SPEED/CAR_ENERGY 的设备存在性记录来自用户已提供的 Phase 0 输出，未重复采集。
它们的源码 protectionLevel 与设备观测分开存储：设备观测不证明源码版本或保护级别相同。
其余权限没有写入虚构的设备验证结果。

## 可追溯来源

- Car commit：`f9a252f4a3b621daabd330531fce555300a1d4c0`。
- hardware/interfaces commit：`40e9f1537e308ed49e3b561ce333e3f2bb64f31e`。
- `sources.lock.json` 保存固定 commit、AOSP URL、传输 URL、文件 SHA-256 和 git blob ID。
- `seed_facts.jsonl` 是抽取结果；`seed_evidence.jsonl` 保存 50 处原始源码摘录及原始行号。
- 抽取器先校验文件哈希，再核对 AIDL/HIDL/Java 属性 ID；不使用运行时反射结果冒充源码事实。
- 两个镜像仅用作传输：Car 来自 LineageOS 仓库中对应的原始 AOSP commit，interfaces 来自 aosp-mirror-neo。
  没有使用 LineageOS 分支上的修改，也没有把镜像 main 当成 Android 版本。
- 固定 tag 和来源可以从 [AOSP Car](https://android.googlesource.com/platform/packages/services/Car/+/refs/tags/android-14.0.0_r1)
  与 [AOSP interfaces](https://android.googlesource.com/platform/hardware/interfaces/+/refs/tags/android-14.0.0_r1) 追溯。

## 两个源码发现

1. 此基线的 `car-lib/AndroidManifest.xml` 只有 1 条匹配权限定义，而 `service/AndroidManifest.xml` 有 130 条。
   当前 6 条种子来自后者，后续全量抽取要合并两个入口并处理重复定义。
2. FUEL_LEVEL 的 Java 注释写 SPEED，但注解与 PropertyHalServiceIds 的服务端映射均为 ENERGY。
   采用服务端映射，并在记录 notes 中保存冲突。没有把注释直接当成执行策略。

## 在电脑离线验证

从上一级 `phase1` 目录执行；你当前使用的 Windows CMD 可以执行下列单行命令。
代码块按项目约定标注 bash，但不使用 Bash 特有语法。

```bash
python -B python/build_seed.py --verify baseline_android14/rules.db
```

没有系统 python 命令时，替换为已有完整路径：

```bash
"C:/Users/OneKyubey/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe" -B python/build_seed.py --verify baseline_android14/rules.db
```

预期：counts 为 6/8/3/22，total_records=41，enabled_rules=0，device_verified=false。
重复验证不会修改数据库。不要求连接设备。

在电脑离线重建到新路径：

```bash
python -B python/build_seed.py --out rebuilt/rules.db
```

使用相同文件、相同 Python/SQLite 构建环境可得到相同数据库 SHA-256；摘要不包含随机路径或时间。
更换 SQLite 版本可能改变数据库字节布局，因此跨版本时还需比较实际记录内容。

## 从原始源码重新抽取

通常无需重下源码；以下用于复现抽取过程。在电脑执行，缓存放工作目录，非设备路径。
第三方原始源码超过 300 行，不作为新编写的项目代码交付；它们按原样保存在源码缓存。

```bash
python -B python/fetch_seed_sources.py --lock baseline_android14/sources.lock.json --out ../../work/aosp-cache --transport mirror
python -B python/extract_seed.py --lock baseline_android14/sources.lock.json --source-root ../../work/aosp-cache --out-dir ../../work/reextracted
```

默认传输为 aosp；示例显式选择经过固定哈希约束的 mirror，适用于本机直连 AOSP 超时的情况。
两个重新抽取的 JSONL 应与本包完全一致；脚本拒绝覆盖已有输出。
源码缓存 SHA 不符立即失败，不能通过忽略校验继续。

## 规则接口与剩余边界

- 规则 ID：VSC-P001～P003、VSC-R001～R003、VSC-E001～E003。
- `POLICY.md` 是规则依据，每条规则保存其版本、条款和文件 SHA-256。
- 3000 ms 是项目实验参数【需实测校准】，不是法规阈值；本轮尚未实现解释器。
- 规则全禁用；时间关联最多给 correlated，读取事实给 observed，权限必要性给 candidate。
- CPM 源码签名不是已验证的注入位置。system_server 中的覆盖范围和原始调用者归属仍需后续验证。
- Generic getProperty 的成功值要检查返回值状态；getFloatProperty 单独返回 0 可能是兼容行为。
- 本基线未包含 subscribePropertyEvents 签名，不以另一版本的注册方法冒充用户设备 API。
- 完整 AIDL 单文件解析有 61 个外部常量引用待解析，本次选定 8 个属性不受影响；全量解析仍未完成。
- Android 编译、Room 装机、设备版本适配、属性支持和权限映射校准未完成。
- Python 仍无新增依赖；沿用前轮 Room 依赖，不改变 schema。

## 许可证

源码摘录保留以下原文件版权声明：

- Copyright (C) 2015 The Android Open Source Project
- Copyright (C) 2016 The Android Open Source Project
- Copyright (C) 2018 The Android Open Source Project
- Copyright (C) 2021 The Android Open Source Project

摘录以 Apache License 2.0 提供，保留原始来源定位；许可证全文见 LICENSE-AOSP.txt。
seed_facts 为程序提取的结构化定义，POLICY 为 V-Scanner 项目草案。
