# 车载规则库的敏感面覆盖与缺口（可复算）

> 日期：2026-11-10 ｜ 范围：`vehicle/rules/` 四版本规则库（v15 = 设备观测）｜ **纯只读分析**
> 复跑脚本：`output/_vehicle-coverage/`（`output/` 不入库）
> 未改动：`rules.db`、`dangerous_apis`、任何 hook / 前端代码；未下载新样本；未提交未推送。

## 0. 一句话结论

规则库对车载敏感面的判定能力，集中在**一个属性面 × 8 个 VHAL 属性**上：
254 个设备实测 `VehicleProperty` 常量里只覆盖 8 个（3.15%）；
19 个 VHAL 读/订阅/回调签名里 12 个有独立钩子（63.2%）、只有 3 个在 `dangerous_apis` 登记（15.8%）。
**注意（2026-11-10 二次核验更正）**：判定链是 `VHAL_READ{prop_id}` → 求值器按
`condition_json.property_id` 匹配，**`api_key`/登记不参与判定**。因此"登记了几条"与
"能不能出结论"是两件事，本文件第 3 节的三态标签已据此更正，见 §3.1。
订阅通道、异步读、属性面元数据读在**规则层**完全没有判定能力——但订阅/回调类 7 个签名
全部有独立钩子（补 `registerCallback` 后），异步读与元数据读 6 个签名 0 钩子；
所以「规则库看不见」与「平台看不见」不是同一件事，两者必须分开报。

---

## 1. 口径定义（独立于规则库）

**为什么不从 `dangerous_apis` 反推。** 若分母取自规则表，则"覆盖"必然接近 100%，
因为它测的是"规则有没有引用自己"。本口径的三层枚举来源全部在规则库之外：

| 层 | 内容 | 枚举来源（非 rules.db） | 签名数 |
| --- | --- | --- | --- |
| **L-A** | VHAL 车辆属性通道：`CarPropertyManager` 的读 / 异步读 / 元数据读 / 订阅 / 回调 | `vehicle/rules/device_calibration/cpm-signatures-device35.json`（设备端反射导出的 96 项签名） | **19** |
| **L-B** | 其它车载系统能力：`CarInfoManager` / `CarOccupantZoneManager` / `CarSensorManager` / `CarUxRestrictionsManager` / `CarAudioManager` / `CarPackageManager` / `CarPowerManager` / `CarRemoteAccessManager` / `CarWatchdogManager` / `CarAppFocusManager` | SDK 公开 stub `platforms/android-36/optional/android.car.jar`，机械规则：类在名单内 + 方法名以 `get/is/register/subscribe/request` 开头 + 返回非 void（10 个候选类中 `CarRemoteAccessManager` 无匹配方法，实际产出 9 类） | **37** |
| **L-C** | 通用移动敏感能力 8 类：定位 / 麦克风 / 相机 / 通讯录 / 剪贴板 / 存储 / 已装应用 / 设备标识 | 显式枚举 Android 框架公开 API（`surface.py: LC_ITEMS`），逐项在文档中可复核 | **22** |

**为什么这些算车载敏感面。** 车载场景新增的风险来自"车辆状态本身就是个人数据"：
VIN 可标识车辆与车主、车速/挡位/里程/油门可推断驾驶行为与出行轨迹、
电量/油量可推断行程、HVAC 可推断车内是否有人。L-B 覆盖"车辆 + 乘员 + 已装应用"这类
车载专属侧信道（例如 `CarPackageManager` 暴露车机上的应用清单）。
L-C 是车载 App 与手机 App 共享的常规敏感面——**它的数字不能替代车载数字**，
单独列出只用于说明"同一份规则库在通用面与车载面的登记策略不同"。

**VHAL 属性面**：`device_calibration/vhal-property-ids-device35.json` 的 254 个常量。
交叉核对：SDK `android-36` 的 `VehiclePropertyIds` 有 **250** 个 int 常量，设备侧多 4 个
（OEM/vendor 或已废弃项），说明 254 作为分母基本完整。

---

## 2. 两个分母，以及为什么它们会给不同结论

| 分母 | 定义 | 本测量的值 |
| --- | --- | --- |
| **签名面** | 去重后的 API 形态数（类 + 方法 + 描述符） | L-A 19 / 登记 3 / 被规则消费 1 |
| **调用点加权** | 样本里实际出现的 `invoke-*` 次数 | 4 个样本合计 1,381,307 次 invoke；其中 `android.car.*` 目标 59 次；L-A 面 4 次；被规则覆盖 1 次 |

**为什么可能不同。** 签名面衡量"规则库的判定宽度"，调用点加权衡量"实际风险暴露"。
一个只被 1 个样本调用 1 次、但登记完整的签名，在签名面是 100% 覆盖、在调用点面可能只占 5%；
反之 `subscribePropertyEvents` 有 5 个重载而规则一条都没登记，签名面记 0/5，
但真实 App 只要用其中一个就能持续拿到车辆数据，风险权重远高于"一个罕见读重载"。
**两种口径都对，回答的是不同问题**：签名面答"规则库还缺哪些能力"，
调用点面答"这些缺口在真实样本里有没有被踩到"。

---

## 3. 签名面：三态 + 钩子列（L-A 逐项）

状态定义（严格区分，不合并为"覆盖不足"）：

- **S1 真正覆盖**：登记了，且至少一条规则消费它 → 能产出候选
- **S2 有行无钩子**：登记了，但没有任何规则消费 → 最容易被误算成"已覆盖"
- **S3 结构性不可见**：完全没登记

| # | 签名 | 状态 | 有独立钩子 |
| --- | --- | --- | --- |
| 1 | `getProperty(II)` | **S1** 有钩子，观测 8 属性即出候选 | 是 |
| 2 | `getProperty(Class, II)` | **S1** 有钩子，同上（原标 S2，已更正见 §3.1） | 是 |
| 3 | `getFloatProperty(II)` | **S1** 有钩子，同上（原标 S2，已更正见 §3.1） | 是 |
| 4 | `getIntProperty(II)` | S3 未登记 | 是 |
| 5 | `getBooleanProperty(II)` | S3 未登记 | 是 |
| 6 | `getIntArrayProperty(II)` | S3 未登记 | 否 |
| 7 | `getPropertiesAsync(List, long, CancellationSignal, Executor, Callback)` | S3 未登记 | 否 |
| 8 | `getPropertiesAsync(List, CancellationSignal, Executor, Callback)` | S3 未登记 | 否 |
| 9 | `getPropertyList()` | S3 未登记 | 否 |
| 10 | `getPropertyList(ArraySet)` | S3 未登记 | 否 |
| 11 | `getCarPropertyConfig(int)` | S3 未登记 | 否 |
| 12 | `isPropertyAvailable(II)` | S3 未登记 | 否 |
| 13 | `subscribePropertyEvents(I, CB)` | S3 未登记 | 是 |
| 14 | `subscribePropertyEvents(I, float, CB)` | S3 未登记 | 是 |
| 15 | `subscribePropertyEvents(II, CB)` | S3 未登记 | 是 |
| 16 | `subscribePropertyEvents(II, float, CB)` | S3 未登记 | 是 |
| 17 | `subscribePropertyEvents(List, Executor, CB)` | S3 未登记 | 是 |
| 18 | `registerCallback(CB, int, float)` | **S3** 未登记规则，但**已挂钩子**（2026-11-10 补） | 是 |
| 19 | `CarPropertyEventCallback.onChangeEvent(CarPropertyValue)` | S3 未登记 | 是 |

聚合：

| 层 | 签名数 | 登记（`dangerous_apis`/`api_key`） | 有独立钩子 | 未登记 |
| --- | --- | --- | --- | --- |
| L-A | 19 | 3 (15.8%) | 12 (63.2%) | 16 (84.2%) |
| L-B | 37 | 0 | 0 | 37 |
| L-C | 22 | 0 | 7 | 22 |

> 「登记且被规则消费」这一列已删除：它按 `api_key` 统计，而求值器**不看** `api_key`（见 §3.1）。
> 原表的 1 (5.3%) 无判定意义；「有独立钩子」由 11 更正为 12（补 `registerCallback`）。

### 3.1 勘误：`getProperty(Class,II)` 到底缺什么（2026-11-10 核验）

先前记过一句「`getProperty(Class,II)` 钩子挂了但 0 条规则消费，导致观测到也不出结论」。
**该判断是错的**，核验如下：

- `vehicle/analyze/evaluation.py` 的 `evaluate_sensitive_read()` / `evaluate_data_egress()`
  只按 `json.loads(rule['condition_json'])['property_id']` 与事件的 `prop_id` 比对，
  **没有任何一处读 `api_key`**。
- `risk_rules` 的 16 条 `api_key`（全部指向 `getProperty(II)`）是**描述性元数据**，
  不参与匹配；`vhal_properties` 也没有 `data_type_key` 列（列名是 `api_key` / `property_key`）。
- 因此这是**第三种情况**：既不是"规则库缺 `data_type_key`"，也不是"规则在但求值器没接"——
  `api_key` 本来就不在判定链上。`getProperty(Class,II)` 只要读到 8 个 watch 属性之一，
  照样进 `VHAL_READ` 并产出候选。

结论：**本轮不动规则库**，也没有"要加哪条规则 / 影响多少条计数"这回事（需要新增的规则行为 0）。

按能力分组（L-A 内部）：

| 分组 | 签名数 | 有钩子 |
| --- | --- | --- |
| L-A1 同步读 | 6 | 5 |
| L-A2 异步读 | 2 | 0 |
| L-A3 属性面元数据读 | 4 | 0 |
| L-A4 订阅/注册（含 `registerCallback`） | 6 | **6** |
| L-A5 回调通道（`onChangeEvent`） | 1 | 1 |

**规则侧的结构事实**：v15 的 29 条规则中 16 条绑定 `api_key`，全部指向同一个
`getProperty(II)`；另外 13 条（`over_permission` 6 / `sensitive_read` 5 / `data_egress` 2）
走 evaluator + 值匹配，不绑定 API 签名。`dangerous_apis` 的 3 行里有 2 行无人消费。

---

## 4. 逐样本实测（本地已有车载样本，未下载新样本）

样本取自 `output/p1p2-runtime/` 与 `output/vehicle-samples-20261102/`；
统计方式为自写 DEX 解析器（`dexparse.py`，纯标准库）逐条解码 `invoke-*` 指令，
不是推断、不是 `strings` 匹配。

| 包名 | 总 invoke | `android.car.*` 目标 | L-A | L-B | L-C | 口径外 `android.car` |
| --- | --- | --- | --- | --- | --- | --- |
| `com.tommasov.mg4browser` | 98,186 | 0 | 0 | 0 | 13 | 0 |
| `hu.muzso.fileslauncher` | 9,863 | 2 | 0 | 0 | 2 | 2 |
| `de.vito0912.yaabsa` | 214,217 | 0 | 0 | 0 | 31 | 0 |
| `io.homeassistant.companion.android.minimal` | 1,059,041 | 57 | 4 | 2 | 36 | 51 |
| **合计** | **1,381,307** | **59** | **4** | **2** | **82** | **53** |

> 原表另有「L-A 被规则覆盖 = 1」一列，已删除：该列按 `api_key` 静态推算，而判定实际取决于
> 运行时 `prop_id`（见 §3.1），静态推不出来。

**只有 1 个样本真正读 VHAL**（HA）。`mg4browser` / `fileslauncher` / `yaabsa` 静态代码里
`CarPropertyManager` 读取调用点为 **0**——它们只调 `Car.createCar` / `Car.getCarManager`
拿 manager 对象，或根本不接车机（`yaabsa` 连 `android.car` 都没有）。
**所以调用点加权这一列，实际上由 1 个样本的 4 次调用决定，代表性有限，见 §7。**

HA 的 VHAL 调用点落在同一个类 `PropertyRequestProcessor` 里：其中 4 次命中 L-A 口径，
另 1 次是 `unregisterCallback`（解除订阅，不计入读取面）；这 5 处调用正好各踩一类缺口：

| 调用点所在方法 | 目标签名 | 状态 | 后果 |
| --- | --- | --- | --- |
| `fetchCarPropertyProfiles` | `getProperty(II)` | S1 | 能产出候选（若属性在 8 个 watch 内） |
| `fetchCarPropertyValues` | `getProperty(Class, II)` | **S1**（原标 S2，见 §3.1） | 有钩子且按 `prop_id` 判定 → 能产出候选 |
| `getPropertyConfig` | `getPropertyList(ArraySet)` | S3 | 规则与钩子都没有 → 属性清单读取完全不可见 |
| `registerProperty` | `registerCallback(CB, int, float)` | 规则 S3 / **钩子已补（§10）** | 钩子已覆盖，规则层仍无判定 |
| `unregisterProperty` | `unregisterCallback(CB, int)` | S3 | 同上（属解注册，不计入读取面） |

`registerCallback` 这条是可验证的具体洞：静态证据显示 HA 用 `registerCallback` 建立订阅，
而修复前的 `subscription_hooks.js` 只遍历 `CPM.subscribePropertyEvents.overloads`。
即**该样本的注册型调用在当时的动态观测下必然不会被记录**。该缺陷已于 2026-11-10 修复，
并在真机上验证钩子生效——但 HA 自身的运行时并不走这条路径，见 §10.4。

---

## 5. 缺口按形态拆分

要求的三类，在本次测量里的实际归属：

**(a) 整类未登记**
- L-B：9 个能力型 Manager 类、37 个签名，登记数 0。
- L-C：8 个能力类别、22 个签名，`dangerous_apis` 登记数 0。
  （注意：其中 5 类有**独立的隐私钩子** `privacy_targets.generated.js` 覆盖——
  定位、麦克风、通讯录、Android ID、AAID——这是"签名未登记但另有观测通道"，
  不能与"完全不可见"混为一谈。）

**(b) 类已登记但方法未登记**
- `CarPropertyManager` 类已登记，但 19 个签名里 16 个未登记（84.2%）。
  最要紧的是**整个订阅通道**（`subscribePropertyEvents` 5 个重载 + `registerCallback`
  + `onChangeEvent`）和一个**整个异步读通道**（`getPropertiesAsync` 2 个重载）。
  这两类都是"持续获取"而非"点读"，在隐私风险上权重更高。

**(c) 罕见 / 非主重载**
- `getProperty(Class, II)`：登记了，但 16 条规则全部只引用 `getProperty(II)` →
  S2。这类最容易在统计里被误算成"已覆盖"。
- `subscribePropertyEvents` 的 5 个重载（含带 `float rate` 与 `List` 版本）全部未登记。
- `getPropertiesAsync` 带 `long timeout` 的重载与无 timeout 重载，均未登记。
- `getPropertyList()` 与 `getPropertyList(ArraySet)` 两个重载，均未登记。

---

## 6. VHAL 那 8 个属性

| 项 | 值 |
| --- | --- |
| 设备实测 `VehicleProperty` 常量总数 | **254** |
| SDK `android-36` 公开 `VehiclePropertyIds` int 常量数（交叉核对） | **250** |
| 规则库 `vhal_properties` 行数（每版） | **8** |
| 8 / 254 | **3.15%** |
| 8 / 250（仅公开常量） | 3.20% |

8 个属性：`INFO_VIN`、`PERF_VEHICLE_SPEED`、`GEAR_SELECTION`、`CURRENT_GEAR`、
`PERF_ODOMETER`、`ENGINE_RPM`、`FUEL_LEVEL`、`EV_BATTERY_LEVEL`
（与 `hook_vhal.js` 的 `CFG.watch` 逐项一致，也与设备常量表逐值一致，已校验）。

**"还有多少属性是可读但规则库没管"——本地无法给出精确数字，原因如下（不猜）：**

- 属性 ID 的位布局里，access（READ/WRITE）字段位置**无法用本地数据可靠反推**。
  实测：按常见掩码解码后，`INFO_VIN` / `GEAR_SELECTION` / `CURRENT_GEAR` 解出空 access、
  `EV_BATTERY_LEVEL` 解出 W，与 AOSP 文档已知的 READ 语义矛盾；而值类型字段
  （bits 20-23）解码结果与已知值一致（STRING=1 / INT32=4 / FLOAT=6），说明只有 access 位对不上。
  在这种矛盾下给出"N 个可读"就是编造。
- 精确的可读子集需要 AOSP `VehicleProperty.aidl` 的属性→权限映射，或真机
  `CarPropertyManager.getPropertyList()` 的反射导出。**两者本地都没有**：
  前者需要 AOSP 源码树（本机镜像只有 rules 侧的 seed 抽取，不含 VHAL 定义），
  后者需要启动 AAOS 模拟器并跑导出脚本（超出"纯只读分析、不启设备"的边界）。
- 可以确定的定性事实：254 个常量里包含大量 write-only 执行器（HVAC 设定、车窗、
  座椅调节等）与 OEM/vendor 私有属性，**App 实际"读"的面显著小于 254**。
  因此 3.15% 是**分母偏大的下界**，不是"漏报率"。

---

## 7. 这段数字能说什么、不能说什么

### 能说

1. 规则库对 VHAL 的判定宽度是 **1 个同步读签名 × 8 个属性**；订阅、异步读、元数据读
   在**规则层**没有任何判定能力（S3）。这三个数字（1 / 3 / 19、8 / 254）都可复算。
2. `dangerous_apis` 有 **2 行无人消费**（`getFloatProperty`、`getProperty(Class, II)`）——
   这是"有行无钩子"，在按"登记数"统计覆盖时会被算成已覆盖。
3. 现有钩子面**宽于**规则库面（11 / 19 vs 3 / 19），所以"规则库没登记"不等于"平台看不到"；
   反过来 `registerCallback` 是钩子也没覆盖到的实际使用点（HA 已踩到）。
4. 4 个本地车载样本里 3 个静态代码没有任何 VHAL 读取——说明"车载 App"不等于"读车辆数据的 App"，
   用样本数当覆盖率分母会严重失真。

### 不能说

1. **"不可见 96.85%" 不是漏报率。** 分母是"能力面"（254 个属性常量 × 19 个签名），
   分子是"规则库登记的形态"。漏报率的分母必须是"样本里真实发生的行为"。
   本测量给出的是**判定宽度**，不是**判定错误率**——后者需要人工标注的真值集，
   当前没有（参见项目既有口径：无独立标注前不计算 precision/recall）。
2. **"未观测到读取"不能反过来当"没有读取"。** 3 个样本的 L-A 调用点为 0，
   只说明静态代码里没有直接 invoke；反射、JNI、动态代理、AIDL 自实现都可能绕过。
3. **不能把 L-C 的数字当成车载结论。** 通用敏感面在 4 个车载样本里命中 82 次，
   但这与"车机专属风险"是两件事；本报告只把 L-C 用作对照。
4. **调用点加权列不能外推。** 它由 HA 单个样本的 4 次调用支撑，
   `n=1` 的样本量不足以谈分布。
5. **静态调用点无法确定 `propertyId`。** 已尝试反汇编 `PropertyRequestProcessor`
   的 `const` 字面量，未取到 254 个属性 ID 中的任何一个（属性 ID 来自字段/参数，不是立即数）。
   因此**无法判断 HA 实际读的是否就是那 8 个 watch 属性**——需要数据流分析或动态采集。

### 本地无法评估（需什么条件才能补）

| 缺口 | 缺的条件 |
| --- | --- |
| 每个属性的 READ/WRITE 真值 | AOSP `hardware/interfaces/automotive/vehicle/aidl/.../VehicleProperty.aidl` 源码树，或真机跑 `getPropertyList()` 反射导出 |
| 样本实际读的属性 ID | 启动 AAOS 模拟器 + Frida 采 `VHAL_READ`（本分析限定为纯只读、不启设备） |
| AAID / GMS 类在车载环境的可达性 | 带 Google Play services 的 automotive 镜像（本机 `system-images/` 无 automotive 镜像） |
| L-B 在真实样本上的调用点 | 目前只有 HA 命中 2 次（`CarUxRestrictionsManager`）；样本池不足 |
| 漏报率 / 精确率 | 人工标注真值集（`n≤6` 也不可外推） |

---

## 8. 复跑

```powershell
.\tools\python313.ps1 output\_vehicle-coverage\surface.py      # 生成口径枚举 surface.json
.\tools\python313.ps1 output\_vehicle-coverage\sample_stats.py # 生成样本调用点 samples.json
.\tools\python313.ps1 output\_vehicle-coverage\coverage.py     # 生成覆盖率数字 coverage.json
```

| 文件 | 作用 |
| --- | --- |
| `dexparse.py` | 纯标准库 DEX 解析器：方法表 + `invoke-*` 调用点（含 payload 跳过与指令宽度表） |
| `classfile.py` | 最小 class-file 解析器：提取 SDK stub 的 public 方法签名 |
| `surface.py` | 三层口径枚举（L-A 显式 / L-B 机械 / L-C 显式），不读 `rules.db` 作分母 |
| `sample_stats.py` | 逐样本调用点统计 |
| `coverage.py` | 与 `rules.db` 的登记/消费关系做 join，输出三态与聚合表 |

口径变更时只需改 `surface.py` 顶部的列表，其余脚本无需改动。

---

## 9. 与既有文档的关系

- 本报告只回答"规则库判定宽度与缺口在哪"，不改任何规则、不增删除规则行。
- 与 `vehicle/coverage/generated/COVERAGE.md` 的关系：后者是"规则 → 证据"的覆盖链，
  本报告是"能力面 → 规则"的反向缺口；两者口径不同，数字不可相加或相除。
- 与 `mobile/analyze/coverage_gap.py`（移动端静态/动态覆盖差集）的关系：
  同一思路的移动端实现，但本报告的签名分母来自设备反射导出的 `android.car` API，
  不是 `dangerous_apis`。

---

## 10. `registerCallback` 覆盖补齐（2026-11-10 修复记录）

### 10.1 重载清单（`javap -s`，不凭印象）

来源：`%LOCALAPPDATA%\Android\Sdk\platforms\android-36\optional\android.car.jar`，
命令 `javap -s -classpath <jar> android.car.hardware.property.CarPropertyManager`，
原始输出保存为 `output/_vehicle-coverage/javap-cpm-registration.txt`。

**`registerCallback` 只有 1 个重载**：

| # | 签名 | 描述符 |
| --- | --- | --- |
| 1 | `public boolean registerCallback(CarPropertyEventCallback, int, float)` | `(Landroid/car/hardware/property/CarPropertyManager$CarPropertyEventCallback;IF)Z` |

对照组 `subscribePropertyEvents` 有 **5 个重载**（`(I,CB)` / `(I,F,CB)` / `(I,I,CB)` /
`(I,I,F,CB)` / `(List,Executor,CB)`，全部 `→ boolean`），这就是修复前 `ARMED` 里
`"subscribePropertyEvents (runtime overloads)"` 的实际覆盖面。

### 10.2 改了什么

`vehicle/hooks/subscription_hooks.js` 由"只遍历 `subscribePropertyEvents`"改为
"两条注册路径分别遍历各自全部重载"：

- 两条路径共用 `hookRegistration(methodName, source, eventName)`，按参数类型
  （`CarPropertyManager$CarPropertyEventCallback`）定位第几个实参，**全部重载都挂**，
  去掉 `findIndex` 命不中的重载（当前为 0 条）。
- 只观测：`original.apply(this, args)` 先执行、返回值原样 `return`、异常原样 `throw`；
  记录失败被 `try/catch` 罩住，不会把异常抛回被挂方法（D310 的老坑）。
- **两种来源分别计数**，不混算：
  - `SUBSCRIPTION_REGISTER`（`source:'subscribe'`）—— 持续接收属性变化
  - `CALLBACK_REGISTER`（`source:'registerCallback'`）—— 把回调对象交给系统
  - 显式 ABSENT：`SUBSCRIPTION_REGISTER_ABSENT` / `CALLBACK_REGISTER_ABSENT`
- `VHAL_READ` 增加 `registration_source`（数组）与 `callback_target`，同一回调被两条路径
  注册过时两者都会出现，`SUBSCRIPTION_CALLBACK_ARMED` 用 `already_armed:true` 表示不重复挂。

### 10.3 改动前后对比（真机 emulator-5554，HA 样本）

`ARMED` 行是最硬的差异证据（`subscription_hooks.js` 自己上报挂了什么）：

| | `ARMED.hooks` |
| --- | --- |
| 改动前 | `["cpm.getProperty(II)","cpm.getProperty(Class,II)","cpm.getFloatProperty(II)","cpm.getIntProperty(II)","cpm.getBooleanProperty(II)","subscribePropertyEvents (runtime overloads)"]` |
| 改动后 | `[...,"subscribePropertyEvents x5","registerCallback x1"]` |

**"改动前那些事件丢在哪一步"= 没挂，不是挂了没落盘。** 依据是 `ARMED` 里根本没有
`registerCallback` 条目；若挂了但落盘失败，`ARMED` 会列出它而日志里出现 `ERROR`。

样本自身在观测窗口内**没有**产生任何 CPM 事件（`SUBSCRIBED`/`VHAL_READ` 均为 0），
所以纯 A/B 只能得到 0→0。原因已定位（见 10.4），因此改用**进程内只调用公开 API 的探针**
（`harness_ab.py`，只调用 `registerCallback` / `subscribePropertyEvents`，
不修改被测应用逻辑）把两条路径各走一次：

| 事件 | 改动前 | 改动后 |
| --- | --- | --- |
| `CALLBACK_REGISTER`（`source:'registerCallback'`） | **0** | **1**（`accepted:false`） |
| `SUBSCRIPTION_REGISTER_ERROR`（`source:'subscribe'`） | 2（无 `source` 字段） | 2（有 `source` 字段） |
| `SUBSCRIPTION_CALLBACK_ARMED` | 1 | 3（含 `already_armed:true` 与 `sources:["registerCallback","subscribe"]`） |
| 合计 | 3 | 6 |

`accepted:false` 是真实语义：`PERF_VEHICLE_SPEED` 对第三方不可读，框架 `registerCallback`
**返回 false 而不是抛异常**，`subscribePropertyEvents` 则抛 `SecurityException`。两种返回值/异常
语义在 Hook 前后完全一致，符合"只观测不改行为"。

原始日志：`output/_vehicle-coverage/ha_harness_{before,after}.jsonl`。

### 10.4 HA 为什么自身不产生事件（重要，别误读成"钩子没生效"）

静态事实：HA 的 `registerCallback` 调用点在
`androidx/car/app/hardware/common/PropertyRequestProcessor.registerProperty(IF)V`（1 处）。
运行时探针（`probe_cpm.py`）结果：

- `PropertyRequestProcessor` / `CarHardwareManager` / `CarPropertyManager` **类都已加载**；
- 但 `PropertyRequestProcessor` 的 4 个方法（`registerProperty` / `unregisterProperty` /
  `fetchCarPropertyProfiles` / `fetchCarPropertyValues`）在 35s 窗口内**调用 0 次**；
- dex 里没有任何代码调用 `CarSensors`；HA 只用 `HaCarAppService$onCreateSession$1`
  → `CarHardwareManager.getCarInfo()`。`registerProperty` 只被 `AutomotiveCarSensors`
  （加速度计/陀螺仪/指南针/定位）用到，**HA 不走这条路**。

结论：`registerCallback` 对这个样本是**承重为零的静态调用点**；补钩子是对的（同类 App 会用），
但不能把"HA 没事件"当成钩子失败的证据。要拿到 HA 自身的事件，需要它的车机模板真正在前台渲染
并启用 CarSensors，本机当前状态下做不到。

### 10.5 下一步（本轮**未动**，等确认可复算性）

- `getPropertiesAsync(List, long, CancellationSignal, Executor, Callback)` 与
  `getPropertiesAsync(List, CancellationSignal, Executor, Callback)`
- `getPropertyList()` / `getPropertyList(ArraySet)`
- `getCarPropertyConfig(int)` / `isPropertyAvailable(II)` / `getIntArrayProperty(II)`
- `unregisterCallback` / `unsubscribePropertyEvents`（解注册，用于成对计算订阅时长）

补这些会**新增事件类型**，已封存的采集产物将无法与新版钩子逐条对齐；按用户要求先确认
再动。`vehicle/coverage/export.py` 的 `async_getProperties: 'not_hooked'` 说的就是这批。

### 10.6 待统一重建的 bundle

本轮只重建了 `vehicle/hooks/dist/hook_vhal.bundle.js`（`752550` 字节，含新钩子）。
`hook_vehicle_all.bundle.js` 也 import 了 `subscription_hooks.js`（经 `hook_vhal.js`），
**但它仍是旧构建**；没有顺手重建的原因是它同时 import 了 `ssl_pinning_bypass.js` /
`hook_privacy.js`，而这两个文件当前有**别人的未提交改动**，重建会把那些改动一起固化进
dist，超出本轮范围。等那批改动定稿后统一跑：

```powershell
.\tools\python313.ps1 -m core.frida_host.build --platform vehicle   # 或 --only hook_vehicle_all.js
```

在此之前，凡是用 `hook_vehicle_all` 的采集**还没有 `registerCallback` 覆盖**，
只有 `hook_vhal` 单文件路径有。

