# 车载定位：采集侧规范形态与误配率离线量化（2026-11-10）

**范围**：只动采集侧（`vehicle/hooks/`）。**未**新增规则行、**未**改启用/禁用计数、**未**重建
`rules.db`、**未**改求值器阈值（`value_len >= 8` 原样保留）、**未**改任何前端。
所有结论仅用于授权测试（自有设备与自有 APK）。

前置文档：[VEHICLE_PRIVACY_EGRESS_FEASIBILITY_20261110.md](VEHICLE_PRIVACY_EGRESS_FEASIBILITY_20261110.md)
（本文是它的「第一步：先补采集侧」）。

---

## 0. 结论

| 问题 | 判定 |
| --- | --- |
| 不保留原文的前提下，能否产出稳定可比的规范形态？ | **能**。7 种无损形态全部只落 SHA-256 前 16 hex 与字符长度，事件里没有任何坐标原文（有用例钉住）。 |
| 它与出站值比较时，谁生成、谁消费？ | 生成在 `privacy_location.js`；消费端（`request_hashes` + `value_len >= 8`）**这次没动**，定位目前仍只出 `VSC-GR-location`，**不会**产生 `VSC-GE-location`。 |
| 只能部分可比吗？ | **是，且是"结构性部分可比"**：能对上的只有「字符串叶子」这一种正文形态，且只覆盖 4 种编码 × 2 种经纬度顺序。数值叶子、其他小数精度、派生编码、非 JSON 正文**必然对不上**（§3 表 E）。 |
| 误配率量级 | 成对形态 **≈1.5e-17/次比较**（域比特 55.8）；单值形态 **≈5.6e-9 / 2.8e-9**；64 bit 哈希截断 **≈1.6e-17**。真实语料 3,696 次比较**命中 0**，且语料里"同形叶子"**0 个**。 |
| 主形态的编码可靠性 | `toFixed(6)` 与 Java `String.format("%.6f")` 在 **388,641 个取值上 0 偏差**（含 6 位小数正好是中点的正负两侧）。 |

**一句话**：采集侧现在能给出"可与出站字符串逐字节比较"的定位值，误配率低到可以忽略；
但**能不能匹配仍然主要取决于应用怎么编码**，并且当前**没有规则消费它**——这一轮只补了采集侧，
把"值有了但没有可比形态"这个缺口补上了，没有把它抬成外发结论。

> 未观测到 ≠ 安全：本文全部数字只说明"我们产出的证据是否可比、误配多不多"，
> 不说明被测应用有没有外发定位。

---

## 1. 改动清单

| 文件 | 变动 |
| --- | --- |
| `vehicle/hooks/privacy_location.js` | **新增**（93 行）。规范形态表 + 边界处理，纯计算，不调任何 Java API。 |
| `vehicle/hooks/hook_privacy.js` | `capture === 'location'` 分支改为委托 `locationEvidence(ret)`；去掉不再使用的 `sha256hex16` 导入。其余分支未动。 |
| `vehicle/hooks/test_runtime.mjs` | 新增 5 组用例（形态表顺序、无原文、零坐标/越界不出哈希、异常不抛出）。 |
| `vehicle/hooks/test_privacy.mjs` | 往 vm 上下文注入 `locationEvidence`（该用例用正则剥掉 import 后执行源码，必须显式注入）；新增 `value_len`/零坐标断言。 |
| `vehicle/hooks/dist/*.bundle.js` | 按新鲜度闸要求重建（15 个产物）。 |

新增事件字段（只有 `PRIVACY_READ` 且 `data_types` 含 `location` 时出现）：

```
value_len        : 主形态字符数（>=8，越过求值器门槛，不是放宽门槛）
value_hash       : 主形态 SHA-256 前 16 hex
value_kind       : 'location_pair'
location_form    : 'pair_d6'（主形态名）
location_precision: 6
location_forms   : [{form, len, hash} × 7]   # 全部候选形态，供离线评估/后续匹配器
value_capture_gap: 明确的不可比清单（常量串）
location_fix     : 仅在坐标不可用时出现（zero_pair_unverified / out_of_range / unhashable）
```

**语义变更（必须知道）**：`location` 的 `value_hash` 含义变了。旧值是
`sha256(JSON.stringify([lat, lon]))`（即 `"[30.2741,120.1551]"` 这种带方括号的串），
任何应用都不会把这种串发出去，所以它**从来没可能匹配**；新值是主形态 `"30.274100,120.155100"`。
新旧事件可凭 `location_form` 有无区分。已封存产物不改写，其 `value_hash` 保持原样（记录即事实）。

**没有改的**：`vehicle/privacy/evaluation.py`（`value_len >= 8`、`dtype in ('android_id','contacts')`
两处硬门槛原样）、`vehicle/privacy/POLICY.md`、`rules.db`、`vehicle/privacy/coverage.py`、
`core/privacy/*`、任何 hook 的 `matches()`/返回值/异常语义。

---

## 2. 形态设计

主形态 `pair_d6` = `lat.toFixed(6) + ',' + lon.toFixed(6)`。其余 6 种：

| # | 形态 | 例 | 依据 |
| --- | --- | --- | --- |
| 0 | `pair_d6` | `30.274100,120.155100` | 第三方 SDK 最常见的 `"%.6f"` 拼接；主形态 |
| 1 | `pair_d6_lonlat` | `120.155100,30.274100` | 高德/百度系地图 SDK 普遍 `lng,lat` |
| 2 | `pair_raw` | `30.2741,120.1551` | `Double.toString` 最短表示拼接 |
| 3 | `pair_raw_lonlat` | `120.1551,30.2741` | 同上，反序 |
| 4 | `geo_d6` | `geo:30.274100,120.155100` | RFC 5870 geo URI，常见于链接/分享字段 |
| 5 | `single_lat_d6` | `30.274100` | 经纬度分成两个字段时的纬度一侧 |
| 6 | `single_lon_d6` | `120.155100` | 同上，经度一侧 |

设计约束（三条，都是为了压误配）：

1. **只收无损形态**。6 位小数（约 0.11 m）与全精度两档，**不做**任何取整/量化编码。
   取整形态（2 位小数、geohash-5、整数微度）会把大片坐标压成同一个串，是误配的主要来源，
   宁可漏配也不用。
2. **零坐标不出哈希**。Android 无定位时返回 `(0,0)`，`"0.000000,0.000000"` 在正文里极其常见，
   算哈希等于自造高频误配源。此时只标记 `location_fix: zero_pair_unverified`，**不产出**
   `value_hash`/`value_len`。`collection_state` 仍是 `obtained`（**不改写旧证据语义**）。
3. **越界/非有限值同样不出哈希**，标 `out_of_range` / `unknown`。字段读不到记 `unknown`
   而不是 `empty`（"没读到" ≠ "没定位"），且**永不抛出**（钩子记录失败不得传回应用）。

---

## 3. 离线量化结果

复跑：`.\\tools\\python313.ps1 output\\vehicle-location-canonical-20261110\\quantify.py`
（脚本会先用 node 跑真正的 `privacy_location.js` 做交叉校验，再统计。）

### 3.0 语料口径与局限（先说清楚）

- 语料 = 本仓库 `output/**/flows.jsonl` 里的**真实抓包正文**：
  **112 个文件 / 424 条可用请求正文 / 297 个去重后长度 >= 8 的字符串叶子**。
- 口径与 `vehicle/privacy/evaluation.py:request_hashes` 严格一致（跳过 `raw_truncated` /
  `text_truncated` / `decode_error` / >2MB；只收字符串叶子且 `len >= 8`）。
- **局限**：这批正文以本项目自建夹具为主，不是第三方 App 的真实分布；且只覆盖我们跑过的
  少量包。因此下表是**下界**，不是"全网 App 的误配率"。

### 3.1 表 A：形态本身

| 形态 | 示例长度 | 结构正则 | 语料中同形叶子 | 占比 | 域比特 |
| --- | --- | --- | --- | --- | --- |
| pair_d6 | 20 | `^-?\d{1,3}\.\d{6},-?\d{1,3}\.\d{6}$` | 0 | 0.000% | 55.8 |
| pair_d6_lonlat | 20 | 同上 | 0 | 0.000% | 55.8 |
| pair_raw | 16 | `^-?\d+(?:\.\d+)?,-?\d+(?:\.\d+)?$` | 0 | 0.000% | — |
| pair_raw_lonlat | 16 | 同上 | 0 | 0.000% | — |
| geo_d6 | 24 | `^geo:-?\d{1,3}\.\d{6},-?\d{1,3}\.\d{6}$` | 0 | 0.000% | 55.8 |
| single_lat_d6 | 9 | `^-?\d{1,2}\.\d{6}$` | 0 | 0.000% | 27.4 |
| single_lon_d6 | 10 | `^-?\d{1,3}\.\d{6}$` | 0 | 0.000% | 28.4 |

"同形叶子 0 个"意味着：这批真实正文里**根本没有任何**字段长得像坐标——所以任何坐标都不可能
在这批语料里误配。这是最强的结论，但只对这批语料成立。

### 3.2 表 B：精确命中

| 坐标集 | 比较次数 | 7 种形态命中数 |
| --- | --- | --- |
| 城市(20) | 140 | 全部 0 |
| 边界(8，含 ±90/±180、1e-6、6dp 中点) | 56 | 全部 0 |
| 全球随机(500，固定种子) | 3,500 | 全部 0 |

### 3.3 表 C：理论上界

| 对象 | 单次比较误配概率 |
| --- | --- |
| pair_d6 / pair_d6_lonlat / geo_d6 | 2^-55.8 ≈ **1.54e-17** |
| pair_raw / pair_raw_lonlat | 全精度 double，**< 2^-56** |
| single_lat_d6 | 2^-27.4 ≈ **5.56e-09** |
| single_lon_d6 | 2^-28.4 ≈ **2.78e-09** |
| 64 bit 哈希截断（297 叶子 × 1 次读取） | ≈ **1.61e-17** |

**结论**：成对形态的误配已低到与哈希截断同级（都在 1e-17），可以视为零。
单值形态高 8 个数量级（1e-9）——量级上仍然很低，但它比成对形态差得多，
所以**只作候选，不当主形态**。

### 3.4 表 D：分辨率下限

- 亚 6dp 差异（`30.2741` vs `30.2741001`）→ **同哈希**：分辨率就是 1e-6（约 0.11 m），符合预期。
- 改第 6 位小数（`30.274100` vs `30.274101`）→ **不同哈希**：匹配器不是松的。

### 3.5 表 E：出站形态覆盖判定（判定，不是语料测得）

| 出站形态 | 覆盖 | 依据 |
| --- | --- | --- |
| `"30.274100,120.155100"`（lat,lon / %.6f） | ✅ 命中 | 与 pair_d6 逐字节相同 |
| `"120.155100,30.274100"`（lng,lat） | ✅ 命中 | pair_d6_lonlat |
| `"30.2741,120.1551"`（Double.toString） | ✅ 命中 | pair_raw（1e-6 以下的指数写法除外） |
| `"geo:30.274100,120.155100"` | ✅ 命中 | geo_d6 |
| `{"lat":"30.274100","lon":"120.155100"}` 分离字符串 | ⚠ 部分 | `single_*` 各自可比，但求值器只吃一个 `value_hash` |
| `{"lat":30.2741,"lon":120.1551}` **数值叶子** | ❌ **必然对不上** | `request_hashes` 只收 `str` 叶子，数值永不进哈希集合 |
| `"%.4f"` / `"%.7f"` / 去尾零等其他精度 | ❌ **必然对不上** | 只生成 6dp 与 Double.toString 两档 |
| geohash（`"wtmkn9x"`） | ❌ **必然对不上** | 未生成派生编码 |
| base64 / hex（成对或 double 字节） | ❌ **必然对不上** | 未生成派生编码 |
| protobuf / msgpack / 加密 / 压缩正文 | ❌ **必然对不上** | 非 JSON 或 `decode_error`，哈希集合直接为空 |
| `"Location[gps 30.274100,120.155100 acc=3 ...]"` | ❌ **必然对不上** | 叶子是整串 |
| 本地化小数（`"30,274100"`） | ❌ **必然对不上** | 小数点变逗号 |
| 整数微度（`"30274100"`） | ❌ 故意不做 | 8 位整数通用性强，误配风险最高 |

**最重要的一条**：如果应用把经纬度当**数字**发（这是最常见的 JSON 习惯），
那么无论采集侧怎么规范化都匹配不上——瓶颈不在采集侧，在求值器的 `request_hashes` 只收字符串。
这条已进入 §6 的下一步，本轮按约束**不动**。

---

## 4. 编码一致性证据（实测，不是推断）

主形态用 `toFixed(6)`；若应用用 Java `String.format("%.6f")`，两者必须逐字节相同。
在 **388,641 个取值**（分母 ≤ 1024 的二进小数，覆盖 6 位小数正好是中点的正负两侧，外加 2 万随机
double）上比对：**0 个不一致**。

复跑：`.\\tools\\python313.ps1 output\\vehicle-location-canonical-20261110\\_rounding\\rounding_check.py`
（需要 `JAVA_HOME`；脚本自建临时文件，跑完不留大文件）。

Python 侧的 `.6f` 是 **HALF_EVEN**，与 Java 的 HALF_UP 不同——`quantify.py` 里已改用
`Decimal.quantize(ROUND_HALF_UP)`，否则中点取值会算错（这是本轮实际踩到的偏差，
不是"应该没问题"）。

---

## 5. 验证

| 入口 | 结果 |
| --- | --- |
| `node vehicle/hooks/test_runtime.mjs` | 19/19 通过 |
| `node vehicle/hooks/test_privacy.mjs` | 通过（含新增 `value_len` / 零坐标断言） |
| `tools/run_regressions.py` | 19 组全 0（首轮 `privacy-runtime` 红，原因是 vm 上下文没注入 `locationEvidence`，注入后转绿） |
| `mobile/tools/run_mobile_checks.py` | 63 项，`failed: []` |
| `tools/check_mobile_branch.py` | 24 组，`passed: true` |
| 产物重建 | `core/frida_host/build.py --platform vehicle`，15 个 bundle |
| 新鲜度闸 | `hook_privacy` → `tier=warn_dirty`、`changed_sources: []`、`fingerprint_matches: true`（放行）；`hook_vehicle_all` 同 |

新产物哈希：`hook_privacy.bundle.js` = `9c54b8456f1e59ae4461d92e24b057088ed42e6f762c192351bbe919be7ba307`，
`hook_vehicle_all.bundle.js` = `7aba12bf00537669265d881755bb418fcccfe43719502d122a61fc3af3fe45de`。

---

## 6. 代价与边界

- **规则库零改动**：`vehicle/rules/rules_library/` 无 diff，`rules.db` 摘要未变，四版本计数
  （116 风险规则 / 96 启用 / `19-29-29-19`）不变，Android 侧 `RulesVerifier` 的 SHA256 不受影响。
- **判定链路零改动**：定位现在仍然只出 `VSC-GR-location`；`vehicle/privacy/test_evaluation.py`
  的"location 不得升级为 egress"用例原样通过。
- **已封存产物**：不做迁移。旧事件没有 `location_form`/`value_len`，新事件有；两者并存可区分，
  但不建议跨版本直接比较 `value_hash`。
- **未观测到 ≠ 安全** 不变。

### 下一步（本轮按约束未做）

1. **求值器侧**：`request_hashes` 要不要也收**数值叶子**（`str(node)` 后哈希）。
   这是定位能不能真正可比的最大瓶颈；改它会影响所有 data_type 的匹配面，必须单独评估。
2. **多哈希匹配**：求值器现在只读一个 `value_hash`。`location_forms` 已经有 7 份哈希，
   但消费端还没接；接之前要先决定"命中任一形态"的误配预算（成对 1e-17，单值 1e-9）。
3. **规则行**：在 1、2 之前不加 `VSC-GE-location`——加了也验不出东西，只会多一条永远
   `observed` 的规则，属于虚增覆盖。
4. **麦克风**：本方案不适用（`audio_count` 只有计数值，无值可比）。
5. **设备端实测**：本轮只做了离线（node + 真实语料）。要在设备上看到新字段，需按
   `docs/AGENT_TEST_SUITE_RUNBOOK_20261019.md` 跑一次带定位夹具的捕获；本轮未占用设备。
