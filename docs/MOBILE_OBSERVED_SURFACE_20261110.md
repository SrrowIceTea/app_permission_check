# L2 只读覆盖统计 `observed_surface`（2026-11-10）

**仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。**

- 这份统计**不是结论**：不产出候选、不改四桶、不产 `policy_violation`、不折算成检出率。
- 一句话：闭集（`dangerous_apis`，58 行）**看得见**的敏感 API 形态是少数；本文给出可复现的
  「看不见多少」的两个分母，并用一个**正对照夹具**证明这个数字不是自己说自己。
- 作用域文件：`mobile/rules/targets/sensitive_surface_v1.json`（`MOB-SURFACE-V1`，
  sha256 `4c0b939d42fb36662facfe38459788b08c699a5927e58205d117f37db1aa31dd`，40 条，15.7 KB）。
- 实现：`mobile/tools/surface_target.py`（加载/校验/匹配）、`mobile/tools/observed_surface.py`
  （扫描/统计/CLI）、`mobile/tools/target_set_build.py`（重生成目标集）。
- 接线：`mobile/tools/static_scan_thirdparty.py` 默认产出 `observed_surface.json`，
  `--skip-observed-surface` 可关；`static-manifest.json` 里是**独立顶层字段**，不进 `mobile_supplement`。

---

## 1. 目标集从哪来

`target_set_build.py` 里是枚举，产出的 JSON 是运行期唯一依据（改枚举 → 重生成 → sha 变）。

| 项 | 值 |
| --- | --- |
| 品类 | 9 类（定位 8 / 通讯录 2 / 相机 5 / 麦克风 2 / 传感器 2 / 剪贴板 3 / 设备标识 10 / 已装应用 3 / 存储 5） |
| 类清单 | **独立枚举**，不从 `dangerous_apis` 反推（反推会让分母被闭集定义，比例永远 100%） |
| 类是否存在的核对 | 31/40 条能在 `android.jar`（API 36）里用 `javap -public -s` 核实，逐条记了 `jar_method_count`；其余 9 条是 GMS/androidx/国内 SDK，`in_android_jar=false` |
| **签名来源** | **样本 APK 的 dex**（`dexdump -d` 的实测 `invoke-*` 目标）。**不取 android.jar 的方法全表** |
| 复现 | `.\tools\python313.ps1 mobile/tools/target_set_build.py --verify`（重算 sha 并与仓库文件比对） |

**为什么签名取 dex 而不是 `android.jar` / AOSP：**

- `android.jar` 的方法全表把几百个**从未被调用**的重载也算进分母（`LocationManager` 一个类 87 个方法），
  得到的比例不对应任何真实行为，也不能回答"这个样本看不见多少"。
- AOSP 源码树的版本与本机 API 36 不一致，且 `androidx` 根本不在 AOSP platform 里；
  它只能解释"某个方法为什么存在"，不能给出可信的分母。
- 因此 `android.jar` 只用于**核对类是否存在**（可一对一对账），签名一律实测。
- 代价（写进目标集 `scope_rule.distortion`，不藏）：**分母是样本内口径**——某 API 没被这个样本调用
  就不在它的分母里，所以跨样本只能比各自比例，不能比大小；方法句柄 / `invoke-custom` /
  `invoke-polymorphic` 不展开；静态 final 字段会被编译期内联（字段通道单列）；
  只扫 `classes*.dex`，`assets/` 里的二次 dex 不算（加固样本会失真）。

**方法级不挑选**，唯一例外：`android.content.ContentResolver` 只算取数/写数的 10 个方法
（不含 `registerContentObserver` / `notifyChange`），理由写在目标集 `method_allowlist_note`。

---

## 2. 两个分母（禁止只给一个）

| 分母 | 定义 | 为什么必须给 |
| --- | --- | --- |
| **A 签名面** | 该样本敏感类上出现过的不同 `(类, 方法, 描述符)` | 反映"碰过多少种敏感 API 形态"，不受高频包装放大 |
| **B 调用点加权** | 这些签名的 `invoke-*` 指令条数（跨 dex 累加） | 反映"实际执行路径上有多少处"，`ContentResolver.query` 这类包装会被放大 |

分子只认 `dangerous_apis` 的**精确三元组**——那是闭集唯一能变成候选的形态。

### 2.1 池级（39 个第三方 APK，签名跨样本去重；与 §8.1 逐位一致）

| 视图 | 分母 | 闭集看得见 | 样本内不可见 |
| --- | ---: | ---: | ---: |
| A 签名面 | **719** | **40**（5.56%） | **94.4%** |
| B 调用点加权 | **11,778** | **936**（7.95%） | **92.1%** |
| 　其中平台组 `android.*`/`androidx.*`/`java.net` | 630 / 11,653 | 40 / 936 | 93.7% / 92.0% |
| 　其中 GMS `com.google.android.gms.*` | 89 / 125 | **0 / 0** | **100%** |
| 　国内 SDK（高德/腾讯/百度/autonavi） | **0** | — | 本地池子无法评估 |

形态拆解（签名）：`class_gap` 453（整类没登记）、`method_gap` 225、`exact` 40、`overload` **1**。
`class_gap` 里 89 条是 GMS，364 条是平台组——与 §8.3 的平台组数字一致。

### 2.2 样本内（逐样本各算，才是报告里该用的口径）

39 个样本的签名面不可见比例落在 **85.7% – 96.1%**，其中 **30/39 个 ≥ 90%**。
9 个跑过可达性（reach9）的样本（逐样本相加，非去重）：

| package | 签名面 | 看得见 | 不可见 | 调用点 | 看得见 | 不可见 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| org.kiwix.kiwixmobile.standalone | 55 | 4 | 92.7% | 102 | 11 | 89.2% |
| org.breezyweather | 55 | 6 | 89.1% | 109 | 13 | 88.1% |
| com.beemdevelopment.aegis | 112 | 5 | 95.5% | 278 | 16 | 94.2% |
| com.fsck.k9 | 125 | 6 | 95.2% | 270 | 22 | 91.9% |
| com.kunzisoft.keepass.libre | 125 | 9 | 92.8% | 267 | 22 | 91.8% |
| keepass2android.keepass2android | 138 | 10 | 92.8% | 355 | 38 | 89.3% |
| app.organicmaps.web | 173 | 7 | 96.0% | 263 | 9 | 96.6% |
| im.status.ethereum | 180 | 11 | 93.9% | 418 | 37 | 91.2% |
| chat.simplex.app | 264 | 12 | 95.5% | 587 | 31 | 94.7% |
| **合计** | **1,227** | **70** | **94.3%** | **2,649** | **199** | **92.5%** |

---

## 3. 正对照：证明它真能看见闭集之外

夹具 `mobile/tools/fixtures/surface_probe/com/vscanner/surfaceprobe/SurfaceProbe.java`
在测试里**现场**用 `javac` + `d8` 编成 dex 再打包成 APK（不依赖 Gradle、不联网），
里面**故意**放了三类闭集看不见的东西 + 一条看得见的对照：

| 夹具里的调用 | 期望 | 实测 |
| --- | --- | --- |
| `ClipboardManager.getPrimaryClip()` | 闭集登记了 → `exact` | ✅ `registered`，`form=exact` |
| `ContentResolver.openInputStream(Uri)` | 类登记、方法没登记 → `method_gap` | ✅ `unregistered`，`method_gap` |
| `new MediaRecorder()` → `<init>` | 整类没登记 → `class_gap` | ✅ `unregistered`，`class_gap` |
| `Build.MODEL` | 字段通道，单列 | ✅ 出现在 `field_reads.by_field`，`counted_in_denominators=false` |

如果 `observed_surface` 只是把 `dangerous_apis` 复述一遍，后三项**一条都报不出来**。
这是本方案唯一能自证的地方，因此它在回归里（新增 `observed_surface` 组，12 项）。

另外两条防假：APK 里没有 dex → `status=no_dex` 且 `denominators=null`（不用 0 冒充）；
`dangerous_apis` 的版本传错（例如传车载的 `13`）→ `SystemExit` 并列可用版本，
不允许"空闭集 → 100% 不可见"这种看起来严谨的假数。

---

## 4. 一条真实样例输出（`keepass2android.keepass2android`，已删路径）

`observed_surface.json` 是**整份 doc**：`target_set` 在顶层，与 `observed_surface` 平级
（两者不在同一层，取字段时别混——这正是本轮端到端接线时踩到的 `KeyError`）。

```json
{
  "generated_by": "mobile/tools/observed_surface.py::run",
  "target_set": {"target_set_id": "MOB-SURFACE-V1", "version": "1",
                 "sha256": "4c0b939d42fb3666…", "generated_at": "…",
                 "signature_source": "sample_dex"},
  "sample": {"apk": "keepass2android.apk", "apk_sha256": "…", "rules_db_version": "36"},
  "standalone": true,
  "not_merged_with": "四桶统计（reachability）…不合并、不加权、不折算成检出率、不可相加",
  "observed_surface": {
    "status": "ok",
    "denominators_scope": "样本内（sample-scoped）",
    "denominators": {
      "signature_surface": {"total": 138, "registered": 10, "unregistered": 128,
                            "forms": {"class_gap": 58, "method_gap": 69,
                                      "exact": 10, "overload": 1}},
      "call_points":       {"total": 355, "registered": 38, "unregistered": 317,
                            "forms": {"class_gap": 120, "method_gap": 196,
                                      "exact": 38, "overload": 1}}
    },
    "invisible": {
      "signature_share": 0.9275, "call_point_share": 0.893,
      "statement_zh": "样本内不可见 92.75%（签名面 128/138）；按调用点加权 89.30%（317/355）。
                       这是**样本内口径**：…不是行业结论；不得折算成检出率，不得与四桶统计相加或加权。"
    },
    "unregistered": [
      {"class": "android.content.pm.PackageManager", "method": "getPackageInfo",
       "form": "method_gap", "categories": ["installed_apps"], "call_points": 22},
      {"class": "android.content.pm.PackageManager", "method": "hasSystemFeature",
       "form": "method_gap", "categories": ["installed_apps"], "call_points": 22},
      {"class": "android.content.ClipData", "method": "getItemAt",
       "form": "class_gap", "categories": ["clipboard"], "call_points": 7}
    ],
    "registered": [
      {"class": "android.content.ContentResolver", "method": "query",
       "form": "exact", "call_points": 25, "mapped": true},
      {"class": "android.provider.Settings$Secure", "method": "getString",
       "form": "exact", "call_points": 2, "mapped": false}
    ],
    "field_reads": {"total": 677, "distinct": 12, "counted_in_denominators": false,
                    "by_field": {"android.os.Build$VERSION.SDK_INT": 1173,
                                 "android.os.Build.MODEL": 10}}
  }
}
```

### 4.1 端到端接线后的实跑（同一个入口，`org.breezyweather`）

`static_scan_thirdparty.py --apk breezy.apk --skip-decompile` 一次跑通，产物三处并列、
互不覆盖：`observed_surface.json`（完整统计）、`static-manifest.json` 的**顶层**
`observed_surface` 字段、`mobile_supplement` 的四桶（`app_reachable 3 / downgraded_library 0 /
downgraded_unreachable 0 / unknown_findings 2`，合计 5 条候选，与本轮改动前一致）。

| 视图 | 分母 | 登记 | 样本内不可见 |
| --- | ---: | ---: | ---: |
| 签名面 | 55 | 6 | **89.09%** |
| 调用点 | 109 | 13 | **88.07%** |

品类拆解（签名 / 调用点）：`installed_apps 22/49`（登记 0）、`location 10/22`（3/8）、
`clipboard 13/19`（1/2）、`sensor 3/7`（1/2）、`device_id 4/6`（1/1）、`storage 3/6`（0/0）。

注意 `Settings$Secure.getString` 那条：**登记了却 `mapped=false`**——`dangerous_apis` 有这一行，
但它没有 `data_type_key` 映射，任何规则都不会消费它。所以"闭集看得见"本身还隔着一层，
`observed_surface` 把这个也标出来了，不把 40 条当成 40 条真能出候选。

---

## 5. 这一轮哪些是新的、哪些原来就有

**原来就有（不算本轮成果）**

- `dangerous_apis` 闭集（58 行）与四桶可达性；**719 / 11,778 / 40 / 936 这组数字**已在
  [MOBILE_SAMPLE_POOL_STRUCTURE_20261110.md](MOBILE_SAMPLE_POOL_STRUCTURE_20261110.md) §8 发表，
  当时来自未入库的原型脚本 `output/_pool-analysis/closed_set_gap.py`。
- 本轮把这组数字**逐位复现**了一遍——那是**验证**，不是新发现，也不是检出提升。

**本轮新增**

1. 目标集成为**带版本号 + sha256 + 逐条来源**的独立文件，可 `--verify` 重算（原型是一段脚本常量）。
2. `observed_surface.json` 成为**一等产物**：两分母 + 形态拆解 + 品类/命名空间分组 + 类清单 +
   `field_reads` 单列 + **样本内口径的降级句**；与四桶并列，不合并。
3. **正对照夹具**（javac+d8 现场编译）+ 测试，含篡改 sha 拒绝、无 dex、错版本三条例外路径；
   2026-11-10 第二轮补到 **20 项**（新增汇总层与流水线阶段两组）。
4. 单样本入口接线：`static_scan_thirdparty.py` 默认产出 + `--skip-observed-surface`，
   失败软着陆（`status` 区分 `ok` / `skipped` / `unavailable` / `no_dex` / `scan_failed`）。
   **注意：第一轮只做到单样本入口，流水线与批量都还没接**——下面 §7/§8 是第二轮补的。
5. L1 准入条件 2 改口径：`unknown` 是正当结论，且规定它在报告里怎么呈现才不被读成"已排除"
   （[MOBILE_DETECTION_LAYERING_DESIGN_20261110.md](MOBILE_DETECTION_LAYERING_DESIGN_20261110.md) §1.1）。

**本轮没有做**：没有加任何一条签名到 `dangerous_apis`，没有改 `rules_mobile.db`，
没有改动四桶结论，没有把 `observed_surface` 换算成检出率或风险分。

---

## 6. 不能用它说什么

- 不能写"这个 App 有 94% 的敏感行为没被检测"——分母是**该样本实际调用到的敏感签名**，
  且含"敏感类上但不取数"的方法（`release()`、`hasSystemFeature`、`isProviderEnabled`），属**上界**。
- 不能写行业结论、不能与其他产品比覆盖率，也不能把 94% 当成漏报率（漏报要有真值标签）。
- GMS 89 签名 / 125 调用点 **0 命中**是真实的，但同批样本里 GMS 调用总量也只占 1%，
  不能据此说"GMS 侧影响小"——只能说"闭集对 GMS 完全没有表达力"。
- 国内 SDK（高德/腾讯/百度/autonavi）在本地池子里 **0 签名**，这一格的缺口是**未评估**，不是 100%。

---

## 7. 接进流水线编排（2026-11-10 第二轮）

**阶段数 16 → 17，阶段 id `surface`，标签「敏感面统计」。**

插在 `static` 之后、`boot` 之前，三条理由（也写进 `mobile/pipeline/README.md`）：

1. 它是**派生统计**：输入是 APK 的 dex + 静态扫描口径，抢在 `static` 前面跑会让时间线读成
   "先统计后扫描"；
2. 它**不依赖设备**：所以放在 `boot` 之前，并显式排除在 `stages.DYNAMIC_STAGES` 之外
   （否则设备起不来时它会被标成 `skipped`，那是假的"没跑"）；
3. 它**不出结论**：不产候选、不进四桶、不折算检出率。

实现是 `mobile/pipeline/surface_stage.py`（约 100 行），`runner.py`（默认路径）与
`formal_runner.py`（`--audit-config` 路径）**共用这一份**，避免两个执行器各写一套而漂移。

### 7.1 软着陆的具体行为

| 情形 | 阶段事件 | `job.result.observed_surface` | 流水线 |
| --- | --- | --- | --- |
| 正常 | `done` + 两分母摘要 | `status=ok` + `file` + `target_set.sha256` | 继续 |
| 目标集 sha256 不匹配 | `unavailable` + 原因 | `status=unavailable` + `reason` | **继续** |
| 目标集文件丢失 / 读盘异常 | `unavailable` + 原因 | 同上 | **继续** |
| APK 无 dex | `unavailable` + 原因 | `unavailable` + `upstream_status=no_dex` | **继续** |
| 显式 `--skip-observed-surface` | `unavailable` + 原因 | `unavailable` + 原因 | 继续 |

配套改了 `static_scan_thirdparty.py`：**L2 的异常不再以非零码退出**（原先 `SystemExit` 会把
已落盘的四桶一起废掉，等于 L2 拖垮主链）。现在它收敛成 manifest 里的
`observed_surface.status = skipped / unavailable` + `reason`，四桶与 `static.json` 不受影响。

阶段事件新增一个状态值 `unavailable`（`running / done / failed / skipped / unavailable`），
前端 `app.css` 给了单独的样式（橙色，**不画 skipped 的删除线**——它不是"没跑"）。

---

## 8. 批量汇总脚本入库（`mobile/tools/surface_batch.py`）

原先只是 `output/_pool-analysis/` 下的临时件，不可复现；现在是仓库产物，两种模式：

```bash
# 1) 现扫一批
python mobile/tools/surface_batch.py --apk-dir output/xxx/apk --out output/_surface-batch
# 2) 汇总已有单样本产物（不重扫、不重新裁决）
python mobile/tools/surface_batch.py --from output/thirdparty-round2-20260909 --out output/_surface-batch
```

`surface-batch.json` 里每一行都带 `apk` / `apk_sha256` / `file`（该样本自己那份
`observed_surface.json` 的绝对路径），**任何一行都能追回单样本产物**。

### 8.1 汇总层只相加分母

```json
"pool": {
  "method": "sum_of_per_sample_denominators",
  "summed_denominators": {"signature_surface": {"total": 55, "registered": 6, ...},
                          "call_points": {"total": 109, "registered": 13, ...}},
  "invisible_share_from_summed": {"signature": 0.8909, "call_point": 0.8807},
  "note": "相加的是**分母**不是比例：池级比例 = 相加后的登记 / 相加后的分母，不是逐样本比例的平均，也没有任何加权。"
}
```

- 没有 `mean` / `weight` / `score` 字段（回归里有一项专门断言这点：两份各 10/100 与 100 分母的样本，
  逐样本比例平均会得 0.30，相加后现算才是 0.4636，两者必须分开）；
- 不可用样本（`no_dex` / 目标集校验失败）不进分母，但**单列**在 `samples_unavailable`；
- 同一 `apk_sha256` 重复出现只计一次，被丢的记在 `duplicates` 里，不静默吞掉。

**口径警告（写死在产物 `limitations` 里）**：池级数字是**逐样本分母之和**，同一签名在 N 个样本
出现就计 N 次；它与 [样本池盘点](MOBILE_SAMPLE_POOL_STRUCTURE_20261110.md) §8.1 的
719 / 11,778（**跨样本去重并集**）不是同一口径，**不能比较大小**。

实跑（`--from` 与 `--apk` 两种模式，同一样本结果一致）：

```
status                  签名面 登记/总            调用点 登记/总  apk
ok                          6/55              13/109  breezy.apk
样本 1/1 有数；池级分母之和：签名面 6/55，调用点 13/109
```

---

## 9. 这一轮之后，还有哪些能力"只在单样本能用"

如实列，不留同类尾巴：

| 能力 | 现状 | 说明 |
| --- | --- | --- |
| `observed_surface` | **已接入**（单样本 CLI / 流水线 `surface` 阶段 / 批量汇总） | 本轮补完 |
| `Build` 字段通道（`field_reads`） | 已随 `observed_surface` 一起产出，三处入口都有 | 只有计数，**没有**按字段的外发关联（那属 L1，未做） |
| L1 四条准入的机读实现 | **没有单独实现** | 只有口径文档（`MOBILE_DETECTION_LAYERING_DESIGN_20261110.md` §1.1）；`confirmed` / `undetermined` 的拆分靠 `static_reachability.json` 的 `counts.app_reachable_kind` + 命中点 `reason_code`，没有一键出表 |
| 人工复核 / 误报率 | **本地无数据** | 需要人；口径在方案稿 §4，数值不给 |
| B1 窗口校准、B2 基准、F1 类加载归因 | 车载侧遗留，与 L2 无关 | 未做 |

也就是说：**L2 这一条链已经没有"只能在某一种入口跑"的环节**；剩下的是 L1 的机读聚合
（尚未实现）和需要外部输入的项（人工复核、真值标签）。
