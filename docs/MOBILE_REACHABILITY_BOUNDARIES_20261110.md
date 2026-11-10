# 移动端 static 可达性判定：方法边界与使用方式（2026-11-10）

**仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。**

- 状态：**已冻结，不再迭代**（2026-11-10 决策）。未判定主要来自 R8 混淆、WebView/RN 壳、
  JNI/`.so` 断链，这三类无法靠静态调用图解决；继续投入产出比低，如实保留「未知」即为正确结论。
  **2026-11-10 复核**：只修了「包装重载键」「`webview_shell` 压制过宽」「库命名空间缺项」
  「派生命名空间单列」四处，§3/§4 是复核前口径，复核后数字见 §3.1 与 §4.1；方法本身仍冻结。
- 适用实现：`mobile/tools/reachability.py`、`reach_report.py`、`wrapper_map.py`、
  `library_namespaces.py`、`dex_callgraph.py`、`graph_reach.py`；接线在 `mobile/tools/static_scan_thirdparty.py`。
- 一句话：这是**归属与证据方法**，不是安全过滤方法。

## 1. 能回答什么

对每一条静态候选（`rule_id` + 命中 API），给出可复核的四件事：

1. **归属**：`app` / `app_derived` / `library` / `unattributed`。归属四步为 App 包前缀（含子包）→
   无包名且入口可达（R8 混淆产物）→ 第三方库命名空间（含 `lib`/`libs`/`library`/`libraries`
   包段）→ 与声明前缀共享前两段的派生命名空间（`app_derived`，单列）→ 未归属。
   **manifest 注册本身不再把类算作 App**。
2. **分桶**：`app_reachable`（App 入口可达）/ `downgraded_library`（库来源）/
   `downgraded_unreachable`（App 类但从入口不可达）/ `unknown_findings`（未判定）。
3. **命中点与路径**：`hit_site`（类#方法）、`path`（入口 → … → 命中点）、`hop_count`。
4. **包装层信息**：命中包装类时附 `via_wrapper=true` 与 `root_api`，路径保留包装层；
   同一次实际读取由多层包装命中时合并为一条，附 `merged_hit_sites`。

配套产物：`static_reachability.json`（统计与失效声明）、`static_mobile_supplement.json`
（逐条证据）、`dex_callgraph.json`（调用图与缓存键）、`manifest_components.json`、
`static-manifest.json`。四桶都不删除候选，合计恒等于候选总数。

## 2. 不能回答什么

- **不等于安全、无风险、已排除**。`unknown_findings` 只表示「证据不足 / 可达性未知」，
  报告与字段中不得出现任何可被读成「安全」「无风险」「已排除」的表述。
- **不能证明「没读」**。静态图上没有边 ≠ 运行时没有调用；反射、lambda、JNI/`.so`、
  动态加载、壳内脚本都可能绕开静态图。
- **不能给出违规结论**。等级仍为 `candidate`；不产 `policy_violation`；不修改 observed 侧
  与 INTERNET 逻辑；是否违规仍需人工复核。
- **不能判断业务语义**。不知道读取是否在用户同意之后、是否为实现功能所必需。

## 3. 四类失效条件与实测占比（含残余）

统计口径：本轮 9 个样本、`unknown_findings` 桶内 **169 个命中点**（`reason_code` 逐条计数）。
分母用命中点而非候选，因为同一条候选常含多个不同归属的命中点。

先看**原因码实测**（可复核，合计 169）：

| `reason_code` | 命中点 | 占比 | 含义 |
| --- | ---: | ---: | --- |
| `unattributed_class` | 97 | 57.4% | 有包名但既不在 App 前缀、也不在库命名空间 |
| `wrapper_caller_unknown` | 37 | 21.9% | 包装层可确认，但调用方是库/未归属/被剪枝，无法上溯 |
| `framework_js_or_dart` | 20 | 11.8% | 识别为壳（WebView/Flutter/RN），业务不在 dex |
| `dynamic_dispatch` | 11 | 6.5% | 反射 / lambda / JNI 目标无法静态解析 |
| `obfuscated_class` | 4 | 2.4% | 无包名（R8 产物）且入口不可达 |

再按四类失效条件归并（同一批 169 个命中点，不重复计数）：

| 失效条件 | 可观测依据 | 未知命中点 | 占未知命中点 | 涉及样本（未知候选/总数） |
| --- | --- | ---: | ---: | --- |
| R8 混淆 | `obfuscated_class` | 4 | 2.4% | breezy（2/5） |
| WebView / React Native 壳 | `framework_js_or_dart` 20（kiwix）+ RN 第三方模块命名空间未归属 67（status） | 87 | 51.5% | kiwix（5/11）、status（14/18） |
| JNI / `.so` 断链（近似） | `dynamic_dispatch`（反射 / lambda / JNI 统一归此） | 11 | 6.5% | aegis（7/10）、organicmaps（5/10） |
| manifest 包名与代码命名空间不一致 | `unattributed_class`：simplex 15（`chat.simplex.common.*` vs 包名 `chat.simplex.app`）+ keepassdx 1（`com.kunzisoft.keepass.timeout.*` vs 包名 `com.kunzisoft.keepass.libre`） | 16 | 9.5% | simplex（12/18）、keepassdx（4/10） |
| 其他未归属（第三方 SDK 未入库名单） | `unattributed_class`：keepass2android 7（dropbox / google-api）+ simplex 7（boofcv / exoplayer2） | 14 | 8.3% | keepass2android（11/15） |
| 残余：包装调用方不可上溯 | `wrapper_caller_unknown`，跨样本，无法按上述四类唯一拆分 | 37 | 21.9% | aegis / keepass2android / keepassdx / simplex / status |

说明：

- **JNI/`.so` 没有独立原因码**。当前实现只沿 dex 内真实 `invoke-*` 连边，不解析 native 调用；
  JNI 目标与反射/lambda 一样落 `dynamic_dispatch`，因此 6.5% 是**近似下界**，不能单独归因。
- **`wrapper_caller_unknown` 单列为残余，不并入前四类**。它表示包装方法能确认是包装层，但调用方
  是库/未归属/被剪枝，无法判定谁触发；其中一部分与命名空间不一致重叠，无法从原因码分离。
- 阅读 `static_mobile_supplement.json` 时注意：`unknown_findings` 里的命中点可能包含
  `library_origin`（库来源证据）。那是同一条候选的**混合证据**，不是未知的成因；
  只有 `bucket == "unknown_findings"` 的命中点才计入上表。
- `downgraded_unreachable` 本轮为 0：断链按口径一律落未知，不判不可达。

### 3.1 其中 44/169 是调用图断裂：静态可达性的结构上限

169 个未知命中点里，**44 个（26.0%）**属于「调用图本身没有那条边」，换任何归属规则、
扩任何映射表都消不掉（2026-11-10 逐条核对 `dex_callgraph.json` 的 `wrapper_callers`）：

| 断裂形态 | 命中点 | 判定依据 | 代表命中点 |
| --- | ---: | --- | --- |
| 无静态调用方 | 33 | `wrapper_callers[命中点]` 为空；dex 里没有任何 `invoke-*` 指向该包装方法 | `androidx.core.telephony.TelephonyManagerCompat$Api26Impl#getImei`、`androidx.camera.camera2.internal.compat.CameraManagerCompat*Impl#openCamera`、`androidx.core.location.LocationManagerCompat#requestLocationUpdates` |
| 间接派发 | 11 | 反射 / lambda / JNI / 虚分派目标无法静态解析（`dynamic_dispatch`） | aegis 的相机与生物识别回调、organicmaps 的 GMS 回调 |
| 合计 | 44 | | |

结论：这 44 个只能靠动态观测补，静态侧如实保留「未判定」就是正确结论。
剩下的未知（`unattributed_class` / `obfuscated_class` / `framework_js_or_dart`）才是**规则可修**的部分。


## 4. 本轮 9 样本真实数字

9 个 F-Droid 样本、110 条候选，四桶合计 110 = 110（一条未删）：

| 桶 | 条数 | 占比 |
| --- | ---: | ---: |
| `app_reachable`（有效，App 入口可达） | 11 | 10.0% |
| `downgraded_library`（库来源） | 39 | 35.5% |
| `downgraded_unreachable`（App 类但不可达） | 0 | 0.0% |
| `unknown_findings`（未判定 / 可达性未知） | 60 | 54.5% |

**9 个样本中 7 个触发「本方法对该样本失效」声明**（未知占非库候选 ≥ 50%）：
aegis、keepass2android、keepassdx、kiwix、organicmaps、simplex、status。
未触发的是 k9mail（未知 0）与 breezy（未知 2/5 = 40%，未达阈值，但可归 App 的只有 3 条）。
因此**不得**把这轮结果表述为「过滤成功」。

两件已单独核实的结论：

- keepass2android 改前 5 条 `HistoryProvider#appendNameAndRealUri` 假阳
  （`MOB-R008/R009/R010/R013/R015`）已全部移出 `app_reachable`；
- organicmaps 的定位读取 `MOB-R006/R007` 现归 App：`via_wrapper=true`，
  `root_api=android.location.LocationManager.requestLocationUpdates`，路径含
  `AndroidNativeProvider#start → LocationManagerCompat#requestLocationUpdates`，
  两层包装命中点已合并为一条。

改前/改后对照与逐样本分解见 `output/thirdparty-round2-20261109-reach` 与
`output/thirdparty-round3-20261109-reach`（`output/` 不入库，按需重跑）。

### 4.1 2026-11-10 复核后的四桶（同一批 9 样本，同一批候选）

| 桶 | 改前 | 改后 | 变化来源 |
| --- | ---: | ---: | --- |
| `app_reachable` | 11 | 17 | **+6 全部是派生命名空间**（simplex 5、keepassdx 1）；「已确认 App」仍是 **11** |
| `downgraded_library` | 39 | 57 | +18：第三方库前缀补表 18（keepass2android 7、status 10、simplex 1） |
| `downgraded_unreachable` | 0 | 0 | 无（kiwix 的 15 个命中点下移到桶内命中点级，未改变 finding 级归属） |
| `unknown_findings` | 60 | 36 | −24：库 18 + 派生 App 6 + kiwix 0（见下）+ 其余为混合证据重算 |

`counts.app_reachable_kind = {"confirmed": 11, "namespace_derived": 6}`，
`counts.app_namespace_derived_sites = 16`；命中点级未知 **169 → 69**。

改后 69 个未知命中点的成因：

| `reason_code` | 命中点 | 说明 |
| --- | ---: | --- |
| `wrapper_caller_unknown` | 39 | 全部是**无静态调用方**（改前 4 个重载自环已消除，无残留） |
| `dynamic_dispatch` | 17 | 反射 / lambda / JNI（kiwix 的 `$$ExternalSyntheticLambda1#call` 5 个归此） |
| `obfuscated_class` | 8 | breezy |
| `unattributed_class` | 5 | k9mail 的 `com.skydoves.landscapist.coil3.Coil3ImageSourceFileKt#resolveUriToFile`（第三方图片库，未在本次补表范围，属残余） |

三处必须写清的细节：

1. **kiwix 的 `framework_js_or_dart` 是判定写宽了**：`webview_shell` 只说明打包了 Web 资源，
   Java/Kotlin 业务代码仍在 dex 中，不应压制可达性。改后 15/20 命中点落
   `downgraded_unreachable/no_path_from_entry`、5/20 落 `dynamic_dispatch`；
   **但 finding 级仍是 5 条未知**——每条候选都还留着一个 lambda 命中点，这是真实结果，不是没修好。
   Flutter / React Native 仍按「业务逻辑不在 dex」保留未判定（`OUT_OF_DEX_SIGNALS`）。
2. **重载键改动只产生 2 个更保守的归因**：k9mail `BiometricFragment$Api28Impl#authenticate`
   的 5 参版改前借用了同名 4 参版的调用方（`showPromptForAuthentication`）而判为库来源，
   改后如实报 `wrapper_caller_unknown`。逐样本 `wrapper_callers` 边数**无一例下降**。
   说明：库内部「库→库」转发边在 `edges` 里会被剪（`_graph_class` 只放行 App/入口端点），
   所以 5 参版的真实调用方在索引里也查不到——这是记录口径的已知上限，不是本次改动引入的。
3. **派生命名空间不是安全网**：`chat.simplex.common.*` 在补上前缀后确实出现了到入口的
   `invoke-*` 链（`chat.simplex.app.CallService#updateNotification` 起），因此这 16 个命中点是
   **真的有静态路径**，只是命名空间靠前两段推断，所以单列在 `app_namespace_derived`，
   不计入「已确认 App」。根比已知库更宽时（`com.google` 对 `com.google.android.gms.*`）直接跳过派生。

## 5. 使用建议

1. **报告中四桶分开写，不合并**：
   - `app_reachable`：可写「App 自身代码可从此入口到达该读取」，仍是候选，不写违规；
   - `downgraded_library`：写「命中点在第三方库」，不归责 App；
   - `downgraded_unreachable`：写「App 类但入口不可达」，不写「不会执行」；
   - `unknown_findings`：必须写「未判定 / 证据不足 / 可达性未知」，禁止任何安全化措辞。
2. **50% 阈值与失效声明**：未知占非库候选（`app_reachable + down. unreachable + unknown`）
   **≥ 50%** 时，该样本报告必须出现一句「本方法对该样本失效」。依据：未知与已知各占一半
   时，分桶已不具备区分度，不能据此过滤或降级结论；这是**操作性约定**，不是统计显著性阈值。
   现有实现见 `reach_report._failure_statement()` 与 `counts.method_failed_on_this_sample`。
3. **壳 / 高混淆 / JNI 样本不要依赖本方法**：直接改用动态观测（Frida + 流量）取证；
   静态分桶只作为「哪些候选值得动态复核」的线索。
4. **可复现**：同一 APK 重跑，`manifest_components.json`、`dex_callgraph.json`、
   `static_reachability.json`、`static_mobile_supplement.json`、`static-manifest.json`
   应逐字节一致；缓存键含 APK sha256、dexdump 指纹、App 前缀（含派生）、API 集、包装映射哈希
   （`GRAPH_VERSION=5`，包装调用方索引按完整签名分键）。
5. **一条不删**：任何过滤都不得删除候选；若报告只显示 `app_reachable`，必须同时给出
   其余三桶计数，否则读者会误以为未列出的候选不存在。

## 6. 代码与测试索引

| 文件 | 职责 |
| --- | --- |
| `mobile/tools/apk_entrypoints.py` | manifest 组件 / Application / 框架壳信号 |
| `mobile/tools/dex_callgraph.py` | `dexdump -d` 流式调用图 + 包装调用方反向索引 + 缓存键 |
| `mobile/tools/graph_reach.py` | 入口可达 BFS（虚/接口分派按签名 + 继承补边） |
| `mobile/tools/wrapper_map.py` | 包装类 → 根 API 映射与调用方上溯（≤3 层，节点按完整签名区分重载） |
| `mobile/tools/library_namespaces.py` | 第三方库命名空间表（每条带依据；归属判定第三步） |
| `mobile/tools/reachability.py` | 归属四步 + 派生命名空间 + 四桶证据 + 原因码 |
| `mobile/tools/reach_report.py` | 合并同一次读取、统计（含 `app_reachable_kind` 拆分）、失效声明、写回产物 |
| `mobile/tools/test_reachability.py` / `test_reachability_wrapper.py` | 归属与包装正负例（45 项） |

**以后谁用这套过滤，先读第 2 节「不能回答什么」和第 5 节第 2 条（50% 失效阈值）。**
