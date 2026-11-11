# core/evidence 决策记录

本目录从 `D712` 起编号（`core/collector`、`vehicle/workbench` 各有自己的 DECISIONS，
编号到 D711 / D818）。evidence 层的坑单独记录在此。

## D712 SDK 归属只做"运行时调用链半程"，不引入 LibScout 全套

2026-11-11，基于 `docs/VEHICLE_RESEARCH_OPTIONS_20261111.md` §3 落地。

**问题**：`app_classes.is_app_class` 只回答"这一帧是不是被测 APK 的代码"。
于是第三方 SDK（`com.google.firebase.*`、`com.adjust.sdk.*`）——它们也打包进了 APK、
也在 `dexfacts` 类表里——被一律算成"应用代码"，敏感读取被误归到宿主开发者头上。
这对应报告里"缺少 SDK 级行为归属"的短板。

**为什么不做 LibScout 全套**：LibScout 需要原始 SDK 的 profile（JAR/AAR）做库指纹
匹配，是静态侧的高成本 sidecar；其精确版本不唯一、混淆/裁剪仍需评估。它回答的是
"APK 包含哪些 SDK（及版本）"，而**当前报告最缺的、且零新依赖就能补的**，是
"本次敏感读取的调用链里，到底是不是 SDK 的帧"——后者用项目已有的
`dexfacts.json` 类表 + 运行时栈即可完成。

**落地**（三个新文件，纯增量、零新工具）：
- `sdk_registry.py`：SDK 包名前缀清单（每个带 Maven 坐标来源），只作候选；
- `sdk_attribution.py`：栈帧五分类（host / sdk / third_party_unknown / system / unknown）
  + 链级摘要；关键契约是"含 SDK"与"SDK 在链上"分开表达；
- `codeloc.locate` 产出新增 `sdk_attribution` / `sdk_frames` 字段，接入既有证据链。

**五分类的判定顺序**（从严到宽）：
1. 系统前缀 → `system`（沿用 `app_classes.SYSTEM_PREFIXES` 一票否决）；
2. 已知 SDK 前缀 → `sdk`（**长前缀优先**，否则 `com.google.firebase` 会吞掉
   `com.google.firebase.analytics`——实测踩到）；
3. 宿主包名前缀 → `host`；
4. 在类表里、但非宿主也非已知 SDK → `third_party_unknown`（**认不出是哪家，就诚实保留
   unknown，不硬猜一个 SDK 名**）；
5. 全不命中 → `unknown`。

**三条不能互相推出的命题**（报告 §3 原话的工程化）：
1. `apk_contains_sdk`（静态，`sdk_classes_in_apk`）——APK 打包了该 SDK；
2. `sdk_in_call_chain`（运行时，`chain_sdk_summary.sdk_in_chain`）——SDK 帧出现在链上；
3. "该 SDK 采集了数据"——**本层不做**，需要数据流向/传播追踪，越界即假结论。

**通用库与采集 SDK 分开**：`OkHttp`/`Retrofit`/`Glide`/`Chromium` 等也命中 SDK 前缀，
但它们不是采集类 SDK。`is_generic` 标记 + `has_collection_sdk` 摘要把两者区分开，
否则报告会出现"OkHttp 采集了位置"这种没有意义的话。

**负控**：APK 打包了 SDK 但本次栈里没出现，`sdk_in_chain` 为空——测试
`test_negative_control_contain_without_chain` 钉死这条，防止"带了 = 采集了"的外推。

**边界（记录在案，不装作已解决）**：
- 前缀召回率 < 100%：SDK 被重打包改名或裁剪内联后认不出，落到 `third_party_unknown`，
  这不是"没有 SDK"；
- 静态侧（LibScout 式的版本/库指纹识别）仍未做，属后续专项；
- 本层不宣称"SDK 采集了数据"，只宣称"SDK 的代码出现在这次读取的调用链上"。
