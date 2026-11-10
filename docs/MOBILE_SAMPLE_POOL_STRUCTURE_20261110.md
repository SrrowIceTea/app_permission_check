# 本地样本池结构盘点（2026-11-10）

**仅用于授权测试（自有设备 / 公开开源样本）。只读盘点：未下载新样本、未跑动态采集、未改仓库代码。**

- 目的：这批样本让覆盖率数字好看，但可能掩盖真实失效点。先把**池子的结构**量出来，再决定补什么。
- 数据来源：本机 `output/`、`vehicle/`、`apk/` 下全部 APK（**76 个文件 → 52 个不同 SHA256**），
  用 `aapt2 dump badging/xmltree` + `dexdump` 只读分析；流水线数字**直接复用已有产物**，
  未重跑：`output/thirdparty-round3-20261109-reach/`、`output/memhook-pinning-samples-20261110/static/`、
  `output/thirdparty-dynamic-20261110/`。
- 口径脚本（临时、`output/` 不入库）：`output/_pool-analysis/pool_scan.py`（六维扫描）、
  `dist.py` / `summarize.py`（分布）、`commercial.py`（商业特征）、`table.py`（主表渲染）。

## 0. 池子构成（先看这一层，否则会把夹具算进分布）

| 类别 | 个数 | 说明 |
| --- | ---: | --- |
| 移动端第三方样本 | **35** | 9 个 reach9（跑过可达性）+ 11 个 acq（仅采集）+ 15 个 memhook（仅 pin 静态） |
| 车载第三方样本 | 4 | `mg4browser`、`fileslauncher`、`yaabsa`、`homeassistant-minimal`；**没进过移动端流水线** |
| 自建夹具 | 13 | `com.vscanner.*`（rules / targetapp / aaidprobe）及其多版本副本，**不计入分布** |

下面所有分布都只统计 **35 个移动端第三方样本**；车载 4 个单列在 §5。

## 1. 六维分布（含"空格"）

| # | 维度 | 分档 | 样本数 | 空格？ |
| --- | --- | --- | ---: | --- |
| 1 | 混淆 | yes（短类名 ≥25% 或单字母顶层包 ≥5） | 9 | |
| | | partial（短类名 10–25%） | 7 | |
| | | no | 19 | |
| | | `mapping.txt` 残留 | **0** | **空** |
| 2 | GMS | dex 引用 `Lcom/google/android/gms` | 5 | |
| | | 仅清单声明 `com.google.android.gms.*` | 4 | |
| | | 无任何 GMS 信号 | 26 | |
| | | 声明 GMS **权限**（`com.google.android.gms.permission.*`） | **0** | **空** |
| | | dex 引用且带 `FusedLocationProviderClient`/`LocationServices` | 2 | 偏少 |
| 3 | Hybrid WebView | 有 `WebView` API | 24 | |
| | | 有 `addJavascriptInterface` | 13 | |
| | | `assets/` 内 `.html`：1–3 个 / ≥4 个 | 9 / 3 | |
| | | React Native bundle | 2 | 偏少 |
| | | Flutter | 1 | 边缘 |
| | | 三项全无 | 11 | |
| 4 | 第三方命名空间数 | 1–4 / 5–9 / 10–19 / 20–39 / 40+ | 7 / 6 / 10 / 3 / 9 | 0 个 |
| | | 最大 / 最小 | 81（element）/ 2（monocles、privacybrowser） | ≥100：**空** |
| 5 | 声明式 pin | `res/**/*.xml` 含 `pin-set` | **2**（protonmail `res/4u.xml`、threema `res/8GD.xml`） | 极少 |
| | | 仅代码级 pin（`CertificatePinner`/`sha256/`） | 18 | |
| | | 无任何 pin | 15 | |
| 6 | 多进程 | `android:process` 0 / 1 / 2 / 4 次 | 29 / 3 / 2 / 1 | ≥2 次：4 个 |

补充事实（不在这 6 维内，但决定"这批样本像不像商业 App"）：

| 特征 | 命中 | 说明 |
| --- | ---: | --- |
| 广告 SDK（AdMob / AppLovin / Unity Ads / Facebook Ads / 穿山甲 / 友盟） | **0/35** | 无一家 |
| 加固壳（360 StubApp / 梆梆 / 腾讯乐固 / 爱加密 stub） | **0/35** | 无一家 |
| Play Integrity / SafetyNet | **0/35** | 无一家 |
| Firebase | 4/35 | 均为开源项目自建用途（keepass2android、status、protonmail、signal） |
| 自带 native `.so` | 31/35 | 说明 JNI 断链是普遍条件，不是个别样本 |

## 2. 逐样本主表（35 个移动端第三方样本）

可达性列 = `候选数 / 未知占非库候选`；"未跑" = 本机没有该样本的 `static_reachability.json`。

| # | 包名 | 批次 | 混淆 | 短类名 | GMS(清单/dex) | WebView(JS桥/html) | 命名空间 | NSC pin | 进程 | 可达性 | 动态 |
| --- | --- | --- | --- | ---: | --- | --- | ---: | --- | ---: | --- | --- |
| 1 | `app.organicmaps.web` | reach9 | no | 6.8% | 清单/dex | WV/3 | 10 | - | 1 | 10 / 62% | reads1/eg70/明文/meta.omaps.app |
| 2 | `chat.simplex.app` | reach9 | no | 0.2% | -/- | JS/3 | 79 | - | 2 | 18 / 100% | - |
| 3 | `com.beemdevelopment.aegis` | reach9 | partial | 11.1% | -/- | WV/2 | 15 | - | 0 | 10 / 100% | - |
| 4 | `com.fsck.k9` | reach9 | no | 4.7% | -/- | JS/0 | 56 | - | 0 | 13 / 0% | - |
| 5 | `com.kunzisoft.keepass.libre` | reach9 | no | 0.5% | 清单/- | WV/0 | 10 | - | 0 | 10 / 100% | - |
| 6 | `im.status.ethereum` | reach9 | no | 0.1% | 清单/dex | JS/0 | 44 | - | 0 | 18 / 100% | - |
| 7 | `keepass2android.keepass2android` | reach9 | no | 0.4% | 清单/dex | WV/0 | 40 | - | 0 | 15 / 100% | - |
| 8 | `org.breezyweather` | reach9 | no | 9.3% | -/- | -/0 | 4 | - | 0 | 5 / 40% | reads8/eg11/无明文/host空 |
| 9 | `org.kiwix.kiwixmobile.standalone` | reach9 | no | 0.0% | -/- | JS/1 | 18 | - | 1 | 11 / 100% | - |
| 10 | `ch.protonmail.android` | memhook | yes | 32.4% | 清单/dex | JS/0 | 47 | 有 | 0 | 未跑 | - |
| 11 | `ch.protonvpn.android` | memhook | yes | 84.7% | -/- | JS/2 | 11 | - | 4 | 未跑 | - |
| 12 | `ch.threema.app.libre` | memhook | no | 0.4% | -/- | WV/1 | 36 | 有 | 0 | 未跑 | - |
| 13 | `com.dimowner.audiorecorder` | acq | partial | 14.7% | -/- | -/0 | 5 | - | 0 | 未跑 | - |
| 14 | `com.kylecorry.trail_sense` | acq | partial | 20.6% | -/- | -/0 | 3 | - | 0 | 未跑 | - |
| 15 | `com.mendhak.gpslogger` | acq | no | 0.1% | -/- | -/0 | 19 | - | 0 | 未跑 | - |
| 16 | `com.stoutner.privacybrowser.standard` | memhook | yes | 58.1% | -/- | JS/144 | 2 | - | 0 | 未跑 | - |
| 17 | `com.wire` | memhook | no | 5.0% | -/- | WV/0 | 8 | - | 0 | 未跑 | - |
| 18 | `com.zulipmobile` | memhook | yes | 54.4% | 清单/- | WV/0 | 3 | - | 0 | 未跑 | - |
| 19 | `cx.ring` | memhook | partial | 15.3% | 清单/- | -/0 | 14 | - | 0 | 未跑 | - |
| 20 | `de.dennisguse.opentracks` | acq | no | 0.6% | -/- | WV/0 | 5 | - | 1 | 未跑 | - |
| 21 | `de.monocles.browser` | memhook | yes | 89.5% | -/- | JS/144 | 2 | - | 0 | 未跑 | - |
| 22 | `de.tutao.tutanota` | memhook | no | 0.1% | -/- | JS/4 | 9 | - | 2 | 未跑 | - |
| 23 | `im.vector.app` | memhook | no | 0.4% | 清单/- | JS/2 | 81 | - | 0 | 未跑 | - |
| 24 | `me.proton.android.lumo` | memhook | yes | 92.8% | -/- | JS/1 | 3 | - | 0 | 未跑 | - |
| 25 | `me.zhanghai.android.files` | acq | partial | 19.5% | -/- | WV/0 | 24 | - | 0 | 未跑 | - |
| 26 | `net.clench.wallet` | memhook | partial | 13.3% | -/- | -/0 | 5 | - | 0 | 未跑 | - |
| 27 | `org.eu.exodus_privacy.exodusprivacy` | acq | yes | 46.2% | -/- | -/0 | 4 | - | 0 | 未跑 | - |
| 28 | `org.fossify.contacts` | acq | yes | 56.4% | -/- | -/0 | 16 | - | 0 | 未跑 | - |
| 29 | `org.fossify.gallery` | acq | partial | 14.2% | -/- | -/0 | 17 | - | 0 | 未跑 | - |
| 30 | `org.fossify.phone` | acq | yes | 87.5% | -/- | -/0 | 13 | - | 0 | 未跑 | - |
| 31 | `org.glpi.inventory.agent` | acq | no | 0.7% | -/- | WV/0 | 9 | - | 0 | 未跑 | - |
| 32 | `org.owntracks.android` | acq | no | 2.9% | -/- | -/0 | 25 | - | 0 | 未跑 | - |
| 33 | `org.thoughtcrime.securesms` | memhook | no | 1.2% | 清单/dex | WV/1 | 52 | - | 0 | 未跑 | - |
| 34 | `proton.android.authenticator.fdroid` | memhook | no | 0.7% | -/- | JS/0 | 44 | - | 0 | 未跑 | - |
| 35 | `proton.android.pass.fdroid` | memhook | no | 0.4% | -/- | JS/0 | 40 | - | 0 | 未跑 | - |

## 3. 每类样本卡在流水线哪一环

先给覆盖率本身——**这是最刺眼的空格**：

| 环节 | 有产物的样本 | 占 35 |
| --- | ---: | ---: |
| 静态可达性（`static_reachability.json`） | 9 | 25.7% |
| pin 静态（`pin_scan.json`） | 15 | 42.9% |
| 动态（`manual-session/summary.json`） | **2** | **5.7%** |

所以"每类卡在哪一环"的第一层答案是：**74% 的样本从没进过可达性，94% 从没跑过动态**——
不是它们过不了，而是没跑。下面只对**有产物**的样本谈卡点。

| 类别（按维度） | 样本 | 静态候选 | 可达性 unknown | 动态 | 卡点判定 |
| --- | --- | ---: | ---: | --- | --- |
| 无混淆 + 无壳 | breezy、k9mail | 5 / 13 | 40% / **0%** | breezy：8 读 / 11 外发 / **无明文** / **host 空**；k9mail 无产物 | 静态能过；**动态侧卡在明文**（breezy 走系统 Conscrypt，`TM_CLASS_ABSENT=2`，`target_host` 无值） |
| 无混淆 + WebView/RN 壳 | kiwix、simplex、status | 11 / 18 / 18 | **100% / 100% / 100%** | 无 | 静态直接失效（`framework_js_or_dart` + RN 命名空间未归属）；业务不在 dex，无解 |
| 无混淆 + GMS | keepass2android、organicmaps | 15 / 10 | 100% / 62% | organicmaps：1 读 / 70 外发 / **明文 15905** / `meta.omaps.app`；keepass2android 无产物 | 静态失效在"第三方 SDK 命名空间未入库"（dropbox / google-api）；organicmaps 是唯一**全链路跑通到 host + 明文**的样本 |
| partial 混淆 | aegis | 10 | 100% | 无 | `obfuscated_class` + 包名不一致；短类名 11% 已足以让入口可达性全灭 |
| **yes 混淆** | protonmail、protonvpn、monocles、privacybrowser、lumo、zulip、fossify.contacts、fossify.phone、exodus_privacy | **全部无产物** | **无数据** | 无 | **完全没有数据**——这是池子里最大的黑洞 |
| 声明式 pin | protonmail、threema | 无 | 无 | 无 | pin 静态只做到"有没有"（`pin_strings=1`、类 11/21），**绕过效果零验证** |
| 多进程 ≥1 | protonvpn(4)、simplex(2)、tutanota(2)、kiwix、organicmaps、opentracks | 部分 | 见上 | 无 | 子进程是否被 hook 覆盖，本地**无任何实证** |

9 个跑过可达性的样本合计 110 条候选：`app_reachable` 11（10.0%）、`downgraded_library` 39（35.5%）、
`downgraded_unreachable` 0、`unknown_findings` 60（54.5%），**7/9 触发"本方法对该样本失效"**
（详见 [MOBILE_REACHABILITY_BOUNDARIES_20261110.md](MOBILE_REACHABILITY_BOUNDARIES_20261110.md)）。

一个关键对照：那 4 个 `unknown_findings` 原因码里 `obfuscated_class` 只占 **2.4%**（169 个命中点里 4 个），
**不是因为混淆不重要，而是因为 9 个样本里 obf=yes 的有 0 个**——真正混淆的样本全在 memhook 批次，
从没跑过可达性。这个 2.4% 是抽样偏差，不是能力结论。

## 4. 最需要补的 2 个维度

### 4.1 混淆（含 `mapping.txt` 这条空路径）

现状：yes 9 个、**0 个跑过可达性**、`mapping.txt` **0 个**。

补进去（让这 9 个跑可达性 + 收 1–2 个带 `mapping.txt` 的样本）**预期暴露的问题**：

1. `obfuscated_class` 会从 4 个命中点（2.4%）变成主路径。参考本地最重的一档：
   `monocles` 短类名 89.5%、`lumo` 92.8%、`protonvpn` 84.7%、`privacybrowser` 58.1%。
   按现有归属规则（"无包名且入口可达才算 App"），App 类会大量落 unknown，
   **unknown 预计 ≥80%，`app_reachable` 可能直接归零**。aegis 只是 partial（11.1%）就已经 100% unknown。
2. `wrapper_map.py` 会同时失效：它按类名/方法名做包装映射，而 R8 后包装类是 `qe.h` / `pg.invokeSuspend`
   这种短名（breezy 实测栈里就是这个形态），映射表命中不了 → `wrapper_caller_unknown` 上升。
   现在 organicmaps 靠包装映射把定位读取归回 App 的那条路径，在混淆样本上会不存在。
3. 没有 `mapping.txt` 时，"反混淆后重算可达性"这条唯一的补救路径**无法验证**——
   本地一个 mapping 样本都没有，所以"有 mapping 能不能救回 app_reachable"目前**无法评估**。
4. 顺带暴露度量缺陷：`mapping.txt` 缺失导致 `obf` 只能靠短类名启发式，R8 保留名（keep 规则）会**低估**混淆。

### 4.2 GMS

现状：dex 级 GMS 5 个（keepass2android、organicmaps、status、protonmail、signal），
其中 2 个跑过可达性：keepass2android（15 候选 / **100% unknown** / 0 条 app_reachable）、
organicmaps（10 / 62% / 3 条 app_reachable）。
但**真正调用 `FusedLocationProviderClient` 的只有 organicmaps 1 个**：3 处调用点
（`getFusedLocationProviderClient` ×1、`requestLocationUpdates` ×2），全部来自 App 自己的
`app.organicmaps.sdk.location.gms.GoogleFusedLocationProvider`；
signal 只有 1 处 `LocationServices` 字符串、没有 Fused 类。GMS **权限**声明 0 个。
keepass2android 虽声明 `ACCESS_FINE_LOCATION`，但 **GMS 定位类 0 个、`FusedLocationProviderClient`
与 `LocationServices` 字串 0 次、调用图里没有 App 类的 LocationManager 调用点**，
它的 11 条 unknown 与 GMS 无关，**不能当 GMS 假阴性的例子**。

补进去（收 3–5 个"清单声明 `com.google.android.gms.permission.*` + dex 真调 `FusedLocationProviderClient`"的样本）
**预期暴露的问题**：

1. **静态侧：候选根本没生成，不是归属判错**（2026-11-10 反事实实测修正本条初稿）。
   `dangerous_apis` 58 行里 `com.google.android.gms*` **0 行**，GMS 调用从不成为候选，
   归属四步根本没机会执行。在内存里临时加入 3 条 GMS 三元组重跑 organicmaps：
   `LocationServices.getFusedLocationProviderClient` 的命中点归属 = **app**（第 1 步 App 前缀
   `app.organicmaps` 命中）、桶 = `app_reachable`；`FusedLocationProviderClient.requestLocationUpdates`
   的命中点在 R8 lambda 里，落 `unknown_findings` / `dynamic_dispatch`。
   即：**真正的缺口在候选生成（规则库无 GMS 签名），不在归属规则**；`com.google.android.gms`
   虽在 `LIBRARY_PREFIXES`，但归属看的是调用方类，App 调 GMS 时调用方就是 App 类。
2. **动态侧：不是"采不到"，是"没挂"**（同上修正）。GMS 客户端类由 `play-services-location`
   静态链接进 App dex——organicmaps 的 APK 内定义了 **380 个 `com.google.android.gms` 类**
   （其中 35 个在 `.location`，含 `LocationCallback` / `LocationResult` / `FusedLocationProviderClient`），
   跑在 **App 进程**，回调也在 App 进程分发，不存在进程边界。真实障碍是：
   现有 targets 只挂 `android.location.LocationManager` 的 7 个签名；Java 侧原先在 ARMED 阶段
   一次性 `Java.use`（`hook_privacy.js`），GMS 类通常晚于 arm 才加载。该缺口已于 2026-11-10
   补上：Java 侧 2s × 30 轮有界补挂（`JAVA_RESCAN_ROUND` / `JAVA_RESCAN_STOPPED`，
   与 native `RESCAN_STOPPED` 同构，幂等靠 `ARMED_KEYS`），**但"类晚到"的真机复现仍未做**。
   另：本机 AAOS 模拟器**没有 Play services**，
   `LocationProviderFactory` 很可能根本不走 GMS 分支，要复现必须换带 GMS 的设备。
3. **一致性风险**：商业 App 常见的 Play Integrity / 签名校验会中断 attach 或让进程直接退出
   （本地 0 个样本带该特征，**无法实证**，属待实测项，不作为结论）。

### 为什么不选第三/第四名

- **WebView/RN 壳**（13 个 JS 桥 + 2 RN + 1 Flutter）：不是"没样本"，是**已有样本已经证明失效**
  （kiwix/simplex/status 三个 100% unknown）。补它不会暴露新问题，只是重复已知结论。
- **声明式 pin**（2 个）与**多进程**（6 个）样本量不足，但补的优先级低于上面两个：
  NSC pin 只影响"pin 绕过是否生效"，多进程只影响"子进程事件是否漏采"，都不改变主结论方向。

## 5. 车载 4 个第三方样本（单列，不是移动端分布）

| 包名 | 混淆 | 短类名 | GMS(清单/dex) | WebView(JS桥/html) | 命名空间 | NSC pin | 进程 |
| --- | --- | ---: | --- | --- | ---: | --- | ---: |
| `com.tommasov.mg4browser` | no | 0.7% | -/- | WV/0 | 0 | - | 0 |
| `hu.muzso.fileslauncher` | yes | 51.5% | -/- | -/0 | 0 | - | 1 |
| `de.vito0912.yaabsa` | yes | 83.8% | 清单/dex | JS/2 | 9 | - | 0 |
| `io.homeassistant.companion.android.minimal` | no | 0.4% | 清单/- | JS/0 | 51 | - | 1 |

`yaabsa` 是本地最接近"商业形态"的样本（R8 混淆 83.8% + GMS dex + JS 桥 + 本地 assets 页面），
但它只跑过**车载**流水线（`output/vehicle-yaabsa-*`），**从未进过移动端可达性/动态**。
如果要一次拿到"混淆 + GMS + Hybrid"叠加的真实失效数据，它是现成的、不需要下载的第一个候选。

## 6. 明确"本地无法评估"的维度

以下项**一个样本都没有**，不得用推断代替：

| 项 | 现状 | 影响 |
| --- | --- | --- |
| `mapping.txt` 反混淆样本 | 0/35 | 无法评估"有 mapping 时可达性能否救回" |
| GMS **权限**声明（`com.google.android.gms.permission.*`） | 0/35 | 只能按 dex 引用判 GMS 依赖，清单级判据在本地为空 |
| 广告 / 归因 SDK（AdMob、AppLovin、Unity、Facebook、穿山甲、友盟、Adjust、AppsFlyer） | 0/35 | 无法评估"带广告 SDK 的商业 App 的第三方外发归因" |
| 加固壳（360/梆梆/乐固/爱加密） | 0/35 | 无法评估脱壳路径 |
| Play Integrity / SafetyNet | 0/35 | 无法评估 attach 被完整性校验打断的比例 |
| 命名空间 ≥100 的样本 | 0/35（最大 81） | 无法评估"SDK 数量爆炸"时归属策略的表现 |

## 7. 测量口径与已知误差（复现前先看这段）

1. **混淆是启发式**：短类名占比 + 单字母顶层包数 + `mapping.txt` 三者取或；R8 开 keep 规则会低估。
2. **"命名空间数"不是 SDK 数**：取 dex 类名前两段（`com.google`），排除平台前缀、App 自身包/org 段、
   `crc64.`、`com.vscanner.`、以及 R8 顶层包（`a`/`A0`/`p000`/`aa` 这类 1–2 字母名），只保留 ≥2 个类的命名空间。
   修前曾把 R8 顶层包当成 SDK（protonvpn 6732），修后 11——**说明这一列在重混淆样本上两端都会错**：
   混淆浅时膨胀、混淆深（privacybrowser/monocles 只剩 2）时塌缩。它只能当"量级参考"，不能当 SDK 清单。
3. **GMS 判据**：dex 里出现字节串 `Lcom/google/android/gms` 才算依赖；
   单独出现 `LocationServices` 不算（kiwix/gpslogger/owntracks 都有该串但无 GMS dex）。
4. **声明式 pin 必须按字节扫全部 `res/**/*.xml`**：回编译后资源被压平成 `res/4u.xml`，
   只看 `res/xml/` 会全漏（protonmail / threema 就是这样被找到的），编码要同时试 UTF-8 与 UTF-16-LE。
5. **多进程 = `AndroidManifest.xml` 里 `android:process` 属性出现次数**，含 application 级与组件级；
   它不等于"运行时真的有 N 个进程"。
6. **可达性对齐键是 `manifest.meta.apk_sha256`**，不是 `manifest.apk` 路径（产物里没有后者，按路径对齐会静默全 None）。

## 8. 闭集缺口：`dangerous_apis` 漏了多少（2026-11-10 实测）

`dangerous_apis` 是**闭集签名表**：没有签名就成不了候选，归属四步根本不会执行。organicmaps 的
GMS 定位路径就是这样整条不可见的。本节把"构造上就不可能被看见"的部分量出来。

### 8.0 数据来源与复现

- 范围：池内 **52 个唯一 APK 全部跑通 `dexdump -d`，解析失败 0 个**（无需单列失败样本）。
  其中 **39 个第三方**（35 移动 + 4 车载）、13 个自建夹具；夹具不计入下面的比例。
- 脚本（`output/` 不入库）：`output/_pool-analysis/closed_set_gap.py`（扫描）、
  `gap_agg.py` / `gap_detail.py` / `gap_fields.py`（汇总）；原始结果 `gap.json`、`gap_report.txt`、`gap_detail.txt`。
- 只读：未下载、未跑动态、未改规则库、未改代码。

### 8.1 口径：两个分母

敏感品类是**独立枚举**的（品类 → 类名/前缀），**不是从 `dangerous_apis` 反推**——否则分母被闭集定义，
比例永远 100%。品类覆盖定位、通讯录、相机、麦克风、传感器、剪贴板、设备标识（IMEI/ANDROID_ID/序列号）、
已装应用列表、存储；敏感类里的方法**全收**（不做方法级挑选，挑方法等于提前假定该挑哪些），
唯一例外是 `ContentResolver` 只算取数/写数的 10 个方法（不算 `registerContentObserver` 之类）。

| 分母 | 定义 | 值（39 个第三方样本） |
| --- | --- | ---: |
| **A 签名面** | 全部 invoke 目标按 `(类, 方法, 描述符)` 去重后的并集，落在敏感品类上的**不同 API 形态数** | **719** |
| **B 调用点** | 同一签名的 `invoke-*` 指令条数，跨样本累加 | **11,778** |

### 8.2 两组命中率

| 组 | 签名（分母 A） | 命中 | 命中率 | 调用点（分母 B） | 命中点 | 命中率 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 平台 `android.*` / `androidx.*` / `java.net` | 630 | 40 | **6.3%** | 11,653 | 936 | **8.0%** |
| GMS `com.google.android.gms.*` | 89 | **0** | **0%** | 125 | **0** | **0%** |
| 国内 SDK（高德/腾讯/百度/autonavi） | **0** | — | — | 0 | — | — |
| 合计 | 719 | 40 | 5.6% | 11,778 | 936 | 7.9% |

**必须同时写出的上界与下界：**

- **上界 93.7%（平台组，分母 A）；含 GMS 为 94.4%。** 这是品类级口径，含"敏感类上但不取数"的方法
  （`release()`、`hasSystemFeature`、`isProviderEnabled`），所以是**高估**。
- **下界 85.0%。** 只算**类已被闭集登记**的那 266 个签名（630 减掉 364 个整类没登记的），
  命中 40，漏 226。这是**已进入闭集视野的部分里仍然漏掉的比例**，与品类枚举是否过宽无关。
- 按调用点加权为 **92.0%**（11,653 中 10,717 不可见），落在两者之间。

自建夹具 13 个单独算：126 个平台签名 / 10 命中 / 缺口 92.1%——**夹具能验证"规则命中"，
验证不了"闭集完整性"**，它的 exact 命中集中在规则特意覆盖的那几条上。

### 8.3 形态拆解：不是"少见重载"，是"整类 + 整方法"

| 形态 | 平台组签名 | 占比 | 含义 |
| --- | ---: | ---: | --- |
| `class_gap` 整类没登记 | **364** | 57.8% | `ClipData`、`DocumentsContract`、`MediaRecorder`、camera2 的 `CameraDevice`/`CameraCaptureSession`、`Environment`、`MediaStore`、`ActivityManager`、`androidx.core.location.LocationManagerCompat`、`ProcessCameraProvider` |
| `method_gap` 类登记了、方法没有 | **225** | 35.7% | `ContentResolver.openInputStream`（374 次）、`PackageManager.getPackageInfo`（486 次）、`LocationManager.isProviderEnabled`/`getCurrentLocation`、`SensorManager.getDefaultSensor`、`ClipboardManager.setPrimaryClip`、`TelephonyManager.registerTelephonyCallback` |
| `overload` 类+方法对、描述符不同 | **1** | 0.16% | 唯一一条 |

结论：**"少见重载"几乎不存在（1 条）**。补签名不是补几条，而是按类/按命名空间补一整片；
GMS 则是整片 100% 不可见（89 签名 / 125 调用点 / 0 命中）。

按品类（签名数 / 命中 / 缺口）：

| 品类 | 签名 | 命中 | 缺口 | | 品类 | 签名 | 命中 | 缺口 |
| --- | ---: | ---: | ---: | --- | --- | ---: | ---: | ---: |
| 麦克风 | 70 | 1 | 98.6% | | 定位 | 145 | 6 | 95.9% |
| 相机 | 171 | 4 | 97.7% | | 已装应用 | 91 | 5 | 94.5% |
| 存储 | 89 | 3 | 96.6% | | 通讯录 | 25 | 2 | 92.0% |
| 剪贴板 | 29 | 1 | 96.6% | | 传感器 | 15 | 2 | 86.7% |
| | | | | | 设备标识 | 84 | 16 | 81.0% |

### 8.4 命中率为 0 的命名空间（5 / 18）

| 命名空间 | 组 | 签名 | 调用点 |
| --- | --- | ---: | ---: |
| `com.google.android.gms.location` | gms | 89 | 125 |
| `android.app`（ActivityManager） | platform | 22 | 294 |
| `androidx.documentfile.provider` | platform | 23 | 264 |
| `androidx.core.location` | platform | 15 | 126 |
| `androidx.camera.lifecycle` | platform | 32 | 96 |

### 8.5 闭集表达力之外：`Build` 字段读取通道

**38/39 个样本读取 `android.os.Build` 的静态字段**：`MODEL` 1255 次、`BRAND` 827、`MANUFACTURER` 647、
`DEVICE` 436、`FINGERPRINT` 207、`ID` 124、`VERSION.RELEASE` 82、`PRODUCT` 50。
闭集是**方法签名表**，字段读取从一开始就不在它的表达力内——**任何按签名补库的方案都补不到这里**。
另有 `Settings$System.DEFAULT_NOTIFICATION_URI`（20 个样本）、`Environment.DIRECTORY_*`（20 个样本）同类。
该通道单列统计、不计入上面的比例。

### 8.6 闭集自检：58 条里 18 条从未出现

40 条在本地池子出现过；18 条**一次都没出现**（说明"库里有"和"池子能验"是两件事）：

| 类 | 未出现的签名 |
| --- | --- |
| `BluetoothAdapter` | `getAddress` / `getBondedDevices` / `getName` |
| `SensorManager` | `registerListener(…)` 的 4 个变体（`II` ×2、`SensorListener` ×2） |
| `BiometricPrompt` / `FingerprintManager` | `authenticate` ×3 |
| `LocationManager` | `requestLocationUpdates` 的 4 个变体（`Criteria`+`PendingIntent`、`Criteria`+`Executor`、`String,J,F`+`Executor`、`LocationRequest`+`PendingIntent`） |
| 其它 | `ClipboardManager.getText`、`MediaProjectionManager.getMediaProjection`、`TelephonyManager.getMeid`、`AudioRecord.startRecording(MediaSyncEvent)` |

### 8.7 本地无法评估：国内 SDK 这一组

39 个第三方样本里 `com.amap.*` / `com.tencent.*` / `com.baidu.*` / `com.autonavi.*` 的敏感调用点
**签名 0、调用点 0**。所以：

- **国内 SDK 组本地无法评估**，不得用 GMS 的 100% 去代表它——两者只是"都属于第三方 SDK"这一点相同；
  缺陷机制同类（闭集没登记就不可见），但**缺陷规模无法从本地数据推断**。
- 要量这一组必须补国产位置/推送 SDK 样本，本地现有 39 个样本一个都没有。

### 8.8 本节与其他节的关系

- §3 的"94% 从没跑过动态"与本节是两件事：那是**有签名但没跑**，本节是**根本没签名、跑了也成不了候选**。
- 本节只量"可见性缺口"，**不推出"漏报率"**：候选不可见 ≠ 一定有隐私读取，可见也不保证归因正确
  （§3 的 9 样本 unknown 54.5% 是另一层问题）。
