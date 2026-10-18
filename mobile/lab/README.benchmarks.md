# Android 隐私泄露检测：论文测试集与分层评测

核实日期：2026-10-17。范围：非 root Android、自有源码/获授权 APK、Frida Gadget。
本文包含测试集选型、评测协议与已下载工件状态；实际结果见第 5 节。本项目自有合成夹具的实测另见 README.md。
只使用合成标识、虚构账户与本地接收端，不使用真实个人信息。

## 1. 选型结论

优先用 Ghera 覆盖存储、弱加密、网络，再用 DroidBench 补事件顺序与数据流。
ReproDroid 用于核对标签和结果结构，不是现成的动态 UI 驱动平台。
CryptoAPI-Bench 用于加密规则与负例设计；原仓库是 Java/JAR，不是 Android APK 集。
CCA-Droid 有 Android 工件，但许可和动态驱动信息不完整，暂列候选。
“静态存在路径”“运行时 API 被调用”“敏感数据已到达风险出口”必须分别评价。

## 2. 五组资源：工件、真值、许可与动态适配

下表中的“可适配 Gadget”是工程判断，不表示作者或本项目已完成适配验证。

| 优先级/资源 | 论文与官方工件 | 源码/APK/标签 | 许可边界 | 动态运行及 Gadget 判断 |
| --- | --- | --- | --- | --- |
| 1 · Ghera | [PROMISE 2017 论文](https://arxiv.org/abs/1708.02380)；[官方仓库](https://bitbucket.org/secure-it-i/android-app-vulnerability-benchmarks/)；[官方 README](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/README.md) | 论文初版 25 项，master README 后续记为 60 项；源码、示例 APK、Benign/Secure、演示攻击应用、Testing 与逐项说明 | [BSD-3-Clause](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/LICENSE)；保留声明，不能把论文版权当代码许可 | 官方验证范围为 Android 5.1–8.1/API 22–27；需按用例启动应用、点击或配本地服务；源码适合嵌 Gadget，现代系统标签需重验 |
| 2 · DroidBench | [FlowDroid / PLDI 2014 论文](https://jacquesklein2302.github.io/papers/2014-PLDI-flowdroid.pdf)；[官方仓库](https://github.com/secure-software-engineering/DroidBench) | 当前 README 列 190 项；projects 源码、apk 预编译包、正负数据流说明；兼顾动态，但重点包括静态分析难点 | 未确认统一许可证；[OSS license #40](https://github.com/secure-software-engineering/DroidBench/issues/40) 仍 open；公开可读不等于可任意改造分发 | 需 UI/生命周期/位置/ICC 触发；源码可作适配基础；[运行兼容问题 #51](https://github.com/secure-software-engineering/DroidBench/issues/51) 指出现代 Android 的空 device ID 与权限申请问题 |
| 3 · ReproDroid 整理版及扩展 | [ESEC/FSE 2018 论文](https://arxiv.org/abs/1804.02903)；[官方项目及下载](https://github.com/FoelliX/ReproDroid) | 整理版 DroidBench、Feature-Checking/Intent-Matching 等；APK、源码、AQL XML 预期结果与历史结果；部分扩展分 API 19/26 | 框架仓库 GPL-3.0；不能由框架许可推定所有输入 App/数据集同为 GPL | 是分析编排与标签整理，不是设备触发器；动态事件需独立适配；优先更新包并核对 errata，避免与 DroidBench 重复计样本 |
| 4 · CryptoAPI-Bench | [SecDev 2019 论文](https://yaogroup.cs.vt.edu/papers/IEEE_SecDev19_CryptoAPI-Bench.pdf)；[官方仓库](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench) | 论文 171 个 Java 用例、16 类误用；Java 源码、Gradle 构建 JAR、CryptoAPI-Bench_details.xlsx 安全/不安全标签 | [MIT](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench/blob/master/LICENSE)；保留许可；数量和标签固定到实际 commit，不混用不同论文版本 | 不是即装 APK，不能直接接 Gadget；可包装为自有 Android 调用夹具，另验密码提供者、入口及参数是否实际执行 |
| 5 · CCA-Droid 扩展集（候选） | [AsiaCCS 2026 论文](https://dl.acm.org/doi/abs/10.1145/3779208.3807487)；[作者论文目录](https://sanghakoh.github.io/publications/)；[官方数据目录](https://github.com/AndroidSeclab/CCA-Droid/tree/main/dataset) | APK 与 Java 片段，含 ECB、固定 IV、弱随机数、短 MAC、非认证模式及 Corrected 对照；[README 规则映射](https://github.com/AndroidSeclab/CCA-Droid#dataset) | 核查仓库未发现 LICENSE；上游 CryptoAPI-Bench 的 MIT 不能自动覆盖新增工件，使用/再分发前核实授权 | 面向静态检测；未找到统一动态触发、完整 Android 构建工程和支持版本声明；APK 存在不证明可运行，暂不计作已就绪基准 |

### Ghera 与本项目三条目标的对应

- 存储：[官方 Storage 清单](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/Storage/README.md)。
- 首选 ExternalStorage-InformationLeak-Lean 及 InternalToExternalStorage-InformationLeak-Lean。
- [外部存储用例说明](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/Storage/ExternalStorage-InformationLeak-Lean/README.md) 给出输入、启动顺序和预期观察。
- 弱加密：[官方 Crypto 清单](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/Crypto/README.md)。
- 可选 ECB、非随机 IV、固定 salt、硬编码 key；按具体威胁模型配安全对照。
- 网络：[官方 Networking 清单](https://api.bitbucket.org/2.0/repositories/secure-it-i/android-app-vulnerability-benchmarks/src/master/Networking/README.md)。
- 可选明文 socket、HTTP、证书/主机名验证；后两类是传输验证风险，不直接等同隐私外泄。

## 3. 原始 truth 与适配 truth 分开保存

1. original_truth：记录作者标签、类别、来源 URL、数据集版本/commit、原始 Android 范围。
2. adapted_truth：记录本项目定义的规则、平台、合成输入、触发步骤、预期事件及独立验证证据。
3. 以原始 case_id 关联两者，不覆写原标签；新增 variant_id，说明源码、权限、服务端和入口变化。
4. 固定输入、超时、重试次数与状态复位方法；同一变体的安全/风险配对使用相同触发条件。
5. synthetic source 替换 IMEI 等受限来源时，标为“合成数据传播”，不能声称验证了真实受限 API 读取。
6. Android 新版本阻止旧漏洞时记 platform_mitigated/unsupported，不倒改作者历史真值。
7. Gadget 嵌入、重签名可能改变签名权限、ICC 信任和完整性行为，适配后必须重验该用例。
8. [ReproDroid errata](https://github.com/FoelliX/ReproDroid#errata) 列出 4 项错标与 Reflection 统计问题，旧包不能直接当最终真值。

静态标签仅证明作者研究模型中的预期；不证明某台手机、某次测试已触发风险行为。
独立 oracle 应来自夹具的调用/落盘断言、本地接收端或可复核产物，而不是检测器自己的告警。
标签有争议或证据不充分时记 ambiguous，复核前不放进正负样本分母。

## 4. 非 root + Gadget 的观测边界

- Gadget 仅用于有源码与安装授权的变体；不能承诺无条件注入任意第三方 App。
- 不依赖 adb root、跨 UID 读取 /data/data、系统 CA 安装或全局抓包权限来建立基本指标。
- 本进程文件/SharedPreferences/SQLite 写入可在授权夹具内观察；这不证明别的 App 能读取。
- “私有目录明文存储风险”与“已验证越界可读/泄露”分两类标签和指标，不互相替代。
- 加密前明文观测用于连接数据来源与算法参数；看到 Cipher.doFinal 本身不构成弱加密真值。
- HTTP/TCP 接收内容可独立核对；HTTPS 内存明文与接收端分别取证，不以抓包空白判安全。
- 仅观测一个进程时不能声称覆盖整个 ICC 链；未纳入进程、native/QUIC 等能力缺口单列。
- ARMED、设备存活、事件实际捕获是三层检查；阳性对照不过，记录采集故障，不给安全结论。

## 5. 首批规模与执行状态

建议先挑 15–25 个 Ghera 用例，覆盖 Storage/Crypto/Network，并包含安全配对。
再挑 10–15 个 DroidBench 用例，覆盖覆写、跨 Activity、顺序点击、生命周期与无泄露对照。
上述数量指去重后的逻辑用例数；另报 APK 数、变体数、正负实例数，不能混为同一分母。
ReproDroid 与 DroidBench 重叠项只算一次；CryptoAPI-Bench 可供第二批补规则负例。
旧平台复现组与当前非 root 平台适配组分表，不用旧平台标签直接给现代平台打分。

### 已下载的论文工件（2026-10-17）

本地目录：`output/benchmark-corpus-20261017/`（Git 忽略，不提交 APK/语料私钥）。

| 数据集 | 固定提交 | 实际 APK 数 | Manifest 解析 / 签名验证 |
| --- | --- | ---: | ---: |
| DroidBench | `a57fa6f42f278591695672f1aa8b37c275139370` | 188 | 188 / 188 |
| Ghera（Crypto、Storage、Networking） | `ea1dbe234e4d3433161a3b85e96648913a36e83c` | 55 | 55 / 55 |
| 合计 | 分别固定版本 | **243** | **243 / 243** |

- DroidBench README 标称 190 个测试用例；此提交 `apk/` 实际 188 个 APK，按实物计数。
- Ghera 本次为 20 个逻辑案例：Crypto 5/17、Storage 7/21、Networking 8/17（案例/APK）。
- Ghera 的 55 个 APK 含 20 Benign（作者含漏洞目标）、20 Secure、14 Malicious、1 Benign-V2。
  不把作者命名的 Benign 当安全阴性；没有运行 Malicious 变体。
- 官方 ZIP 中 Ghera APK 是 Git LFS 指针，已由固定提交的官方 REST 接口取得真实二进制，
  逐一核对 LFS SHA256 和 size；最终遗留指针为 0。
- 签名验证为 apksigner 默认 Manifest minSdk 范围的静态验证，不代表 Android 14 可安装。
  DroidBench 有 185 个 APK 的有效 targetSdk < 23，不能无条件在当前真机跑批。
- `static-inventory.json` / `.csv` 记录包名、SDK、签名、权限、入口和每个原始工具输出路径。
  各数据集 `manifest.json` 记录上游 URL、提交、文件摘要及下载状态。
- 原始 APK、作者源码与许可均留在本地语料目录。DroidBench 未确认统一许可，不随本项目分发。

### 真机已完成的最小签名对照

Ghera `BlockCipher-ECB-InformationExposure-Lean` 的 Benign、Secure 两个原 APK，
各运行“原签名”“替换为本地测试签名”两种状态，共 **4 次 / 4 次通过**。
当前 Android 14/API 34、user 构建，不使用 root。每次独立安装、启动，输入合成邮件标识，
点击 Get Token，确认非空 token 日志和进程存活，再卸载本次测试包。
重新签名不改 DEX、Manifest、资源；非 META-INF 的 ZIP 内容摘要保持一致，签名证书确已变化。

证据：`output/benchmark-corpus-20261017/signing-baseline/verification.json`、
`artifacts.json` 及每次的 install/launch/UI/logcat/cleanup 记录。
测试输入为 `VSCAN_TEST_GHERA_20261017@example.test`；源码核对 sendTokenAsEmail 只 Toast/Log，不发送邮件。

这验证的是上述两个 APK 的重签名路径兼容，不是签名自检绕过成功、Gadget 重打包成功，
也不是 243 个 APK 的动态检测通过。尚无第三方基准的 Gadget 成功率或 precision/recall。
重打包兼容的实测分层见 [README.repack.md](README.repack.md)。

## 6. 评价单位与运行状态

固定一个评价实例 u = (dataset, case_id, variant_id, rule_id, Android/API, ABI, run_id)。
同一实例重复 Hook/重试事件先去重，不以 API 调用次数、报表条数或截图数充当样本数。
按存储/弱加密/网络分别统计，先报各类结果；需要汇总时再给 macro 与 micro，公开权重。
每个实例预先固定 adapted_truth：positive 或 negative；不能观察完输出再选择标签。

| 运行状态 | 含义与计分 |
| --- | --- |
| evaluable | 支持范围内，独立 oracle 确认预定风险/安全路径已触发，采集链路健康且标签可判定 |
| not_triggered | 未达到预定路径；不当作 TN，也不纳入条件检测 precision/recall |
| unsupported | 平台/ABI/权限/观测面不支持；不当作 TN，单列原因与数量 |
| failed | 构建/安装/插桩/采集崩溃或超时等失败；不当作 TN，单列失败阶段 |
| ambiguous | 真值或证据不足；不当作 TN，人工复核后才能进入条件检测分母 |

负例的 evaluable 指安全对照行为确已执行，而不是期待不存在的“泄露事件”被触发。
未触发/unsupported 上产生的告警仍保留并单列为未验证告警，不能删除来美化 precision。

## 7. 分层指标与明确分母

记 S 为预先声明纳入的全部实例，E 为 evaluable 实例，P_E/N_E 为 E 中预标正/负实例。
TP = P_E 中正确报对应规则的实例数；FN = P_E 中未正确报告的实例数。
FP = N_E 中错误报对应规则的实例数；TN = N_E 中未误报的实例数。
错报其他规则按那个规则计 FP；不得用一次任意告警抵消目标规则 FN。
precision = TP/(TP+FP)，分母是 E 内产生该规则阳性判定的实例数。
recall_triggered = TP/(TP+FN) = TP/|P_E|，分母是已触发、可判定的正例数。
任何分母为 0 时记 N/A，不能填 0%、100% 或用平滑值冒充实测。

| 层级 | 评价内容 | 指标与分母 |
| --- | --- | --- |
| L0 可用性 | 构建/安装/接入 Gadget/健康采集 | 各阶段成功数/进入该阶段实例数，同时报成功数/全部 S；unsupported/failed 单列 |
| L1 触发覆盖 | 风险/安全路径是否实际执行 | evaluable 数/预声明支持的实例数；另报 not_triggered 数和 unsupported 数占 S 的比例 |
| L2 事件检测 | 文件写入、加密参数、网络发送是否捕获 | 对有独立事件 oracle 的实例算上述 precision/recall；按 API/出口分组，未观测不等于未发生 |
| L3 数据流关联 | 合成敏感值是否从来源到指定 sink | 以预定 source→sink 关系为单位另算 TP/FP/FN；precision 分母为预测关系数，recall 分母为 oracle 正关系数 |
| L4 风险判定 | 明文存储、弱加密、网络暴露是否判对 | 对各 rule 的 P_E/N_E 算上述 precision/recall，并单列“风险存在”与“泄露已验证” |
| L5 端到端 | 从选入用例到正确产出证据 | 成功检出的正例数/预声明支持的全部正例数；触发失败、采集失败留在此分母，不冒充条件 recall |
| L6 证据质量 | 结论是否有来源、路径/目标、参数与结果 | 证据完整告警数/全部告警数；另报未验证告警数/全部告警数，不把完整性当准确率 |

对 L3 必须说明匹配是否仅值级，是否支持变换；编码、加密、哈希后的关系不能只凭时间接近定真。
对 L5 另报成功正例数/|S 中全部预标正例|，展示包含 unsupported 的实际覆盖，不称为分类 recall。
性能单列：相同触发脚本下有/无 Gadget 的延时、CPU、内存、崩溃率；写清有效运行数与失败数。
同一逻辑用例的多次运行报告波动与成功次数，不能把挑出的最好一次当整批结果。

## 8. 三条目标的验收证据

- 存储：合成标记、写入 API、路径/存储域、明文/密文产物断言、安全对照；越界读取另需独立证据。
- 弱加密：敏感值进入加密的证据、算法/模式、key/IV/salt 的安全属性、执行路径与安全变体。
- 网络：合成标记、发送 API、目标端点、实际接收内容、HTTP/TLS 状态；本地服务输出作独立 oracle。
- 只读权限、请求权限或 API 名命中不是上述任一类的泄露证据；报告保持事实、风险与合规判断分层。

## 9. 不纳入首批的真实恶意样本

TaintBench 提供真实恶意应用与流标注，但[作者说明](https://taintbench.github.io/taintbenchSuite/) 指出老样本服务端可能已下线。
它不能直接提供当前环境下的动态执行真值；本次未下载、执行，不计入首批推荐规模。
先完成自有合成夹具与开放基准适配，再决定是否在隔离环境下另建获授权的真实样本评测。

## 10. Root 模拟器实际进展（2026-10-18）

Ghera 首批 5 组、10 个原始 Benign/Secure APK 已在 API 36 root 模拟器上完成：
全量 DEX 静态扫描与反编译、原包安装摘要核对、Frida 早期观察、确定性触发、独立文件/端点/PCAP 对照、卸载清理。
最终目标行为观察 10/10，原始事件 60 条；含修复版的拒绝控制，不把 observed 当“违规”。
本轮是 root Frida Server，不是第三方 Gadget 重打包成功率，也不是下载的 243 APK 全量动态通过。
最终结果见 `output/root-benchmark-20261018-verified/verification.json`；
复跑、网络分包修复及结论口径见 [README.root.md](README.root.md)。
