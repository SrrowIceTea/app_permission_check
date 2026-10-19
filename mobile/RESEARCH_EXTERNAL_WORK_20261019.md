# 移动 App 隐私数据安全检测：外部既有工作调研与 V-Scanner 借鉴评估

> 版本：2026-10-19 · 面向 `mobile/`（V-Scanner Mobile）
> 本报告**只做调研与建议**，不修改任何代码。所有借鉴点均需遵守项目硬约束：
> 静态证据封顶 `candidate`、不写进 `code_locs`、不产出 `policy_violation`；
> 观察不改写；结论可追溯；缺失写 gap；单文件 ≤300 行；仅授权测试。
> 核实状态四档：`论文原文核实`（直接读到 PDF/摘要/官方元数据）/
> `官方页面核实`（官网/注册表/官方仓库） / `仅二手来源` / `未核实`。
> 全部来源访问日期：**2026-10-19**。

---

## 1. 摘要

本调研核对了 13 项学术工作、6 项行业平台、3 项开源/CI 工具与 2 项机器可读报告标准，结论如下：

1. **通用静态污点引擎（FlowDroid 路线）继续不值得做**。TSE 2021 受控评测的关键数字已核实：
   FlowDroid 在 25 个真实 App 上崩溃 11 个、其余 14 个只检出 2 条预期流；Amandroid 对同一 App
   四次运行报 0/3/28/43 条流（§3.1）。这与 V-Scanner「静态只做引用级佐证、结论封顶 candidate」的既有路线一致。
2. **GNChecker（重点）已找到一手出处**：ASE 2024 "Giving without Notifying"
   （DOI 10.1145/3691620.3695528）。其「分段策略」经论文摘要与索引正文核实为：**按
   source→sink 可达路径的源代码集合切分子包**（LDPG，基于 FCG），只对与 sink 连通的路径代码做数据流分析，
   **不是按包名/SDK/入口分段**（§3.4）。1,134 个真实 App 上 379 个检出 1,410 条真实不合规传输，precision 93.1%。
3. **PIChecker（重点）已核实**：FORGE@ICSE 2026（DOI 10.1145/3793655.3793721，开放获取）。
   「147 个流行 App、17 个无政策、**其余 130 个中超过 64% 未能准确描述内嵌 TPL 的隐私行为**」这一口径与论文摘要
   逐字一致（§4）。方法三阶段 = Soot/FlowDroid 静态污点 + DroidBot 动态验证 + GPT-4o 政策解读，
   TPL 定位靠 ATVHunter。对 V-Scanner 的落地形态是「**TPL 行为—政策声明矩阵**」（§4.5、§6-B4）。
4. **ML 的位置应当严格受限**：LeakSemantic（INFOCOM 2017，1,404 个 App / 2,279 条敏感连接 / 91% 准确率）
   证明「URL 词法特征分类器」可做**合法/异常传输的降噪与排序**；GDPR-Bench-Android（1,951 条人工标注违规、
   23 条 GDPR 条款）证明当前 LLM/Agent/形式化方法**从代码直接判违规的最高分仅 17.38%**（文件级 Acc@1）。
   对 V-Scanner：ML/LLM 只能产出 hint、优先级与「需人工复核」，不能作为谓词证据、不能升级结论等级（§3.5、§7.1）。
5. **行业平台（百度史宾格/梆梆/华为云/汉华信安等）的差异化不在检测算法，而在报告形态与服务闭环**
   （问题描述+整改建议+截图存证+代码堆栈；20 分钟级出报告；人工/法务复核）。V-Scanner 已有同等证据深度，
   缺的是**发现卡片五要素的完整性断言、法规映射矩阵、复测对比**三类报告工程（§5、§8）。
6. **机器可读配套**：SARIF 2.1.0（OASIS 标准）适合静态补充扫描与校验问题清单的 CI 化导出；
   OSCAL（NIST）适合「法规条款—检测项—结果」矩阵的长期机器化。二者均为离线增量、不触碰现有九章 PDF 骨架（§8）。
7. **不应借鉴**：全量通用污点引擎、AndroByte 式「LLM 直接判流」、PriAgent/GDPR 系「直接产出违规定性」、
   大规模 SDK 签名库、mock/影子数据、PIChecker 的 APK 重打包插桩、Oncecheck/SubmitGate 的源码引入（§9）。

落地优先级：**P0**（纯离线）：stage2 五分类并入 OD/VD 语义、报告卡片五要素断言+法规矩阵渲染、
「ML 位置约束」写入决策文档；**P1**（需设备）：TPL 行为—政策声明矩阵真跑、隐私定向 UI 探索目标、
「同意被拒后仍外发」观察项、复测对比章节；**P2**（研究级）：SDK 隐私配置 API 引用观察、
VScanBench 中加 GDPR-Bench/AndroByte 对照（§6、§7）。

---

## 2. 事实核对表

| # | 工作 | 出处 | 核实状态 | 关键数字 | 一句话方法 |
|---|------|------|----------|----------|------------|
| 1 | FlowDroid | PLDI 2014, DOI 10.1145/2594291.2594299 | 论文原文核实（ACM 元数据+官方仓库） | DroidBench 基准随文发布；~500 Play App + ~1,000 恶意样本评测 | Soot/Jimple + IFDS 正向污点传播，生命周期建模（dummyMain），source/sink 配置 |
| 2 | Taint Analysis Tools 横评 | Zhang, Wang, Qiu, Rubin, IEEE TSE 48(10):4014–4040, 2022（2021 在线）, DOI 10.1109/TSE.2021.3109563 | 论文原文核实（IEEE 元数据；关键数字经被索引正文+二手精读交叉验证，全文付费墙） | 25 个真实 App：FlowDroid 崩 11 个、其余 14 个仅 2 个检出预期流；Amandroid 同 App 四次运行 0/3/28/43 条流 | 统一配置下横评 FlowDroid/Amandroid/DroidSafe（DroidBench/ICC-Bench/真实 App） |
| 3 | KASTroid | Nazzal, Alalfi, Cordy, COMPSAC 2025（STPSA 研讨会）, IEEE doc 11126835 | 论文原文核实（Queen's 官方 PDF 全文已读） | 1,716 个 Kotlin App；>70% 广播为隐式；LocalBroadcastManager 采用率 ~19.5%、setPackage ~7.5% | TXL 源级变换做 Kotlin 静态污点，sink=隐式广播 sendBroadcast |
| 4 | AndroByte | Khatun, Noureddine, Sui, Ali-Gombe, ACSAC 2025；arXiv:2510.15112 | 论文原文核实（ACSAC 官方 PDF + arXiv 摘要均直接读取） | 摘要称 Fβ 89%；正文表 2：P 95.95%/R 78.05%/F1 86.10%/Fβ 91.70%（β=0.5，对 AndroGuard 调用图）；DroidBench 86 + UBCBench 24 + 300 真实 App；Gemma3 最佳 | LLM 对 smali 字节码逐方法摘要 → 动态生成数据流感知调用图 D2CFG（LLM 选下一方法+判 sink） |
| 5 | **GNChecker**（"Giving without Notifying"） | Fan, Shi, Wang, Yu, Zhang, Wang, Jin, Liu, ASE 2024, DOI 10.1145/3691620.3695528 | 论文原文核实（摘要级，经 Semantic Scholar 官方 API 全文摘要；分段细节经被索引正文片段核实） | 1,134 个真实 App → 379 个 App 检出 1,410 条真实不合规传输（33.4%）；precision 93.1%（105/1,515 误报全归因政策分析）；政策分析 P 95.8%/R 95.1%（143 元组） | 静态数据流+动态流量 → (信息类型,传输地址) 元组；LLM 政策映射；OD/VD 两型不一致；静态侧用分段策略降搜索范围 |
| 6 | LeakSemantic | Fu, Zheng, Bose, Bishop, Mohapatra, INFOCOM 2017, DOI 10.1109/INFOCOM.2017.8057221；arXiv:1702.01160 | 论文原文核实（IEEE 元数据+arXiv 摘要） | 1,404 个 App / 2,279 条敏感连接上 91% 准确率 | 静态调用图+定制 Dalvik 动态污点抓流 → URL 词法特征 ML 分类合法/异常传输 |
| 7 | **PIChecker** | Huang, Zhan, Xia, FORGE 2026（IEEE/ACM 第三届 AI 基础模型与软件工程会议，ICSE 2026 同址）, DOI 10.1145/3793655.3793721（CC-BY 开放获取） | 论文原文核实（摘要级，Semantic Scholar 官方 API 全文摘要逐字核对） | 147 个 App：17 个无政策；**其余 130 个中近 11% 完全未提 TPL 收集、超过 64% 未能准确描述 TPL 隐私行为**；vs ATPChecker accuracy 55%→90%；静态 P 94.12%、动态 P 1.0、文本 P 96.96%；第三方代码流合规率 35.38% vs 第一方 90.77% | Soot/FlowDroid 静态污点（355 API→18 类数据）+ DroidBot 动态验证 + GPT-4o 三阶段政策解读 + ATVHunter 定位 TPL |
| 8 | PolicyGapper | Ferrari, Habbati, Guerar, Ceccato, Verderame（热那亚大学）, arXiv:2604.16128；GitHub Mobile-IoT-Security-Lab/PolicyGapper | 论文原文核实（arXiv 摘要+官方仓库） | 330 个 top App（33 类目）：2,689 处遗漏披露（2,040 收集+649 共享）；人工复核分层 10% 子集：P 0.75/R 0.77/F1 0.76 | 抓 Google Play Data Safety Section + 渲染政策 PDF → 多 prompt LLM 比对声明间遗漏（无需二进制） |
| 9 | MiniScope | Wang 等（西电/UNSW/NTU/HUST）, ACM TOSEM 34(6) 2025, DOI 10.1145/3709351；arXiv:2401.03218 | 论文原文核实（ACM 元数据+arXiv） | 120K+ 小程序爬取、10,786 个有政策并分析；P 99.2%/R 95.6%/F1 97.4%（超 TaintMini P+7.9/R+23.5 个百分点）；5.7% 超范围收集、33.4% 过度声明 | 两阶段迭代混合：分包定向 BFS 探索 → 隐私实践定向 DFS 探索 + Frida 钩 JSBridge 验证 + LLM 政策分析 |
| 10 | PriAgent | Zhang, Li, Jiang, Yin, Wang, Chen, Liu（中科院大学）, AAAI-40 2026, DOI 10.1609/aaai.v40i2.37135 | 论文原文核实（AAAI OJS 开放全文） | FlowDroid 在 TaintBench 上 precision 73.7%→93.2%；真实 App 误报 −58%；300 App 审计集 verdict precision 93.7%（54 App/119 条真违规） | 四阶段多智能体：FlowShaper 流抽象 → 语义定位 → RAG API 知识库验证 → 与政策综合研判 |
| 11 | GDPR-Bench-Android | Ran, Zhang, Tang, arXiv:2511.00619；GitHub Haoyi-Zhang/GDPR-Bench-Android | 论文原文核实（arXiv+官方仓库） | 1,951 条人工标注违规（15 个开源仓库）、23 条 GDPR 条款；最佳结果：ReAct 文件级 Acc@1 17.38%、Qwen2.5-72B 行级 61.60%、Formal-AST 1.86%、Claude-Sonnet-4.5 macro-F1 5.75% | 三级粒度（文件/模块/行）定位+多标签分类任务，横评 8 LLM/RAG/ReAct/形式化 AST 四类方法 |
| 12 | PICOSCAN | Zhang 等, USENIX Security 2024 "Navigating the Privacy Compliance Maze"（官网开放 PDF） | 论文原文核实（USENIX 官方 PDF 可下载，数字经索引正文核实） | 65 个 PICO SDK、48,000+ Play App：51.4% 集成 PICO SDK；31.5% 完全未配置；50.2% 用无隐私 API 旧版；28/36 SDK 默认值侵犯隐私；22 个包装器 SDK 中 16 个不完整传递配置 | 静态分析 App+SDK 代码，检查 SDK 隐私配置 API 是否被正确调用、包装器是否把配置传给内嵌 SDK |
| 13 | TCF 合规研究 | Morel, Santos, Carlsson, Ahlinder, Duvignau, PoPETS 2026(3), DOI 10.56553/popets-2026-0068；arXiv:2602.20222 | 论文原文核实（PoPETS 官网+DOI） | 4,482 个流行 Play App：12.85%（576 个）实现 TCF；拒绝同意后仍无合法依据共享 AAID 占 66.2%；横幅交互前共享占 55.3%；Google CMP 占 82.54–89.76% | 模拟器大规模下载安装+动态分析，检测 TCF 字符串、同意状态与 AAID 传输时序 |
| 14 | 百度智能云「史宾格」 | cloud.baidu.com 主题页 + mtcatmp.n.shifen.com/privacy/ | 官方页面核实（上架护航版页直接抓取） | 对标 164 号文 37 项；上传 APK（≤500MB）→ 约 20 分钟出《检测报告》+《应用行为数据》；19 种基础安全漏洞+20 种代码级漏洞 | AI 云手机模拟运行+动态监控；报告含敏感权限分析、SDK 集成分析、问题描述/整改建议/截图/堆栈 |
| 15 | 阿里云 App 合规检测 | 云市场 cmfw00045669 + EMAS 宣传页 | 官方页面核实（云市场条目经搜索索引；独立 help 产品页未找到） | — | 隐私协议 AI 解析+权限/采集/SDK 检测+动静态分析+真机模拟点击 |
| 16 | 梆梆安全「移动应用合规平台」 | bangcle.com cat_id/278 + cat_id/24/id/70 | 官方页面核实（页面为 JS 渲染壳，内容经官方域搜索索引核实） | 通过 CCRC App 个人信息安全测试认证；宣称服务 10 万+企业 | 定制检测沙箱+自动化脱壳+UI 自动遍历+人工深度辅助；成分/安全/行为/合规四维分析；GB/T 35273-2020 对标 |
| 17 | 华为云移动应用安全（CodeArts AppSec） | huaweicloud.com/product/vss/appSecurity.html | 官方页面核实（内容经官方域搜索索引；页面 JS 渲染） | 专业版 ¥5,000/月（1 次扫描）；分钟级扫描；支持 APK/HAP | 静态+动态；NLP/ML/OCR 解析隐私政策文本做声明-行为一致性；上架自检联动 |
| 18 | 汉华信安「APP个人信息收集行为检测系统」（棱眼矛） | bjhhxa.com.cn/?p=2426 | 官方页面核实（直接抓取） | 国家 APP 专项治理工作组技术支撑单位；参与 GB/T 42582-2023 制定 | 沙箱+AI Agent 无人值守：上传 APK → AI 遍历界面触发场景 → 声明 vs 行为比对 → 含整改建议+法条依据的研判报告 |
| 19 | PackagePrivacy | github.com/stonehill-2345/package-privacy | 官方仓库核实（README 经搜索索引；直接 raw 抓取未成功） | ~2 stars；MCP 服务接口 | JADX 反编译 + 规则配置的隐私 API 调用检测 + LLM/MCP 辅助 + Markdown 合规报告；支持 Maven/URL/本地包 |
| 20 | Oncecheck | pypi.org/project/oncecheck/（v0.7.8） | 官方注册表核实；**GitHub 仓库未核实**（PyPI 声明的 oncecheck/oncecheck-cli 返回 404） | iOS 20/Android 18/Web 27/Common 8 条规则（73+） | 终端 CLI 合规扫描（manifest/权限/隐私清单等），导出 JSON/SARIF 2.1/文本，退出码接 CI |
| 21 | SubmitGate | npmjs.com/package/submitgate（v0.35.2） | 官方注册表核实；**源码未核实**（UNLICENSED、无 repository 字段、dist 编译产物） | 需 license token；退出码 0/1/6 | 扫描 iOS/Android 构建产物（权限/网络安全配置/可调试/广告 ID 等），导出 JSON/Markdown/SARIF，GitHub Actions 集成 |
| 22 | SARIF 2.1.0 | OASIS（github.com/oasis-tcs/sarif-spec） | 官方仓库核实（spec 仓库结构与 2.1.0 委员会规范、2.2 草案确认） | 2.1.0 为 OASIS 标准；2.2 草案进行中 | runs/results/locations/codeFlows/reportingDescriptors/taxonomies 的 JSON 交换格式 |
| 23 | OSCAL | NIST（pages.nist.gov/OSCAL/） | 官方页面核实（直接抓取） | XML/JSON/YAML 三种格式 | 控制基线/评估结果/行动计划（catalog/assessment-results/POAM）机器可读化 |

---

## 3. 分主题分析

### 3.1 静态污点：FlowDroid 与「真实 App 失效」证据（对应缺口 A1）

**做了什么**：FlowDroid（Arzt, Rasthofer, Fritz, Bodden, Bartel, Klein, Le Traon, Octeau, McDaniel，PLDI 2014，
DOI 10.1145/2594291.2594299）是 Android 静态污点分析的事实标准：Soot 转 Jimple IR → IFDS 框架做
上下文/流/字段/对象敏感的正向污点传播；**source/sink 由配置文件声明**（后由 SuSi 机器学习辅助分类）；
**生命周期建模**靠 dummyMain 把组件入口、回调、异步执行统一进一个假 main；配套发布 DroidBench 基准与
taint wrapper 机制。官方实现维护至今：github.com/secure-software-engineering/FlowDroid（1,274 stars，访问日核实）。

**可核实的关键数字（TSE 2021 横评）**：Zhang, Wang, Qiu, Rubin 的 *Analyzing Android Taint Analysis Tools:
FlowDroid, Amandroid, and DroidSafe*（IEEE TSE 48(10):4014–4040，2022 年卷期、2021 年在线，DOI
10.1109/TSE.2021.3109563）在统一配置下于 DroidBench / ICC-Bench / 25 个 Google Play 真实 App（82 条
人工确认的预期流）上评测：**FlowDroid 在 25 个真实 App 上崩溃 11 个**（Services 内 ICC 流、`PendingIntent.send()`
等处的运行时异常、Soot 对 `Method.invoke` 反射调用处理失败）；**成功分析的 14 个中仅 2 个检出预期流**；
**Amandroid 只完整分析 3 个 App，且对同一 App 四次独立运行分别报 0/3/28/43 条流**（结果不可复现）。
失败主因：反射、回调/生命周期建模、Intent 字符串分析。作者把失败用例沉淀为新基准 UBCBench。
> 说明：RESEARCH_OUTLOOK §3 簇 A 引用本工作时写作「Zhang et al., IEEE TSE 2021」——按卷期应为
> TSE 2022（2021 在线发表）；作者为 Junbin Zhang, Yingying Wang, Lina Qiu, Julia Rubin。关键数字
> 与 RESEARCH_OUTLOOK 一致，本次补充 DOI 与页码。全文在 IEEE 付费墙后，上述数字经 IEEE 元数据、
> 被搜索引擎索引的正文片段与中文精读二手来源交叉验证一致。

**局限**：benchmark 表现不能外推到真实 App（该论文的核心结论）；工具链重（Soot 依赖、Android 版本适配）；
结果是「存在一条流」的路径级证据，不含值级证明。

**对 V-Scanner 的借鉴点**：
1. 再次确认现有路线：`static_scan_thirdparty.py` 的「dex 方法引用 + candidate 封顶」就是本项目对静态分析的
   合理边界，**不要升级成数据流**（§9 第 1 条）。
2. source/sink 清单工程可借鉴其「集中配置文件」形态：本项目 `dangerous_apis` 三元组已有该结构，
   可补一个 `api_role` 维度的完整性检查（写入类已声明不覆盖，见 M022），离线可验收。
**代价与优先级**：无代码改动（第 1 条是「不做」）；第 2 条为规则库小检查，P2。

### 3.2 KASTroid：Kotlin 静态污点分析

**出处与做法（论文原文核实，PDF 全文已读）**：Bara' Nazzal, Manar H. Alalfi, James R. Cordy,
*KASTroid: A Static Taint Analysis Framework for Kotlin-Based Android Applications*，
COMPSAC 2025 的 STPSA 研讨会（IEEE 文档 11126835；开放 PDF：
research.cs.queensu.ca/home/cordy/Papers/STPSA-KASTroid.pdf）。做法：**源级（非字节码）**分析，
基于 TXL 源变换语言自研 Kotlin 文法 + 变换规则，做 sink 识别 → 局部后向追踪 → 全局追踪 →
输出污点流；**sink 聚焦一类**：隐式广播（`sendBroadcast` 不指定包名，任何 App 可接收）。
评测 1,716 个 Kotlin Android App（387 个 F-Droid/FAMAZOA + 1,329 个 GitHub 仓库）：
仅 ~14% 的项目用 `sendBroadcast`；其中 **>70% 的广播是隐式的**（潜在不安全）；
`LocalBroadcastManager` 采用率 ~19.5%、`setPackage` 保护 ~7.5%。案例：AndroidAPS（人工胰腺医疗 App）
旧版存在可向本地其他 App 泄露敏感信息的隐式广播。

**局限**：源级工具（需源码，不适配闭源 APK）；sink 面窄（只广播）；无大规模真实漏洞确认（案例式验证）；
工具公开性未见承诺。

**借鉴点**：① Kotlin 与 Java 编译到同一 dex，`sendBroadcast` 相关签名可直接进 `dangerous_apis`
（作为敏感 egress 观察，candidate 封顶）——但「隐式 vs 显式」是**流条件**（是否调 `setPackage`），
静态引用级判断不了，只能做「引用了 sendBroadcast 且未引用 setPackage」的粗粒度观察并写 gap 说明局限；
② 医疗/IoT 类高风险 App 的组件间通信泄露，可加进 `fixture-app` 或 VScanBench 的一个用例。
**代价与优先级**：P2（研究级观察项）。

### 3.3 AndroByte：LLM 对字节码摘要 + 动态生成数据流调用图

**出处与做法（论文原文核实）**：Mst Eshita Khatun, Lamine Noureddine, Zhiyong Sui, Aisha Ali-Gombe,
*AndroByte: LLM-Driven Privacy Analysis through Bytecode Summarization and Dynamic Dataflow Call Graph
Generation*，ACSAC 2025（官方 PDF 已读：acsac.org/2025/files/web/acsac2025-435-khatun.pdf；
arXiv:2510.15112）。做法：对 smali 字节码逐方法做 **LLM 摘要**，摘要驱动「下一方法选择 + sink 判定」，
动态构建数据流感知调用图 **D2CFG**（方法为节点、调用为边，队列空或发现 sink 即停），不依赖预定义
传播规则与 sink 清单。评测：DroidBench（86）+ UBCBench（24）+ 300 真实 App；本地 Ollama 低比特量化
8–15B 模型（LLaMA3/DeepSeek/Qwen3/Gemma3），Gemma3 最佳；泄漏检测 precision ~93.98%、F1 ~83%
（对 FlowDroid/Amandroid）；解释性用 G-Eval（LLM-as-judge）打分。

**「89% Fβ」口径核对（重要）**：arXiv 摘要原文为「AndroByte achieves a significant Fβ-Score of **89%**
in generating dynamic dataflow call graphs on the fly」；但 ACSAC 正式版正文表 2 的调用图生成指标是
Precision 95.95% / Recall 78.05% / F1 86.10% / **Fβ 91.70%（β=0.5）**（对 AndroGuard 生成的调用图）。
即：**89% 是摘要口径、91.70% 是正文口径，且正文注明 β=0.5（偏 precision）**——两个数字都属实但不一致，
摘要未注明 β 值。引用时必须写明口径与 β。

**局限**：纯静态（自认看不到动态加载类）；大 App 的 LLM 上下文与耗时；量化模型性能损耗；
300 真实 App 的 ground truth 来源与召回未在摘要级核实（**部分未核实**）；ACM 发布页为付费墙。

**借鉴点**：① 与 V-Scanner 三阶段 AI 的**形态相似、定位相反**——AndroByte 让 LLM 直接产流（行为事实），
V-Scanner 的 system.md 硬约束「AI 不引入新行为事实」。**不可照搬**（§9 第 2 条）；
② 可取的只有「字节码/反编译代码摘要作为 AI 上下文」的低风险形态：在 stage2/stage3 的输入里**附**
`static_scan_thirdparty.py` 已产出的引用级事实（本来就在 bundle 里），无需新能力；
③ 作为 VScanBench 的**外部对照工具**（P2 研究项）：在自有夹具上对比「LLM 判流」与「值哈希链路」的证据强度。
**代价与优先级**：P2，仅研究对照。

### 3.4 GNChecker 的「分段策略」（本次重点，对应缺口 A1/C2）

**出处**：Ming Fan, Jifei Shi, Yin Wang, Le Yu, Xicheng Zhang, Hai-Jun Wang, Wu-Xia Jin, Ting Liu,
*Giving without Notifying: Assessing Compliance of Data Transmission in Android Apps*，
IEEE/ACM ASE 2024，DOI 10.1145/3691620.3695528。摘要已通过 Semantic Scholar 官方 API 逐字取得；
正文细节经搜索引擎索引的 ACM PDF 片段核实；全文在付费墙后，**实现级细节（子包粒度、路径合并、去重）
未逐条核实**（见 §11 未核实清单）。

**方法图景（三段式）**：
1. **程序行为分析**：静态数据流 + 动态网络流量，统一产出 `(信息类型, 传输地址)`（IT-TA）元组——
   静态侧擅长系统 API 类信息（IMEI/IMSI），动态侧补齐非系统 API 数据（AppKey/UserId）；
2. **隐私政策分析**：LLM 把政策条文映射为同一 IT-TA 元组形式（政策元组）；
3. **一致性比对**：行为元组 vs 政策元组，检出两型不一致——**OD（Omitted Declaration，遗漏声明）**
   与 **VD（Vague Declaration，模糊声明**，如政策只写「设备标识信息」以覆盖 IMEI/IMSI/设备 ID）。

**「分段策略」到底指什么（核实结果）**：论文摘要原句为「an efficient static data flow analysis technique
with a **segmentation strategy**, significantly reducing the search scope and improving efficiency」。
被索引的正文给出实现：先构建**函数调用图 FCG**（处理生命周期、回调与反射）→ 在其上构建
**LDPG（latent data propagation graph，潜在数据传播图）** → 搜索所有 source→sink 的可达路径 →
**把每条路径对应的源代码集合切成一个子包（sub-package）** → 只对子包做污点分析，不必一次加载整 App。
**结论：分段维度是「源-汇可达路径的代码子集」，不是按包名、按 SDK、按入口分段**；缩小搜索范围的机理是
「与任何 sink 不连通的代码根本不进分析」。这正好回答了调研问题——此前二手材料对「分段」的说法含糊
（有称按包/按 SDK 的），一手摘要+正文片段均不支持那些说法。

**实验数字（已核实）**：50 个流行 App 上优于 SOTA 数据流工具（效率/有效性，具体榜单在付费墙后未逐条核实）；
**1,134 个真实 App 上检出 379 个 App 的 1,410 条真实不合规传输行为（33.4%）**，显著高于 PPChecker
（159 App/541 元组）与 PoliCheck（180 App/692 元组）；整体 precision **93.1%**（1,515 个元组中 105 个误报，
**全部归因于政策分析错误**）；政策分析模块单独在 143 个人工标注元组上 P 95.8%/R 95.1%。
案例：装机 7,000 万+ 的 SinaSports 经 SSO SDK 外发 IMEI/ICCID/WiFi 信息（ICCID 属 OD，IMEI/WiFi 声明属 VD）。

**局限**：误报全部来自政策语义层（静态/动态行为侧反而是干净的）；静态侧对系统 API 信息有效、
动态侧对非系统 API 有效——**必须动静结合**；LDPG 依赖 FCG 质量（反射/混淆下退化）；全文付费墙。

**对 V-Scanner 的借鉴点（按代价升序）**：
1. **OD/VD 命名与语义直接并入已规划的 stage2 五分类（E1）**：`vague` 类即 VD，`omitted` 类即 OD，
   提示词里可引用 GNChecker 的判定口径（「政策写宽泛上位词以覆盖具体数据类型」= vague）。
   纯提示词+枚举改动，P0。
2. **IT-TA 二元组核对视角**：V-Scanner 的 `read_before_egress_within_window` + `sensitive_data_to_third_party_domain`
   已经产出「类型×地址」观测；缺的是把**静态引用到的第三方地址/API 与动态地址对齐**形成
   「静态引用—动态观测」双列对照（仍 candidate 封顶）。这是 C2（覆盖差集）的自然扩展，P1。
3. **分段思想的降级复用（关键）**：不建 LDPG、不做污点，只做**敏感引用可达性聚类**——用
   `dexfacts` 的方法引用图（或 jadx 反编译类）按「哪些类簇引用了敏感 API 且引用了网络/存储 API」排序，
   输出给 UI 探索器做**触发目标排序**（哪些 Activity/入口最可能产生敏感流）。
   这是 GNChecker「缩小搜索范围」思想在本项目约束下的合法形态：缩小的不是数据流搜索，而是
   **运行时触发搜索**（对应缺口 B4，与 MiniScope 的「隐私实践定向探索」同向，见 §4.3）。
   代价：一个 ≤300 行的离线模块 + 单测，P1。
4. **「误报全部归因政策层」的经验**：GNChecker 的 105 个误报全部来自政策语义错误，佐证 V-Scanner
   「政策关键词是 regex 代理、LLM 输出必须机校验」的设计——可把这句话连同出处写进 stage2 提示词
   的判定口径段，提醒模型政策侧更易错，P0（文档级）。
**不建议**：完整复刻 LDPG+子包污点（§9 第 1/7 条）。

### 3.5 机器学习：LeakSemantic 与 ML 的合理/不合理位置

**LeakSemantic（论文原文核实）**：Hao Fu, Zizhan Zheng, Somdutta Bose, Matt Bishop, Prasant Mohapatra,
*LeakSemantic: Identifying Abnormal Sensitive Network Transmissions in Mobile Applications*，
IEEE INFOCOM 2017（DOI 10.1109/INFOCOM.2017.8057221；arXiv:1702.01160）。方法：**静态+动态+ML 三合一**——
静态分析构建每组件调用图指导执行；动态侧用定制 Dalvik VM 执行器做污点跟踪，捕获敏感流并解密 URL；
ML 侧基于 **URL 词法特征**训练分类器（host-based 与 network-based 两模式），区分「合法传输」与
「异常敏感传输」。**关键数字**：在 1,404 个 App 的 2,279 条敏感连接上取得 **91% 准确率**，
比纯污点分析误报更少。出处与口径均已核实（IEEE 元数据 + arXiv 摘要一致）。

**局限**：定制 VM 绑定旧 Android 版本（工程不可持续）；URL 词法特征对无 URL 协议（如纯 TCP/自定义协议）
与加密语义失效；分类器输出是「异常度」而非「违规」——这正是本项目应借鉴的克制。

**ML 在隐私检测中的合理位置（结合本项目证据门控）**：

| 位置 | 形态 | 对本项目 | 判定 |
|---|---|---|---|
| 优先级排序 | findings/流量按风险排序，供人工复核 | `RISK_SCORE_MODEL.md` 已有规则化排序，可补 ML 重排作为可选实验 | 合理（P2 实验） |
| 降噪 | 过滤明显非敏感/系统流量 | 现有白名单机制已做；ML 可做「疑似第三方域名」置信度 | 合理（仅作 hint） |
| 流量分类 | 域名/流量类型分类（广告、分析、崩溃上报） | `sensitive_data_to_third_party_domain` 目前不判定第三方归属——分类器可给「疑似第三方」**置信度字段**，**不改变结论等级** | 合理（P2） |
| 异常检测 | 时间序列/行为异常 | 设备侧长时采集的超阈值外发频率观察 | 合理（P2，观察项） |
| **直接定性违规** | 模型输出「违规/不违规」进结论 | 违反 M012「不产 policy_violation」 | **不合理，禁止** |
| **升级结论等级** | ML 置信度把 candidate 抬到 correlated | 违反静态封顶与等级语义 | **不合理，禁止** |
| **补充行为事实** | 模型「推断」某数据被收集 | 违反「AI 不引入新行为事实」 | **不合理，禁止** |

GDPR-Bench-Android（arXiv:2511.00619）为此提供了硬证据：在 1,951 条人工标注违规上，最强组合
（ReAct agent）文件级定位 Acc@1 仅 17.38%，形式化 AST 方法仅 1.86%——**「从代码直接判违规」当前整体
不可用**。该结论可作为本项目「工具不产 policy_violation」的对外佐证引用（写进报告方法章与申报材料，P0 文档）。

**证据门控落地建议**：任何 ML/LLM 辅助输出只能挂三种字段之一进入 bundle：
`hint`（供人参考）、`review_priority`（排序用）、`needs_human_review: true`（默认）；
不得作为八谓词任何一侧的判定输入。该约束建议写入 `mobile/DECISIONS.md`（新增一条 M0xx），P0 文档级。

---

## 4. PIChecker（重点）

### 4.1 出处（论文原文核实）

*PIChecker: Automatic Privacy Detector for Third Party Libraries in Android Apps*，
Ke-Rui Huang, Xian Zhan, Xin Xia，FORGE 2026（IEEE/ACM Third International Conference on AI Foundation
Models and Software Engineering，与 ICSE 2026 同址），DOI 10.1145/3793655.3793721，
**CC-BY 开放获取**（Semantic Scholar 标注 GOLD/CCBY；摘要经官方 API 逐字取得）。
注意：用户转述的「130 个有隐私政策的流行应用中超过 64% 未能准确描述内嵌 TPL 隐私行为」
与论文摘要**逐字一致**：147 个总样本、17 个完全无隐私政策、**其余 130 个中近 11% 完全未提任何
TPL 数据收集、超过 64% 未能准确描述内嵌 TPL 的隐私行为**。

### 4.2 方法（三阶段 + TPL 定位）

1. **静态程序分析**：APK 反编译到 Jimple，构建 CFG，用 **Soot + FlowDroid** 做污点/def-use 分析
   追踪隐私数据流；预定义 **355 个隐私相关 API → 18 类个人信息**的映射；TPL 代码定位用 **ATVHunter**；
2. **动态程序分析**：对 APK 插桩（source/sink 打日志）→ Android 模拟器（android-34 x86_64）上
   用 **DroidBot DFS 策略**探索（超时 10 分钟，经 5/10/30 分钟对比选定，~80% Activity 覆盖），
   用 logcat 验证静态路径在运行时真实执行；
3. **LLM 政策分析**：**GPT-4o 三阶段提示**——全文理解 → 精确数据分类 → 模糊/否定陈述剖析，
   提取政策的「收集/共享」声明（如正确解读 "attempt to avoid collecting sensitive data" 这类否定句）。

检测四类问题：incomplete（不完整）、incorrect（错误）、imprecise（不精确）、over-declaration（过度声明）。

### 4.3 可核实的关键数字（摘要+索引正文级核实）

- 147 个流行 App（各类 TPL 组合）；17 个无隐私政策；**130 个中 >64% 未能准确描述 TPL 隐私行为、~11% 完全未提**；
- top-20 子集与 ATPChecker（前作，arXiv:2301.12348）对比：**accuracy 55% → 90%**；
- 静态 precision **94.12%** vs ATPChecker 2.60%（后者关键词匹配在单 App 上曾出 185 个误报）；
- 动态验证 precision **1.0**（7 条 TPL 流）；文本分析 precision **96.96%**（F1 93.18%）；
- 平均 40.68s/App vs ATPChecker 176.02s；
- 真实世界发现：**第三方代码数据流的政策合规率仅 35.38%，第一方代码 90.77%**；
  最常被政策漏报的类别是 bluetooth、sensor、audio。

### 4.4 局限（按用户点名四项逐条）

1. **TPL 识别**：依赖 ATVHunter——TPL 静态识别的版本级识别与召回是公认短板
   （Zhan et al., ASE 2020 横评结论，RESEARCH_OUTLOOK 簇 F 已引）；错归属/漏归属会直接传播到矩阵；
2. **政策语义**：否定句/模糊句靠 LLM，幻觉与提示敏感仍存在（其 P 96.96% 是特定标注集口径，
   GNChecker 的教训是「误报全在政策层」——两者方向一致：政策层是错误主源）；
3. **动态覆盖**：10 分钟 DFS 探索，登录墙/深路径/网络依赖功能不可达；动态验证只确认了 7 条流，
   绝大多数结论仍是静态证据；
4. **LLM 幻觉**：论文未在摘要级给出幻觉率/跨运行一致性数字（**该指标未核实**）；
5. 额外注意：147→20 的 ground-truth 对比只在前 20 个 App 上做，**64% 口径的复核方式
   （抽样比例/人工复核人数）在摘要级不可见**（**部分未核实**）。

### 4.5 对 V-Scanner 的借鉴：三阶段 AI 升级为「TPL 行为—政策声明」矩阵

现有资产：`third_party_share` 谓词（域名第三方归属不判定、封顶 candidate）；RESEARCH_OUTLOOK 已规划的
F1（运行时类加载归因）；`static_scan_thirdparty.py` 的补充扫描；stage1 政策抽取已有
`supporting_documents` 与 SDK 清单的谨慎处理（stage1_user.md 明示「不把文件中列出的 SDK 当作已实际使用」）。

升级路径（不违反任何硬约束）：
1. **政策侧（stage1，P0 提示词级）**：新增专门条款组 `PP-TPL-xx`（第三方 SDK 收集/共享披露，
   数据类别 × 共享对象），输出 `tpl_disclosures` 结构化字段；SDK 清单只从政策**引用**出发，
   不假设 App 实际集成（延续 stage1 现有口径）。
2. **行为侧（工具侧，P1）**：`origin` 归因（F1，运行时类加载 + 前 30 主流 SDK 包名前缀种子表，
   `unknown` 不写成已知）→ 每条读取/外发事件带 `origin: host | third_party:<前缀> | unknown`；
   静态补充扫描给出「SDK 前缀 × 敏感 API 引用」候选（candidate 封顶）。
3. **比对侧（stage2，P0 枚举+P1 真跑）**：输出**矩阵**：`(数据类别 × 收集方(宿主/各 TPL 前缀) × 披露状态
   {clear, vague, omitted, incorrect, ambiguous, not_applicable})`，状态语义与已规划的五分类（E1）对齐；
   `validate.py` 增加矩阵字段的枚举与引用校验（引用的 TPL 前缀必须出现在行为侧或政策侧证据里）。
4. **报告侧（report_ai_sections.py 一致性章，P1）**：矩阵渲染为表格；「第三方代码合规率 35.38% vs
   第一方 90.77%」这类**分组统计**可作为模板输出（只统计、不定性）。
5. **口径护栏（P0 文档）**：矩阵结论一律 `needs_human_review: true`；不产出 `policy_violation`；
   「政策未提 TPL」≠「违规」，进 gap 说明（延续现有「未命中 ≠ 未声明」）。

代价：阶段 1/2/4/5 纯离线（提示词+校验+渲染+单测）；阶段 3 需一次设备轮次验证归因。总优先级 P1，
其中提示词/枚举部分可 P0 先行。

---

## 5. 声明—行为一致性其他工作

### 5.1 PolicyGapper（声明 vs 声明，无二进制）

出处：Luca Ferrari, Billel Habbati, Meriem Guerar, Mariano Ceccato, Luca Verderame（热那亚大学），
arXiv:2604.16128（2026-04）；复现包 GitHub Mobile-IoT-Security-Lab/PolicyGapper（提示词/数据集/代码全公开，
Zenodo DOI 10.5281/zenodo.19628493）。方法：抓 Google Play **Data Safety Section**（DSS）+ 无头浏览器把
隐私政策渲染成 PDF → **六个专门 prompt** 的 LLM 协作（覆盖 Google Play 全部 39 种数据类型/14 类目，
用户/技术/位置数据三域）→ 合并 → 后处理。**不需要 App 二进制**——只查「DSS 声明 vs 政策声明」的遗漏。
数字：330 个 top App（33 个类目，2025 Q3）；检出 **2,689 处遗漏披露**（2,040 数据收集 + 649 数据共享）；
对分层 10% 子集三次运行人工复核：**P 0.75 / R 0.77 / Acc 0.69 / F1 0.76**。局限：准确率中等；
不涉及行为；依赖 Gemini。
**借鉴**：V-Scanner 政策侧目前只解析主政策；可加「政策 vs 应用市场描述/官方告知」的声明间交叉核对
（国内无 DSS，但应用市场简介与官方隐私告知普遍存在），产出 `declaration_gap` 观察项，P2；
其「多专门 prompt 分域」结构与 stage1 的条款清单化同构，可直接参考提示词切分方式（P0 文档级）。

### 5.2 MiniScope（小程序，两阶段混合分析）

出处：Shenao Wang 等，*MiniScope: Automated UI Exploration and Privacy Inconsistency Detection of
MiniApps via Two-phase Iterative Hybrid Analysis*，ACM TOSEM 34(6) 2025（DOI 10.1145/3709351；
arXiv:2401.03218）。方法：**阶段一**构建小程序依赖图 MDG + 分包定向**广度优先** UI 探索（把懒加载分包
全部拉起）；**阶段二**合并完整包重建 MDG + **隐私实践定向深度优先**探索 + Frida/objection 钩微信 JSBridge
交叉验证检测到的隐私实践 + LLM 政策分析找不一致。数字：120K+ 小程序爬取，10,786 个有政策并分析；
P 99.2%/R 95.6%/F1 97.4%（超 TaintMini：P +7.9 / R +23.5 个百分点）；5.7% 秘密超范围收集、33.4% 过度声明；
向 2,282 个开发者负责任披露、44 个确认。局限：微信生态绑定（JS 端 hook 点）、非 APK 场景。
**借鉴**：① 「**隐私实践定向**」探索——用敏感 API 引用反向选择下一步 UI 动作——直接强化已规划的 G1
UI 探索器目标函数（与 GNChecker 借鉴点 3 合流，P1）；② 「先广后深」两轮探索策略可做 G1 的默认调度（P1）；
③ 负责任披露模板与流程（授权范围内向被测样本方反馈）可文档化（P2，伦理规范）。

### 5.3 PriAgent（多阶段/多智能体合规审计）

出处：Ziwei Zhang, Zhao Li, Zhuojun Jiang, Jiangyi Yin, Xuebin Wang, Jiangchao Chen, Qingyun Liu
（中国科学院大学），*PriAgent: A Collaborative Multi-Agent Framework for Auditing Android Privacy
Compliance*，AAAI-40 2026（DOI 10.1609/aaai.v40i2.37135，AAAI OJS 开放全文）。四阶段：
**FlowShaper**（包内流聚合、循环/递归路径用 `<CYCLE:>` 抽象，把待 LLM 分析的流数量压下来）→
**语义定位**（在调用链中定位真正决定数据处理的环节）→ **RAG 语义验证**（Android API 知识库检索，
区分「违规行为 vs 良性功能」）→ **综合研判**（代码证据与政策关联产出可解释裁决）。
数字：FlowDroid 在 TaintBench 上 precision **73.7% → 93.2%**（识别出四类误报：数据变换、API 语义误读、
条件不可行路径、反射误解析）；真实 App 误报 **−58%**；300 App 审计集 **verdict precision 93.7%**
（54 App / 119 条真违规：79 条未声明行为 + 40 条高风险违规）。后端试过 Gemini 2.5 Pro / Claude 3.5 Sonnet /
GPT-4o / LLaMA3-70B / Qwen2.5-Coder-32B / DeepSeek-R1。
**借鉴**：① 四阶段与 V-Scanner 三阶段同构，其 **RAG 验证**可降级移植：stage3 判定「合规语义」时检索
规则库法规条款+API 语义表（本地 sqlite，非外部向量库），**仍禁止引入新行为事实**（只解释已有事实）；
② 四类误报消解清单可直接写成 stage2 的「疑似误报复核提示」（数据变换/语义误读/不可行路径/反射误析），
P1 提示词级；③ 注意 PriAgent 输出「违规裁决」——V-Scanner 只取方法、不取结论等级（§9 第 3 条）。

### 5.4 GDPR-Bench-Android（评测基准）

出处：Huaijin Ran, Haoyi Zhang, Xunzhu Tang，arXiv:2511.00619（2025-11）；数据集与评测脚本公开
GitHub Haoyi-Zhang/GDPR-Bench-Android。内容：**1,951 条人工标注违规实例**（15 个开源仓库的真实
Android RAT/间谍软件）、**23 条 GDPR 条款**、文件/模块/行三级粒度；两任务（定位 Accuracy@k、
片段级多标签分类）。横评 11 种方法（8 个 LLM 零样本 + Formal-AST ~35 条手工规则 + RAG（条款+1,900 代码例）
+ ReAct agent）。最佳结果（**整体水平很低**）：ReAct 文件级 Acc@1 17.38%；Qwen2.5-72B 行级 61.60%；
Formal-AST 1.86%；Claude-Sonnet-4.5 macro-F1 5.75%；RAG macro-P 7.10%。结论：没有一种范式全面领先；
形式化方法确定性强但语义弱、agent 综合推理强但定位差。
**借鉴**：① 作为「AI 不能从代码直判违规」的**外部证据**（§3.5，P0 文档）；② 其标注 schema
（违规实例→条款→粒度）可作 VScanBench 对照集格式参考（P2）。

### 5.5 PICOSCAN（SDK 隐私配置 API 误用，48,000+ App 规模）

出处：Yifan Zhang 等，*Navigating the Privacy Compliance Maze: Understanding Risks with
Privacy-Configurable Mobile SDKs*，USENIX Security 2024（官网开放 PDF：
usenix.org/system/files/usenixsecurity24-zhang-yifan.pdf）。内容：静态分析 App 与 SDK 代码，检查
**PICO SDK（隐私可配置 SDK，GDPR/CCPA/COPPA 合规配置 API）是否被正确使用**。数字：65 个流行 PICO SDK、
**48,000+ Google Play App**；51.4% 的 App 集成 PICO SDK（AdMob 出现在 14,497 个 App）；
**31.5% 完全未做隐私配置**；50.2% 用无隐私 API 的旧版 SDK；**28/36 个 PICO SDK 默认值即侵犯隐私**；
**22 个「包装器 SDK」中 16 个违反「完整隐私委托」**——不把 App 的配置转发给内嵌 SDK，或按 IP 地理位置
条件性转发（Appodeal/BidMachine/Admost）。漏配最严重：Criteo 99.2%、Amplitude 94.3%、Bytedance 79.0%。
**借鉴**：① 「配置 API 存在 ≠ 配置生效」是政策一致性的**第三层**（政策声明 ≠ 行为一致之外）——
静态侧可加「SDK 隐私配置 API 的方法引用存在性」观察（candidate 封顶、进 gap），P2；
② 需要配置 API 签名种子表（先做前 N 个主流 SDK，`uncovered_by_design` 声明其余）——**不做全量 65 个**（§9 第 4 条）。

### 5.6 TCF 在大规模 Android App 上的合规研究

出处：Victor Morel, Cristiana Santos, Pontus Carlsson, Joel Ahlinder, Romaric Duvignau，
*The TCF doesn't really A(A)ID – Automatic Privacy Analysis and Legal Compliance of TCF-based Android
Applications*，PoPETS 2026 第 3 期（DOI 10.56553/popets-2026-0068；arXiv:2602.20222；Chalmers 硕士论文
为前身）。方法：模拟器上大规模下载安装 4,482 个流行 Play App，动态检测 TCF 实现与 AAID 传输时序。
数字：**12.85%（576 个）实现 TCF**（较 2023 年 ~6.6% 两年增长 2.8 倍）；**用户拒绝同意后仍无合法依据
共享 AAID 的占 TCF App 的 66.2%**；**同意横幅交互之前就共享 AAID 的占 55.3%**；15 个 App（2.6%）只在
用户同意时存储选择、拒绝者每次启动都被重复弹窗；Google 是主导 CMP（82.54–89.76%）；游戏类违规最多。
**借鉴**：① 「**拒绝后仍外发**」与「**横幅交互前外发**」正是 V-Scanner 同意时序（PERM_RESULT denied /
POLICY_VIEW 前后）的镜像谓词——现有八谓词覆盖「grant 前读取」，未覆盖「**denied 后读取/外发**」，
建议新增观察项/谓词（走 M022 式流程：规则语义层改动需回归反例，P1）；
② 「拒绝者每次启动被重复弹窗」可用 POLIcy_VIEW 事件频率做观察（P2）；③ 国内无 TCF，仅取**时序语义**，
不引入 IAB 生态检测。

---

## 6. 行业平台与开源/CI 工具

### 6.1 国内行业平台（交付物/报告形态/CI/人工复核对比）

| 平台 | 检测项 | 报告形态 | CI/API | 人工复核 | 出处（访问 2026-10-19） |
|---|---|---|---|---|---|
| 百度智能云**史宾格** | 隐私专项（164 号文/认定方法/GB-T 35273 对标）、隐私合规（政策内容/收集使用/用户权利）、权限分析（过度/冗余权限+三方 SDK 识别）、漏洞（19 基础+20 代码级） | 《检测报告》（含敏感权限使用分析、SDK 集成使用情况分析）+《应用行为数据》（行为记录、堆栈信息、截图取证），约 20 分钟出；上架护航版 37 项 164 号文测评结果 | 面向应用市场提供定制化接口；无公开 CI | 专家模式检测报告、法务团队逐条对应分析 | 官方页：cloud.baidu.com/theme/R/821950-1-7-4；上架护航版 mtcatmp.n.shifen.com/privacy/ |
| 阿里云（云市场「APP个人信息保护合规检测服务」+ EMAS） | 政策协议合规、代码权限、个人信息采集项、三方 SDK、风险项与整改建议；EMAS 侧另有动静态污点+沙箱真机模拟点击 | 检测报告（报告页可下载，据宣传「根据报告整改并复测」） | EMAS 控制台/OpenAPI 生态；无公开 CI 模板 | 未在公开页承诺（法务人工未明确） | market.aliyun.com/detail/cmfw00045669；EMAS 宣传（掘金/博客园，仅二手线索） |
| 梆梆安全「移动应用合规平台」 | 成分分析（商业/开源 SDK+权限关联）、安全分析（漏洞定位+修复示例）、行为分析（内核级沙箱识别权限使用与个人信息传输）、合规分析（内置清单+自定义模板，GB/T 35273-2020） | 《移动应用个人信息数据安全检测报告》《应用违法违规收集使用个人信息评估报告》等类型；批量检测（自动装/启动/遍历/卸载） | 未公开 CI；私有化/服务化交付 | **人工深度辅助测试**与审计服务（App 审计=安全+个人信息双维度，专业团队出报告+整改+复测） | bangcle.com/index/index/pages/cat_id/278.html；App 审计 cat_id/24/id/70 |
| 华为云 CodeArts AppSec「移动应用安全」 | 隐私合规（违规/超范围收集、强制/频繁/过度索权；NLP/ML/OCR 解析政策文本做声明-行为一致性）+ 安全漏洞（权限/组件/网络/存储/证书）；支持 APK/HAP | 扫描报告+修复建议；分钟级 | 云服务 API；AppGallery Connect 上架自检联动 | 未见公开人工复核承诺 | huaweicloud.com/product/vss/appSecurity.html |
| 汉华信安「APP个人信息收集行为检测系统」（棱眼矛） | AI Agent 无人值守：上传 APK → 自动遍历界面触发业务场景 → NLP 语义分析隐私政策提取声明收集范围 → 声明 vs 实测行为交叉比对 → 自动研判违规点 | **AI 精准研判报告**：违规点+大模型生成的整改建议+法律依据解析 | 未公开 CI | 「无人值守」定位（人工复核未在公开页承诺） | bjhhxa.com.cn/?p=2426（官方页直抓） |

**共性结论（对 V-Scanner 的启示）**：① 检测项高度同质（权限/采集/SDK/政策/行为），V-Scanner 的八谓词+值哈希
在证据深度上不落后甚至更强（值级证据、栈行号、可追溯规则 ID 是学术工具都缺的）；② **差异化都在报告与服务**：
问题描述+整改建议+截图存证+代码堆栈四件套、20 分钟级闭环、复测流程、法务/人工复核——V-Scanner 的 PDF
已有大部分要素，缺「复测对比」与「整改-复测闭环编号」（§8）；③ 行业平台均宣称对标 164 号文/认定方法/
GB/T 35273——V-Scanner 规则库已引用同源法规，可在报告判定依据章加「行业对标矩阵」一句话说明（P0）。

### 6.2 开源/CI 工具

- **PackagePrivacy**（github.com/stonehill-2345/package-privacy）：基于包的 Android 静态隐私合规检测工具，
  支持 Maven/URL/本地 JAR/AAR/APK 获取 → JADX 反编译 → manifest/权限/组件/JNI 解析 → **规则配置式
  隐私 API 调用检测**（按隐私类别组织、含调用位置与上下文）→ Markdown 合规报告；集成 LLM 与 MCP 服务。
  社区极小（~2 stars）。**借鉴**：其「按隐私类别组织的 API 调用清单+位置」与
  `static_scan_thirdparty.py` 的 supplement 同构，可对照其报告模板（调用位置必须显式标注「静态引用、
  不证运行时」——本项目已有该口径）。注意 §8.6 第 2 条：只借鉴结构、不引入代码。
- **Oncecheck**（pypi.org/project/oncecheck/，v0.7.8）：终端 CLI，扫 iOS/Android/Web 项目**上架级合规风险**
  （Android 18 条：manifest/目标 SDK/权限/ProGuard/Play Integrity 等），导出 **JSON、SARIF 2.1、纯文本**，
  退出码 0/1/2 接 CI，支持 ignore/rc 抑制文件。**GitHub 仓库未核实**：PyPI 元数据声明的
  github.com/oncecheck/oncecheck-cli 返回 404（可能未公开/已迁移）。**借鉴**：退出码分级+SARIF 导出+
  抑制文件三项工程形态（§8.3），结构借鉴即可。
- **SubmitGate**（npmjs.com/package/submitgate，v0.35.2）：扫 iOS（.xcarchive/.ipa/.app）与 Android
  （.apk/.aab）**构建产物**的上架/合规风险（网络安全配置、可调试构建、target SDK、广告 ID、权限声明等），
  导出 JSON/Markdown/**SARIF**，GitHub Actions 集成（`security-events: write` 上传 Code Scanning），
  基线机制（只对新问题失败）。**源码未核实**：npm 元数据 license=UNLICENSED、无 repository 字段、
  分发包为编译产物；需 `SUBMITGATE_LICENSE` token（免费试用）。**借鉴**：只取其「**SARIF 上传 Code
  Scanning + 基线只对新问题失败**」的 CI 工程形态（§8.3），**不引入其包**（许可不明+§8.6 第 2 条）。

---

## 7. 审计报告 / PDF 格式（重点）

### 7.1 学术工具与行业报告的通用结构（来源：§6 各平台报告形态 + §5 各论文的评测口径 + SARIF/OSCAL 概念）

综合上述一手来源，主流审计/合规报告的结构要素与 V-Scanner 现状对照：

| 要素 | 外部实践出处 | V-Scanner 现状 | 建议 |
|---|---|---|---|
| 执行摘要与风险总览 | 史宾格/梆梆/汉华报告；MobSF | 已有（一章概览 + 风险章 report_risk） | **保留**；增补一行「与 164 号文/认定方法/GB-T 35273 对标」说明 |
| 检测范围与授权声明 | 全部行业平台首页声明 | 已有（封面授权字样 + 概览设备/会话） | **增补**「范围卡片」：样本哈希、设备/镜像、采集窗口、触发方式、环境版本一览（部分在 meta 里，需集中） |
| 方法与工具版本 | 学术论文评测章；行业报告 | 方法章有；工具版本不全（jadx/frida/mitmproxy/emulator 版本散落日志） | **增补**工具版本清单表（meta 已收集部分字段，渲染成表） |
| 发现卡片（现象/证据/法规/严重度/置信度/整改） | 史宾格「问题描述+改进建议+截图存证+代码堆栈」；梆梆「定位+修复示例」 | 工具结论章有规则/法规/等级；整改在 AI 章 | **增补**卡片五要素完整性断言：每条 finding 必须可渲染（现象/证据/法规/严重度/置信度/整改或「整改建议缺失=gap」），写进 test_report_gates.py |
| 证据链与哈希 | 学术可复现要求；本报告引用 SARIF partialFingerprints 概念 | 已有 bundle_sha256 / APK sha256 / 规则库 sha256 | **增补**附录「证据文件清单+逐文件 sha256」表（离线生成） |
| 法规映射矩阵 | 史宾格 37 项 164 号文；SARIF taxonomies；OSCAL catalog | 判定依据章有规则→法规列表 | **增补**「规则×条款×结论计数」矩阵表 + 机器可读导出（§8.3） |
| 覆盖缺口 | 学术评测「limitations」；本项目 gaps 是差异化强项 | 已有（概览 gaps + 附录） | **保留**（这是卖点） |
| 整改建议 | 全部行业平台 | AI stage3 整改章已有 | **增补**整改项编号 → 供「复测对比」引用 |
| 复现附录 | 学术 artifacts（PolicyGapper 全开源复现包是标杆） | 有复现命令（CLAUDE.md），未入 PDF | **增补**附录复现命令段（从 pipeline README 提取） |
| 免责声明 | 行业报告标配 | 已有（不产 policy_violation、不构成法律意见） | **保留**，措辞与 GDPR-Bench-Android 结论联动强化 |
| 版本与复测对比 | 行业「整改并复测」闭环；AI 三阶段提示词版本已入报告 | 无（每轮独立） | **增补**可选「复测对比」章：同一 App 两轮 bundle 的结论/分数差值（P1，需两次运行数据） |

### 7.2 机器可读配套格式

- **SARIF 2.1.0（OASIS 标准；github.com/oasis-tcs/sarif-spec，2.2 草案进行中）**：核心对象
  `runs/tool/driver/rules`（规则定义，对应 V-Scanner 的 rule_id+法规映射）、`results`（finding）、
  `locations`（证据位置）、`codeFlows`（流）、`taxonomies`（法规分类）、`partialFingerprints`
  （去重/复测比对指纹）。消费方：GitHub Code Scanning、各类 IDE/CI。**对 V-Scanner 的价值**：
  ① 把 `static_mobile_supplement.json` 与 `validate.py` 的 problems 导出为 SARIF → CI 可在 PR 上
  展示「静态引用级提示」与「AI 校验问题」，**静态证据仍不进 code_locs**（SARIF 的 location 指向
  反编译产物路径并带 property `evidence_kind=static_reference`，与行为结论严格分桶）；
  ② `partialFingerprints` 天然支持「复测对比」（§8 增补章）。**限制**：SARIF 是代码缺陷语义，
  「隐私合规结论」需用 property/extension 承载——只导出机器可读、**不改 PDF 结论语义**。导出器
  一个 ≤300 行模块，P1（纯离线，可先做 supplement 侧）。
- **OSCAL（NIST，pages.nist.gov/OSCAL/，XML/JSON/YAML）**：面向控制基线的评估语言——catalog
  （控制目录）、assessment-results（评估结果）、POAM（行动计划）。适合把 V-Scanner 的
  「法规条款→规则→检测结果→整改」映射导出为 OSCAL assessment-results，向监管/测评机构对接。
  价值中长期、国内生态使用少 → P2 研究项。
- **JSON（现有）**：bundle.json / findings.jsonl / static-manifest.json 已是机器可读主链，
  保持并文档化 schema 版本即可。

### 7.3 对现有九章 PDF 的逐章建议（落点 report_mobile.py 的章节顺序）

| 章 | 现状 | 建议 | 动作 |
|---|---|---|---|
| 一、检测概览（sec.section_overview） | 包名/哈希/设备/类目/规则库/证据规模/gaps | **保留**；增补「范围卡片」（采集窗口、触发方式、环境版本）与「行业对标」一行 | 增补 |
| 二、风险总览（report_risk） | 四维乘积风险分+置信度 | **保留**；预留「复测对比」挂载点（分数差值） | 保留+预留 |
| 三、判定依据（sec.section_basis） | 规则分布+法规列表+等级含义 | **增补**「规则×法规条款×结论计数」矩阵表；SARIF/OSCAL 导出处留钩子 | 增补 |
| 四、证据摘要（sec.section_evidence） | 钩子健康/读取/同意/流 | **保留**；**增补**钩子健康与「未触发 API 清单」（C2 落地后）的 gap 联动 | 保留+增补 |
| 五、存储/加密与六、补充证据 | 技术观察 | **保留**（不加定性） | 保留 |
| 七、工具规则结论（sec.section_findings） | 规则结论逐条溯源 | **增补**卡片五要素完整性断言（缺失=gap 渲染）；`origin` 归因字段落地后加「各数据由谁收集」分组统计 | 增补 |
| 八、AI 综合研判（ai_sec.section_ai_assessment） | stage3 输出+置信度 | **保留**；**增补**跨运行一致性注记（B3 评测集落地后自动写入） | 保留+增补 |
| 九、行为—政策一致性（ai_sec.section_consistency） | 逐数据类别/同意链路比对 | **升级**：渲染「TPL 行为—政策声明矩阵」（§4.5）+ 五分类状态（E1） | 调整（P1） |
| 十、整改建议（ai_sec.section_recommendations） | 整改+不确定性 | **增补**整改项编号（供复测引用） | 增补 |
| 十一、AI 校验问题（ai_sec.section_ai_validation） | problems 清单 | **保留**（诚实性工程的差异化卖点）；同步导出 SARIF（§8.3） | 保留+导出 |
| 十二、方法与局限（sec.section_method） | 方法说明 | **增补**工具版本清单表 | 增补 |
| 附录（sec.section_appendix） | 附录 | **增补**证据文件逐文件 sha256 清单、复现命令段、免责声明强化、未核实/缺口汇总 | 增补 |

验收方式：以上每项渲染变更配 `mobile/report/test_report_gates.py` 或新增离线用例
（如「每条 finding 卡片五要素缺一时渲染 gap 文案」），并入 `run_mobile_checks.py`。

---

## 8. 对 V-Scanner 的借鉴矩阵

> 优先级定义沿用 RESEARCH_OUTLOOK：`P0`=纯离线可验收、改动小；`P1`=需设备或中等改动；`P2`=研究/论文级。

| ID | 借鉴点 | 出处 | 落点文件 | 预期收益 | 代价 | 优先级 | 验收方式 |
|---|---|---|---|---|---|---|---|
| B1 | stage2 五分类并入 **OD/VD 语义**与判定口径（含「政策层是误报主源」警示） | GNChecker ASE'24；PoliCheck（已有 E1 规划） | `mobile/ai/prompts/stage2_consistency.md`、`stage2_user.md`、`ai/validate.py`、`report_ai_sections.py` | 一致性结论从二分类升五分类，信息量翻倍 | 提示词+枚举+渲染，低 | **P0** | 离线 dry-run：5 类各一示例；越界枚举被校验拦下 |
| B2 | 报告卡片**五要素完整性断言**+法规映射矩阵渲染 | 史宾格/梆梆报告形态；SARIF taxonomies | `report_sections.py`（section_findings/section_basis）、`report/test_report_gates.py` | 交付物与行业报告对齐，可直接用于竞赛/申报 | 渲染+断言，低 | **P0** | 离线：构造缺「整改建议」的 finding，断言渲染 gap 文案；矩阵计数与 findings 一致 |
| B3 | **ML 位置约束**写入决策文档（hint/priority/needs_human_review 三字段制） | LeakSemantic INFOCOM'17；GDPR-Bench-Android | `mobile/DECISIONS.md` 新增 M0xx + `RISK_SCORE_MODEL.md` §六 | 防止未来误用 ML 破坏证据门控 | 文档，极低 | **P0** | 评审确认约束写入 |
| B4 | 「AI 不可从代码直判违规」外部证据引用进报告方法章/申报材料 | GDPR-Bench-Android（Acc@1 17.38%） | `report_sections.py` section_method + 申报材料文档 | 为「不产 policy_violation」提供同行评议背书 | 文案，极低 | **P0** | 离线：方法章出现该引用与数字 |
| B5 | **TPL 行为—政策声明矩阵**（政策侧条款组 PP-TPL-xx → 行为侧 origin 归因 → stage2 矩阵 → 一致性章渲染） | PIChecker FORGE'26 | 提示词 stage1/stage2 + `validate.py` + `report_ai_sections.py`；行为侧 `hooks/hook_classload.js`（F1） | 直接补缺口 A3 的合规语义，形成差异化章节 | 提示词+校验离线；归因需设备一轮 | **P1**（提示词/枚举部分 P0 先行） | 离线 dry-run 矩阵 schema 全路径；设备：夹具 App 上 host/third_party 归因稳定复现 |
| B6 | **隐私定向 UI 探索目标排序**：敏感引用聚类 → Activity/控件触发优先级；先广后深两轮调度 | GNChecker 分段思想（降级）；MiniScope TOSEM'25 | 新模块 `mobile/tools/ui_explore.py`（≤300 行，G1 增强）+ `device_run_thirdparty.py` 调用 | 触发覆盖率从「不可度量」到「有目标」，缓解 B4 | 离线聚类模块+设备一轮验证 | **P1** | 离线：夹具 APK 上敏感聚类输出稳定；设备：同 App 两轮探索的目标命中差异可解释 |
| B7 | 「同意**被拒后**仍读取/外发」观察项/谓词（denied 语义时序） | TCF PoPETS'26（66.2%/55.3% 两数字的时序语义） | `analyze/evaluation_mobile.py`（新谓词，M022 式流程）+ `rules/` 规则条目 | 补上同意时序镜像盲区（现有谓词只看 grant 前） | 谓词+反例回归+设备验证 | **P1** | 离线：构造 denied 后读取事件命中、grant 前读取不误命中；设备：夹具权限拒绝路径 |
| B8 | 工具版本清单+复现命令+证据逐文件哈希附录 | 行业报告；PolicyGapper 复现包；SARIF partialFingerprints | `report_mobile.py` meta + `report_sections.py` 附录 | 复现性与证据链完整性 | 离线，低 | **P0** | 离线：附录表存在且哈希与实际文件一致 |
| B9 | **SARIF 2.1.0 导出**（静态补充扫描 + AI 校验问题；静态 location 带 `evidence_kind=static_reference` 分桶） | OASIS SARIF；Oncecheck/SubmitGate 的 CI 形态 | 新模块 `mobile/report/export_sarif.py`（≤300 行）+ CI workflow 注释 | 静态提示与校验问题可进 Code Scanning/PR 流 | 离线模块+用例 | **P1**（可 P0 先出 supplement 侧） | 离线：导出 JSON 过 SARIF schema 校验；location 分桶断言 |
| B10 | 复测对比章（同 App 两轮：结论差/分数差/新消失项） | 行业「整改-复测」闭环；SARIF fingerprints | `report_mobile.py` 新章节（可选输入 `--baseline`） | 支撑「整改验证」使用场景 | 中等，需两轮产物 | **P1** | 离线：构造两轮 bundle 断言 diff 渲染；设备：同 App 两次运行实测 |
| B11 | stage2「疑似误报复核清单」（四类：数据变换/API 语义误读/不可行路径/反射误析） | PriAgent AAAI'26 | `stage2_consistency.md` 提示词段 | 降 AI 误报、提升复核效率 | 提示词，低 | **P1** | 离线 dry-run 校验输出含该清单字段 |
| B12 | SDK 隐私配置 API 引用观察（配置 API 存在性 candidate 级） | PICOSCAN USENIX'24 | `static_scan_thirdparty.py` supplement 扩展 + 种子表（前 N 个 SDK，uncovered_by_design） | 政策一致性第三层（配置层） | 种子表维护，中 | **P2** | 离线：含配置 API 的夹具 APK 命中、无配置 API 不误报 |
| B13 | 声明间交叉核对（政策 vs 市场描述/官方告知的遗漏声明） | PolicyGapper arXiv'26 | `policy/` 新检查 + stage1 输入扩展 | 政策完整性多一维 | 抓取+提示词，中 | **P2** | 离线：构造「政策未提、市场描述已提」样例产出 declaration_gap |
| B14 | 外部工具对照实验（AndroByte/GNChecker 指标口径与 V-Scanner 值哈希链路对比） | AndroByte ACSAC'25（注意 89% vs 91.70% β=0.5 口径） | `tools/vscanbench/`（I1 扩展） | 论文级对比材料 | 需外部工具环境，高 | **P2** | 自有夹具：双方在 8 类 VScanBench 用例上的结果表 |
| B15 | ML 流量分类器「疑似第三方域名」置信度字段（不改结论等级） | LeakSemantic INFOCOM'17 | `traffic/tagging_mobile.py` 可选旁路 | third_party_share 的人工复核排序 | 训练数据+实验，高 | **P2** | 离线：分类器输出为 hint 字段、断言不改等级 |

---

## 9. 分阶段落地清单

### P0：纯离线（1–2 周，全部可用 dry-run/单测验收，不动设备链路）

- [ ] **B1** stage2 五分类 + OD/VD 口径（提示词 + validate.py 枚举 + 一致性章渲染）；
- [ ] **B2** 发现卡片五要素断言 + 法规映射矩阵（report_sections.py + test_report_gates.py）；
- [ ] **B3** ML 位置约束写入 `DECISIONS.md`（新 M0xx）；
- [ ] **B4** GDPR-Bench-Android 证据引用进方法章/申报材料；
- [ ] **B8** 工具版本清单 + 证据逐文件哈希附录；
- [ ] **B5-前半** TPL 矩阵的政策侧（PP-TPL-xx 条款组 + stage2 矩阵 schema + validate 枚举，dry-run 验证）；
- [ ] **B9-前半** SARIF 导出静态 supplement 侧（离线可全验）。
- 验收：`run_mobile_checks.py` 全过且新增 ≥4 项；`check_mobile_branch.py` 不回归。

### P1：需设备（2–4 周，每项都要一轮真实样本验证）

- [ ] **B5-后半** F1 运行时类加载归因（host/third_party/unknown）+ 矩阵真跑一次真实 App；
- [ ] **B6** UI 探索器隐私定向目标排序（夹具验证后推广第三方流）；
- [ ] **B7** 「denied 后仍读取/外发」谓词（夹具拒绝路径 + 反例回归）；
- [ ] **B10** 复测对比章（同 App 两轮实测）；
- [ ] **B11** stage2 误报复核清单提示词（真跑验证 AI 输出字段）。
- 验收：一轮 `device_run_thirdparty.py` 全流程通过；新字段全部有「unknown 不写成已知」回归用例；bundle_version 递增。

### P2：研究级（学期/论文级，可并行申报材料写作）

- [ ] **B12** SDK 隐私配置 API 引用观察（前 N 个 SDK 种子表）；
- [ ] **B13** 声明间交叉核对（政策 vs 市场描述）；
- [ ] **B14** VScanBench 外部工具对照（AndroByte/GNChecker 指标口径对照表）；
- [ ] **B15** ML 流量分类器实验（严格 hint 制）；
- [ ] OSCAL assessment-results 导出的可行性试验。

---

## 10. 不应借鉴的部分及理由

1. **全量通用污点引擎（FlowDroid/Amandroid 复刻或 LDPG 完整实现）**：TSE 2021 已证明真实 App 上
   大面积失效（25 个崩 11 个）；与本项目「可运行优先于完整」「静态封顶 candidate」双重冲突；
   GNChecker 的分段策略是论文级投入（FCG+数据流+路径切分），收益被「静态结论封顶」约束大幅削减。
   **只取其思想（引用聚类/触发目标排序），不取其引擎。**
2. **AndroByte 式「LLM 直接判流/生成调用图作为行为事实」**：违反 system.md「AI 不引入新行为事实」与
   静态封顶铁律；且其「89% Fβ（摘要）vs 91.70% Fβ(β=0.5)（正文）」的口径漂移提示该方法论成熟度不足。
3. **PriAgent/GDPR 系「直接产出违规裁决」的结论等级**：V-Scanner 只取 PriAgent 的误报消解清单与
   RAG 验证思想，**不取**其 verdict 级结论（M012 不产 policy_violation）。
4. **大规模 SDK 签名库（ATVHunter 18.9 万库、PICOSCAN 65 个 PICO SDK 配置 API 全量）**：
   违反「可运行优先于完整」与 §8.6 第 2 条（不引入外部代码/数据）；用前 30 个 SDK 包名前缀种子表 +
   `uncovered_by_design` 声明即可产生价值。
5. **mock/影子数据（AppFence/MockDroid）与 PIChecker 的 APK 重打包插桩**：违反「观察不改写」。
   V-Scanner 的 Frida 外置钩子 + mitmproxy + 系统 CA 在不动 APK 的前提下已覆盖 PIChecker 动态验证的
   同等能力（且 PIChecker 动态只确认了 7 条流——插桩路线的回报有限）。
6. **Oncecheck/SubmitGate 的代码或二进制引入**：Oncecheck 仓库 404 不可审计；SubmitGate UNLICENSED
   无源码。两者仅作 SARIF/CI 工程形态的结构参考（§8.6 第 2 条）。
7. **TCF 的 IAB 生态检测（TC string/CMP 解析）**：国内无此生态；只取其「拒绝后仍共享」「横幅交互前共享」
   的**时序语义**。
8. **LeakSemantic 的定制 Dalvik VM**：绑定旧 Android 版本、维护不可持续；其 ML 思想用 B15 的轻量旁路
   形态承接即可。

---

## 11. 参考文献与检索记录

### 11.1 参考文献（全部访问日期 2026-10-19）

1. S. Arzt, S. Rasthofer, C. Fritz, E. Bodden, A. Bartel, J. Klein, Y. Le Traon, D. Octeau, P. McDaniel.
   *FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps*.
   PLDI 2014. DOI: 10.1145/2594291.2594299. https://dl.acm.org/doi/10.1145/2594291.2594299
   官方实现：https://github.com/secure-software-engineering/FlowDroid
2. J. Zhang, Y. Wang, L. Qiu, J. Rubin. *Analyzing Android Taint Analysis Tools: FlowDroid, Amandroid, and DroidSafe*.
   IEEE TSE 48(10):4014–4040, 2022（2021 在线）. DOI: 10.1109/TSE.2021.3109563. https://ieeexplore.ieee.org/document/9529015
3. B. Nazzal, M. H. Alalfi, J. R. Cordy. *KASTroid: A Static Taint Analysis Framework for Kotlin-Based Android Applications*.
   COMPSAC 2025（STPSA 研讨会）, pp. 2295–2300. IEEE 文档 11126835.
   开放 PDF：https://research.cs.queensu.ca/home/cordy/Papers/STPSA-KASTroid.pdf
4. M. E. Khatun, L. Noureddine, Z. Sui, A. Ali-Gombe. *AndroByte: LLM-Driven Privacy Analysis through Bytecode
   Summarization and Dynamic Dataflow Call Graph Generation*. ACSAC 2025.
   官方 PDF：https://www.acsac.org/2025/files/web/acsac2025-435-khatun.pdf
   arXiv: https://arxiv.org/abs/2510.15112 ；工件：https://github.com/Eshita66/AndroByte
5. M. Fan, J. Shi, Y. Wang, L. Yu, X. Zhang, H.-J. Wang, W. Jin, T. Liu. *Giving without Notifying: Assessing
   Compliance of Data Transmission in Android Apps*（GNChecker）. ASE 2024. DOI: 10.1145/3691620.3695528.
   https://dl.acm.org/doi/10.1145/3691620.3695528
6. H. Fu, Z. Zheng, S. Bose, M. Bishop, P. Mohapatra. *LeakSemantic: Identifying Abnormal Sensitive Network
   Transmissions in Mobile Applications*. IEEE INFOCOM 2017. DOI: 10.1109/INFOCOM.2017.8057221.
   https://ieeexplore.ieee.org/document/8057221 ；arXiv: https://arxiv.org/abs/1702.01160
7. K.-R. Huang, X. Zhan, X. Xia. *PIChecker: Automatic Privacy Detector for Third Party Libraries in Android Apps*.
   FORGE 2026（IEEE/ACM 第三届 AI 基础模型与软件工程会议，ICSE 2026 同址）. DOI: 10.1145/3793655.3793721（CC-BY）.
   https://dl.acm.org/doi/10.1145/3793655.3793721
8. L. Ferrari, B. Habbati, M. Guerar, M. Ceccato, L. Verderame. *PolicyGapper: Automated Detection of
   Inconsistencies Between Google Play Data Safety Sections and Privacy Policies Using LLMs*. arXiv:2604.16128.
   https://arxiv.org/abs/2604.16128 ；复现包：https://github.com/Mobile-IoT-Security-Lab/PolicyGapper
9. S. Wang 等. *MiniScope: Automated UI Exploration and Privacy Inconsistency Detection of MiniApps via
   Two-phase Iterative Hybrid Analysis*. ACM TOSEM 34(6) 2025. DOI: 10.1145/3709351.
   https://dl.acm.org/doi/10.1145/3709351 ；arXiv: https://arxiv.org/abs/2401.03218
10. Z. Zhang, Z. Li, Z. Jiang, J. Yin, X. Wang, J. Chen, Q. Liu. *PriAgent: A Collaborative Multi-Agent Framework
    for Auditing Android Privacy Compliance*. AAAI-40 2026, pp. 1587–1595. DOI: 10.1609/aaai.v40i2.37135.
    https://ojs.aaai.org/index.php/AAAI/article/view/37135
11. H. Ran, H. Zhang, X. Tang. *GDPR-Bench-Android: A Benchmark for Evaluating Automated GDPR Compliance
    Detection in Android*. arXiv:2511.00619. https://arxiv.org/abs/2511.00619
    https://github.com/Haoyi-Zhang/GDPR-Bench-Android
12. Y. Zhang 等. *Navigating the Privacy Compliance Maze: Understanding Risks with Privacy-Configurable Mobile
    SDKs*（PICOSCAN）. USENIX Security 2024, pp. 6543–6560.
    https://www.usenix.org/conference/usenixsecurity24/presentation/zhang-yifan
    PDF: https://www.usenix.org/system/files/usenixsecurity24-zhang-yifan.pdf
13. V. Morel, C. Santos, P. Carlsson, J. Ahlinder, R. Duvignau. *The TCF doesn't really A(A)ID – Automatic Privacy
    Analysis and Legal Compliance of TCF-based Android Applications*. PoPETS 2026(3):6–31.
    DOI: 10.56553/popets-2026-0068. https://petsymposium.org/popets/2026/popets-2026-0068.php
    arXiv: https://arxiv.org/abs/2602.20222
14. 百度智能云史宾格安全及隐私合规平台：https://cloud.baidu.com/theme/R/821950-1-7-4 ；
    APP上架隐私合规检测（上架护航版）：http://mtcatmp.n.shifen.com/privacy/
15. 阿里云云市场 APP个人信息保护合规检测服务：https://market.aliyun.com/detail/cmfw00045669 ；
    EMAS 隐私合规检测宣传（二手线索）：https://juejin.cn/post/7147561234466865165
16. 梆梆安全移动应用合规平台：https://www.bangcle.com/index/index/pages/cat_id/278.html ；
    App 审计服务：https://www.bangcle.com/index/index/detail/cat_id/24/id/70.html
17. 华为云移动应用安全（CodeArts AppSec）：https://www.huaweicloud.com/product/vss/appSecurity.html
18. 汉华信安「以AI Agent重塑数字安全与合规」（含棱眼矛 APP个人信息收集行为检测系统）：
    http://www.bjhhxa.com.cn/?p=2426
19. PackagePrivacy（基于包的安卓静态隐私合规检测工具）：https://github.com/stonehill-2345/package-privacy
20. Oncecheck CLI：https://pypi.org/project/oncecheck/ （PyPI 声明仓库
    https://github.com/oncecheck/oncecheck-cli 访问时返回 404）
21. SubmitGate：https://www.npmjs.com/package/submitgate ；https://www.producthunt.com/products/submitgate
22. OASIS SARIF：https://github.com/oasis-tcs/sarif-spec （2.1.0 委员会规范 + 2.2 草案）
23. NIST OSCAL：https://pages.nist.gov/OSCAL/

### 11.2 关键检索词记录

- 英文：「FlowDroid PLDI 2014」「Analyzing Android Taint Analysis Tools TSE 2021 FlowDroid Amandroid DroidSafe」
  「KASTroid Kotlin taint」「AndroByte LLM bytecode dataflow call graph」「GNChecker Android compliance
  segmentation」「latent data propagation graph LDPG」「PIChecker third party library privacy policy LLM」
  「LeakSemantic INFOCOM 2017」「PolicyGapper Data Safety LLM」「MiniScope MiniApps two-phase」「PriAgent
  multi-agent AAAI」「GDPR-Bench-Android 1951 23 articles」「PICOSCAN privacy configuration SDK」
  「TCF Android apps PoPETS」「PackagePrivacy github」「Oncecheck github」「SubmitGate github」「SARIF OASIS」「OSCAL」
- 中文：「百度智能云 史宾格 隐私合规」「阿里云 App个人信息隐私合规检测」「梆梆安全 移动应用合规平台」
  「汉华信安 APP个人信息收集行为检测系统」「华为云 App合规检测」
- 复核工具：Semantic Scholar API（DOI 直查摘要）、arXiv API/export、GitHub/PyPI/npm 注册表 API、
  官方 PDF 直接下载（KASTroid/AndroByte/USENIX Security 24）、官方页面直接抓取（百度上架护航版、汉华信安、NIST OSCAL）。

### 11.3 未核实/部分未核实清单（汇总）

1. **GNChecker 分段策略的实现细节**（LDPG 构建算法、子包粒度、路径去重/合并、与动态侧的衔接）——
   全文在 ACM 付费墙后；「按源-汇可达路径切子包」经摘要+被索引正文片段核实，其余**未核实**。
2. **AndroByte「89% Fβ」与正文「91.70% Fβ(β=0.5)」不一致的原因**——两数字出处均核实，差异原因**未核实**；
   300 真实 App 的 ground truth 构建方式**部分未核实**（发布页付费墙）。
3. **TSE 2021 全文细节**（崩溃堆栈归类、DroidBench 分表数字、工具配置细节）——付费墙；
   关键数字经 IEEE 元数据+被索引正文+中文精读二手交叉验证一致，其余**未核实**。
4. **PIChecker 的「>64%」结论的复核方式**（抽样比例、人工复核人数）与 LLM 幻觉率——摘要级不可见，**未核实**。
5. **Oncecheck 的 GitHub 源码仓库**——PyPI 声明地址 404，**未核实**（仅 PyPI 元数据与功能描述核实）。
6. **SubmitGate 的源码与许可证细节**——UNLICENSED、无公开仓库，**未核实**（仅 npm 注册表元数据核实）。
7. **阿里云「App个人信息隐私合规检测评估服务」的独立官方产品页**——仅找到云市场商品条目与 EMAS
   宣传文（后者为二手线索），独立 help/产品页**未核实**。
8. **梆梆安全、华为云页面正文**——官网为 JS 动态渲染，内容经官方域搜索索引片段核实，页面全文**未核实**。
9. **PackagePrivacy 的 README 全文**——GitHub 页面内容经搜索索引核实，直接抓取 raw 失败，细节**部分未核实**。
10. **PriAgent/PoliCheck 等对 FlowDroid 精度数字的口径**（73.7%→93.2%）——取自 AAAI 开放全文的搜索
    索引内容，未逐行核对正文表格（开放全文可下载，读者可复核）。

---

## 12. 附：与 `mobile/RESEARCH_OUTLOOK.md` 的差异说明

**新增（RESEARCH_OUTLOOK 未覆盖）**：
- GNChecker（ASE 2024）全文核对：分段策略的准确含义（按源-汇可达路径切子包，非按包/SDK/入口）、
  三段式方法、1,134 App/1,410 条/93.1% precision、OD/VD 两型定义（对应其「两型不一致」）；
- AndroByte（ACSAC 2025）与 KASTroid（COMPSAC 2025）两篇新工具论文及数字；
- LeakSemantic（INFOCOM 2017）的出处、方法与 1,404 App/91% 数字（RESEARCH_OUTLOOK 簇 B/C 未列）；
- PIChecker（FORGE 2026）全文核对（130/>64% 口径逐字确认）；
- 声明—行为一致性新作五篇：PolicyGapper、MiniScope、PriAgent、GDPR-Bench-Android、PICOSCAN、TCF-PoPETS'26
  （RESEARCH_OUTLOOK 簇 E 只到 2025 的 LLM-PrivCheck 为止）；
- 行业平台五家 + 开源/CI 工具三家（PackagePrivacy/Oncecheck/SubmitGate）的交付物/报告形态/CI/人工复核对比；
- SARIF 2.1.0 与 OSCAL 的机器可读配套方案及对九章 PDF 的逐章建议；
- 「ML 合理/不合理位置」表格与证据门控三字段制。

**更新（对 RESEARCH_OUTLOOK 既有条目的修订）**：
- TSE 2021 条目补全作者（Junbin Zhang, Yingying Wang, Lina Qiu, Julia Rubin）、卷期页码
  （TSE 48(10):4014–4040，2022 卷期、2021 在线）与 DOI；失效数字（11/25 崩溃、2/14、0/3/28/43）交叉验证一致；
- FlowDroid 条目补官方仓库地址与维护现状；
- RESEARCH_OUTLOOK 簇 A「DROIDSAFE 精度最高、FlowDroid 次之、Amandroid 最低」为 benchmark 口径——
  本次核实补充「Amandroid 检出流数量最多但误报多」的数量/精度之别，避免误读；
- E1（stage2 五分类）获得 GNChecker OD/VD 的命名与判定口径支持，落地细节上移为 B1；
- G1（UI 探索器）获得 MiniScope「隐私实践定向探索」与 GNChecker 分段思想的落地形态（B6）；
- F1（第三方归因）获得 PIChecker 矩阵的消费场景（B5），优先级从 P1 保持不变但验收更具体；
- 新增「denied 后仍外发」谓词方向（B7，TCF 时序语义），是八谓词之外的新增项，需 M022 式流程。

**确认不重复的既有内容**：RESEARCH_OUTLOOK 的簇 A–I 主体（FlowDroid/TaintDroid/Agrigento/Reardon/
PoliCheck/MAPS/LibScout/DroidBot/Themis 等）本文不重复展开，仅在借鉴矩阵中以 ID 引用（C1/C2/E1/E2/F1/G1/A5-1/A5-2/I1 等）。
