# Android / AAOS 车载 App 敏感数据访问与外发检测：论文、开源项目与项目定位

> 核实日期：2026-11-03
> 范围：Android 隐私数据流、权限滥用、隐私政策一致性、动态 Hook 开销、多用户/多配置文件、AAOS/VHAL、流量归因与长连接
> 项目基线：`d:\AAA\mobile-app-permission-check`（AAOS 35 主线，普通第三方 App）
> 核实口径：论文以会议/期刊官方页、DOI 或 arXiv 摘要为准；开源项目维护状态以 GitHub 提交记录为准并记录到具体日期；无法核实的内容标注“未核实”或直接省略。本文不把“本次检索不到”写成“不存在”。

## 0. 总体判断

Android 侧的隐私检测已经进入“工程集成”阶段：污点分析、权限映射、政策一致性、流量 PII 识别各自都有十年以上的方法积累和公开基准；AAOS 侧则刚起步，公开工作集中在少数团队，其中 SAE 2023、arXiv 2024 和 PRIDRIVE 均出自 Pesé 团队，对象多是 OEM 镜像、系统应用或几十个样本的手工分析。本项目的相对位置很清楚：**工程链路（VHAL + 四类通用来源 + 四态区分 + 值级/派生值归因 + 五类场景 + 覆盖链 + 证据分级）在本次检索到的公开 AAOS 隐私工作中属于较完整的一档，但测量学明显落后**——没有独立标注、没有 precision/recall、没有跨版本设备矩阵、没有可对外比较的 benchmark。换句话说，当前缺的不是“再接一个 Hook”，而是把已有链路变成可测量、可复现、可被别人引用的证据系统。下一阶段的投入应优先落在标注与基准、批次因果配对、协议覆盖、Hook 开销预算和官方可访问数据面，而不是继续扩大厂商私有属性或规则数量。

### 0.1 口径校正（与任务描述不一致的三处）

1. **API 34 不是“无设备验收”**。`vehicle/COMPATIBILITY.md`（核实日 2026-11-03）记录：API 34 使用官方 Android 14 ext9 x86_64 r05 车载镜像，四类通用来源、查询未消费负控、错误键、拒绝和不同值对照全部通过（`output/vehicle-api34-20261103/general-001/verification.json`）。真正缺设备验收的是 API 33 和 API 36；且 API 34 的“全量车载”仍是 `dynamic_verified=false`，只有通用来源通过。API 36 本轮查询的官方车载镜像索引无对应 x86_64 条目，宿主机已有的 API 36.1 镜像属于手机变体。
2. **845 ms 不是单次 Hook 开销**。`vehicle/bench/README.md` 的口径是“每轮 276 条 `VHAL_READ` + 12 条外发事件的 CPU 增量中位数 845 ms”，相对无 Hook 基线 77.5%；另一组 `--pairs 6 --actions 4` 的中位增量为 0 ms，说明夹具噪声可以大于 Hook 开销。它不能和 TaintART 的“Java 运行时 <15%”或 Frida 单次调用约 24 ms 直接横向比较。
3. **窗口校准已经做过，而且 30 秒不够**。`vehicle/bench/WINDOW_CALIBRATION.md`（2026-11-03）显示：5/10/30 秒都只命中 14 个参考配对、漏 14 个、额外候选 14 个；60/120 秒命中 28、漏 0、额外候选 28。也就是说，30 秒是“常规基线”，但对缓存/断网恢复批次会系统性漏配；正确方向是批次令牌/因果标记，而不是把窗口一律调大。另外，`AGENTS.md` 的“仍未被做”清单里写 `WINDOW_CALIBRATION.md` 不存在，该文件实际已存在，文档需要同步。

## 1. 论文地图

筛选标准：优先近 5 年；保留定义方法的奠基性工作；只列能给出明确会议/期刊或 arXiv 编号的文献；数字只取摘要或正文明确给出的。共 8 个主题、36 篇（TaintART 在 1.1 与 1.4 复用）。

### 1.1 Android 隐私数据流与污点分析

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 动态污点追踪 | **TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on Smartphones**（2010，OSDI）[链接](https://www.usenix.org/conference/osdi10/presentation/enck) | 改系统层做污点标记与传播，覆盖网络、文件、IPC、短信等汇聚点 | “来源→汇聚点”链路可以作为证据；四类汇聚点可直接映射到本项目的 `reads` / `egress` 事件 | 需改 ROM；Android 5+ ART 不适用；CPU-bound 微基准约 14% 开销；不能用于未 root 第三方设备 |
| 静态污点 | **FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps**（2014，PLDI）[链接](https://dl.acm.org/doi/10.1145/2666356.2594299) | 基于 IFDS 的上下文、流、字段、对象敏感与生命周期感知分析 | 可生成“读取 API → 外发 API”的静态候选，补覆盖差集的静态侧 | 反射、native、动态加载、混淆是盲区；DroidBench 精度不能外推到真实 App；Soot 环境重 |
| 组件间数据流 | **Amandroid: A Precise and General Inter-component Data Flow Analysis Framework for Security Vetting of Android Apps**（2014，ISSTA；扩展版 2018，ACM TOPS）[链接](https://dl.acm.org/doi/10.1145/3183575) | 组件间数据流与环境建模 | 可补 exported component 矩阵的静态侧，尤其是 ContentProvider 路径 | 对现代 Jetpack/Compose 生命周期建模有限；工程复杂度高 |
| ICC 泄漏 | **IccTA: Detecting Inter-Component Privacy Leaks in Android Apps**（2015，ICSE）[链接](https://arxiv.org/abs/1404.7431) | 将 ICC 调用转为显式数据流；DroidBench precision 95.0% / recall 82.6%；3,000 个 App 中 14 个检出 147 处跨组件泄漏 | 说明真实 App 的 ICC 泄漏确实存在但阳性率低；可作为跨 profile 的静态线索 | 评估仍以 DroidBench 为主；真实样本阳性率低，不能据此估总体流行度 |
| 形式化信息流 | **DroidSafe: Information Flow Analysis of Android Applications in DroidSafe**（2015，NDSS）[链接](https://www.ndss-symposium.org/ndss2015/ndss-2015-programme/information-flow-analysis-of-android-applications-in-droidsafe/) | 精确建模 Android 运行时语义的静态信息流分析 | 为“静态信息流是可能路径，不是实际发生”提供论证；支持本项目不直接产出违规结论 | 工程复杂度高、落地成本高；闭源 APK 仍受反射/native 限制 |
| ART 动态污点 | **TaintART: A Practical Multi-level Information-Flow Tracking System for Android RunTime**（2016，CCS）[链接](https://dl.acm.org/doi/10.1145/2976749.2978343) | ART 上的多级污点追踪；Java 运行时开销 <15%，IPC <5% | 证明 ART 时代动态污点仍可行；其开销量级可作为 Hook 预算参照 | 仍需定制 ROM/ART；不能直接注入任意第三方 APK |

### 1.2 权限过度申请与权限模型

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 权限映射 | **PScout: Analyzing the Android Permission Specification**（2012，CCS）[链接](https://dl.acm.org/doi/10.1145/2382196.2382222) | 从 Android 源码静态抽取 API→权限映射 | 可用 PScout 表交叉核对覆盖链里为空的“属性→权限”字段 | 版本绑定；厂商定制与 SystemApi 不覆盖；不解释运行时授权结果 |
| 过度申请 | **Reevaluating Android Permission Gaps with Static and Dynamic Analysis**（2015，IEEE GLOBECOM）[链接](https://yaoguopku.github.io/papers/Wang-Globecom-15.pdf) | 静态分析 91% 应用过度申请；静态+动态 83% | 说明“只看清单会高估”；支持本项目“拒绝不算采集”的口径 | 过度申请不等于数据实际被读取或外发，不能作为违规结论 |
| 同行推断 | **You Are (not) Who Your Peers Are**（2021，IEEE TrustCom）[链接](https://www.ittc.ku.edu/~fli/papers/2021_trustcom_mallojula.pdf) | 用同类应用的权限集合推断过度申请 | 在没有独立标注时，可作为风险排序的先验 | 同类定义敏感；车载小众 App 样本不足 |
| 车载 App 权限 | **A Multi-Tier Security Analysis of Official Car Management Apps for Android**（2021，Future Internet 13(3):58）[链接](https://doi.org/10.3390/fi13030058) | 清单、静态、动态多层分析车企官方 App | 与本项目“普通第三方车载 App”最接近的公开对照之一；可对照其权限分层 | 对象是手机端车企 App，不是 AAOS 原生车机 App；样本小 |

### 1.3 隐私政策与行为一致性

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 政策-权限匹配 | **WHYPER: Towards Automating Risk Assessment of Mobile Applications**（2013，USENIX Security）[链接](https://www.usenix.org/conference/usenixsecurity13/technical-sessions/presentation/pandita) | NLP 从政策文本识别权限相关句子；三个权限平均 precision 82.8% / recall 81.5% | 可作为条款级映射的基线；但必须加否定与上下文，不能只做关键词 | 只覆盖少量权限；对长政策与法律措辞不鲁棒 |
| 描述-API 偏离 | **CHABADA: Identifying Misuse of Android Apps Using Machine Learning**（2014，ICSE）[链接](https://dl.acm.org/doi/10.1145/2568225.2568276) | 22,500+ App；描述主题聚类 + API 离群检测 | “行为与描述偏离”可作为 AI 复核的输入特征 | 描述不等于隐私政策；聚类粒度粗；不能定位具体数据流 |
| 政策-代码一致性 | **Automated Analysis of Privacy Requirements for Mobile Apps**（2017，NDSS）[链接](https://shomir.net/pdf/publications/uppp_ndss_2017.pdf) | 17,991 个免费 App；机器学习政策分类 + 静态代码特征 | 政策文本分类 + 代码特征的双侧证据结构，可直接借鉴到 AI 复核 | 静态代码不等于运行时读取；政策分类受标注集限制 |
| 政策内部矛盾 | **PolicyLint: Investigating Internal Privacy Policy Contradictions on Google Play**（2019，USENIX Security）[链接](https://www.usenix.org/conference/usenixsecurity19/presentation/andow) | 11,430 个 App；否定检测 + 本体 | 条款级映射必须处理否定与例外，否则“未披露”precision 会崩 | 只判政策内部一致性，不判政策与行为的一致性 |
| 百万级政策-行为 | **MAPS: Scaling Privacy Compliance Analysis to a Million Apps**（2019，PoPETs）[链接](https://www.petsymposium.org/2019/files/papers/issue3/popets-2019-0037.pdf) | 1,035,853 个 App；12.1% 至少一个 location 相关潜在合规问题 | 给出“潜在问题比例”的规模基线；其 “potential” 措辞与本项目“不直接产出 policy_violation”一致 | 依赖商店元数据与政策可得性；只做 location 单一维度 |
| 三方对比 | **On the (Un)Reliability of Privacy Policies in Android Apps**（2020，IJCNN；工具名 3PDroid）[链接](https://arxiv.org/abs/2004.08559) | >95% App 访问隐私敏感信息；约 1% 完全符合 Google Play 隐私指南 | 提供“绝大多数不满足”的宏观参照；提醒不要用单一政策源判断 | “符合”定义依赖 Google Play 指南；不是法律合规 |

### 1.4 动态 Hook 开销与可用性

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 全系统动态污点成本 | **TaintART**（2016，CCS；同 1.1）[链接](https://dl.acm.org/doi/10.1145/2976749.2978343) | ART 多级污点；Java <15%、IPC <5% | 作为“可接受开销”的量级参照 | 需改 ART，不能直接用于第三方 APK |
| Hook 框架规模化 | **Scaling Android Hooking: Usability and Performance of Frida and Xposed for Mass API Interception**（2026，SciTePress；会议名未核实）[链接](https://www.scitepress.org/Papers/2026/143195/143195.pdf) | 对比 Frida/Xposed；关闭 logging 时单次调用约 24 ms；约 400 个活跃 Hook 会显著拖慢；JSON 序列化/传输是主要成本 | 直接对上本项目的 845 ms：应先减少 Hook 数量与序列化/传输，而不是先换框架 | 基准 workload 与车载 VHAL 不同，不能直接外推 |
| 动态污点方向 | **Dynamic Taint-tracking: Directions for Future Research**（2019，SciTePress）[链接](https://www.scitepress.org/PublishedPapers/2019/81185/81185.pdf) | 综述动态污点的限制与研究方向 | 支持“动态污点不是唯一证据”的设计 | 综述，不是实验 |
| 非 root 追踪 | **Odile: A scalable tracing tool for non-rooted and on-device Android phones**（2022，ACM MobiCom）[链接](https://dl.acm.org/doi/10.1145/3545948.3545951) | 重打包 APK 后做设备端追踪；重打包耗时 10–65 秒，改变 APK 身份 | 警示：非 root 追踪的代价是 APK 身份变化，破坏“原始签名哈希可复现” | 需重打包；不适合要求原始签名哈希的审计 |

### 1.5 多用户 / 多配置文件与数据残留

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 多用户框架 | **A Systematic Security Evaluation of Android's Multi-User Framework**（2014，MoST）[链接](https://arxiv.org/abs/1410.7752) | 系统评估多用户隔离与共享机制 | 提供 profile/用户隔离的威胁模型；可映射到“顺序用户切换残留”场景 | 年代早；未覆盖工作资料、克隆应用等新形态 |
| 跨 profile 组件 | **A Tale of Four Gates: Privilege Escalation and Permission Bypasses on Android through App Components**（2022，ESORICS）[链接](https://research.birmingham.ac.uk/files/177832428/A_Tale_of_Four_Gates_Privilege_Escalation_and_Permission_Bypasses_on_Android_through_App_Components.pdf) | 利用 app components 跨 user profile 泄漏数据/绕过锁屏；影响 Samsung/Huawei/Google/Xiaomi；spyware 后台访问 camera/mic 直到 Android 10 | exported component 矩阵应覆盖 Activity/Service/ContentProvider + URI grant，并区分“普通第三方”与“需 shell/特权”的向量 | 部分攻击向量需要 ADB/shell 或系统权限，普通第三方威胁面更窄 |
| 虚拟化隔离 | **Cells: A Virtual Mobile Smartphone Architecture**（2011，SOSP）[链接](https://sigops.org/s/conferences/sosp/2011/current/2011-Cascais/13-andrus-online.pdf) | 设备端轻量虚拟化，运行多个 Android 实例 | 说明“多实例”是隔离手段；可作为残留对比的对照设计 | 需内核/虚拟化支持；不是普通 App 检测方法 |
| 安全配置 | **MOSES: Supporting and Enforcing Security Profiles on Smartphones**（2014；IEEE TDSC 期刊版，卷期未核实）[链接](https://www.zhauniarovich.com/publication/2014/moses-journal-zhauniarovich-2014/moses-journal-zhauniarovich-2014.pdf) | 通过配置切换隔离应用数据 | 可借鉴“profile 切换即数据边界”的建模 | 需系统改造；年代早 |

> 近 5 年直接做“普通第三方 App 在 Android 多用户/工作资料切换后的数据残留系统测量”的公开论文，本次未检索到；不要把取证/安全删除方向的工作硬套成这个问题的答案。

### 1.6 车载 AAOS / VHAL

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| AAOS 安全分析 | **Security Analysis of Android Automotive**（2020，SAE Int. J. Adv. & Curr. Prac. in Mobility 2(4):2337-2346）[链接](https://doi.org/10.4271/2020-01-1295) | 早期 AAOS 攻击面与安全机制分析 | 提供 VHAL/系统服务的威胁面清单 | 早于 AAOS 35；不涉及普通第三方隐私采集 |
| AAOS 隐私首览 | **A First Look at Android Automotive Privacy**（2023，SAE 2023-01-0037）[链接](https://doi.org/10.4271/2023-01-0037) [PDF](https://mpese.com/publication/pese-2023-first/SAE_AAOS_Privacy_Paper.pdf) | 55 个 AAOS App；>78% 未在隐私政策中提及所有 dangerous permissions；36% 请求 signature permissions | 与本项目最接近的“AAOS App 隐私”公开测量；其“政策未覆盖权限”可直接对照本项目的政策一致性短板 | 样本 55；以政策文本为主；未做运行时值级外发归因 |
| AAOS 数据采集 | **Analyzing Privacy Implications of Data Collection in Android Automotive OS**（2024，arXiv:2409.15561）[链接](https://arxiv.org/abs/2409.15561) | PriDrive 方法论文；三套 OEM 平台；vehicle speed 约 25 Hz；model info/climate/AC/seat 在启动 30 秒内批量采集；OEM A 政策只覆盖 110 个属性（13.02%） | 直接支持本项目“启动/批传/缓存”场景与“政策只覆盖少部分属性”的判断；25 Hz 可作为订阅采样预算参照 | 依赖 OEM 镜像与系统应用；不是普通第三方；平台数 3 |
| 工具化 | **PRIDRIVE: An Advanced Privacy Analysis Tool for Android Automotive**（2024，VehicleSec poster）[链接](https://www.ndss-symposium.org/wp-content/uploads/vehiclesec2024-24-poster.pdf) [DOI](https://doi.org/10.14722/vehiclesec.2024.25024) | 静态 + 动态 + DPI；OEM A 753 个自定义 VHAL 属性/225 个自定义权限，B 436/193，C 338/34，D 156/21；工具链含 jadx/Frida-Trace/mitmproxy/Wireshark/tcpdump/logcat/Magisk | 工具链与本项目高度重叠，可作为交叉验证参照；厂商属性数量说明“枚举厂商属性”工作量巨大 | poster；完整同行评审论文本次未核实；需 OEM 镜像/root |
| 车联网配置 | **Evaluating Network Security Configuration (NSC) Practices in Vehicle-Related Android Applications**（2024，SAE 2024-01-2881）[链接](https://doi.org/10.4271/2024-01-2881) | 车辆相关 Android App 的 NSC 实践评估 | 可作为 TLS/证书固定与抓包可行性的前置检查项 | 对象是车辆相关手机 App，不是 AAOS 原生 |

### 1.7 流量归因与目的推断

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| 因果解释 | **AppIntent: Analyzing Sensitive Data Transmission in Android for Privacy Leakage Detection**（2013，CCS）[链接](https://secsys.fudan.edu.cn/_upload/article/files/ed/66/dc30ac7d4167bc649e772a5626d5/9535a1c7-733b-4fe4-ba9f-0195144f621a.pdf) | 符号执行 + GUI 事件序列，判断外发是否由用户操作触发 | 本项目的同意/撤回、模拟行驶场景本质是因果问题；事件序列思路可补“谁触发了外发” | 符号执行可扩展性差；现代 App/混淆下成本高 |
| 流量 PII 检测 | **ReCon: Revealing and Controlling PII Leaks in Mobile Network Traffic**（2016，MobiSys）[链接](https://dl.acm.org/doi/10.1145/2906388.2906392) | 机器学习从流量识别 PII，无需特权/改 OS；TLS 需 MITM | 与本项目“值级匹配”互补：没有值可匹配时用统计/ML 兜底 | 需要训练数据；TLS 需中间人；误报需人工复核 |
| 目的推断 | **Why Are They Collecting My Data? Inferring the Purposes of Network Traffic in Mobile Apps**（2018，IMWUT/UbiComp）[链接](https://dl.acm.org/doi/10.1145/3287051) | 从 URL path/命名约定 + app metadata/domain 推断收集目的 | 可直接用于本项目“外发目的”字段，补政策条款映射的 purpose 维度 | 目的推断是启发式；对二进制/混淆域名弱 |
| 不可见状态 | **Panoptes: Detecting Out-of-Sight Privacy Exposure in Android**（2026，PoPETs）[链接](https://crysp.petsymposium.org/popets/2026/popets-2026-0125.pdf) | 15,456 个 App；13,068（84.5%）在不可见时建立网络连接；7,534/13,068（57.7%）在关闭/从未打开时仍活动 | 直接支撑本项目“后台/最小化”场景的优先级：这是高发行为，不是边缘 case | 检测连接与曝光，不做值级归因；需设备/网络环境 |

### 1.8 长连接、SDK 数据共享与合规有效性

| 主题 | 文献（标题 + 年份 + 会议/期刊 + 链接） | 核心方法 | 对本项目的可借鉴点 | 局限 |
| --- | --- | --- | --- | --- |
| WebSocket 生态 | **WebSocket Adoption and the Landscape of the Real-Time Web**（2021，WWW）[链接](https://dl.acm.org/doi/10.1145/3442381.3450063) | 大规模测量 WebSocket 采用；发现其被用于 tracking/analytics/scam/malware | 支撑本项目“同连接消息 ID 配对”的必要性；长连接不是稀有协议 | 测量对象是 Web 生态；移动 SDK 细节少 |
| 无线扫描 SDK | **Your Signal, Their Data: An Empirical Privacy Analysis of Wireless-scanning SDKs in Android**（2025，PoPETs）[链接](https://arxiv.org/abs/2503.15238) | 52 个 wireless-scanning SDK；86% App 至少收集一类敏感数据（AAID/email/GPS/WiFi-BLE scan results）；存在 SDK-to-SDK sharing / ID bridging | 直接补本项目“广告标识未覆盖”与“SDK 间共享”；AAID 常与 WiFi/BLE 扫描结果组合，不是孤立字段 | 聚焦无线扫描 SDK；不是全部 SDK |
| 退出权有效性 | **Exercising the CCPA Opt-out Right on Android: Legally Mandated but Practically Challenging**（2024，arXiv:2407.14938；PoPETs 录用，卷期未核实）[链接](https://arxiv.org/abs/2407.14938) | 1,811 个 App；GPC 基本无效；禁用 AdID 后 338 个 App 仍 opted_in Vungle，26 个 opted_out | 说明“用户关闭广告标识”不能当作合规证明；本项目应记录实际请求/响应而不是只看设置 | 加州法域；样本以免费 App 为主 |
| 平台政策效果 | **The Effect of Platform Policies on App Privacy Compliance: A Study of Child-Directed Apps**（2025，PoPETs）[链接](https://www.petsymposium.org/popets/2025/popets-2025-0094.pdf) | 7,377 个 child-directed App；评估平台政策对合规的影响 | 说明“平台政策”是可测量变量；可用于本项目纵向漂移研究设计 | 儿童类 App 特殊；外推到车载需谨慎 |

### 1.9 官方规范（非论文，但决定“能不能做”）

| 文档 | 关键结论 | 对本项目的作用 |
| --- | --- | --- |
| [AOSP: Vehicle system isolation](https://source.android.com/docs/automotive/security/vehicle_system_isolation) | VHAL 是 AAOS 唯一连接 IVI 的组件；访问应限制给 system apps，使用 SELinux + 权限 | 支撑“普通第三方预期被拒绝”的判断；拒绝不是采集 |
| [AOSP: Special properties](https://source.android.com/docs/automotive/vhal/special-properties) | vendor properties 仅通过 system APIs 访问；默认权限 `android.car.Car.PERMISSION_VENDOR_EXTENSION`；可通过 `SUPPORT_CUSTOMIZE_VENDOR_PERMISSION` 细粒度控制；`PERMISSION_NOT_ACCESSIBLE` 时 Android App 不能访问 | 直接支撑“不编造厂商常量”的约束；厂商属性必须先拿授权镜像 |
| [AAOS 25Q2 release notes](https://source.android.com/docs/automotive/start/releases/aaos-25q2) | 新增/开放 8 个 third-party-accessible vehicle properties（导航、语音助理、天气、驾驶状态相关）；常量从 `@SystemApi` 更新为 public API，但原有权限仍需要 | API 36 适配的最权威抓手：先做这 8 个，而不是猜厂商属性 |

## 2. 开源项目与工具

只列与 APK 静态/动态、隐私扫描、流量采集、车载测试直接相关的项目；维护状态核实到 2026-11-03。GitHub API 可能返回缓存，以下以 Atom feed 最新提交时间为主。

| 名称 | 类型 | 能力 | 维护状态 | 可复用程度 |
| --- | --- | --- | --- | --- |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | 静态+动态一站式 | 权限/组件/证书/追踪器扫描 + 动态 sandbox | 活跃（2026-11-01 提交；15,249 stars；GPL-3.0） | 中：报告结构与清单规则可参考；动态 sandbox 不适合 AAOS 车机 |
| [jadx](https://github.com/skylot/jadx) | 反编译 | DEX→Java、APK 资源 | 活跃（2026-10-30 提交；51,482 stars；Apache-2.0） | 高：可作反编译后端 |
| [androguard](https://github.com/androguard/androguard) | 静态解析库 | DEX/APK/Manifest 解析 | 最近推送 2023-12-10（4,732 stars；Apache-2.0） | 中：库可用，维护放缓 |
| [Mariana Trench](https://github.com/meta/mariana-trench) | 静态污点 | Meta 的 Android taint 分析 | 活跃（2026-10-30 提交） | 中高：可生成静态候选；需规则适配 |
| [FlowDroid](https://github.com/FlowDroid/FlowDroid) | 学术静态污点 | IFDS 污点分析 | 维护状态未核实（Atom feed 404） | 低-中：方法与基准可引用；工程集成成本高 |
| [CodeQL](https://github.com/github/codeql) | 通用代码查询 | 数据流查询 | GitHub 官方维护（本次未记录具体提交日） | 中：自有源码强；闭源 APK 不适合 |
| [APKLeaks](https://github.com/dwisiswant0/apkleaks) | 静态扫描 | URI/endpoint/secret 扫描，依赖 jadx | 最近提交 2025-08-20 | 中：可作外发端点先验 |
| [Exodus Privacy](https://reports.exodus-privacy.eu.org/en/) | 隐私报告平台 | 静态 tracker 检测（不反编译） | 报告平台持续运营；代码仓库最近提交未核实 | 中：tracker 签名与报告结构可参考 |
| [TrackerControl](https://github.com/TrackerControl/tracker-control-android) | 流量监控/阻断 | 本地 VPN；组合 Disconnect、DuckDuckGo Tracker Radar、Exodus/ClassyShark3xodus 签名 | 活跃（2026-11-01 提交） | 中：blocklist/归类可复用；不做值级归因 |
| [Frida](https://github.com/frida/frida) | 动态 instrumentation | Hook、native、RPC | 活跃（2026-11-01 提交；22,594 stars） | 高：项目已用；注意 Frida 17 API 变更 |
| [objection](https://github.com/sensepost/objection) | 运行时探索 | 常见 Hook 集合与运行时检查 | 活跃（2026-10-27 提交） | 中：手工验证辅助 |
| Odile | 非 root 追踪 | 重打包 + 设备端追踪 | 研究工具（MobiCom 2022） | 低：改变 APK 身份，不适合原始签名审计 |
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid) | 设备侧抓包 | 无 root VPN、PCAP、TLS 解密（mitmproxy）、SSLKEYLOGFILE、HAR | 活跃（2026-11-02 提交） | 高：可作为设备侧采集备选 |
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | 中间人代理 | HTTP/2/WebSocket、脚本扩展 | 官方仓库维护中（本次未记录具体提交日） | 高：项目已用 |
| [Caring Caribou](https://github.com/CaringCaribou/caring-caribou) | 汽车安全测试 | CAN/UDS 扫描与诊断 | 维护状态未核实（Atom feed 404） | 低-中：CAN 层，不是 AAOS/VHAL |
| python-can / can-utils / SavvyCAN / ICSim | CAN 工具/仿真 | 总线读写、仿真 | 本次未逐一核实 | 低：非本项目主线 |
| [OWASP MASTG/MASVS](https://mas.owasp.org/) | 测试规范 | 移动安全测试项与验证要求 | 社区维护 | 中：可映射到本项目验收清单 |
| [DroidBench](https://github.com/secure-software-engineering/DroidBench) | 静态基准 | 污点分析基准 App | 学术维护 | 中：静态回归 |
| [AndroZoo](https://androzoo.uni.lu/) | APK 数据集 | 百万级 APK，需申请 | 持续运营 | 高：中期规模测量的样本源 |
| DuckDuckGo Tracker Radar / Disconnect blocklist | 追踪器域名库 | 域名/实体归类 | 持续更新（本次未逐一核实） | 中：域名先验，不是值级证据 |

## 3. 对照分析

### 3.1 本项目已经覆盖的方法

| 方法 | 本项目实现 | 证据入口 | 判断 |
| --- | --- | --- | --- |
| VHAL 读取采集 | `hook_vhal.js` + 8 个属性 | `vehicle/hooks/hook_vhal.js`、`vehicle/coverage/generated/coverage.json` | 覆盖 8 属性；异步 `getProperties` 与旧 `registerCallback` 仍未覆盖 |
| 通用隐私源 | `hook_privacy.js` 四类来源 | `vehicle/coverage/generated/coverage.json` | 仅部分 API surface：location 只覆盖 `getLastKnownLocation`，microphone 覆盖 `AudioRecord.startRecording/read` 与 `MediaRecorder.start`，contacts 只覆盖 `ContentResolver.query` + `Cursor.getString`，android_id 只覆盖 `Settings.Secure.getString` |
| 四态区分 | reads 事件 + evaluate | `vehicle/privacy/pipeline.py`、`vehicle/privacy/evaluation.py` | 区分“调用了接口/返回为空/被拒绝/确实取得数据”；拒绝不算采集 |
| 值级 + 派生值归因 | derive 候选 + 值匹配 | `core/collector/derive.py` | 覆盖原值、md5/sha*、base64、urlencode、hex、gzip+b64 候选 |
| 正文归因 | flows 正文 | `vehicle/traffic/` | JSON/表单为主；二进制与未知协议弱 |
| 30 秒关联窗口 | 规则窗口 + 窗口初评 | `vehicle/bench/WINDOW_CALIBRATION.md` | 夹具上 30 秒漏 14/28；60 秒补齐，但额外候选 28 |
| WebSocket 同连接配对 | `ha_socket_evidence` | `vehicle/privacy/ha_socket_evidence.py`、`vehicle/hooks/hook_ha_socket.js` | 有同连接消息 ID 配对；仍受协议解析限制 |
| 五类场景 | 场景目录 | `vehicle/scenarios/CATALOG.md` | 同意与撤回、缓存批传与清理、顺序用户切换残留、模拟行驶、断网重连 |
| 覆盖链 | coverage.json + COVERAGE.md | `vehicle/coverage/generated/COVERAGE.md` | 每行带未覆盖原因；但属性→权限仍是 `policy_candidate_not_device_permission_mapping`，`definition_status=pending`，`source_refs=[]` |
| 证据分级 | conclusion_level + codeloc | `core/evidence/` | 静态核对、关联分析、场景统计、AI 复核、PDF 复排；不直接产出 `policy_violation` |
| 评估诚实性 | labels schema + `not_measured` | `vehicle/bench/README.md`、`vehicle/bench/metrics.py` | schema 已有，缺标注执行；`accuracy` 仍为 `not_measured` |

### 3.2 可直接借鉴的方法（按投入产出排序）

| 借鉴点 | 来源 | 具体落地方式 | 成本/优先级 |
| --- | --- | --- | --- |
| 可见性状态矩阵 | Panoptes（PoPETs 2026） | 在 reads/flows 增加 `visibility_state`（foreground/background/screen-off/force-stop），按状态统计 | 低；P0/P1 |
| 启动 30 秒批量窗口 | arXiv 2409.15561 | 增加 `app_start` 时间基准与 30 秒批传统计，与现有缓存批传场景合并 | 低；P0 |
| 否定与例外处理 | PolicyLint（USENIX Security 2019） | 条款级映射加 negation/exception 标注，避免把“不会收集”判成“未披露” | 中；P1 |
| 政策条款评估口径 | WHYPER（USENIX Security 2013） | 用 precision/recall + 双人标注评估条款抽取，而不是只看关键词命中率 | 低；与 S1 共用 |
| 因果事件序列 | AppIntent（CCS 2013） | 在同意/撤回场景记录 UI 动作序列 + 外发时间，输出 causal chain | 中；P1 |
| PII 机器学习兜底 | ReCon（MobiSys 2016） | 值匹配失败的 flow 用轻量分类器打候选，不直接下结论 | 中高，需训练数据；P2 |
| 目的推断 | MobiPurpose（IMWUT 2018） | 从 URL/域名/参数名推断 purpose，补政策 purpose 维度 | 低；P1 |
| 长连接优先级 | WebSocket（WWW 2021） | 把 WebSocket 当常规协议而非特例；message ID + visibility + connection ID | 低；P0 |
| AAID + 无线扫描组合 | Your Signal, Their Data（PoPETs 2025） | 增加 AAID Hook，并记录与 WiFi/BLE 扫描结果的共现 | 中；P1 |
| Hook 成本结构 | Frida/Xposed（2026，SciTePress） | 先减 Hook 数与 JSON 传输，再谈优化 | 低；P0 |
| 官方 8 属性清单 | AAOS 25Q2 | 作为 API 36 适配的封闭清单，不做厂商属性枚举 | 低；P0 |

### 3.3 已被证明效果有限 / 不建议重复投入

| 方向 | 为什么有限 | 证据 | 本项目应怎么做 |
| --- | --- | --- | --- |
| 纯静态污点作为违规结论 | 反射/native/混淆是盲区；DroidBench 精度不能外推到真实 App | FlowDroid、IccTA、DroidSafe | 只做候选与覆盖差集，不写 `policy_violation` |
| 纯权限过度申请 | 91%/83% 衡量的是“申请超出”，不是“读取或外发” | GLOBECOM 2015 | 作为风险排序，不作结论 |
| 纯政策关键词/NLP | 三个权限 82.8% precision；否定/例外会反转语义 | WHYPER、PolicyLint | 条款级 + 否定 + 人工复核 |
| 纯流量字符串匹配 | TLS、派生值、二进制、长连接都会打断匹配 | ReCon | 值级 + 派生 + 正文 + ML 兜底 + 显式 `unparsed` |
| 全系统动态污点 | 需改 ROM/ART，不能注入任意第三方 APK | TaintDroid、TaintART | 保持 Frida 观察路线，不追求系统级污点 |
| 多用户特权提升 | 多数向量需要 shell/系统权限，普通第三方威胁面窄 | Tale of Four Gates | 只做 exported component + URI grant 矩阵 |
| 厂商 VHAL 属性枚举 | vendor properties 仅 system APIs；各 OEM 有 156–753 个自定义属性 | AOSP special properties、PRIDRIVE | 先做官方 8 个；OEM 必须授权镜像 |
| AdID 退出作为合规证明 | GPC 基本无效；禁用 AdID 后仍有 App opted_in | CCPA 2024 | 记录实际请求/响应与 SDK 行为，不看设置 |
| 大规模 tracker 名单匹配 | 域名归类是先验，不是值级证据 | Exodus、TrackerControl | 只作域名先验与报告分类 |

### 3.4 项目相对位置（能力矩阵）

| 维度 | 公开工作代表 | 本项目 | 差距 |
| --- | --- | --- | --- |
| 数据流检测 | TaintDroid、FlowDroid、TaintART | 运行时 Hook + 值级匹配 | 工程可用性更强，形式化保证更弱 |
| 权限映射 | PScout | 覆盖链 | 可追溯性更强，但属性→权限未闭环 |
| 政策一致性 | MAPS、PolicyLint、WHYPER | 政策快照 + AI 复核 | 有政策，缺条款级映射 |
| 流量归因 | ReCon、MobiPurpose、AppIntent | 值级 + 派生值 + 正文 + 30 秒 + WS 消息 ID | 长连接配对有工程优势，缺协议覆盖与目的推断 |
| 多用户 | MoST、Tale of Four Gates | 场景测试 | 有场景，缺跨 profile 组件矩阵与残留 hash |
| 车载 | SAE 2020/2023、arXiv 2024、PRIDRIVE | 8 个 VHAL 属性 + 证据分级 | 普通第三方 + 证据分级更细，缺 OEM 镜像与规模 |
| 评估 | MAPS、3PDroid | labels schema + `not_measured` | 诚实，但缺数字与置信区间 |
| 后台/不可见 | Panoptes | 五类场景，但无 visibility 矩阵 | 缺 visibility state 与后台流量统计 |

## 4. 优化方向

以下每条都按“做什么 / 验收标准 / 补哪个短板 / 依据”写。验收标准尽量用可计算的数字，避免“加强”“完善”这类无法验收的表述。

### 4.1 短期可落地（不需要新设备或新数据）

#### S1 建立 10–20 个独立 App 的标注 mini-benchmark（P0）

- **做什么**：复用 `vehicle/bench` 的 `--labels` schema；每个样本产出 `expected_pairs`（`[rule_id, read_event_id, flow_event_id]`）；2 名 reviewer 独立标注 + 1 次仲裁；`origin` 区分 `independent_review` / `owned_fixture` / `agent_review`；`human_signoff` 从 `pending` 改为实名签核。样本来源：`apk/vehicle/` 自有样本 + F-Droid-60 中可在 AAOS 安装的普通 App；VHAL 参考配对主要来自自有夹具，必须标 `origin=owned_fixture`，不能冒充独立样本。
- **验收标准**：≥10 个独立 App、≥100 对参考配对；Cohen's κ ≥0.80；输出 precision/recall + 95% CI（Wilson）；`accuracy` 从 `not_measured` 变为带 n、CI、label set hash 的实测值；独立样本与夹具样本分开报告，不合并；负控（不同值/未读取）false positive ≤10%。
- **补短板**：无独立人工标注、`accuracy=not_measured`。
- **依据**：`vehicle/bench/README.md` 已有 schema；WHYPER/MAPS 的评估口径。

#### S2 用批次令牌/因果配对替代“一律扩窗”（P0）

- **做什么**：在缓存、断网恢复、批传场景给读取批次和上传请求加可核验的 `sourceBatchToken`（复用 `WINDOW_CALIBRATION.md` 002/004 轮的离线动作回执令牌做法）；配对优先用令牌，其次用 30 秒窗口；60/120 秒只用于令牌可对齐的实验复核。
- **验收标准**：同夹具同动作下，30 秒 + 令牌的参考配对命中 28/28、漏 0；额外候选不超过当前 30 秒的 14；每条配对记录 `origin_proven=true/false` 与 token 证据；常规 30 秒基线不改变。
- **补短板**：30 秒漏配（夹具 14/28）、缓存批传归因。
- **依据**：`vehicle/bench/WINDOW_CALIBRATION.md`（2026-11-03）；`vehicle/privacy/ha_socket_evidence.py` 的同连接 ID 思路。

#### S3 协议适配层与显式 `unparsed`（P0）

- **做什么**：覆盖 JSON、form、multipart、URL-encoded、protobuf、msgpack、WebSocket binary；解析失败写 `unparsed` + payload hash + content-type + 截断长度；禁止静默丢弃。
- **验收标准**：20 个 App / 50 条 flow；≥80% 被分类（parsed 或显式 `unparsed`），静默丢弃 0；对已知值注入的负控 false positive ≤10%；每条 flow 有 `parser` 与 `parse_status`。
- **补短板**：非 JSON/表单/二进制协议适应有限。
- **依据**：ReCon 的流量 PII 检测边界；项目边界“未解析协议无明文能力”。

#### S4 Hook 开销预算与优化（P0）

- **做什么**：事件批处理（NDJSON/二进制）、异步落盘、合并高频 VHAL 订阅、按需启用 Hook 集；用 `vehicle.ps1 overhead` 同夹具同 workload 复测。
- **验收标准**：`--pairs 4 --actions 12` 的中位 CPU 增量从 845 ms 降到 ≤400 ms（≥50%），事件数不丢（276 条 `VHAL_READ` + 12 条外发）；`--pairs 6 --actions 4` 仍为 0 ms 量级；报告同时给中位数、P95、事件数。
- **补短板**：845 ms 开销。
- **依据**：Frida/Xposed 2026 的成本结构（Hook 数 + 序列化/传输）。

#### S5 官方可访问数据面补齐：AAOS 25Q2 8 属性 + AAID（P0/P1）

- **做什么**：按 AAOS 25Q2 的 8 个 third-party-accessible properties 补 `required_permissions`、`read_apis`、正反例、拒绝/空值用例；只对有官方来源的项把 `definition_status` 改为 `defined_by_official_source`；为每个属性写 API 36 验收用例，API 35 设备上标 `not_applicable_api_level`；AAID 增加 `AdvertisingIdClient` Hook，四态区分，不与 Android ID 混同；无 GMS 标 `unavailable`。
- **验收标准**：8/8 有 official `source_refs`、8/8 有可执行用例；API 35 报告显式 `not_applicable`，不复用 15 的结论；AAID 在 API 35 GMS 镜像四状态齐全；`coverage.json` 不再有官方属性行 `source_refs: []`。
- **补短板**：属性→权限未闭环、广告标识未覆盖。
- **依据**：AAOS 25Q2 release notes；AOSP special properties；`coverage.json` 现状。

#### S6 政策条款级映射（P1）

- **做什么**：把政策拆成 `(data_type, purpose, sharing, retention)` 四元组；每条观测 read/flow 映射到条款；输出 `disclosed` / `not_disclosed` / `unclear` + 条款原文 + 政策快照 hash；否定/例外单独标注。
- **验收标准**：30 个 App / 100 条条款；2 名 reviewer；`not_disclosed` precision ≥0.80；每条结论可回溯到条款 span 与 hash；协议（`AGR-*`）不得判 `met`（沿用 M040 约束）。
- **补短板**：政策与行为一致性。
- **依据**：PolicyLint 的否定/本体；WHYPER 的 P/R 口径；MAPS 的 “potential” 措辞。

#### S7 后台/不可见状态 + 长连接（P1）

- **做什么**：记录 `visibility_state`（foreground/background/screen-off/force-stop）+ `connection_id` + WebSocket `message_id`；home/recents/screen-off/force-stop 各 5 分钟；统计后台 flow。
- **验收标准**：10 个 App；≥3 个出现后台 flow；每条后台 flow 带 visibility state + connection ID + message ID（若是 WS）；前台与后台分开报告；不把后台连接直接判违规。
- **补短板**：长连接/后台场景。
- **依据**：Panoptes 的 84.5%/57.7%；WWW 2021 的 WebSocket 生态。

#### S8 多用户 exported component 矩阵（P1）

- **做什么**：2 个 profiles × 3 类组件（Activity/Service/ContentProvider）+ URI grant；每格记录 expected deny/allow 与 observed；profile 切换后记录缓存/DB 文件 hash 与 mtime；区分普通第三方与需 shell/特权的向量。
- **验收标准**：2×3 矩阵每格有结论；≥1 个 expected deny 实际 deny；≥1 个 URI grant 用例；切换后残留文件/DB 有 hash 对比；无法执行的格标 `not_executed`，而不是默认安全。
- **补短板**：多用户残留。
- **依据**：Tale of Four Gates（组件向量）；MoST（多用户隔离）。

### 4.2 中期需要设备或数据

#### M1 API 33/36 设备验收（P1）

- **做什么**：API 33/36 各准备一台官方镜像（API 33 需可获取的 AAOS 镜像；API 36 若官方无 x86_64 车载镜像，记录“不可得”而不是跳过）；每版跑四类通用来源 + 8 个官方属性（若该版支持）+ 拒绝/空值/错误键；记录 device fingerprint。
- **验收标准**：每 API 有 fingerprint、镜像版本、权限授予、逐项结果；API 33/36 的规则不得复用 15 的结论；无镜像的版本在 `COMPATIBILITY.md` 标 `blocked_no_image` 并给证据链接。
- **补短板**：API 33/36 无设备验收。
- **依据**：`vehicle/COMPATIBILITY.md` 现状。

#### M2 100–300 App 规模测量（P1）

- **做什么**：F-Droid + AndroZoo（需申请）+ 自有样本；静态 3 并行、动态单设备串行；5 场景；per-app status（completed/failed/skipped + reason）。
- **验收标准**：≥95% completion；失败样本保留日志与 stage；输出每场景分布、失败分类、每 App 的 read/flow/attribution 计数；不把失败样本算作阴性。
- **补短板**：真实第三方样本少。
- **依据**：MAPS/3PDroid 的规模口径；项目 batch 入口。

#### M3 二进制/长连接协议（P1）

- **做什么**：20 个 App 的 protobuf/gRPC/WebSocket binary；用字段长度/类型/重复模式做启发式恢复；未知字段标 `unknown_field`；与值级匹配联动。
- **验收标准**：≥60% 消息至少恢复 1 个字段；负控 false positive <10%；每 App 有协议类型与恢复率；无法恢复的标 `unparsed_binary` 并给 hash。
- **补短板**：二进制协议。
- **依据**：项目边界；ReCon 的 ML 兜底。

#### M4 OEM 镜像厂商属性（P2）

- **做什么**：1–2 个授权 OEM 镜像；静态枚举 `VehiclePropertyIds` / VHAL config；动态 probe 每个属性的 access outcome；记录 permission source；不生成常量。
- **验收标准**：属性列表 + access outcome + permission source 三列齐全；普通第三方不可访问的标 `restricted`；无设备证据的项不进入规则库；与 PriDrive 的 156–753 量级对照。
- **补短板**：厂商私有属性未覆盖。
- **依据**：AOSP special properties；PRIDRIVE。

#### M5 标注流水线与仲裁（P1）

- **做什么**：2–3 名 reviewer、adjudication、label store with provenance（reviewer、时间、参考证据路径 + SHA-256）；`human_signoff` 完整；版本化 label set。
- **验收标准**：200 对参考配对；κ ≥0.80；每条 label 有 provenance；label set hash 进入报告；争议项有仲裁记录。
- **补短板**：labels/accuracy 的可持续性。
- **依据**：`vehicle/bench/README.md` 的 schema。

### 4.3 长期需要合作或标注资源

#### L1 公开 AAOS 隐私 benchmark（P2）

- **做什么**：50+ App、5 场景、ground truth、版本化、可复现、leaderboard；发布样本哈希与标注协议；需要 OEM/监管/学术合作。
- **验收标准**：第三方可复现 ≥80% 的样本；榜单含 precision/recall/开销；数据授权与隐私合规审查通过。
- **补短板**：对外可比性；公开工作空白。
- **依据**：SAE 2023、arXiv 2024、PRIDRIVE 的样本规模与局限。

#### L2 12 个月纵向漂移（P2）

- **做什么**：100 App × 4 季度，政策/行为/SDK 变化；固定样本哈希与场景脚本。
- **验收标准**：≥80% 样本四季度可追踪；输出政策变更、SDK 变更、外发行为变更三类事件；每类有置信区间。
- **补短板**：单时点测量；政策一致性。
- **依据**：Child-directed（PoPETs 2025）的平台政策效果；CCPA 2024 的退出权。

#### L3 法律条款映射（P2）

- **做什么**：GDPR/CCPA/PIPL 条款 → 控制项矩阵；律师参与；输出 `disclosed/not_disclosed/unclear` 与法律依据，不自动产出违规结论。
- **验收标准**：每条款有法律原文 + 解释 + 对应观测项；专家复核 ≥2 人；不出现 `policy_violation` 自动判定。
- **补短板**：合规语义；政策一致性。
- **依据**：项目“不输出 policy_violation”原则；MAPS 的 potential 措辞。

#### L4 AAOS vs 移动端跨平台对比（P2）

- **做什么**：同一 App 在 AAOS 与手机上的权限/读取/外发差异；device farm；控制变量（版本、网络、账号）。
- **验收标准**：≥20 个跨平台 App；每 App 有平台差异表；差异可归因到权限模型/API/政策；不把平台差异误判为 App 违规。
- **补短板**：跨平台解释力；样本少。
- **依据**：Future Internet 2021 的车企 App 多层分析；AAOS 与 Android Auto 的区别。

#### L5 硬件辅助 provenance（P3）

- **做什么**：TEE/硬件计数器/系统级 provenance 的可行性研究；与高校/芯片厂合作。
- **验收标准**：只在论文/原型层面；不进入生产链路；明确不替代现有证据分级。
- **补短板**：因果证明的强度。
- **依据**：TaintDroid/TaintART 的系统改造代价；项目“观察不改写”原则。

### 4.4 优先级建议

| 优先级 | 项目 | 理由 | 依赖 |
| --- | --- | --- | --- |
| P0 | S1、S2、S3、S4、S5（离线部分） | 先建立“可测量”，再谈覆盖；S2 直接修复 30 秒漏配 | 无需新设备 |
| P1 | S5（设备部分）、S6、S7、S8、M1、M2、M5 | 补齐合规语义与版本矩阵；M2 需要 S1 的标注口径 | API 36 镜像、GMS 镜像、样本 |
| P2 | M3、M4、L1–L4 | 依赖授权镜像、规模样本、法律/学术合作 | OEM/数据集/律师 |
| P3 | L5 | 研究性质，非当前必需 | 高校/芯片厂 |

## 5. 结论：给负责人的 5 条决策建议

1. **先买“数字”，再买“覆盖”**：S1 的 10–20 个独立 App、100 对标注、κ≥0.80 是当前最高杠杆；没有它，任何新增规则都无法证明有效。
2. **窗口不要一律调大，改用批次令牌**：30 秒在夹具上漏 14/28，60 秒补齐但额外候选 28；令牌配对能把“漏配”和“误配”分开，这是比调参更根本的修复。
3. **下一版覆盖链只承诺官方可访问面**：AAOS 25Q2 的 8 个属性 + AAID；厂商私有属性必须等授权镜像，且不得生成常量。
4. **把 `unparsed` 当一等公民**：规模测量中，静默丢弃的流量会让 precision 虚高；显式 `unparsed` + hash 是可比性的前提。
5. **对外定位**：普通第三方 AAOS App + 证据分级 + 可复现 benchmark；不要在 OEM 厂商属性枚举上与 PriDrive 竞争，那里需要镜像和 root，且普通第三方大多不可访问。

## 6. 来源与核实说明

### 6.1 核实方法

- 论文：以会议/期刊官方页、USENIX/NDSS/ACM DOI、arXiv abs 为准；数字只取摘要或正文明确给出的。
- 开源项目：GitHub API 与 Atom feed 交叉；API 可能返回缓存，以 Atom feed 最新提交为准；stars/提交日期是 2026-11-03 的快照。
- 项目能力：以仓库文件为准（`vehicle/coverage/generated/coverage.json`、`vehicle/COMPATIBILITY.md`、`vehicle/bench/README.md`、`vehicle/bench/WINDOW_CALIBRATION.md`），不用任务描述替代实测口径。

### 6.2 未核实 / 未采用

- Frida/Xposed 2026 的会议名未核实（只有 SciTePress PDF）。
- MOSES 的 IEEE TDSC 卷期未核实。
- CCPA 论文的 PoPETs 卷期未核实（arXiv 2024）。
- Exodus 代码仓库最近提交未核实；FlowDroid、Caring Caribou 的维护状态未核实（Atom feed 404）。
- PRIDRIVE 是否有完整同行评审论文未核实；本文只按 VehicleSec 2024 poster + DOI 引用。
- 近 5 年“Android 多用户数据残留”的系统测量：本次未检索到直接对应工作；不把取证/安全删除方向硬套。
- 开源项目的 stars/提交日期之后可能变化，引用时请重新核对。

### 6.3 文档漂移

- `AGENTS.md` 的“仍未被做”清单里写 `WINDOW_CALIBRATION.md` 不存在，但 `vehicle/bench/WINDOW_CALIBRATION.md` 已于 2026-11-03 存在，并有 002/004 轮证据；建议同步更新，避免后续排期重复投入。
- `AGENTS.md` 还写 API 33/34/36 的验收状态为“未做/待适配”，与 `vehicle/COMPATIBILITY.md` 的 API 34 通用来源已通过不一致；以 `COMPATIBILITY.md` 的核实日期与证据路径为准。

### 6.4 复现入口

```powershell
. ./environment.ps1

# 窗口校准（002 轮冻结夹具源码，可重放）
& $VScanPython -m vehicle.bench.window_calibration `
  --capture output/vehicle-offline-window-20261103-002/capture `
  --labels output/vehicle-offline-window-20261103-002/labels.json `
  --out output/window-replay.json

# Hook 开销配对实验
./vehicle.ps1 overhead --pairs 4 --actions 12
```

- 覆盖链：`vehicle/coverage/generated/COVERAGE.md`
- 版本状态：`vehicle/COMPATIBILITY.md`
- 评估 schema：`vehicle/bench/README.md`
- 窗口初评：`vehicle/bench/WINDOW_CALIBRATION.md`
