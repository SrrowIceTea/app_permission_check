# 论文调研与 V-Scanner 改进决策

检索日期：2026-11-10。以下是针对当前五类缺口的定向调研，并非系统性文献综述。只使用论文原文、作者/机构论文库和作者项目页；网页抓取日期不当作论文发表日期。
各文献的技术结论与“建议本项目怎样实现”分开；后者属于本方案的工程推断，须通过实验验证。当前排期以[一周方案](ONE_WEEK_DEVELOPMENT_PLAN_20261110.md)为准。下文保留方法选型分析，包含超出本周范围的研究，不是本周必做清单。

## 1. ReCon：内容识别能扩展，但不证明 App 内部来源

Jingjing Ren 等，**ReCon: Revealing and Controlling PII Leaks in Mobile Network Traffic**，MobiSys 2016。
来源：[作者项目论文 PDF](https://recon.meddle.mobi/papers/recon-mobisys2016.pdf)，DOI：10.1145/2906388.2906392。
论文以网络侧可见内容识别 PII，并用有参考真值的受控实验评估；它也讨论加密流量可见性和混淆的限制。
对应项目：目前完整 JSON 字符串叶子限制过窄，位置数字、表单、不同序列化会漏检；可借鉴网络内容识别路线扩展载荷解析，而非逐 App 写专用求值器。
可借鉴的方法：陶俊哲 做有限解析器和规范化，毛宇淇 保留“正文出现敏感值”和“来自哪个读取”的等级区别；杨琰 用按 App 隔离的测试评价泛化。
暂不纳入的方法：从少量现有样本训练一个“通用泄露分类器”；项目缺训练数据，也不能把关键词预测变成来源证明。论文的阻断/改写能力不纳入本项目观察阶段。
验证：同输入对比 JSON-string-only 与新增数字/表单解析；并列新增真阳性、碰撞、误报和正文不可见比例。

## 2. ThirdEye：HTTPS 明文不等于应用层明文

Sajjad Pourali、Nayanamana Samarasinghe、Mohammad Mannan，**Hidden in Plain Sight: Exploring Encrypted Channels in Android apps**，ACM CCS 2022。
来源：[作者论文 PDF](https://users.encs.concordia.ca/~mmannan/publications/ThirdEye-CCS2022.pdf)，[作者 arXiv 记录](https://arxiv.org/abs/2209.15107)，DOI：10.1145/3548606.3560665。
论文通过动态插桩、网络采集及加密相关观测研究 HTTP/S 之外与自定义加密通道；其实现采用 Frida、tcpdump、mitmproxy，并配套输入驱动。
对应项目：已有 TLS/Cipher/native 模块不应只检查“文件存在/ARMED”，还要证明真实数据从调用事件进入统一证据；TLS 解密后的正文仍可能是应用层密文。
可借鉴的方法：么贵行 复用现有采集链，记录方向、完整性、请求边界和变换前后关系；陶俊哲 只对有明确证据的有限派生匹配进行候选关联。
暂不纳入的方法：复制论文的大规模设备农场；宣称任意加密、自定义协议或无符号 native 都能解开；把 Cipher 输入等同于已上传。
验证：受控自有夹具中使用明文、派生、分块、截断和无法解析载荷；在新采真实 App 上逐层检查可见性，不混同“看到解密调用”与“看到完整上传内容”。

## 3. Haystack：端侧上下文是另一条观测路线

Abbas Razaghpanah 等，**Haystack: A Multi-Purpose Mobile Vantage Point in User Space**，技术报告，2015 首稿、2016 修订。
来源：[作者 arXiv 记录](https://arxiv.org/abs/1510.01419)。注意它是技术报告，不写成已确认的 IMC 会议论文。
论文提出基于 Android VPN API 的端侧观测，结合流量与本地上下文，减少仅在远端代理观察的局限。
对应项目：代理侧 NAT 信息损失不能靠扩大时间窗口弥补。应优先利用已经有身份的 App 进程内观测，或日后评估端侧可验证上下文。
可借鉴的方法：么贵行 先复用 D419 native write 和多进程链；真机对照在资源允许时验证具体假设。该选择是结合项目成本的推断，并非论文保证。
暂不纳入的方法：从零开发 VPNService/TUN 转发栈；VPN API 也不自动赋予现代 Android 任意流量的确定归属，更不会自动解密 TLS。
验证：在白名单、重复正文、多包并发与短连接下分别统计身份已核验/候选/未知；无端侧身份时保持 unknown，不以单 App 运行推断所有流量归它。

## 4. FlowDroid / DroidBench：静态提示与最小基准值得借鉴

Steven Arzt 等，**FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps**，PLDI 2014。
来源：[合著者提供的论文 PDF](https://jacquesklein2302.github.io/papers/2014-PLDI-flowdroid.pdf)，DOI：10.1145/2594291.2594299。
论文重视生命周期/回调建模、上下文及字段等敏感性，并提出 DroidBench 微基准；原文也讨论反射、native 方法和多线程等局限。
对应项目：通用定位不能只 Hook 缓存读取而忽略回调交付；静态发现 source/sink 可辅助挑选触发动作，不能等于动态已经发生。
可借鉴的方法：陶俊哲/杨琰 为位置回调、延迟、多来源、拒绝等路径建立小型正负基准；已有静态引用继续用来提示触达缺口。
暂不纳入的方法：重建全量静态污点分析；把 FlowDroid 的静态路径灌入运行时 code_locs；将旧论文的基准成绩当作现代 AAOS 的保证。
验证：比较“注册过”“收到非空返回/回调”“内容匹配”“来源候选”四层证据是否被清晰分开。

## 5. DroidBot：可重放动作与触达证据先于复杂自动探索

Yuanchun Li 等，**DroidBot: a lightweight UI-guided test input generator for Android**，ICSE Companion 2017。
来源：[作者项目页](https://honeynet.github.io/droidbot/)，[作者维护仓库及论文条目](https://github.com/honeynet/droidbot)。
项目支持 UI 状态驱动、脚本化输入和 UI 转移图；这些是测试输入生成与触达记录的手段，不能直接证明敏感 API 路径全覆盖。
对应项目：没有后端、登录、USB 或权限前提时，动态采集零输出可能只是没触达；盲目扩大规则和窗口不会补出业务行为。
可借鉴的方法：杨琰 先维护明确的工作流前提、关键步骤完成标志、动作时间线与截图；么贵行 关联同一会话和原始事件。
暂不纳入的方法：要求新手本周内接好通用自动探索器；默认该旧工具无需适配就能在 AAOS 多显示器、驾驶限制和 Python 3.13 环境稳定运行。
验证：同一 APK 固定事件数/时长预算，比较脚本前后关键动作触达、敏感来源观测和采集完成率；点击数、Activity 数不叫代码覆盖率。

## 6. 后续组合路线与实验问题

后续完整路线：确认新版本采集→统一证据语义→通用解析/定位→固定场景触达→留出集验证。本周仅修已有结果口径、重采有限真实工作流、验证现有坐标摘要支持的有限匹配；数字/表单解析、留出评估和 UI 扩展不列为本周目标。

| 研究问题 | 实验控制 | 主要观察量 | 结论边界 |
|---|---|---|---|
| 新采集是否增加可见性？ | 同 APK/设备/脚本；旧 bundle 可得才做前后对照 | 已就绪 API、有效值、完整正文、进程覆盖 | 无旧 bundle 只报当前能力，不能做增益归因 |
| 通用定位能否替代 App 特例？ | 固定通用字段，不读取 App 名；开发/留出 App 隔离 | TP/FP/FN、unknown、来源候选数 | 用过的 OwnTracks 不再是未知 App 泛化证据 |
| 窗口放大是在补漏还是增加混淆？ | 同一冻结输入，30/120 秒等开发集设置 | 匹配召回、歧义率、平均候选数 | 来源不唯一时不宣称因果更准确 |
| 场景驱动能否减少空采集？ | 同输入预算、相同前提，记录动作结果 | 触达率、取得值、完整采集率 | UI 触达不等于全部代码覆盖 |
| 保守门禁是否只是全弃判？ | 分别呈现精度、端到端召回、可判覆盖 | FP/(TP+FP)、正例未检出、unknown 比例 | 0 错误断言同时 0 覆盖不算有效改进 |

论文支持方法选择，不替代本项目实验。尤其“传输了个人信息”与“违反政策/法律”是不同命题；本轮只交付可追溯事实、证据等级和复核线索，不形成自动法律判决。
