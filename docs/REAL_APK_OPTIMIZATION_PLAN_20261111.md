# 商用与数据集APK检测能力：现状评估及整体优化方案

> **历史快照（2026-11-11 归档，不作当前清单）**：现在什么状态、本周做什么见 [CURRENT_STATUS.md](CURRENT_STATUS.md)。

> 范围更正（2026-11-11）：用户明确移动端暂不开发。本文包含移动端内容，保留为历史调研，
> 不作为当前开发清单；当前执行范围见[仅车载优化方案](VEHICLE_ONLY_OPTIMIZATION_PLAN_20261111.md)。

日期：2026-11-11；评估代码main=`0cc32a96268d117cbd7da33c65a4b82cb64f05f0`。
仅用于授权测试（自有设备与已获授权APK）。本文提出开发与验证计划，不代表新设备实验已经完成。
本轮只阅读代码/记录、查询原始论文与官方项目、运行27项新增模块相关单测和合成代码反例。
未运行商用APK整批、未安装工具、未改采集器；本机未找到runbook指定的F-Droid-60目录，不将其记成0个样本或失败批次。

## 1. 结论与范围

当前是具备静态、动态、流量、政策、AI和证据展示的审计原型；尚无充分证据证明可稳定批量检测商用闭源APK。
主要问题从“缺模块”转为“已有模块能否在当前入口、真实工作流、当前APK版本上形成可核验的完整链”。
提高报告数量、扩大规则数、降低身份门槛和把业务证据转为违规，都不是提高真实检测率。
建议主线：批次身份与健康 → 场景触达 → 进程/连接归因 → 正文与通用关联 → SDK/政策解释。
以下优先级、预算和验收门槛是工程建议，不是论文已证明本项目会获得的收益。

## 2. 更新后已经具备的能力

| 当前能力 | 核实位置 | 仍需区分的边界 |
|---|---|---|
| SDK调用链候选归属、PDF文字 | core/evidence/sdk_{registry,attribution}.py、codeloc.py；mobile/report/code_loc_text.py | 前缀匹配不是库指纹；在链上不等于该SDK采集/上传 |
| 车载证据状态展示与引用校验 | vehicle/webapp/test_ui_evidence.py、vehicle/frontend/app.js | 展示正确不证明本轮设备采集充分 |
| 有限定位匹配与冻结交接验收 | vehicle/privacy/location_{match,handoff,acceptance}.py | 仍为experimental_only，五种整对字符串；默认无VSC-GE-location |
| 通用采集/明文与派生值 | core/frida_host、mobile/hooks、core/collector/derive.py | TLS/QUIC/加密格式及启动时点有适用范围 |
| 移动UI启发式、分段恢复 | thirdparty_ui_flow.py、device_run_thirdparty_run3.py | 已有UI状态和存活账本，尚非真实功能覆盖率 |
| 非root夹具＋VPN对照、授权衍生包制备 | mobile/lab/README.phone.md、mobile/repack/README.md | 不是“没有真机/VPN”；夹具通过不等于任意原始商用包可测 |
| 静态并行/动态串行、政策/AI/风险评分 | mobile/tools/batch_*、mobile/policy、mobile/ai、mobile/analyze | 不应重写已有前端、评分或重复实现采集器 |

本轮定向验证core.evidence.test_sdk_attribution、vehicle.webapp.test_ui_evidence、mobile.report.test_code_loc_text：27项通过。
记录在output/optimization-assessment-20261111/recent-modules.log；这是离线模块证据，不是商用检测率。
docs/REAL_APK_ASSESSMENT_20261110.md中的历史案例与本轮代码日期不同，不能直接作为新版本性能结论。
其中“模拟器上一切归因无解”“统一变finding即可提高检出”等表述不应沿用：需区分观测位置和证据等级。

## 3. 已确认的具体开发缺口

| 优先级 | 缺陷/风险及代码依据 | 应开发的内容 | 首个验收 |
|---|---|---|---|
| P0 | batch_static.py:71/80仅认完成文件、按package复用；batch_plan.py:27的resume无新输入身份参数 | 分层缓存键、输入摘要匹配、旧产物显式stale | 同包换APK、规则/工具变化绝不复用错误结果 |
| P0 | 移动start_hook未传--multi-process或--user，而core/run.py默认单进程 | 贯通设备/user/多进程参数；先修下游引用再启用 | :remote产生真实读取，结果可关联且不串用户 |
| P0 | device_run_thirdparty_run1.py:74–86主动DROP UDP/443 | 观察入口移除主动阻断，保存QUIC密文和覆盖缺口 | 主流程没有DROP规则、结束不影响原网络 |
| P0 | 移动_pair_refs/refs_of主要保留src/evt_id，未带PID | 消费带PID的现有事件引用；补进程生命周期身份 | 两PID同号、同PID重启不混并、不制造唯一性 |
| P1 | core/device_target.py:resolve_pids与multi_attach是启动时快照 | 只观察的持续进程发现、重启/晚加载账本 | 附加失败与未附加区间可诊断，时间缺口入报告 |
| P1 | start前行为、连接复用和短连接可能不在Hook/轮询覆盖内 | 冷启动时序账本、设备侧连接观测＋严格交叉核验 | 自有短/长/并发/复用连接分别有归因分母 |
| P1 | UI为文案候选、滚动/BACK启发式；登录/后端/数据前提可能不足 | 脚本＋状态图＋有限语义引导，独立业务成功断言 | 同预算增加有效功能触达，非只增加点击 |
| P1 | 车载通用外发主要覆盖android_id/contacts；定位独立实验、专用业务仍多 | 类型化通用source/sink适配和有限正文解析 | 新增App不必新增整套专用求值器 |
| P1 | SDK前缀不能识别R8重命名；非宿主前缀类可能仍为宿主业务代码 | 未知来源语义修正、可选库指纹侧车、置信度 | 重命名宿主不被断言为第三方SDK |
| P2 | 政策关键词与真实主体/目的/条件关系不同 | 中文结构化条款与逐句依据核验 | 否定/例外/主体/第三方条款有人类参考 |
| P2 | 单设备代理/pcap/前台等全局状态，多个入口契约不同 | 每设备队列、资源隔离、统一产物索引/能力声明 | 多设备可并行，同一设备保持串行不串包 |

前两项缓存门禁和SDK语义的合成反例已运行：旧完成标记会被接纳，重命名宿主类落third_party_unknown。
详见output/optimization-assessment-20261111/counterexamples.json；不冒充实际旧APK串批事件。
UDP阻断改变被测行为，与项目“观察不改写、仅TLS绕过例外”的现行约束冲突，应优先修正。
不以“提高抓包量”为由默认强制协议回退，也不新增无授权的反加固/完整性绕过。

## 4. 一个容易重复开发的分支问题

origin/ch=`3433081`已被fetch，但不是当前main的祖先；其中已有mobile/tools/fastbot_engine.py、
build_fastbot_compat.py、mobile/lab/llm_explore.py及测试。当前main没有这些相同路径。
因此不是“项目从未开发过Fastbot/LLM探索”，而是“旧分支能力尚未完成当前主线集成与设备验收”。
先做选择性移植/接口对照，保留当前主线较新的身份、同意、失败和证据门禁；不整条盲合旧移动分支。
重点核对本轮27项SDK/展示定向单测之外的启动、重启、人工接管、预算和事件输出兼容性。

## 5. 面向两类APK的测试路径

| 样本层 | 目的 | 合理运行环境/前提 | 不能声称 |
|---|---|---|---|
| 自有夹具 | 精确控制source、转换、sink、失败和阴性 | 有源码，可受控插桩；收件/文件事实做独立参考 | 夹具通过=商用有效 |
| DroidBench/Ghera选定案例 | 检测原语、生命周期/回调/ICC等 | 固定提交、规则与适用API；先检可运行性 | 静态路径真值=本轮动态已执行 |
| F-Droid-60 | 自然业务覆盖、稳定性、迁移能力 | 手机Android环境为主；需数据/服务/权限/位置前提 | 开源APK都是隐私阴性；在AAOS起不来=引擎漏检 |
| 授权商业APK | 实际业务、SDK、多协议和成本 | ARM64真机或匹配ABI；原包证书、split全集、账号/服务前提 | 无法解密=没有外发；测试衍生包=原包等价 |
| AAOS App | 车载通用隐私和VHAL | AAOS/user10，实际权限与车辆数据；13/16分别验收 | 手机测试可替代车载；四版本登记=四版本实测 |

Ghera的Benign是作者的含漏洞目标命名，不能按字面当安全负例；Secure才是对应修复版，仍需逐案核验。
商用测试建立“官方原包→只重签名→Gadget衍生包”的三臂对照，现有repack已能制备，不再从零开发。
签名绑定/加固/服务端完整性受影响时，报告compatibility_blocked；不把该组拿来估算原包召回率。
split包先核验整套版本/证书/摘要/ABI；当前单APK入口不完整支持时明确unsupported，不能只测base冒充全包。

## 6. 第一阶段：可信基线与健康采集（P0，建议1周）

交付1：统一run-manifest，绑定产品线、原始/衍生包、split全集、版本/证书/ABI/API/user/设备boot身份、
commit、实际加载bundle、规则/catalog/政策/工具版本、脚本种子、网络和TLS开关、前置状态、健康/收尾。
静态缓存键至少含APK全集摘要＋规则/catalog＋扫描器版本/配置；动态复用另含采集器、场景与条件，不能按包名选择旧报告。
交付2：统一缺口枚举：安装/兼容阻塞、启动失败、Hook失败、进程盲区、触发未验证、身份未知、正文不可用、
格式不支持、无内容候选、歧义、策略证据不足；skipped/unavailable不得伪装成完整动态成功。
交付3：能力矩阵动态生成，每类API×设备×入口列挂载/实际调用/取得值/流量/可比正文/关联/规则状态。
交付4：移动入口贯通已存在多进程能力，引用至少为session/设备/user/UID/PID/进程启动身份/src/evt_id；
主线引用兼容旧产物，旧字段缺失时降级unknown；不重建全部事件库，不把旧引用迁移为新真值。
验收：缓存反例全拒；强制错误不会产出正常零观测；跨用户/进程/会话不串；默认无UDP阻断。

## 7. 第二阶段：驱动真实业务与增加有效观测（P1，建议1–2周）

先复用origin/ch的Fastbot/LLM适配；以现有UI脚本为底座，不把LLM变成每次点击的必经依赖。
任务拆为：前置条件→定位控件/页面→动作→页面变化→业务断言→敏感事件，保存截图/XML、时间和动作来源。
用脚本执行确定性流程，状态图避免循环，LLM仅处理停滞或语义选择；预算耗尽回退并记录。
WebView/Canvas等树缺失场景再加截图/OCR定位，动作必须有前后证据；人工接管登录/验证码状态单列。
权限矩阵与政策同意分开：未响应/拒绝/允许权限，政策未展示/已展示/接受等信号不能混同。
工具输入的VSCANPROBE、填表标记和注入夹具事件均保留来源，不能算自然业务的隐私读取。
固定业务脚本覆盖首启、核心功能、后台/恢复、拒绝权限；账号/文件/联系人/位置仅用授权测试资料。
进程观察采用只读轮询/通知，记录发现延迟、附加前区间、PID重用与未附加原因；不默认启用会挂起子进程的gating。
设备侧VPN已在自有夹具路径存在，优先扩成通用只读侧车：UID/user、连接键/时间、TCP/UDP、IPv4/v6；
与原egress/代理/pcap互证。隔离UID或短连接无法建立绑定时保留unknown，不用单白名单兜底。
验收：10个试点App同一总预算对比“当前启发式/固定脚本＋状态图/可选LLM”，每组3次记录触达与有效证据。
保留无Hook基线与Hook组，记录崩溃增量、CPU/耗时/实际Hook覆盖秒数，不以重启后的存活掩盖原运行死亡。

## 8. 第三阶段：扩大通用检测，而非不断增加专用App（P1，建议1–2周）

规范证据层：静态候选、真实取得、同内容关联、带上下文的转换关联、业务证据、规则结论分别输出。
统一观察记录/索引不等于把summary全部转成findings；业务成功、数据外发、违规是不同命题。
正文适配顺序：完整JSON字符串→数值经纬度对/表单→有明确schema的protobuf/gRPC；按实际缺口选择，不一次全做。
数值坐标需版本化source形态与同一对象/请求中的整对值，保留精度、坐标系、表示与摘要依据；
不能凭字段名、地理接近、单独纬度/经度或猜测坐标转换形成值级候选。新格式先实验、后规则依据与窗口标定。
网络重组保留HTTP/2 stream与连接复用、重试、分段和方向；SSL_write片段不是完整HTTP请求。
现有derive/native TLS/Cipher不是缺失模块；下一步是对已观测转换记录输入/输出摘要、算法、会话/进程/上下文关系，
先验证UTF-8→gzip→AES→HTTP的一种自有链；同线程/时间近或重复内容不自动证明唯一传播来源。
QUIC、无法解密、schema未知的数据保留元数据及覆盖缺口；不得把TLS可解密比例当全流量已解析比例。
通用数据类别按“样本确有调用→Hook有证据→有正负控”扩展；每个新类别带规则ID、来源、API适用性及观测失败原因。
静态source→sink侧车只对高价值缺口运行，设置时间/内存预算，partial/timeout不作为无风险；静态代码不写运行时行号。
验收：至少两类自然样本无需新专用求值器即可消费通用观察；必选跨UID/user/session、截断、异值、缓存重试负控不误升级。

## 9. 第四阶段：SDK、政策与产品功能（P2，建议1–2周）

SDK保持现有前缀候选，增加可选静态profile与版本候选；R8/重打包、多DEX、裁剪、未执行SDK分别验收。
非宿主包名前缀仅能作为来源未定的APK内代码，不默认断言第三方；报告区分“包含/调用链出现/有数据路径证据”。
把SDK/端点/数据类型/场景关联成待复核材料；RDAP、域名及注册组织不能单独证明实际接收者或控制关系。
政策抽取“主体、动作、数据、目的、接收方、条件、否定”，绑定APK/版本、正文快照、段落和字符范围。
先建50条左右中文正负参考（建议规模），覆盖否定、例外、共享、未成年、系统服务、SDK清单；协议不冒充政策。
LLM负责抽取/解释/场景建议，确定性核验原文与证据引用，不能制造动态事实或法律结论。
现有前端增加失败分层、复跑建议、运行对比、SDK来源置信度与模式标识；继续零构建，不重做前端框架。
支持按设备独立队列和断点续跑；隔离端口、代理、日志、pcap和输出路径后才多设备并行，单设备动态继续串行。
风险评分只用于复核排序；先用参考集校准、验证不同App排名稳定性，不当检测器真值或自动合规结论。

## 10. 论文/项目：借鉴什么、如何验证

| 参考原始来源 | 主要借鉴 | 本项目最小试验与限制 |
|---|---|---|
| [DroidBot，ICSE Companion 2017，论文](https://ylimit.github.io/static/files/DroidBot_ICSE2017.pdf)／[代码](https://github.com/honeynet/droidbot) | UI状态转移、可重复事件序列 | 为现有探索加状态图；无源码商用包不宣称代码覆盖率，AAOS需适配 |
| [Fastbot官方项目](https://github.com/bytedance/Fastbot_Android)／[Kea2](https://github.com/ecnusse/Kea2) | 模型探索与脚本/业务断言结合 | 优先复用ch实现，10App同预算对照；官方兼容说明不能当API35车载实测 |
| [DroidAgent论文](https://arxiv.org/abs/2311.08649) | 意图驱动的多步功能任务 | 用业务断言约束LLM；论文的activity coverage不是隐私召回率 |
| [LLMDroid，FSE 2025及官方代码](https://github.com/security-pride/LLMDroid) | 用LLM增强现有测试器，减少低效探索 | 闭源代码覆盖需其插桩条件；原包只测UI/观测覆盖，不伪造方法分母 |
| [GraphDroid，2026-09预印本](https://arxiv.org/abs/2609.10031) | 历史状态记忆、异步意图、轻重动作分工 | 仅借鉴设计；未确认可直接部署代码，不照搬作者收益百分比 |
| [PCAPdroid](https://github.com/emanuele-f/PCAPdroid)／[官方FAQ](https://emanuele-f.github.io/PCAPdroid/faq.html) | 设备侧VPN观测、连接应用元数据 | 在已有夹具侧车上验证短连接/双App负控；FAQ明确仍有unknown，不保证解密 |
| [LibScout，CCS 2016论文](https://group.cispa.io/bugiel/publication/derr-16-ccs/)／[代码](https://github.com/reddr/LibScout) | SDK profile识别、候选版本 | 需JAR/AAR/profile；作为sidecar，与当前运行时栈拼接，不整套强依赖 |
| [LibScan，USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-wu-yafei.pdf) | 更精确的库识别方法对照 | 先做已知依赖、R8/重打包参考集；本次未确认开箱可用代码 |
| [FlowDroid，PLDI 2014论文](https://jacquesklein2302.github.io/papers/2014-PLDI-flowdroid.pdf)／[代码](https://github.com/secure-software-engineering/FlowDroid) | 生命周期与回调感知的静态数据流 | 先2个APK有预算侧车；官方支持超时部分结果，不宣称native/反射/ICC完整覆盖 |
| [ThirdEye，CCS 2022论文](https://users.encs.concordia.ca/~mmannan/publications/ThirdEye-CCS2022.pdf)／[代码](https://github.com/Madiba-Research/ThirdEye) | 多层加密和非标准通道的观测/转换关系 | 复用现有Cipher/native采集；仓库已归档且声明非开箱即用，仅取方法 |
| [PoliGraph，USENIX Security 2023论文](https://www.usenix.org/system/files/usenixsecurity23-cui.pdf)／[项目](https://github.com/UCI-Networking-Group/PoliGraph) | 跨句政策关系与主体/数据层次 | 中文、车载/移动术语需本地参考，不能直接用英语模型替代人工依据 |
| [DroidBench](https://github.com/secure-software-engineering/DroidBench)／[ReproDroid论文](https://arxiv.org/abs/1804.02903) | 可复现的机制微基准、固定真值与可比评估 | 先选当前支持source/sink与API的子集；公开适用/排除表，不择优报全集成绩 |

以上链接于本轮查询；论文负责启发设计，项目负责可集成性验证，两者均不证明本项目已获得增益。
PCAPdroid权限边界见[Android getConnectionOwnerUid官方接口](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress))：
需当前用户活动VpnService等适当观察权限；不能由宿主Python直接调用解决所有UID归因。
采用前冻结实际commit/release、依赖与许可；只取最小组件。GraphDroid为预印本，不误称已同行评审。

## 11. 检测率与实验：固定分母，避免“全弃判也正确”

每批至少报告：样本总数、兼容/安装/启动/健康采集成功数、业务断言通过数、实际覆盖秒数、
来源取得数、连接身份可核验数、完整正文数、支持格式数、候选/唯一来源/歧义/规则/业务证据及每层缺口。
同一事件重复命中规则不当多个独立检出；正文片段/重试按明确观察ID去重，不只看findings_total。
健康率=N健康/N尝试；任务触达率=N业务断言通过/N计划任务；正文可用率=N完整可比正文/N观测出站请求。
无法识别请求边界的密文通道另报包/连接分母，不能混入“请求明文覆盖率”的已解析分母后消失。
机制检测Recall=TP/(TP+FN)，Precision=TP/(TP+FP)，仅在有独立参考且命题可评估的集合内给出。
同时给可评估比例、弃判与失败率；运营端另给“已检出的已知阳性案例/计划已知阳性案例”，未运行也保留在分母。
没有真值的商用批次只报已核验证据产出/可运行/触达/覆盖缺口，不给总体Recall或“合规通过率”。
按App和机制分层报告，置信区间按App聚类计算；不能把一个App的上千请求当上千独立样本。
开发/标定/测试按App家族、版本、SDK划分，避免同包多个版本或同一SDK同时泄漏到调参与最终评测。
独立参考优先用源码/动作/自有接收端事实与两人复核；模型共识只作辅助，不自动当专家金标准。

建议先做10App诊断集，再扩20–30个有授权商用App及F-Droid-60，均按ABI/框架/服务/加固/类别分层。
上述数量是计划规模，当前没有对这些商用App进行本轮测量；样本达不到时报告实际数。
每个新机制单独消融：当前基线→进程补全→探索→连接侧车→格式/转换→SDK/政策；保持同设备/前提/总预算，
至少3次重复、记录随机种子和网络失败。报告新增真阳性、负控误报、弃判变化、时间/内存/LLM成本。
强制发布门槛：关键跨身份/异值/截断/无健康负控不误升级，产物身份全绑定，失败保留，原始与衍生结果不混合。
不预承诺“检测率达到90%”或“提升30%”；根据首轮瓶颈占比决定下一个模块，不凭模块数量排期。

## 12. 团队实施边界与首批任务

若仍按此前五人配置，建议三位熟手各自一条主线，两个新人轻量支持，不共享修改核心文件：

| 人员 | 主责 | 独立交付边界 |
|---|---|---|
| 毛宇淇 | 采集可靠性、进程身份、主线集成 | core/frida_host与采集契约；接收其他人sidecar，不承担全部业务适配 |
| 陶俊哲 | 通用关联、表示/转换与连接互证 | core/collector派生与重组、mobile/vehicle关联；与毛宇淇固定接口对齐 |
| 么贵行 | 场景驱动、批次编排与兼容矩阵 | mobile/tools探索/批次；选择性移植ch，不并发改core身份逻辑 |
| 吕宇嫣 | 样本元数据/运行清单核对 | 少量版本、证书、ABI/前提登记和失败分类；不开发Hook/签核算法 |
| 杨琰 | 场景验收材料与报告检查 | 少量固定脚本复跑、截图/段落定位；不承担独立专家真值或规则判定 |

一位指定所有者维护rules/catalog/共享事件契约与回归清单；其他人只提兼容样例，避免同时改同一模块。
阶段可重叠但按证据闸门晋级；建议总工期约4–7个工作周，需按首轮App兼容与账号/后端实际情况重估。
这不是把旧一周任务延长或要求周末加班；若仅有一周，限定P0＋10App诊断，不承诺完成全部商用能力。

首批按顺序开六个工单：缓存身份→无阻断观察模式→移动多进程及PID引用→选移ch探索→新版本诊断批次→通用定位格式试点。
SDK指纹、FlowDroid、转换图、政策图均以侧车小试推进，不在P0同时全量引入。
下一次讨论排期时用实际漏斗定位“最先损失样本/证据”的层，并将这层的损失减少作为迭代验收目标。
