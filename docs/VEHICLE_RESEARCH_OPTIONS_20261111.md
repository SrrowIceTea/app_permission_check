# 车载端后续优化：问题、已有研究与最小验证

核对日期：2026-11-11。代码基线 HEAD `7fb35c0`。
仅用于授权测试（自有设备及授权APK）。本次为源码阅读与外部原始资料检索，未安装第三方工具、未改业务代码、未运行新设备实验。
下文是当前三人一周计划之后的候选方向，不自动追加本周任务。

## 1. 当前真正的问题

此前若干语义缺陷已经修复，不能继续按“没有异步Hook/没有多进程/没有定位模块”安排工作。
当前更关键的是：

| 问题 | 代码/现状依据 | 后果 |
|---|---|---|
| 多进程覆盖仍有时间边界 | core/frida_host/multi_attach.py在attach_children时枚举进程 | 晚启动、重启及隔离进程仍可能漏采；已附加不等于完整运行期覆盖 |
| 归因仍受观测位置影响 | 严格包名归因遇NAT/短连接可能无法核实身份 | 代理看见内容，不等于能绑定被测App；不能靠唯一白名单兜底解决 |
| 通用化程度不足 | detection_summary保留多个专用样本求值器；通用定位仅为受限实验 | 增加App仍可能需要手工业务适配；专用成功不能说明通用检出率 |
| 内容相关不等于传播路径 | 值匹配、批次对齐依赖可比较表示与时间 | 缓存、重试、编码、混合批次及应用层加密会断链或产生歧义 |
| 缺少SDK级行为归属 | core/evidence/app_classes识别“属于APK”，没有完整库指纹与运行时归属链 | 难以区分宿主和SDK，也难与第三方披露对应 |
| 触发覆盖仍难量化 | gap_scheduler是计划/合成控制，不能替代实际Android业务探索 | 零结果无法区分路径没走到、服务不可用和真正未观测到行为 |
| 政策语义较浅 | vehicle/policy/assessment.py以关键词定位片段、必要性人工复核 | 无法稳定处理否定、例外、主体、接收方和用途 |
| 评估外推不足 | 小规模夹具/样本、不同复核层级和不同设备范围 | 同模型共识不是独立专家验证，不能由少量配对推出总体准确率 |

四版本规则登记不等于四版本设备验证。常量/API的数量也不能直接当作敏感行为漏检率分母。

## 2. 方向一：设备侧归因对照通道（优先可行性验证）

已有实现：[PCAPdroid](https://github.com/emanuele-f/PCAPdroid)。
它提供本地VPN采集、连接/应用元数据及PCAP导出；官方[FAQ](https://emanuele-f.github.io/PCAPdroid/faq.html)也明确短连接可能仍为unknown。
Android官方[getConnectionOwnerUid](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress))要求可观测连接权限，调用者通常须为当前用户的活动VpnService；不能从宿主Python直接调用解决归因。

项目推导：先将它作为独立对照，不替换主采集器。在设备侧NAT之前保存连接身份，比较主采集的严格归因结果。
候选接入点：core/collector身份/连接记录；新增来源必须标source、UID/user、五元组和时间，不伪装成现有egress_hook证据。
只采授权包，关闭阻断/防火墙等改变通信行为的功能；网络路径改变本身应作为实验条件记录。

最小实验：同一自有App工作负载，分别覆盖短连接、长连接、连接复用、两个App并发；统计unknown、歧义、正确归因和资源成本。
AAOS user 10的VPN可用性须先验证；它不是现代AAOS或全部TLS解密的现成保证。
成本：中；先独立验证，再决定集成。
“SLIRP路径当前不可归因”不足以证明“模拟器上一切方案都无解”，但改观测位置能否改善仍是待测假设。

## 3. 方向二：SDK识别与运行时行为归属（新增信息价值高）

论文：[Reliable Third-Party Library Detection in Android and its Security Applications，CCS 2016](https://svenbugiel.de/publication/derr-16-ccs/derr-16-ccs.pdf)。
代码：[LibScout](https://github.com/reddr/LibScout)。较新的方法对照可读[LibScan，USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-wu-yafei.pdf)；本次没有确认其可直接部署的代码入口，不把论文等同现成工具。
LibScout用库profile匹配APK，需原始JAR/AAR或已有profile；精确版本不总是唯一，混淆与裁剪仍须评估。

项目推导：静态输出类/方法到SDK候选，再与已有运行时栈关联，形成“某SDK候选出现在本次敏感读取的调用链”。
接口放在core/static和core/evidence；未知时保留unknown，不仅按包名前缀强行认库。
不能从“APK包含SDK”推出“SDK本轮采集”，也不能从域名注册信息推出实际接收组织。

最小实验：选择少量有合法源码/依赖真值的App，覆盖原包名、重命名、多DEX、裁剪及SDK未执行负控。
分别评估静态识别和运行时调用链归属，不能只报告SDK数量。
成本：中；适合先做独立sidecar，不改默认结论。

## 4. 方向三：真实业务探索与状态覆盖

论文：[DroidBot，ICSE Companion 2017](https://ylimit.github.io/static/files/DroidBot_ICSE2017.pdf)。
代码：[honeynet/droidbot](https://github.com/honeynet/droidbot)。它用GUI状态转移图和可定制脚本生成输入。
另可参考[Fastbot2，ASE 2022](https://se-research.bytedance.com/publication/ase22/ase22.pdf)及[Fastbot_Android](https://github.com/bytedance/Fastbot_Android)的模型复用与探索机制。

项目推导：复用已有触发脚本，保存场景前置条件、UI状态、执行动作、跳转和成功读取；把coverage_layers的缺口映射到可执行场景。
先用有限脚本覆盖登录前/后、前台/后台、断网恢复，不从零训练RL，也不把点击数当覆盖率。
固定时间预算下比较手工固定脚本和模型辅助探索，统计新状态、新敏感读取、有效证据及首次有效证据时间。
账号、USB媒体、后端不可用必须单列；自动化不会凭空创造业务前提。
手机GUI工具在AAOS多显示器、模板App、旋钮和UX限制下需要适配，不宣称开箱即用。
成本：中；先采用状态图/脚本部分。Fastbot文档所列Android范围不能直接证明API35车载兼容。

## 5. 方向四：有限静态source→sink候选

实现：[FlowDroid](https://github.com/secure-software-engineering/FlowDroid)，对应PLDI 2014的数据流分析工作。
它计算Android/Java的静态数据流；它能回答可能存在的路径，不能证明本轮实际发生。

项目推导：作为独立CLI sidecar，在少量授权APK上用既有实测VHAL/通用API签名配置source和网络/存储sink。
输出只进入static candidate、覆盖缺口和下一轮场景，不写入运行时code_locs，不升级为违规。
回调/Android框架摘要、native和反射都要单列范围；没有配置模型不能当作没有路径。
设置单APK时间/内存预算，超时保留partial/unknown，不阻塞默认工作台。
成本：高；只建议先做1–2个APK的可行性试验，不作为下一周主线。

## 6. 方向五：政策中的主体、数据、用途与接收方关系

论文：[PoliGraph，USENIX Security 2023](https://www.usenix.org/system/files/usenixsecurity23-cui.pdf)。
代码：[UCI-Networking-Group/PoliGraph](https://github.com/UCI-Networking-Group/PoliGraph)。
其知识图谱表示政策陈述及不同片段关系，可支持政策矛盾与政策/流量一致性分析。

项目推导：先借鉴结构，不完整搬运行环境。抽取“谁、收集/共享什么、为何、给谁、何种条件、是否否定”，保留政策快照与字符位置。
在vehicle/policy中作为可选review材料，用明确规则或LLM结构化抽取加原文核验；先建立少量中文条款人工参考。
公开工具面向的语言/本体、运行资源与中文车载政策不同，必须单独验证否定、例外和泛称。
不把“有隐私政策/有关键词”当作充分披露，也不把知识图谱节点自动转为法律结论。
成本：中高；优先小规模结构化与引用校验，而非部署完整图数据库。

## 7. 方向六：从明文Hook升级为可解释的转换关联

论文：[ThirdEye，CCS 2022](https://users.encs.concordia.ca/~mmannan/publications/ThirdEye-CCS2022.pdf)。
代码原地址已重定向至[Madiba-Research/ThirdEye](https://github.com/Madiba-Research/ThirdEye)。
它研究自定义/多层加密与非标准通道；仓库已归档，并明确非开箱即用、无后续维护计划。

项目已经有native TLS/JCE采集，本方向不能再包装为“新接一个Cipher Hook”。
值得借鉴的是读取值、已观测转换及网络出口之间的关系：记录转换调用上下文、输入/输出指纹、缓冲长度和表示。
用自有App验证UTF8→压缩→加密→请求等已知链，保留算法、表示、来源及未关联环节。
重复内容、同线程接近或指针相同均不等于完整因果证明；音频样本不留存的边界保持。
先限一种变换链、一种请求形态，避免直接重造全系统动态污点。
成本：中高；以方法和测试设计为主，不整体导入归档工具。

## 8. 方向七：可公开复现的车载微基准

参考：[DroidBench](https://github.com/secure-software-engineering/DroidBench)。它按别名、回调、线程、生命周期、组件等难点拆成小程序。
这是测试设计参考，不是本项目新增的公开AAOS基准，也不是旧APK天然兼容当前系统的保证。

项目已有夹具和故障实验，下一步是补独立参考与固定题目，覆盖：
重复值/重复批次、延迟重试、多个PID同号事件、UID/user隔离、正文转换、不同接收方、未消费SDK、明确采集缺失。
每个案例封存动作/接收回执及版本，由与预测分离的参考过程标注；新会话不继承旧签核。
报告准确率时同时给分母、负控、无法归因、弃判、开销和标签来源。
模型共识可作工程参考，其独立性与层级必须如实陈述，不当作不存在共同错误的证明。
成本：中；可持续扩充，最能支撑本项目证据方法的研究贡献。

## 9. 复用选择与优先顺序

| 顺序 | 候选 | 首个里程碑 | 决定是否继续 |
|---|---|---|---|
| 1 | PCAPdroid归因对照 | 一个自有工作负载、四类连接条件的对照表 | 是否减少unknown且不增加错误归因；AAOS当前用户可用性 |
| 2 | LibScout SDK归属 | 少量已知SDK样本＋运行时栈归属表 | 是否提供当前报告没有的新信息；未知/误认比例 |
| 3 | DroidBot状态覆盖 | 两个可运行App的固定预算对照 | 是否增加有效证据，而非只增加点击/页面 |
| 4 | 微基准 | 一组可独立复现的重复批次/多PID等题目 | 独立参考是否充分、反例是否区分方法边界 |
| 5 | PoliGraph式政策结构 | 小规模中文条款、原文位置、否定/例外参考 | 是否减少错误解释，是否值得进一步投入 |
| 6 | FlowDroid/ThirdEye式深层关联 | 单APK静态侧车或一种已知转换链 | 成本与新增证据是否可接受 |

顺序是结合当前项目的工程判断，不是论文证明的最优路线；实际里程碑应由试验结果调整。
先完成A/B/C本周闭环，再从以上选择一个试点，不一次引入全部工具。
采用前记录release/commit、依赖、许可和适配范围；只取所需最小集，不全量克隆技能/工具集合。

Frida官方[child_gating示例](https://github.com/frida/frida-python/blob/main/examples/child_gating.py)可参考会话生命周期管理，
但[该API会挂起子进程](https://frida.re/docs/frida-core/method.Session.enable_child_gating_finish.html)，与本项目被动观察约束存在冲突。
不能把示例原样启用为默认方案；Android由Zygote启动的其他进程也不等于目标进程直接fork的子进程。
当前优先有限进程重发现、UID/user验证和明确覆盖缺口，不承诺一个gating API解决全部多进程问题。
