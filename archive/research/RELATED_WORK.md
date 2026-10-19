# V-Scanner 领域调研:车载 App 数据安全合规审计相关工作与可行性评估

调研日期:2026-09-21;结论均溯源至一手来源,无来源处标注"未找到公开资料"。[n] 见文末参考文献。

## 一、已有工作

### 1.1 学术界

申报书所引"78%"论文出处已核实:Pesé,"A First Look at Android Automotive Privacy",SAE WCX 2023(2023-01-0037)[1]。该文分析当时 55 个 AAOS 第三方应用,发现超过 78% 未在隐私政策中提及全部危险权限,据此判定部分应用过度索权 [1](注意:该口径是"政策未披露",与"申请超出必要权限"不等同)。

最接近本项目的是 Gözübüyük 等,arXiv:2409.15561(2024)[2]:工具链 PriDrive(mitmproxy 解密+动静态分析+Frida 插桩+LLM 读政策)对 OEM 车机与第三方应用做"实际收集 vs 政策披露"对账,发现某 OEM 以约 25Hz 采集车速、隐私政策仅覆盖静态发现属性的 13.02% [2],是重要学术对标。

其他:Eriksson 等 VEHITS 2019 提出车规 API 静态分析工具 AutoTame [3];Pesé 等 PoPETs 2020 证明方向盘转角可反推行车路线 [4]。整车经典 [5][6] 聚焦 ECU/CAN,未涉 AAOS 应用层。

### 1.2 开源工具

静态:FlowDroid [9]、MobSF [10]、QARK [11] 均无 android.car/VHAL 专属规则(未找到公开资料)。动态:Frida [12]、objection [13],Clemson 论文已用 frida-trace 在车机模拟器记录 VHAL 调用并关联 APK [21]。流量:mitmproxy [14];PCAPdroid 未见 AAOS 支持资料 [15]。解锁脚本:frida-multiple-unpinning [20]、OWASP MASTG-TECH-0012 [19]。

### 1.3 商业与监管

国际:Upstream AutoThreat 报告显示远程信息处理服务器与 API 是 2025 年最大攻击向量 [24];Argus [25]、Cybellum [26]、Karamba [27] 面向整车/云端,未见面向第三方车载 App 的审计产品(未找到公开资料)。国内:梆梆安全有车载 App 检测与合规评估 [28];奇安信有车联网检测平台与 App 渗透测试 [29];绿盟有 AIIOV 检测体系 [30]。

标准:《汽车数据安全管理若干规定(试行)》确立"默认不收集、单独同意、境内存储"原则 [31];GB/T 43697-2024 给出数据分级识别指南 [32];GB 44495-2024 强制国标 2026-01-01 对新车型实施 [34];工信部 2022 指南规划百项标准 [33]。

## 二、可行性评估

**2.1 Frida Hook CarPropertyManager(emulator_car64_x86_64、API 35):可行但有坑。** AOSP 车机 AVD 为 userdebug 镜像、可 adb root [22][23];CarPropertyManager 属 android.car 客户端库、在 app 进程内执行,注入 app 进程即可截获 getProperty 调用栈,有公开先例 [21]。坑:① API 35 上 Frida 有已知问题——#3526(Frida 16 的 frida-java-bridge 分离致 Java Hook 失效)[16]、#3666[17],17.2.6 已修复 AVD 崩溃 [18];x86_64 模拟器须配 x86_64 frida-server [36]。② OEM 车机可能走私有信号服务 [35]。③ 真机 user 构建无 root,只能 gadget 注入,系统级审计只能依托模拟器。

**2.2 SSL Pinning 绕过 + mitmproxy:成熟但有边界。** objection 与 frida-multiple-unpinning 覆盖 TrustManager/OkHttp/Conscrypt,是 OWASP MASTG 标准手段 [19][20][13];PriDrive 已在真实车载应用上验证 [2][21]。边界:native 锁定(BoringSSL/gRPC/Cronet)需逐个定位、双向 TLS 需抽取客户端证书、应用可检测 Frida [19];HSTS 不含锁定、不构成实质障碍(评估结论);非 HTTP 协议(MQTT/gRPC/QUIC)无法解密内容 [19]。

**2.3 "读取→外发"时间窗关联:可行但有坑,有先例。** TaintDroid(OSDI 2010)[7]、FlowDroid [8]、PriDrive 双通道关联 [2] 均为先例。难点:① socket 须归属 UID 才能判定"谁外发";② 设备与抓包主机时钟漂移需统一基准;③ 应用普遍缓冲后批量上报 [2],时间窗需宽关联;④ 加密/二进制协议只能按"主机+时序+属性值指纹"弱匹配。

**2.4 与申报书对照。** 可直接用:mitmproxy+解锁脚本、Frida+Gadget 注入与 Java Hook、FlowDroid/MobSF/QARK 交叉验证。需自研:android.car/VHAL 规则库与过度索权判定(无公开现成规则集)、"读取→外发"关联引擎、证据链溯源(风险与版本组合见 2.1–2.3)。

## 三、对本项目的启示

1. **差异化定位成立**:学术界已有"政策披露对账"研究 [1][2],产业界面向整车/云端 [24]–[30],未见面向第三方车载 App 的"过度索权+敏感读取+外发证据链"一体化审计工具;差异化在于面向监管标准输出合规判定与证据链 [2]。
2. **引用修正**:"78%"应标注 Pesé 2023 的"未在隐私政策提及全部危险权限"口径 [1],并补充 13.02% 覆盖率新数据 [2]。
3. **技术选型**:vehicle/targets 用模拟器 userdebug 镜像 + x86_64 frida-server + Frida 17.2.6,真机预留 gadget 模式 [21][35];vehicle/hooks 关联判定以"主机+时序+频率"为主特征。
4. **合规绑定**:审计结论逐条映射 GB/T 43697-2024、GB 44495-2024 与《汽车数据安全管理若干规定》条款 [31][32][34]。

## 参考文献

1. Pesé, M. A First Look at Android Automotive Privacy. SAE Technical Paper 2023-01-0037, WCX SAE World Congress, 2023. https://www.sae.org/publications/technical-papers/content/2023-01-0037/
2. Gözübüyük, B., Tang, B. J., Shin, K. G., Pesé, M. D. Analyzing Privacy Implications of Data Collection in Android Automotive OS. arXiv:2409.15561, 2024. https://arxiv.org/abs/2409.15561
3. Eriksson, B., Groth, J., Sabelfeld, A. On the Road with Third-party Apps: Security Analysis of an In-vehicle App Platform. Proc. VEHITS 2019, pp. 64–75. https://www.scitepress.org/PublishedPapers/2019/76782/pdf/index.html
4. Pesé, M. D., Pu, X., Shin, K. G. SPy: Car Steering Reveals Your Trip Route! PoPETs 2020(2): 155–174. https://petsymposium.org/popets/2020/popets-2020-0022.php
5. Koscher, K., et al. Experimental Security Analysis of a Modern Automobile. IEEE S&P 2010. https://ieeexplore.ieee.org/document/5504804
6. Checkoway, S., et al. Comprehensive Experimental Analyses of Automotive Attack Surfaces. USENIX Security 2011. https://dl.acm.org/doi/abs/10.5555/2028067.2028073
7. Enck, W., et al. TaintDroid: An Information-Flow Tracking System for Realtime Privacy Monitoring on Smartphones. OSDI 2010. https://dl.acm.org/doi/10.1145/2494522
8. Arzt, S., et al. FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps. PLDI 2014. https://dl.acm.org/doi/abs/10.1145/2594291.2594299
9. FlowDroid 源码仓库. https://github.com/secure-software-engineering/FlowDroid
10. MobSF 源码仓库. https://github.com/MobSF/Mobile-Security-Framework-MobSF
11. QARK 源码仓库. https://github.com/linkedin/qark
12. Frida 源码仓库及官方 Android 文档. https://github.com/frida/frida ; https://frida.re/docs/android/
13. objection 源码仓库. https://github.com/sensepost/objection
14. mitmproxy 源码仓库及 Android 系统 CA 安装指南. https://github.com/mitmproxy/mitmproxy ; https://docs.mitmproxy.org/stable/howto-install-system-trusted-ca-android/
15. PCAPdroid 源码仓库. https://github.com/emanuele-f/PCAPdroid
16. frida/frida issue #3526(Android 15 Java Hook 与 gadget 脚本模式问题). https://github.com/frida/frida/issues/3526
17. frida/frida issue #3666(Android 15/16 gadget "Thread copied methods" 错误). https://github.com/frida/frida/issues/3666
18. Frida 17.2.6 发布说明(修复 Android 14/15 AVD 崩溃). https://frida.re/news/2025/06/27/frida-17-2-6-released/
19. OWASP MASTG-TECH-0012: Bypassing Certificate Pinning (Android). https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0012/
20. frida-multiple-unpinning 脚本(Frida CodeShare). https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/
21. Gözübüyük, B. Analyzing Privacy Implications of Data Collection in Android Automotive OS(Clemson 硕士论文,PriDrive 方法:Magisk + frida-trace + logcat + tcpdump). https://open.clemson.edu/cgi/viewcontent.cgi?article=5505&context=all_theses
22. AOSP 官方文档:Android Virtual Device as a development platform(车机 AVD). https://source.android.com/docs/automotive/start/avd/android_virtual_device
23. AOSP device/generic/car 下 emulator_car64_x86_64 设备配置. https://android.googlesource.com/device/generic/car/+/547e01f4af9099f7bc6e9918a9981060e80b9e26/emulator_car64_x86_64/
24. Upstream Security. 2025 全球汽车与智能出行网络安全报告(AutoThreat). https://upstream.auto/ ;PDF:https://info.upstream.auto/hubfs/Security_Report/Security_Report_2025/Upstream_2025_Global_Automotive_Cybersecurity_Report.pdf
25. Argus Cyber Security(PlaxidityX). https://plaxidityx.com/
26. Cybellum(LG 旗下). https://cybellum.com/
27. Karamba Security. https://karambasecurity.com/
28. 梆梆安全:车联网应用安全解决方案 / 汽车网络安全检测和渗透. https://www.bangcle.com/index/index/pages/cat_id/57.html
29. 奇安信:车联网安全能力(检测平台/靶场/态势感知,TSP 与 App 渗透测试). https://www.qianxin.com/news/detail?news_id=10893
30. 绿盟科技:车联网安全(AIIOV 智能分析系统、CAVD 技术支撑). https://www.nsfocus.com.cn/
31. 《汽车数据安全管理若干规定(试行)》(五部门令第 7 号,2021-10-01 施行). http://www.cac.gov.cn/2021-08/20/c_1631049984897667.htm ;公报:https://www.gov.cn/gongbao/content/2021/content_5647363.htm
32. GB/T 43697-2024《数据安全技术 数据分类分级规则》. https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=F0C385EDC38CBF277AEC021F23126ADE
33. 工信部《车联网网络安全和数据安全标准体系建设指南》(工信厅科〔2022〕5 号). https://xzca.miit.gov.cn/zwgk/zcwj/wjfb/art/2022/art_92728c0da3024e938e9009bed612c121.html
34. GB 44495-2024《汽车整车信息安全技术要求》(2026-01-01 对新车型实施). https://openstd.samr.gov.cn/bzgk/std/newGbInfo?hcno=2DB552CAA58F589705C3DC7AD47AC2AB
35. LynkCoTrack:VHAL 及 ECarX 反射数据源(领克车机私有 CarSignalManager 案例). https://blog.rayfalling.com/2026/08/lynkcotrack-vhal-ecarx.html
36. Stack Overflow:API 35 x86_64 模拟器上 arm64 frida-server spawn 失败讨论. https://stackoverflow.com/questions/79450624/frida-not-able-to-find-libil2cpp-so-or-assembly-csharp

把这一路读到的坑按"会不会再踩"整理一遍。这份项目最值得记住的一点是:**它遇到的几乎每一个坑都是静默失败**——不报错、不崩溃,而是给你一个看起来正确的结果。

---

# 一、贯穿全局的元经验:静默失败比崩溃危险

这个项目里最阴的四处坑,形态完全一致:


| 坑                                    | 表面现象        | 真相                                                                            |
| ------------------------------------- | --------------- | ------------------------------------------------------------------------------- |
| `pm clear` 不带 `--user 10`           | 打印`Success`   | 只清了 user 0 那份不存在的副本,user 10 的库纹丝不动                             |
| Room 打开损坏的预置库                 | 不报错,正常返回 | 按空 schema 自建表,**0 字节 / 垃圾字节 / 截断到 2048 字节三种形态全都静默通过** |
| Phase 0 的`pm list permissions -d -g` | 只列出 2 个权限 | `-d` 只列 dangerous 组,真相是 146 个                                            |
| `getFloatProperty`                    | 返回 0          | 读不到值时的 fallback,不是"车速为 0"                                            |

**开发时的应对**:凡是"成功"的路径,都要问一句"它凭什么算成功"。验证器必须显式比对期望条数——仅靠捕获异常,会把任意一种损坏都误判成"读取成功、四表 0 行"。

---

# 二、环境与构建(确定性坑,已经踩实)

1. **本网络 `dl.google.com` 和 `android.googlesource.com` 都不可达**。AGP / AndroidX / Room 全在 Google Maven 上,`settings.gradle.kts` 必须阿里云镜像优先,**不要改回裸 `google()`**。这条直接改变了项目路线:D009 里 android-15 之所以走设备实测,根源就是源码镜像不可达。
2. **工程路径含非 ASCII 字符**(Windows 用户名),AGP 默认拒绝。已用 `android.overridePathCheck=true`,但 AGP 官方 README 明确警告:这是真实风险,若 aapt2 或 NDK 报错,**应把构建迁到纯 ASCII 路径,而不是继续加开关**。
3. SDK 路径拼写是 `D:\Anroid\SDK`(少个 d),JDK 在 `D:\Anroid\JDK`,写脚本时别"顺手改正"。

---

# 三、设备验证(最耗时间的一组)

**核心陷阱是"哈希对得上但数据是 0 行"**——这个表现的成因是两个坑叠在一起:

* **预置库是粘性的**:Room 的 `PrePackagedCopyOpenHelper` **只比版本号,不比内容**,重新安装或升级 APK 都不会替换已有副本。
* **换过 `assets/rules.db` 后必须 `adb shell pm clear --user 10 <pkg>`**。不带 `--user` 会假成功,于是验证页的 SHA-256(校验的是 APK 里的资产)显示**匹配**,读的却是设备上那份陈旧副本。

**排查口诀**:对照 `databases/vscanner-rules.db` 的大小与 mtime 最快。另外首次成功打开后文件会多出 `room_master_table`,此后报错文案会变但仍属 schema 不匹配。

**还有一条**:Room 的运行时校验**只看列、索引列和外键**,看不到 CHECK 约束、索引名、主键顺序——而这三项恰好是本项目数据完整性主张的依托。所以有 `tools/verify_schema_parity.py` 独立覆盖,**不能只依赖 Room 的结论**。

---

# 四、规则库的数据语义(写代码时最容易搞错)

1. **`definition_status` 不是"可信度",是"来源类型"**。只有源码抽取才配 `source_verified`,设备观测一律 `pending`——设备上确认"属性存在"**不等于**确认了权限映射。
2. **溯源必须拆开**(D009 里"最容易做错的一处"):`basis_refs_json`(项目策略,与版本无关)可以沿用,`source_refs_json`(AOSP 具体 commit 与行号)**绝不能沿用**——否则等于给 android-15 的规则安上 android-14 的出处。这条不变式由设备侧测试锁定,不靠人工检查。
3. **`enabled` 恒为 0 是有意的**:没有求值器就不启用规则。schema 里的 CHECK 约束会强制这一点。
4. **不硬编码 flag 数值**:`protection_level_value` 全部留 NULL,只保留 `protection_level_raw` 原始文本。
5. **属性类型、访问模式、单位禁止从名字猜测**,未知就留 NULL 并进诊断。

---

# 五、未来阶段(vehicle/targets/3)的研究警示

这些还没踩到,但报告里查证过:

**Frida 侧**

* API 35 上 Frida 有已知 issue([#3526](https://github.com/frida/frida/issues/3526)、[#3666](https://github.com/frida/frida/issues/3666)),需 17.2.6+;**x86\_64 模拟器必须配 x86\_64 的 frida-server**,架构不匹配会 spawn 失败。
* **真机 user 构建无 root**,只能走 gadget 注入;系统级审计只能依托模拟器(userdebug)。
* **最大的覆盖盲区**:部分 OEM 车机(如领克/亿咖通)用私有 `CarSignalManager` 反射取数据,**根本不走 CarPropertyManager**——标准 Hook 会完全漏掉。这既是风险,也是论文里"适用范围"该写明的一条。
* App 可以检测 Frida 的存在。

**流量侧**

* 证书解锁本身成熟(OWASP MASTG 标准手段 + frida-multiple-unpinning 脚本),但 **native 锁定**(BoringSSL / Cronet / gRPC)要逐个定位,**双向 TLS** 需要抽取客户端证书。
* **真正的盲区不是证书锁定,而是非 HTTP 协议**:MQTT / gRPC / QUIC 解不了内容,只能按"主机 + 时序 + 属性值指纹"弱匹配。把它当预期,别当意外。
* HSTS 不构成实质障碍(这条是好消息)。

**关联判定**

* socket 必须能**归属到 UID** 才能说"是谁发的"。
* 设备与抓包主机**时钟漂移**需要统一基准(规则库里的 `clock_normalized` 就是为此)。
* **应用普遍缓冲后批量上报**,时间窗要放宽——现有规则里的 3000ms 可能要调。
* 规则库里的 `content_match: required_to_upgrade_beyond_temporal_correlation` 已经写明了这条原则:**只靠时间相近不能定罪**。

---

# 六、值得延续的三个做法

1. **不变式交给测试,不交给人工检查**。`android15RulesCarryDeviceProvenanceNotAndroid14SourceRefs` 这种测试的价值在于——"一次粗心的重建正是它悄悄退化的方式"。
2. **不确定就留 NULL + 写进诊断**,不要补猜。整个库的 `pending`、`TODO`、`unsupported` 都在贯彻这条。
3. **来源与事实分开存**(`source_refs` vs `basis_refs`),让"这是什么"和"我们凭什么这么判"互不污染。
