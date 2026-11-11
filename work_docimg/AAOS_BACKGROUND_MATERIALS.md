# AAOS 背景页素材包（车企采用 · 第三方 App 增长 · 隐私研究）

整理日期：2026-11-11。所有数字均注明来源，答辩引用前建议按来源复核一次。
仅用于授权测试与学术汇报。

## 一、车企采用（"AAOS 已是主流选择"）

### 规模数字
- **超过 1 亿辆车**已运行 Android Automotive OS（含 GAS 与非 GAS 实现）
  来源：Gözübüyük et al., "Analyzing Privacy Implications of Data Collection in
  Android Automotive OS", arXiv:2409.15561（"integrated into over 100M vehicles"）；
  同口径见 NDSS VehicleSec 2024 PRIDRIVE poster
- 其中搭载 Google Automotive Services（带 Play 商店）的约 **1000 万辆**
  来源：Google AAOS 合作负责人 Mithil Munshi，IAA 2025 演讲（Aximote 博客转述）
- **Gartner 预测：2028 年全球 70% 以上新车**将搭载 AAOS
  来源：同上（Aximote 转述 Gartner 预测）
- Google I/O 2025 官方口径：**超过 50 个在售车型**搭载 Google built-in，且持续增加
  来源：Google I/O 2025（theLinkx / AndroidGuys 报道）
- 对照项：手机投射方案 Android Auto 覆盖近 **2.5 亿辆**——注意区分
  AAOS（原生车机 OS）与 Android Auto（手机投射），PPT 中别混用

### 车企清单（2025 年公开报道汇总，TodoAndroid 统计）

**带 Google 服务（有 Play 商店）**：
- **沃尔沃 Volvo**：XC40/XC60/XC90（2022+）、EX30/EX90、S60/S90、V60/V90 等 —— 全系主力
- **Polestar 极星**：2/3/4/5 全系（最早采用者，Polestar 2 为首款）
- **雷诺 Renault**：Mégane E-Tech、Austral、Scénic、Rafale、Captur/Espace（2024+）等 —— 欧洲走量
- **本田 Honda**：Accord（2023+）、Civic（2025+）、Prologue
- **日产/英菲尼迪**：Qashqai、Rogue、Murano、Micra（2024/2025+）、QX80
- **通用系**：凯迪拉克 Lyriq/Escalade/Celestiq、雪佛兰 Blazer EV/Equinox EV、
  GMC 悍马 EV、别克 Enclave —— 北美大举切换（2022–2025）
- **福特**：Expedition/Explorer（2025+）；**林肯**：Aviator/Nautilus/Navigator
- 三菱 ASX、Alpine A290/A390、讴歌 MDX/ZDX

**AAOS 基础版（无 Google 服务，自建应用生态）**：
- **奥迪**：Q6 e-tron、A5/A6（2025+）；**保时捷**：Macan（2024+）、Taycan（2025+）
- **BMW**：X1/X2/X3、1 系（2023/2024+，OS 9 基于 AAOS）
- **领克 Lynk & Co** 01/02、**路特斯** Eletre/Emeya、**Lucid Air**、Rivian R1T/R1S、
  玛莎拉蒂全系、克莱斯勒/道奇、Togg T10X

→ 建议图表：品牌 logo 墙，分两栏（Google built-in / AAOS 基础版），
标注"1 亿辆现役 + 2028 年 70% 新车"两个锚点数字。

## 二、第三方车载 App 爆发增长（"生态正在复制智能手机时刻"）

### App 数量增长曲线（Google 官方目标，IAA 2025）
- 2024 年初：约 **400 款**车载 App
- 2025 年底目标：**>600 款**
- 2026 年底目标：**>1300 款**
  来源：Google（IAA 2025 演讲，Aximote 博客整理）→ 适合画增长曲线图
- Google I/O 2025 另一口径：Play 商店车载 App **300+**，"car-ready mobile apps
  program"（大屏适配 App 自动上车）2025 年 2 月起放量，一次性新增数十款
  （Roblox、F1 TV、Paramount+、Plex、NBC News 等），首发沃尔沃/极星车型
  来源：Android Authority 2025-02、ZDNET、Google I/O 2025
- 分发机制红利：同一 APK/AAB 可同时发手机与 AAOS 车机，开发门槛骤降 →
  第三方 App 加速上车的直接动因（Google I/O 2025）
- 参照系：Google Play 月活 25 亿、300 万开发者、年下载 1400 亿
  （Aximote 引 Google）——"智能手机应用生态正在向车机复制"

→ 建议图表：双轴图——左轴 App 数量折线（400→600→1300），
右轴/标注 装机量（1 亿辆现役 → 2028 年 70% 新车）。

## 三、学术研究：AAOS 隐私风险已被顶会实锤（"风险真实存在且未披露"）

1. **PRIDRIVE / arXiv:2409.15561**（Clemson + 密歇根大学，NDSS VehicleSec 2024 /
   arXiv 2024）：对 3 家 OEM 做静态 + 动态 + 流量（DPI）分析——**与本项目
   "静态剖析 + Hook 观测 + 通信证据"三源方法同构**。关键发现：
   - 某 OEM 车速以约 **25 Hz** 高频采样上传
   - **某 OEM 隐私政策仅披露其静态分析发现车辆属性的 13.02%** ——
     披露缺口实锤，直接支撑本项目"政策-行为双轴对照"的立项理由
   - 车辆数据被用于广告、保险、金融定价并与第三方共享
   - OEM 自定义 VHAL 属性：A 厂 753 项 / B 厂 436 项 / C 厂 193 项 / D 厂 156 项
     （本项目建设 32 项 VHAL 指纹表，可对照引用）
2. **Pesé et al., "Security Analysis of Android Automotive"**（SAE VehicleSec 2024）
3. **Pesé, "A First Look at Android Automotive Privacy"**（SAE Tech Paper 2023）
4. **Eriksson, Groth, Sabelfeld（查尔姆斯理工，VehITS 2019）**：
   "On the Road with Third-Party Apps"——首篇 AAOS 第三方 App 安全分析；
   演示 SoundBlast（高分贝惊吓驾驶员）、位置/语音外泄等攻击，基于沃尔沃测试台
5. 真实案例：**通用汽车（GM）被曝收集车主位置与电台收听习惯用于定向广告**
   （Detroit Free Press 2018，被论文 1/4 引用）——车机数据商业价值实证

→ 建议用法：背景页放"100M 辆车 + 70% 新车（2028）+ 400→1300 款 App +
13% 政策披露率"四个数字；论文清单放脚注，答辩被问"有没有相关工作"时直接报
PRIDRIVE（同方法、不同交付：他们做分析工具，我们做可复核评估平台+报告产物）。

## 四、来源清单

| # | 来源 | 链接 |
|---|---|---|
| 1 | arXiv 2409.15561（PRIDRIVE 长文） | https://arxiv.org/pdf/2409.15561v1.pdf |
| 2 | PRIDRIVE poster（NDSS VehicleSec 2024） | https://www.ndss-symposium.org/wp-content/uploads/vehiclesec2024-24-poster.pdf |
| 3 | Chalmers VehITS'19（AAOS 第三方 App 首篇） | http://www.cse.chalmers.se/~andrei/vehits19.pdf |
| 4 | Google I/O 2025 车载更新报道 | https://androidguys.com/news/gemini-and-games-take-the-wheel-google-i-o-2025-expands-androids-in-car-experience/ ; https://thelinkx.com/?p=13053 |
| 5 | 车载 App 扩量报道（car-ready 计划） | https://www.androidauthority.com/new-android-automotive-apps-announced-3527845/ ; https://www.zdnet.com/article/android-automotive-users-are-about-to-see-a-lot-more-apps-in-their-vehicles/ |
| 6 | AAOS 车型清单（2025 统计） | https://en.todoandroid.es/Cars-that-integrate-Android-Automotive-with-or-without-Google-Automotive-Services:-the-definitive-list-and-everything-you-need-to-know/ |
| 7 | IAA 2025 数字与 Gartner 预测（Aximote 整理） | https://aximote.com/en/blog/android-automotive-os/the-future-of-android-automotive-os |

## 注意事项

- BMW 是否搭载 AAOS 各报道有出入（OS 9 基于 AAOS 的说法见 TodoAndroid 清单），
  引用时写"据公开报道"或只放沃尔沃/极星/雷诺/凯迪拉克等无争议品牌
- "1 亿辆"是 AAOS 全口径（含非 GAS），"1000 万辆"是 Google built-in 口径，
  图表务必分开标注
- 数据核实日 2026-11-11；2026 年底 >1300 款是 Google 目标口径，若答辩时已有
  实际数字可更新
