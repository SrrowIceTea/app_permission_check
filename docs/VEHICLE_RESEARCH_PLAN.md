# 车载隐私评估改造：研究依据与验收

日期：2026-11-01。仅用于授权测试（自有设备与自有 APK）。

## 阅读的原始研究

1. Gözübüyük, Tang, Shin, Pesé，*Analyzing Privacy Implications of Data Collection in Android Automotive OS*，arXiv:2409.15561v1，2024。
   原文：https://arxiv.org/html/2409.15561v1
   PriDrive 联合静态分析、Frida 动态观察、MITM 和政策映射。§4、§7 强调采样频率、缓存批传与复杂车辆状态覆盖；静态引用、读取、外发不能互相替代。
   本项目采用：分级证据、实际值匹配、采集频率统计、场景执行和覆盖缺口。本文不复现 OEM 样本数量或论文性能。
2. Mert D. Pesé，*A First Look at Android Automotive Privacy*，SAE 2023-01-0037，2023，DOI:10.4271/2023-01-0037。
   作者全文：https://mpese.com/publication/pese-2023-first/SAE_AAOS_Privacy_Paper.pdf
   研究比较车载应用权限声明与隐私政策的披露。声明某权限不证明权限授予，更不证明数据已经采集。
   本项目采用：实际权限与读取结果分别留证、业务必要性与政策披露作为人工复核项。
3. Abdul Moiz, Manar H. Alalfi，*An Approach for the Identification of Information Leakage in Automotive Infotainment systems*，arXiv:2011.04066v1，2020。
   全文：https://arxiv.org/html/2011.04066v1
   研究从车辆数据源追踪到 Intent/sendBroadcast 等组件间出口。其评估包含 Android Auto 应用，不能直接等同于 AAOS 真车验证。
   本项目采用：明确 source/sink 与候选/事实区别；ICC 完整污点分析列为后续能力，不能声称本次实现。

## 本次实施与停止条件

- 保留平台无关 core 与独立 vehicle 产品线，不复制整套 mobile。
- 车辆原值/派生值匹配必须绑定属性；普通短数字在无属性语义的文本中不升级证据。
- 用户身份贯穿出站归因与关联，跨 UID/用户拒绝关联，旧证据缺身份如实标注。
- 新增车载审计编排与可重复的自有夹具验收，输出原始日志、场景清单、汇总及报告。
- 测试覆盖：成功读取/读取被拒、只读不发、HTTP/HTTPS、同名不同值、派生值、跨包/跨用户/跨会话、归因歧义、订阅、后台、延迟上传。
- 全量离线回归无失败；设备场景有正反对照且非空；修复后重新运行受影响测试。
- 所有失败轮次保留。最终记录通过范围与未覆盖项；不声称有限测试能证明无任何缺陷。

## 适用边界

AAOS 35 模拟器与自有测试 APK 不代表所有厂商 ROM、预装特权应用或真实道路环境。
静态候选不证明泄露；内容相关也不等于完成因果污点追踪；AI 不直接输出违规成立。
场景标签来自实际执行记录或明确测试输入，不能凭时间猜测用户同意或车辆状态。
真实 AI 服务未配置时必须显示 skipped，不能用固定模板冒充大模型研判。
