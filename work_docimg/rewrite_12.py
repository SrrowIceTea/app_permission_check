# -*- coding: utf-8 -*-
"""重写 设计文档1.5.docx 的 1.2 章节（国内外研究现状）。
- 用新的三大方向结构（学术研究 / 行业实践 / 评估基准）替换原 1.2.1-1.2.4
- 保留原表中（技术路线对照表 表1-1）不动
- 全文引用重排：参考文献由 32 条扩至 52 条，编号按首次出现顺序连续
输出：设计文档1.6.docx
"""
import copy
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

SRC = "设计文档1.5.docx"
DST = "设计文档1.6.docx"

doc = Document(SRC)

# ============================================================
# 0. 定位与模板采集
# ============================================================
paras = doc.paragraphs

def find_para(pred, desc):
    for i, p in enumerate(paras):
        if pred(p.text):
            return i, p
    raise AssertionError("未找到: " + desc)

i_h12, h12 = find_para(lambda t: t.strip() == "1.2 国内外研究现状", "1.2 标题")
i_h13, h13 = find_para(lambda t: t.strip() == "1.3 存在的问题", "1.3 标题")

old_body_idx = None   # 正文段模板（原 1.2 下的普通段落）
old_h3_idx = None     # Heading 3 模板
old_cap_idx = None    # 表题模板
cite_rpr_xml = None   # 上标引用 run 的 rPr
for i in range(i_h12, i_h13):
    p = paras[i]
    if p.style.name == "Heading 3" and old_h3_idx is None and p.text.strip().startswith("1.2.1"):
        old_h3_idx = i
    if p.text.strip().startswith("表1-1 移动应用隐私检测三条技术路线对照"):
        old_cap_idx = i
    if old_body_idx is None and p.style.name == "Normal" and p.text.strip().startswith("学术界与工业界形成了"):
        old_body_idx = i

assert None not in (old_body_idx, old_h3_idx, old_cap_idx), (old_body_idx, old_h3_idx, old_cap_idx)

tpl_body_ppr = copy.deepcopy(paras[old_body_idx]._p.pPr)
tpl_body_rpr = None
for r in paras[old_body_idx].runs:
    if r.text.strip():
        tpl_body_rpr = copy.deepcopy(r._r.rPr)
        break
tpl_h3_ppr = copy.deepcopy(paras[old_h3_idx]._p.pPr)
tpl_cap_ppr = copy.deepcopy(paras[old_cap_idx]._p.pPr)

# 上标引用样式：取原文中 [n] 引用 run 的 rPr
for p in paras:
    for r in p.runs:
        if re.fullmatch(r"\[\d+\]", r.text.strip() or "") and r._r.rPr is not None:
            if r._r.rPr.find(qn("w:vertAlign")) is not None:
                cite_rpr_xml = copy.deepcopy(r._r.rPr)
                break
    if cite_rpr_xml is not None:
        break
assert cite_rpr_xml is not None, "未找到上标引用样式"

# ============================================================
# 1. 提取原参考文献全文（重建列表用）
# ============================================================
ref_texts = {}
ref_paras = []
for p in paras:
    m = re.match(r"^\[(\d+)\]\s", p.text.strip())
    if m and p.style.name == "Normal":
        n = int(m.group(1))
        if 1 <= n <= 60 and ("." in p.text or "[" in p.text[4:]):
            ref_texts[n] = p.text.strip()
            ref_paras.append(p)
assert len(ref_texts) == 32, "参考文献应 32 条，实得 %d: %s" % (len(ref_texts), sorted(ref_texts))
first_ref_p = ref_paras[0]
tpl_ref_ppr = copy.deepcopy(first_ref_p._p.pPr)
tpl_ref_rpr = None
for r in first_ref_p.runs:
    if r.text.strip():
        tpl_ref_rpr = copy.deepcopy(r._r.rPr)
        break

# ============================================================
# 2. 新旧编号映射
# ============================================================
# 旧(1.5 编号) -> 新
OLD2NEW = {
    1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8, 9: 9, 10: 10, 11: 11, 12: 12,
    13: 13, 14: 14, 15: 15, 16: 16, 17: 17, 18: 18,
    19: 33,  # Meng
    20: 24,  # Reardon
    21: 29,  # OWASP MASTG
    22: 27,  # Frida
    23: 22,  # Wijesekera 1
    24: 23,  # Wijesekera 2
    25: 28,  # mitmproxy
    26: 30,  # Wang off-path TCP
    27: 32,  # Andow / PoliCheck
    28: 31,  # Zimmeck
    29: 38,  # LLM-PrivCheck
    30: 50, 31: 51, 32: 52,  # V-Scanner 自引
}
# 新增文献文本（新编号 -> 条目文本）
NEW_REFS = {
    19: "Fan M, Shi J, Wang Y, et al. Giving without Notifying: Assessing Compliance of Data Transmission in Android Apps[C]//Proceedings of the 39th IEEE/ACM International Conference on Automated Software Engineering (ASE). New York: ACM, 2024: 1595-1606.",
    20: "Nazzal D, et al. KASTroid: A Static Taint Analysis Framework for Kotlin-Based Android Applications[C]//IEEE 49th Annual Computers, Software and Applications Conference (COMPSAC). IEEE, 2025.",
    21: "Khatun M E, Noureddine L, Sui Z, et al. AndroByte: LLM-Driven Privacy Analysis through Bytecode Summarization and Dynamic Dataflow Call Graph Generation[C]//Annual Computer Security Applications Conference (ACSAC). 2025.",
    25: "Le A, Varmarken J, Langhoff S, et al. AntMonitor: A System for Monitoring from Mobile Devices[C]//Proceedings of the SIGCOMM C2B(1)D Workshop. New York: ACM, 2015.",
    26: "Fu H, Zheng Z, Bose S, et al. LeakSemantic: Identifying Abnormal Sensitive Network Transmissions in Mobile Applications[EB/OL]. arXiv:1702.01160, 2017.",
    34: "Huang K R, Zhan X, Xia X. PIChecker: Automatic Privacy Detector for Third Party Libraries in Android Apps[C]//Proceedings of the 2026 Conference on Foundations of Software Engineering (FORGE). New York: ACM, 2026: 160-171.",
    35: "Ferrari L, Habbati B, Guerar M, et al. PolicyGapper: Automated Detection of Inconsistencies Between Google Play Data Safety Sections and Privacy Policies Using LLMs[EB/OL]. arXiv:2604.16128, 2026.",
    36: "Wang S, Li Y, Wang K, et al. MiniScope: Automated UI Exploration and Privacy Inconsistency Detection of MiniApps via Two-phase Iterative Hybrid Analysis[J]. ACM Transactions on Software Engineering and Methodology, 2025, 34(6).",
    37: "Zhang Z, Li Z, Jiang Z, et al. PriAgent: A Collaborative Multi-Agent Framework for Auditing Android Privacy Compliance[C]//Proceedings of the AAAI Conference on Artificial Intelligence. 2026.",
    39: "百度智能云. 史宾格安全及隐私合规平台[EB/OL]. https://cloud.baidu.com/product/springer.html.",
    40: "阿里云. App隐私合规检测服务[EB/OL]. https://developer.aliyun.com/article/799068.",
    41: "梆梾安全. 移动应用合规平台[EB/OL]. https://www.bangcle.com/pages/cat_id/6.html.",
    42: "华为云. 移动应用个人信息安全检测平台[EB/OL]. https://marketplace.huaweicloud.com/contents/b346eaaa-f33b-4d3f-ae5a-1e91d59e4849.",
    43: "汉华信安. APP个人信息收集行为检测系统[EB/OL]. http://www.bjhhxa.com.cn/?p=707.",
    44: "stonehill. PackagePrivacy: 基于包的安卓静态隐私合规检测工具[CP/OL]. https://github.com/stonehill-2345/package-privacy.",
    45: "Oncecheck. Oncecheck CLI: A Terminal-first Compliance Scanner[CP/OL]. https://pypi.org/project/oncecheck/.",
    46: "SubmitGate. Catch App Store Rejections Before You Submit[EB/OL]. https://submit-gate.com/.",
    47: "Ran H, Zhang H, Tang X. GDPR-Bench-Android[EB/OL]. arXiv:2511.00619, 2025.",
    48: "Zhang Y, Hu Z, Wang X, et al. Navigating the Privacy Compliance Maze: Understanding Risks with Privacy-Configurable Mobile SDKs[C]//33rd USENIX Security Symposium. 2024: 6543-6560.",
    49: "Morel V, Santos C, Carlsson P, et al. The TCF doesn't really A(A)ID: Automatic Privacy Analysis and Legal Compliance of TCF-based Android Applications[C]//Proceedings on Privacy Enhancing Technologies (PETS). 2026.",
}

# ============================================================
# 3. 重排 1.2 之外正文的旧引用编号
# ============================================================
# 正文里只在第四章出现 [26]/[30]/[31]/[32]
BODY_MAP = {26: 30, 30: 50, 31: 51, 32: 52}
pat = re.compile(r"\[(\d+)\]")

def bump_body(m):
    n = int(m.group(1))
    return "[%d]" % BODY_MAP[n] if n in BODY_MAP else m.group(0)

in_ref = set(id(p._p) for p in ref_paras)
in_12 = set()
collect = False
for p in paras:
    t = p.text.strip()
    if t == "1.2 国内外研究现状":
        collect = True
        continue
    if t == "1.3 存在的问题":
        collect = False
    if collect:
        in_12.add(id(p._p))

warn = 0
cnt = 0
for p in paras:
    if id(p._p) in in_12 or id(p._p) in in_ref:
        continue
    n_par = len(pat.findall(p.text))
    n_run = 0
    for r in p.runs:
        hits = pat.findall(r.text)
        n_run += len(hits)
        if hits:
            r.text = pat.sub(bump_body, r.text)
    if n_par != n_run:
        warn += 1
        print("!! 拆分引用段落:", p.text[:60])
    cnt += n_run
for t in doc.tables:
    for row in t.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for r in p.runs:
                    if pat.search(r.text):
                        r.text = pat.sub(bump_body, r.text)
print("正文旧引用重排: %d 处, 拆分告警 %d" % (cnt, warn))
assert warn == 0

# ============================================================
# 4. 新 1.2 章节内容（c = 上标引用）
# ============================================================
C = lambda n: ("c", n)

CONTENT = [
    ("body", [
        ("t", "当前，移动应用隐私数据泄露检测与合规评估已形成多维度的研究与工程体系，其核心目标是弥合法规文本、隐私政策声明与应用实际行为之间的鸿沟。相关工作主要围绕三个层面展开：学术研究沿“程序分析—声明与行为一致性验证—AI/LLM 智能化检测”的路径持续演进；行业实践将检测能力产品化、平台化，嵌入开发与监管流程；评估基准与大规模实证研究则不断揭示当前应用生态的系统性缺陷。"),
    ]),
    ("h3", "1.2.1 学术研究：从程序分析到语义理解"),
    ("body", [
        ("t", "学术界的检测工作可划分为基于程序分析的敏感数据流检测、隐私政策与代码行为的一致性验证，以及 AI/LLM 驱动的智能化合规检测三个方向，整体呈现出从“看得见行为”向“读得懂政策”演进的轨迹。"),
    ]),
    ("body", [
        ("b", "基于程序分析的敏感数据流检测。"),
        ("t", "这是最基础的技术路径，旨在追踪敏感数据在应用内部的流动与对外传输。静态方向在不运行应用的前提下，从清单、字节码与资源中提取线索：权限与清单分析将声明的权限与业务功能、必要范围对照，但 Android 权限模型与设备标识的可用性随系统版本与目标 SDK 变化，声明不等于可用"),
        C(13), C(14),
        ("t", "；方法调用匹配借助 JADX 等反编译工具定位对设备标识、位置、通讯录等敏感接口的引用"),
        C(15),
        ("t", "。在数据流方向，FlowDroid 建立了上下文、流、字段、对象敏感且生命周期感知的污点分析框架，追踪敏感数据从“源”（如获取位置、通讯录的接口）到“汇”（如网络发送、文件写入的接口）的路径，成为静态污点分析的代表性工作"),
        C(16),
        ("t", "；王蕾等的多源污点分析融合多个来源的信息以降低单一来源的漏报与误报"),
        C(17),
        ("t", "，张捷等基于污染变量关系图改进污点传播的精度与效率"),
        C(18),
        ("t", "。近期工作着重提升可扩展性与适应性：GNChecker 采用分段策略缩小静态数据流分析的搜索范围，在 1134 个应用中识别出 379 个存在不合规数据传输的应用"),
        C(19),
        ("t", "；KASTroid 面向 Kotlin 应用构建专用的静态污点分析框架"),
        C(20),
        ("t", "；AndroByte 利用 LLM 对字节码进行摘要并动态生成数据流调用图，以摆脱对预定义规则与汇点列表的依赖，在泄漏检测上取得 89% 的 Fβ-Score"),
        C(21),
        ("t", "。静态分析的局限依然明显：权限声明与接口引用只说明应用具备访问能力，不能证明调用被实际执行，代码混淆与反射还会进一步影响可见性。"),
    ]),
    ("body", [
        ("t", "动态分析通过运行应用、触发业务路径来观测真实发生的数据流与网络传输，能发现被混淆或仅在特定条件下触发的行为，也常用于验证静态分析的结果。Wijesekera 等通过大规模现场研究揭示了 Android 权限在真实使用中的上下文依赖，指出同一权限在不同场景下的合理性差异很大"),
        C(22),
        ("t", "，其后续工作进一步讨论了动态授予权限与用户偏好对齐的可行性"),
        C(23),
        ("t", "；Reardon 等系统梳理了应用绕过权限系统、从替代来源获取敏感数据的多种方式，说明仅依赖静态权限声明会明显低估风险"),
        C(24),
        ("t", "。工具与系统层面，AntMonitor 在终端侧对网络流量进行运行时监控，支撑大规模、分布式的隐私行为测量"),
        C(25),
        ("t", "；LeakSemantic 结合静态与动态分析并引入机器学习区分合法与异常的敏感网络传输，在 1404 个应用上达到 91% 的准确率"),
        C(26),
        ("t", "。工程实践中，Frida 等插桩框架提供了跨平台的动态 Hook 能力"),
        C(27),
        ("t", "，mitmproxy 等代理工具支持对移动端流量的截获与解析"),
        C(28),
        ("t", "，OWASP MASTG 给出了移动应用安全测试的方法论参考"),
        C(29),
        ("t", "。传输侧研究还表明，即便载荷已加密，报文长度、时序与方向等元数据仍可能构成泄露用户行为的侧信道"),
        C(30),
        ("t", "。动态分析的局限在于结果受触发路径影响：未覆盖的业务分支无法观测，“未观测到”不等同于“不存在”。"),
    ]),
    ("body", [
        ("b", "隐私政策与代码行为的一致性验证。"),
        ("t", "这类工作直接回应合规的核心要求：应用的实际行为是否与其隐私政策中的声明相符。早期工作将政策文本映射到代码数据流：Zimmeck 等较早提出基于自然语言的隐私需求自动化分析方法"),
        C(31),
        ("t", "；Andow 等提出的 PoliCheck 面向实体敏感的隐私政策与数据流分析，将政策条款与代码中的数据流对应"),
        C(32),
        ("t", "；Meng 等评估了 Android 第三方 SDK 的隐私披露合规性，指出 SDK 可在宿主业务之外触发数据访问、责任主体难以定位"),
        C(33),
        ("t", "。近期工作进一步引入 LLM 提升政策理解能力：PIChecker 结合静态与动态程序分析捕获隐私相关数据流，并利用 LLM 解读非结构化的政策文本，专门检测第三方库（TPL）行为与政策声明的不一致，其对 147 个流行应用的评估发现，除去 17 个无隐私政策的应用，超过 64% 未能准确描述内嵌 TPL 的隐私行为"),
        C(34),
        ("t", "。除政策文本外，应用商店的数据安全部分（DSS）也是重要的声明来源：PolicyGapper 利用 LLM 自动检测 Google Play 的 DSS 声明与隐私政策文本之间的差异，在 330 个头部应用中发现 2689 处声明缺失"),
        C(35),
        ("t", "；MiniScope 面向小程序，通过两阶段混合分析检测其 UI 交互提示与实际隐私行为的不一致"),
        C(36),
        ("t", "。"),
    ]),
    ("body", [
        ("b", "AI/LLM 驱动的智能化合规检测。"),
        ("t", "大语言模型的引入正在把合规检测从规则匹配推向语义理解与推理。一类工作让 LLM 直接参与合规判断：已有研究探索利用 LLM 分析反编译代码以识别 GDPR 违规的可行性，PriAgent 将合规审计构建为多阶段、AI 驱动的推理任务，通过协作式多智能体框架提升审计能力"),
        C(37),
        ("t", "；Xiang 等利用 LLM 识别 Android 应用的隐私政策违规"),
        C(38),
        ("t", "。另一类工作将 LLM 定位为增强组件，以规避其“过度对齐偏差”（即虚构不存在的政策-代码关系）：混合方法把确定性检查交给程序分析与知识图谱，LLM 仅承担初步语义分析，PIChecker 中“证据来自程序分析、LLM 负责政策解读”的分工即体现了这一思路"),
        C(34),
        ("t", "。"),
    ]),
    ("h3", "1.2.2 行业实践：平台化与工程化的合规工具"),
    ("body", [
        ("t", "工业界的工作侧重于将检测能力产品化、平台化，以满足应用上架前自查、监管审查和持续监控的需求。综合性云检测平台方面，百度智能云“史宾格”安全及隐私合规平台通过 AI 云端手机模拟应用运行场景、实时监控隐私行为，并将检测项与《App 违法违规收集使用个人信息行为认定方法》等法规标准逐条对应"),
        C(39),
        ("t", "；阿里云的 App 隐私合规检测服务结合静态检测、动态监测与场景检测，覆盖隐私政策、敏感权限与数据采集使用等维度，并辅以专家复核"),
        C(40),
        ("t", "；梆梾安全的移动应用合规平台面向监管机构、测评机构与企业开发者，全面排查 App 隐私权限调用行为"),
        C(41),
        ("t", "；华为云云商店亦上架了针对 App、SDK 和小程序的个人信息安全检测平台"),
        C(42),
        ("t", "。这类平台通常将自动化检测与人工深度测试相结合，输出合规评估报告与整改建议。"),
    ]),
    ("body", [
        ("t", "行业工具也开始集成 AI 能力。汉华信安的 APP 个人信息收集行为检测系统在传统沙箱技术基础上引入 AI Agent，自动遍历应用界面、触发业务场景，并将检测到的实际收集行为与 AI 解读出的隐私政策声明自动比对研判，定位为“全自动 AI 合规审计专家”"),
        C(43),
        ("t", "。面向开发者的轻量级、可集成工具也在出现：开源工具 PackagePrivacy 将应用下载、反编译、隐私敏感 API 静态检测与合规报告生成封装为工具链，并提供 MCP 接口供大模型调用"),
        C(44),
        ("t", "；Oncecheck 与 SubmitGate 则是面向 CI/CD 流程的合规风险扫描 CLI 工具，支持在开发阶段执行确定性检查并以退出码拦截不合规构建"),
        C(45), C(46),
        ("t", "。"),
    ]),
    ("h3", "1.2.3 评估基准与研究发现"),
    ("body", [
        ("t", "为系统评估各类检测方法，研究者构建了专门的基准数据集。GDPR-Bench-Android 是首个评估 Android 应用 GDPR 合规检测方法的综合性基准，包含 1951 个人工标注的违规实例，覆盖 23 条 GDPR 条款，并在文件、模块、行等多个粒度上对 LLM、检索增强生成、智能体与形式化方法进行了评测；结果显示不同方法在不同任务上各有优劣，尚无单一范式在所有场景下胜出"),
        C(47),
        ("t", "。"),
    ]),
    ("body", [
        ("t", "大规模实证研究进一步揭示了当前生态的系统性缺陷。除前述 PIChecker 发现的 TPL 披露缺失问题"),
        C(34),
        ("t", "外，Zhang 等对 65 个提供隐私配置能力的 SDK 与 48000 余个 Google Play 应用的分析发现，大量应用未能正确使用 SDK 提供的隐私配置 API，“包装器 SDK”常常无法将隐私配置准确传递给底层 SDK，形成隐蔽的合规风险"),
        C(48),
        ("t", "；针对 IAB 透明与同意框架（TCF）的大规模测量同样表明，该框架难以在 Android 生态中有效保障法律合规性"),
        C(49),
        ("t", "。第三方库行为不透明、声明与实践系统性脱节，已成为该领域的共性问题。"),
    ]),
    ("h3", "1.2.4 现状小结"),
    ("body", [
        ("t", "总体来看，移动 App 隐私合规检测已从早期单一的静态污点分析，发展为融合静态/动态程序分析、自然语言处理、知识图谱与 LLM 推理的多技术栈体系：学术前沿聚焦 LLM 的深度应用与混合架构优化，行业实践则将检测能力封装为面向开发与监管流程的平台化工具。就本项目所依赖的三条基础技术路线而言，表 1-1 从方法、证据与局限三方面对其进行了归纳。"),
    ]),
    ("caption", "表1-1 移动应用隐私检测三条技术路线对照"),
    ("TABLE", None),
    ("body", [
        ("t", "然而，现有工作仍存在明显的能力边界：静态线索、动态事件与流量事实往往由不同工具分别产出，缺少统一的样本、会话与时间标识，难以确认它们属于同一应用、同一操作，难以串成可回查的证据链；政策语义与业务事实的对照仍较多依赖人工，不同检测范式在覆盖面与精度上各有取舍。本项目以此为切入点，围绕三条路线采集事实并建立统一证据关联，再结合隐私政策与用户选择开展合规研判。"),
    ]),
]

# ============================================================
# 5. 删除原 1.2 段落（保留表格），插入新段落
# ============================================================
tbl = None
for t in doc.tables:
    if "静态" in t.rows[0].cells[0].text or "技术路线" in t.rows[0].cells[0].text:
        tbl = t
        break
assert tbl is not None, "未找到技术路线对照表"
assert "静态" in tbl.rows[1].cells[0].text, "表格内容不符"

# 删除 1.2 区间段落（不含两个标题）
for p in list(paras):
    if id(p._p) in in_12:
        p._p.getparent().remove(p._p)
print("原 1.2 段落已删除")


def make_run(kind, payload):
    r = OxmlElement("w:r")
    if kind == "c":
        r.append(copy.deepcopy(cite_rpr_xml))
        t = OxmlElement("w:t")
        t.text = "[%d]" % payload
        r.append(t)
    else:
        rpr = copy.deepcopy(tpl_body_rpr) if tpl_body_rpr is not None else OxmlElement("w:rPr")
        if kind == "b":
            if rpr is None:
                rpr = OxmlElement("w:rPr")
            rpr.append(OxmlElement("w:b"))
        if rpr is not None:
            r.append(rpr)
        t = OxmlElement("w:t")
        t.set(qn("xml:space"), "preserve")
        t.text = payload
        r.append(t)
    return r


def make_para(kind, segments_or_text):
    p = OxmlElement("w:p")
    if kind == "h3":
        p.append(copy.deepcopy(tpl_h3_ppr))
        r = OxmlElement("w:r")
        rpr = copy.deepcopy(tpl_body_rpr) if tpl_body_rpr is not None else None
        # 标题 run 用标题段落自身样式即可，不强制 rPr
        t = OxmlElement("w:t")
        t.text = segments_or_text
        r.append(t)
        p.append(r)
    elif kind == "caption":
        p.append(copy.deepcopy(tpl_cap_ppr))
        p.append(make_run("t", segments_or_text))
    else:
        p.append(copy.deepcopy(tpl_body_ppr))
        for seg in segments_or_text:
            p.append(make_run(seg[0], seg[1]))
    return p

for item in CONTENT:
    kind = item[0]
    if kind == "TABLE":
        continue
    new_p = make_para(kind, item[1])
    if item is CONTENT[-1]:  # 最后一段（桥接段）放表格之后
        tbl._element.addnext(new_p)
    else:
        tbl._element.addprevious(new_p)
print("新 1.2 段落已插入")

# ============================================================
# 6. 重建参考文献列表（52 条）
# ============================================================
# 旧条目映射到新编号
final_refs = {}
for old_n, txt in ref_texts.items():
    new_n = OLD2NEW[old_n]
    final_refs[new_n] = txt
for new_n, txt in NEW_REFS.items():
    assert new_n not in final_refs, "编号冲突 %d" % new_n
    final_refs[new_n] = txt
total = max(final_refs)
missing = [n for n in range(1, total + 1) if n not in final_refs]
assert not missing, "缺条目: %s" % missing
print("参考文献共 %d 条，编号连续" % total)

# 在第一条旧参考文献位置之前逐条插入，再删除旧条目
anchor = ref_paras[0]._p
for n in range(1, total + 1):
    p = OxmlElement("w:p")
    p.append(copy.deepcopy(tpl_ref_ppr))
    r = OxmlElement("w:r")
    if tpl_ref_rpr is not None:
        r.append(copy.deepcopy(tpl_ref_rpr))
    t = OxmlElement("w:t")
    t.set(qn("xml:space"), "preserve")
    t.text = "[%d] %s" % (n, final_refs[n])
    r.append(t)
    p.append(r)
    anchor.addprevious(p)
for p in ref_paras:
    p._p.getparent().remove(p._p)
print("参考文献列表已重建")

doc.save(DST)
print("已保存:", DST)
