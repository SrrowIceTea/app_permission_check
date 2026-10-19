# -*- coding: utf-8 -*-
"""编辑 设计文档1.4.docx：
1. 删除表1-1（工信部通报表），换成自绘统计图（图1-1）
2. 第三方观测段落后插入官方报告原图两幅（图1-2 / 图1-3）
3. 插入滴滴重大事件段落（新参考文献 [5]，后续引用整体 +1）
4. 表1-2 重编号为 表1-1
输出：设计文档1.5.docx（原文件保留）
"""
import copy
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
from docx import Document
from docx.shared import Pt
from docx.text.paragraph import Paragraph
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

SRC = "设计文档1.4.docx"
DST = "设计文档1.5.docx"
IMGDIR = "../work_docimg"

doc = Document(SRC)

# ---------- 工具 ----------
def new_paragraph_after(anchor_par, ppr_source=None, remove_keepnext=False):
    """在 anchor_par 之后插入新段落，可选复制 pPr"""
    new_p = OxmlElement("w:p")
    anchor_par._p.addnext(new_p)
    np = Paragraph(new_p, anchor_par._parent)
    if ppr_source is not None and ppr_source._p.pPr is not None:
        ppr = copy.deepcopy(ppr_source._p.pPr)
        if remove_keepnext:
            for kn in ppr.findall(qn("w:keepNext")):
                ppr.remove(kn)
        new_p.insert(0, ppr)
    return np

def set_single_text(par, text):
    """清空段落所有 run，保留第一个 run 的格式，写入 text"""
    runs = par.runs
    if not runs:
        par.add_run(text)
        return
    first = runs[0]
    for r in runs[1:]:
        r._r.getparent().remove(r._r)
    first.text = text

def clear_runs(par):
    for r in list(par.runs):
        r._r.getparent().remove(r._r)

# ---------- 第 0 步：引用编号 [5..31] -> [6..32] ----------
pat = re.compile(r"\[(\d+)\]")
def bump(m):
    n = int(m.group(1))
    return "[%d]" % (n + 1) if n >= 5 else m.group(0)

split_warn = 0
cnt_all = 0
for p in doc.paragraphs:
    n_par = len(pat.findall(p.text))
    n_run = 0
    for r in p.runs:
        hits = pat.findall(r.text)
        n_run += len(hits)
        if hits:
            r.text = pat.sub(bump, r.text)
    if n_par != n_run:
        split_warn += 1
        print("!! 拆分引用段落:", p.text[:60])
    cnt_all += n_run
for t in doc.tables:
    for row in t.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for r in p.runs:
                    if pat.search(r.text):
                        r.text = pat.sub(bump, r.text)
print("引用重编号完成：处理 %d 处，拆分告警 %d 处" % (cnt_all, split_warn))
assert split_warn == 0, "存在跨 run 拆分的引用，需人工处理"

# ---------- 定位关键段落（按文本找，不依赖索引） ----------
paras = doc.paragraphs
p88 = p89 = p90 = p91 = p92 = None
for p in paras:
    t = p.text
    if t.startswith("监管部门多年治理的结果反映出"):
        p88 = p
    elif t.startswith("表1-1 工业和信息化部"):
        p89 = p
    elif t.startswith("数据来源：工业和信息化部信息通信管理局"):
        p90 = p
    elif t.startswith("第三方观测进一步刻画了"):
        p91 = p
    elif t.startswith("中央层面已经形成以法律为主干"):
        p92 = p
assert all(x is not None for x in (p88, p89, p90, p91, p92)), "定位失败"

# 取 [4] 引用 run 的格式（上标），供新段落引用编号用
cite_rpr = None
for r in p91.runs:
    if r.text.strip() == "[4]":
        cite_rpr = copy.deepcopy(r._r.rPr)
        break

# ---------- 1. 正文引用 表1-1 -> 图1-1 ----------
for r in p88.runs:
    if "表 1-1" in r.text:
        r.text = r.text.replace("表 1-1", "图 1-1")
print("p88 引用已改为 图1-1")

# ---------- 2. 删除表1-1 ----------
tbl = doc.tables[0]
assert "年份" in tbl.rows[0].cells[0].text, "表0 不是通报表"
tbl._element.getparent().remove(tbl._element)
print("表1-1 已删除")

# ---------- 3. 图1-1：自绘图插到表题前，表题改为图题 ----------
cap_style = p89  # 居中图题样式
img_par = new_paragraph_after(p88, ppr_source=p89, remove_keepnext=False)
# 需要插到 p89 之前：p88 在 p89 之前吗？p88 之后是 p89（原表题），新段落在 p88 后即表题前，正确
img_par.alignment = WD_ALIGN_PARAGRAPH.CENTER
run = img_par.add_run()
run.add_picture(IMGDIR + "/fig_miit.png", width=Pt(415))
set_single_text(p89, "图1-1 工业和信息化部 App（SDK）侵害用户权益通报情况（2023—2026 年 10 月）")
print("图1-1 已插入")

# ---------- 4. 第三方观测段补图引用 ----------
done91 = False
for r in p91.runs:
    if r.text.startswith("。由此可见"):
        r.text = "（图 1-2、图 1-3）" + r.text
        done91 = True
        break
assert done91, "p91 未找到 '。由此可见' run"
print("p91 已补图引用")

# ---------- 5. 图1-2 / 图1-3 + 图源 + 滴滴段落 ----------
anchor = p91
# 图1-2 图
img2 = new_paragraph_after(anchor, ppr_source=p90)
img2.alignment = WD_ALIGN_PARAGRAPH.CENTER
img2.add_run().add_picture(IMGDIR + "/fig3.jpg", width=Pt(400))
anchor = img2
# 图1-2 图题
cap2 = new_paragraph_after(anchor, ppr_source=p89, remove_keepnext=True)
set_single_text(cap2, "图1-2 Android 应用个人信息自动化检测违规类型分布（2022—2024 年）")
anchor = cap2
# 图1-3 图
img3 = new_paragraph_after(anchor, ppr_source=p90)
img3.alignment = WD_ALIGN_PARAGRAPH.CENTER
img3.add_run().add_picture(IMGDIR + "/fig4.jpg", width=Pt(400))
anchor = img3
# 图1-3 图题
cap3 = new_paragraph_after(anchor, ppr_source=p89, remove_keepnext=True)
set_single_text(cap3, "图1-3 Android 应用敏感行为类型分布")
anchor = cap3
# 图源说明
srcn = new_paragraph_after(anchor, ppr_source=p90)
set_single_text(srcn, "数据来源：中国电信安全公司《2024 年全国移动应用安全观测报告》[4]。")
anchor = srcn

# 滴滴事件段落（正文样式复制 p88）
didi = new_paragraph_after(anchor, ppr_source=p88)
clear_runs(didi)
didi_text = (
    "重大数据安全事件进一步印证了隐私风险的现实危害。2021 年 7 月，国家互联网信息办公室通报"
    "\u201c滴滴出行\u201dApp 存在严重违法违规收集使用个人信息问题，通知各应用商店将其下架并启动网络安全审查；"
    "2022 年 7 月，国家互联网信息办公室依据《网络安全法》《数据安全法》《个人信息保护法》等对滴滴全球股份"
    "有限公司作出网络安全审查相关行政处罚决定，查明其存在违法收集用户手机相册截图信息 1196.39 万条、"
    "过度收集剪切板信息与应用列表信息 83.23 亿条、过度收集乘客人脸识别信息 1.07 亿条、在未明确告知乘客"
    "的情况下分析乘客出行意图信息 539.76 亿条等 16 项违法事实，违法处理个人信息总量达 647.09 亿条，"
    "对滴滴公司处以罚款人民币 80.26 亿元，并对董事长兼 CEO 程维、总裁柳青各处 100 万元罚款"
)
tail_text = (
    "。该事件表明，头部应用的敏感数据采集规模与隐蔽程度远超一般预期，违规采集可以在用户长期"
    "无感知的情况下持续发生，仅依靠企业自律与权限清单层面的静态检查难以防范，亟需可复核的自动化"
    "检测与合规评估手段。"
)
r1 = didi.add_run(didi_text)
rc = didi.add_run("[5]")
if cite_rpr is not None:
    rc._r.insert(0, copy.deepcopy(cite_rpr))
r2 = didi.add_run(tail_text)
print("滴滴段落已插入")

# ---------- 6. 新参考文献 [5] ----------
ref4 = None
for p in doc.paragraphs:
    if p.text.strip().startswith("[4] 中国电信安全公司"):
        ref4 = p
        break
assert ref4 is not None, "未找到参考文献 [4]"
new_ref = new_paragraph_after(ref4, ppr_source=ref4)
set_single_text(
    new_ref,
    "[5] 国家互联网信息办公室. 国家互联网信息办公室对滴滴全球股份有限公司依法作出网络安全审查"
    "相关行政处罚的决定[EB/OL]. 网信中国, 2022. https://www.cac.gov.cn/2022-07/21/c_1660021534364976.htm.",
)
print("新参考文献 [5] 已插入")

# ---------- 7. 表1-2 -> 表1-1 ----------
n_renum = 0
for p in doc.paragraphs:
    if "表 1-2" in p.text or "表1-2" in p.text:
        for r in p.runs:
            if "表 1-2" in r.text or "表1-2" in r.text:
                r.text = r.text.replace("表 1-2", "表 1-1").replace("表1-2", "表1-1")
                n_renum += 1
print("表1-2 -> 表1-1 改写 %d 处" % n_renum)

doc.save(DST)
print("已保存:", DST)
