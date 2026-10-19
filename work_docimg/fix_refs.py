# -*- coding: utf-8 -*-
"""修正 设计文档1.6.docx：
1. 参考文献条目去掉重建时残留的双重 "[n] [m]" 前缀
2. 因用户调整了 1.1 段落顺序（法律段前移），[2]-[12] 按首次出现顺序重排：
   新2-8 = 旧6-12（法律类），新9-12 = 旧2-5（工信部/电信/滴滴）
"""
import copy
import re
import sys

sys.stdout.reconfigure(encoding="utf-8")
from docx import Document
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

F = "设计文档1.6.docx"
doc = Document(F)
paras = doc.paragraphs

pat = re.compile(r"\[(\d+)\]")

# ---------- 1. 提取参考文献条目（去双前缀） ----------
ref_paras = []
clean_texts = {}
for p in paras:
    t = p.text.strip()
    m = re.match(r"^\[(\d+)\]\s+", t)
    if m and p.style.name == "Normal":
        n = int(m.group(1))
        rest = t[m.end():]
        rest = re.sub(r"^\[\d+\]\s*", "", rest)  # 去第二重前缀
        if 1 <= n <= 52 and len(rest) > 10:
            ref_paras.append(p)
            clean_texts[n] = rest
assert len(ref_paras) == 52, len(ref_paras)
tpl_ref_ppr = copy.deepcopy(ref_paras[0]._p.pPr)
tpl_ref_rpr = None
for r in ref_paras[0].runs:
    if r.text.strip():
        tpl_ref_rpr = copy.deepcopy(r._r.rPr)
        break

# ---------- 2. 正文引用重排 [2]-[12] ----------
MAP = {2: 9, 3: 10, 4: 11, 5: 12, 6: 2, 7: 3, 8: 4, 9: 5, 10: 6, 11: 7, 12: 8}
ref_ids = set(id(p._p) for p in ref_paras)

def bump(m):
    n = int(m.group(1))
    return "[%d]" % MAP[n] if n in MAP else m.group(0)

warn = 0
cnt = 0
for p in paras:
    if id(p._p) in ref_ids:
        continue
    n_par = len([x for x in pat.findall(p.text) if int(x) in MAP])
    n_run = 0
    for r in p.runs:
        hits = [x for x in pat.findall(r.text) if int(x) in MAP]
        n_run += len(hits)
        if hits:
            r.text = pat.sub(bump, r.text)
    if n_par != n_run:
        warn += 1
        print("!! 拆分:", p.text[:60])
    cnt += n_run
for t in doc.tables:
    for row in t.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for r in p.runs:
                    if pat.search(r.text):
                        r.text = pat.sub(bump, r.text)
print("正文 [2]-[12] 重排: %d 处, 拆分告警 %d" % (cnt, warn))
assert warn == 0

# ---------- 3. 重建参考文献列表 ----------
# 新编号 -> 旧编号（条目文本取自 clean_texts[旧]）
ENTRY_MAP = {1: 1}
ENTRY_MAP.update({n: n - 4 for n in range(2, 9)})     # 新2-8 <- 旧... wait: 新2=旧6 => new->old = {2:6,...,8:12}
ENTRY_MAP.update({9: 2, 10: 3, 11: 4, 12: 5})
ENTRY_MAP.update({n: n for n in range(13, 53)})
# 修正上面的推导错误，直接写全
ENTRY_MAP = {
    1: 1,
    2: 6, 3: 7, 4: 8, 5: 9, 6: 10, 7: 11, 8: 12,
    9: 2, 10: 3, 11: 4, 12: 5,
}
ENTRY_MAP.update({n: n for n in range(13, 53)})
assert set(ENTRY_MAP.values()) == set(range(1, 53))

anchor = ref_paras[0]._p
for new_n in range(1, 53):
    old_n = ENTRY_MAP[new_n]
    p = OxmlElement("w:p")
    p.append(copy.deepcopy(tpl_ref_ppr))
    r = OxmlElement("w:r")
    if tpl_ref_rpr is not None:
        r.append(copy.deepcopy(tpl_ref_rpr))
    t = OxmlElement("w:t")
    t.set(qn("xml:space"), "preserve")
    t.text = "[%d] %s" % (new_n, clean_texts[old_n])
    r.append(t)
    p.append(r)
    anchor.addprevious(p)
for p in ref_paras:
    p._p.getparent().remove(p._p)
print("参考文献列表已重建（52 条，单前缀，按新序）")

doc.save(F)
print("已保存:", F)
