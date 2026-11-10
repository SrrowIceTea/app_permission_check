#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 只读覆盖统计：`observed_surface`（观测面）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

这是**覆盖统计**，不是结论：不产出候选、不改四桶、不进报告结论、不产 policy_violation。
作用域由独立文件 `mobile/rules/targets/sensitive_surface_v1.json` 固定（`surface_target`），
与 `dangerous_apis` / `rules_mobile.db` 物理无关；本模块只**读**规则库来判定「闭集是否登记」。

两个分母必须同时给出，禁止只取一个：
  * 签名面：该样本敏感类上出现过的不同 `(类, 方法, 描述符)`；
  * 调用点：这些签名被 `invoke-*` 的次数（跨 dex 累加）。
分子只认 `dangerous_apis` 的精确三元组——那是闭集唯一能变成候选的形态。
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.evidence.dexlines import find_dexdump  # noqa: E402
from mobile.tools import surface_target  # noqa: E402
from mobile.tools.dex_callgraph import apk_sha256, tool_fingerprint  # noqa: E402
from mobile.tools.static_supplement import _mapped_data_types  # noqa: E402

RULES_DB = HERE.parent / "rules" / "rules_mobile.db"
DEFAULT_VERSION = "36"
MAX_ROWS = 500
STATEMENT = ("样本内不可见 {sig:.2%}（签名面 {sig_u}/{sig_t}）；按调用点加权 {call:.2%}"
             "（{call_u}/{call_t}）。这是**样本内口径**：分母只含该样本实际调到的敏感签名，"
             "不代表 Android 全部敏感 API，也不是行业结论；不得折算成检出率，"
             "不得与四桶统计相加或加权。")
LIMITATIONS = [
    "分母随样本变化：某敏感 API 该样本没调用就不在分母里，跨样本只能比各自比例，不能比大小。",
    "方法句柄 / invoke-custom / invoke-polymorphic 不展开，经它们的敏感调用不可见（低估分母）。",
    "静态 final 字段值会被编译期内联，字段通道单列在 field_reads，不进本分母。",
    "只扫 classes*.dex；assets/ 内的二次 dex（加固/动态加载）不在内。",
    "「登记」只表示 dangerous_apis 有精确三元组；能否变成候选还取决于该行是否有 data_type 映射，"
    "registered[].mapped 给出这一点。",
]
INVOKE_RE = re.compile(
    r"invoke-(?:virtual|static|direct|super|interface)(?:/range)?\s+\{[^}]*\},\s*"
    r"L(?P<cls>[^;]+);\.(?P<method>[^:\s]+):(?P<desc>\([^)]*\)\S*)")
FIELD_READ_RE = re.compile(
    r"\b(?:sget|iget)(?:-[a-z]+)?\s+[^,{}]+,\s*L(?P<cls>[^;]+);\.(?P<name>[^:\s]+):")


class ScanError(RuntimeError):
    """dex 扫描失败（与「扫到了但没命中」严格区分）。"""


def scan_apk(apk: Path, dexdump: str | None = None) -> dict:
    """扫全部 classes*.dex，返回敏感候选目标的出现次数与字段读取。"""
    dexdump = dexdump or find_dexdump()
    sigs: dict[tuple[str, str, str], int] = {}
    fields: dict[tuple[str, str], int] = {}
    with zipfile.ZipFile(apk) as zf:
        names = sorted(n for n in zf.namelist()
                       if n.startswith("classes") and n.endswith(".dex"))
        if not names:
            raise ScanError("no_dex")
        with tempfile.TemporaryDirectory(prefix="vscan-surface-") as tmp:
            for name in names:
                path = Path(zf.extract(name, tmp))
                proc = subprocess.Popen(
                    [dexdump, "-d", str(path)], stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    errors="replace", bufsize=1 << 20)
                assert proc.stdout is not None
                for line in proc.stdout:
                    if "invoke-" in line:
                        m = INVOKE_RE.search(line)
                        if m:
                            key = (m["cls"].replace("/", "."), m["method"], m["desc"])
                            sigs[key] = sigs.get(key, 0) + 1
                    elif "get" in line:
                        m = FIELD_READ_RE.search(line)
                        if m:
                            key = (m["cls"].replace("/", "."), m["name"])
                            fields[key] = fields.get(key, 0) + 1
                err = proc.stderr.read() if proc.stderr else ""
                assert proc.stdout is not None
                proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()
                if proc.wait() != 0:
                    raise ScanError(f"dexdump 失败（{name} 退出码 {proc.returncode}）：{err[-400:]}")
    return {"sigs": sigs, "fields": fields, "dex_count": len(names),
            "dexdump_fingerprint": tool_fingerprint(dexdump)}


def closed_set(rules_db: Path, version: str) -> dict:
    """闭集三视图：精确三元组 / 类+方法（重载）/ 类；附带 data_type 映射。"""
    conn = sqlite3.connect(f"file:{Path(rules_db).resolve().as_posix()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        versions = [r[0] for r in conn.execute(
            "SELECT DISTINCT android_version FROM dangerous_apis")]
        rows = [dict(r) for r in conn.execute(
            "SELECT class_name, method_name, jvm_descriptor, data_type_key, "
            "observation_spec_json FROM dangerous_apis WHERE android_version = ?", (version,))]
    finally:
        conn.close()
    if not rows:
        # 空闭集会让所有签名都判成 class_gap，输出一个看似严谨的 100% —— 宁可停下。
        raise SystemExit(f"[fatal] dangerous_apis 没有 android_version={version!r} 的行；"
                         f"可用版本 {sorted(versions)}（移动库是 API level，不是 13/14/15/16）")
    sigs, pairs, classes, types = set(), set(), set(), {}
    for r in rows:
        cls, meth, desc = r["class_name"], r["method_name"], r["jvm_descriptor"]
        sigs.add((cls, meth, desc))
        pairs.add((cls, meth))
        classes.add(cls)
        mapped, _basis = _mapped_data_types(r)
        types[(cls, meth, desc)] = mapped
    return {"sigs": sigs, "pairs": pairs, "classes": classes, "types": types,
            "rows": len(rows), "version": version}


def _form(cls: str, method: str, desc: str, closed: dict) -> str:
    if (cls, method, desc) in closed["sigs"]:
        return "exact"
    if (cls, method) in closed["pairs"]:
        return "overload"
    return "method_gap" if cls in closed["classes"] else "class_gap"


def _share(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def observe(scan: dict, closed: dict, ts: dict) -> dict:
    """把扫描结果与闭集对齐，产出两分母统计（只读，不改任何候选）。"""
    matcher = surface_target.Matcher(ts)
    rows = []
    for (cls, method, desc), calls in scan["sigs"].items():
        cats = matcher.categories(cls)
        if not cats or not matcher.accepts(cls, method):
            continue
        form = _form(cls, method, desc, closed)
        mapped = closed["types"].get((cls, method, desc)) or []
        rows.append({"class": cls, "method": method, "descriptor": desc,
                     "categories": cats, "group": matcher.group(cls), "form": form,
                     "registered": form == "exact", "mapped": bool(mapped),
                     "mapped_data_types": mapped, "call_points": calls})
    sig_u = sum(1 for r in rows if not r["registered"])
    call_t = sum(r["call_points"] for r in rows)
    call_u = sum(r["call_points"] for r in rows if not r["registered"])

    def bucket(keys_of) -> list[dict]:
        """keys_of(row) → 该行落在哪些分组（品类可多属，故分类小计可大于总数）。"""
        out = {}
        for r in rows:
            for key in keys_of(r):
                item = out.setdefault(key, {"key": key, "signatures": 0, "registered": 0,
                                            "call_points": 0, "call_points_registered": 0})
                item["signatures"] += 1
                item["call_points"] += r["call_points"]
                if r["registered"]:
                    item["registered"] += 1
                    item["call_points_registered"] += r["call_points"]
        return sorted(out.values(), key=lambda x: (-x["call_points"], x["key"]))

    forms = {}
    for r in rows:
        item = forms.setdefault(r["form"], {"signatures": 0, "call_points": 0})
        item["signatures"] += 1
        item["call_points"] += r["call_points"]

    def slim(r: dict) -> dict:
        return {k: v for k, v in r.items() if k != "registered"}

    unregistered = sorted((r for r in rows if not r["registered"]),
                          key=lambda r: (-r["call_points"], r["class"], r["method"]))
    registered = sorted((r for r in rows if r["registered"]),
                        key=lambda r: (-r["call_points"], r["class"], r["method"]))
    cls_map = {}
    for r in rows:
        item = cls_map.setdefault(r["class"], {"class": r["class"], "category": r["categories"],
                                               "group": r["group"], "signatures": 0,
                                               "registered": 0, "call_points": 0,
                                               "form": r["form"]})
        item["signatures"] += 1
        item["call_points"] += r["call_points"]
        item["registered"] += 1 if r["registered"] else 0
        if r["form"] != "exact":
            item["form"] = r["form"]
    field_reads = {f"{cls}.{name}": n for (cls, name), n in scan["fields"].items()
                   if matcher.categories(cls)}
    return {
        "denominators": {
            "signature_surface": {
                "unit": "distinct (class, method, descriptor)", "total": len(rows),
                "registered": len(registered), "unregistered": sig_u,
                "forms": forms,
                "note": "签名面分母只含该样本实际调到的敏感签名"},
            "call_points": {
                "unit": "invoke-* 指令条数", "total": call_t,
                "registered": call_t - call_u, "unregistered": call_u,
                "forms": forms,
                "note": "调用点加权分母把高频包装调用放大，与签名面不可互相替代"},
        },
        "invisible": {
            "signature_share": _share(sig_u, len(rows)),
            "call_point_share": _share(call_u, call_t),
            "statement_zh": STATEMENT.format(sig=_share(sig_u, len(rows)), sig_u=sig_u,
                                             sig_t=len(rows), call=_share(call_u, call_t),
                                             call_u=call_u, call_t=call_t),
        },
        "by_category": bucket(lambda r: r["categories"]),
        "by_group": bucket(lambda r: [r["group"]]),
        "classes": sorted(cls_map.values(), key=lambda x: (-x["call_points"], x["class"])),
        "registered": [slim(r) for r in registered[:MAX_ROWS]],
        "unregistered": [slim(r) for r in unregistered[:MAX_ROWS]],
        "truncated": {"registered": max(0, len(registered) - MAX_ROWS),
                      "unregistered": max(0, len(unregistered) - MAX_ROWS),
                      "note": "明细最多 500 行/栏；统计数字不受截断影响"},
        "field_reads": {
            "unit": "sget/iget 指令条数", "total": sum(field_reads.values()),
            "distinct": len(field_reads), "by_field": dict(sorted(
                field_reads.items(), key=lambda kv: (-kv[1], kv[0]))[:50]),
            "counted_in_denominators": False,
            "note": "闭集是方法签名表，字段读取本就不在其表达力内，因此单列、不并入两分母",
        },
    }


def run(apk: Path, out: Path, rules_db: Path = RULES_DB,
        version: str = DEFAULT_VERSION, target_set=None) -> dict:
    """扫一个 APK 并写 `<out>/observed_surface.json`；失败也写文件（带 status）。"""
    ts = surface_target.load(target_set)
    base = {"generated_by": "mobile/tools/observed_surface.py::run",
            "target_set": surface_target.describe(ts),
            "sample": {"apk": Path(apk).name, "apk_sha256": apk_sha256(Path(apk)),
                       "rules_db_version": version},
            "standalone": True,
            "not_merged_with": ("四桶统计（reachability）。两者并列输出：不合并、不加权、"
                                "不折算成检出率、不可相加"),
            "limitations": LIMITATIONS}
    try:
        scan = scan_apk(Path(apk))
        doc = {**base, "observed_surface": {
            "status": "ok", "denominators_scope": "样本内（sample-scoped）",
            "dex_count": scan["dex_count"],
            "dexdump_fingerprint": scan["dexdump_fingerprint"],
            **observe(scan, closed_set(rules_db, version), ts)}}
    except ScanError as exc:
        doc = {**base, "observed_surface": {
            "status": "scan_failed" if str(exc) != "no_dex" else "no_dex",
            "error": str(exc), "denominators": None,
            "statement_zh": "未产出统计：该样本没有可扫的 dex 或 dexdump 失败。"
                            "这不是「已排除」，只是没有数字。"}}
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "observed_surface.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def main() -> int:
    ap = argparse.ArgumentParser(description="L2 只读覆盖统计 observed_surface")
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", required=True, help="输出目录（写 observed_surface.json）")
    ap.add_argument("--rules-db", default=str(RULES_DB))
    ap.add_argument("--version", default=DEFAULT_VERSION)
    ap.add_argument("--target-set", default=None)
    args = ap.parse_args()
    doc = run(Path(args.apk), Path(args.out), Path(args.rules_db),
              args.version, args.target_set)
    surf = doc["observed_surface"]
    print(json.dumps({k: surf.get(k) for k in ("status", "invisible", "denominators")},
                     ensure_ascii=False, indent=2))
    return 0 if surf.get("status") == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
