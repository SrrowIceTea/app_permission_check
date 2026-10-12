#!/usr/bin/env python3
"""从 rules_mobile.db 生成钩子的监视表 —— 规则库是唯一真源，钩子不手抄 API 表。

仅用于授权测试（已获授权的样本与设备）。

产出 targets.generated.js（ES module）：
    WATCH       每条敏感 API：类名 / 方法名 / Frida overload 类型 / 描述符 / 数据类别或分派规则
    DATA_TYPES  数据类别 → {name_zh, sensitivity}
    META        生成时的规则库 sha256 与版本（事件里回填，保证「哪一版规则在跑」可追溯）

用法：python gen_targets.py [--db ../rules/rules_mobile.db] [--out targets.generated.js]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "rules"))
import jvmdesc  # noqa: E402  （同仓库内的描述符解析，避免重复实现）

HERE = Path(__file__).resolve().parent
DEFAULT_DB = HERE.parent / "rules" / "rules_mobile.db"
DEFAULT_OUT = HERE / "targets.generated.js"


def load(db: Path) -> tuple[list[dict], dict, dict]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    version = conn.execute("SELECT DISTINCT android_version FROM dangerous_apis").fetchone()[0]

    watch = []
    for r in conn.execute(
            "SELECT class_name, method_name, jvm_descriptor, api_role, data_type_key,"
            " observation_spec_json FROM dangerous_apis WHERE android_version=?"
            " ORDER BY class_name, method_name, jvm_descriptor", (version,)):
        spec = json.loads(r["observation_spec_json"]) if r["observation_spec_json"] else {}
        watch.append({
            "cls": r["class_name"], "method": r["method_name"],
            "types": jvmdesc.param_types(r["jvm_descriptor"]),
            "desc": r["jvm_descriptor"], "role": r["api_role"],
            "dataType": r["data_type_key"], "spec": spec,
        })

    data_types = {r["data_type_key"]: {"name_zh": r["name_zh"], "sensitivity": r["sensitivity"]}
                  for r in conn.execute(
                      "SELECT data_type_key, name_zh, sensitivity FROM sensitive_data_types"
                      " WHERE android_version=?", (version,))}
    conn.close()
    return watch, data_types, {"rules_sha256": hashlib.sha256(db.read_bytes()).hexdigest(),
                               "android_version": version, "db": db.name}


def load_consent(facts_path: Path) -> list[dict]:
    """同意类 API 的事实行 → JS 条目（不进 dangerous_apis 表，单列一条链）。"""
    if not facts_path.exists():
        return []
    out = []
    for line in facts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        f = json.loads(line)
        out.append({"cls": f["class_name"], "method": f["method_name"],
                    "types": jvmdesc.param_types(f["jvm_descriptor"]),
                    "desc": f["jvm_descriptor"], "spec": json.loads(f["observation_spec_json"])})
    out.sort(key=lambda w: (w["cls"], w["method"], w["desc"]))
    return out


def render(watch: list[dict], data_types: dict, meta: dict, consent: list[dict]) -> str:
    def js(obj) -> str:
        return json.dumps(obj, ensure_ascii=False, sort_keys=True)

    lines = [
        "// 由 gen_targets.py 生成 —— 请勿手改。",
        f"// 规则库 sha256: {meta['rules_sha256']}",
        f"// android_version: {meta['android_version']}",
        "",
        f"export const META = {js(meta)};",
        "",
        "export const DATA_TYPES = {",
    ]
    for k in sorted(data_types):
        lines.append(f"  {js(k)}: {js(data_types[k])},")
    lines += ["};", "", "export const WATCH = ["]
    for w in watch:
        lines.append(f"  {js(w)},")
    lines += ["];", "", "export const CONSENT_WATCH = ["]
    for c in consent:
        lines.append(f"  {js(c)},")
    lines += ["];", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--db", default=str(DEFAULT_DB))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--consent-facts",
                    default=str(Path(__file__).resolve().parent.parent / "rules" / "build"
                               / "consent_facts.jsonl"))
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    db, out = Path(args.db), Path(args.out)
    if not db.exists():
        sys.exit(f"[fatal] 规则库不存在: {db}（先跑 rules/build_mobile_rules.py）")
    watch, data_types, meta = load(db)
    if not watch:
        sys.exit("[fatal] 规则库里没有 dangerous_apis 行；拒绝生成空监视表")
    consent = load_consent(Path(args.consent_facts))
    text = render(watch, data_types, meta, consent)
    if args.verify:
        if not out.exists() or out.read_text(encoding="utf-8") != text:
            print(f"[verify] FAIL {out} 与规则库不一致（规则库变过？重新生成）", file=sys.stderr)
            return 1
        print(json.dumps({"status": "ok", "apis": len(watch), "consent_apis": len(consent)},
                         ensure_ascii=False))
        return 0
    out.write_text(text, encoding="utf-8")
    print(json.dumps({"status": "generated", "out": str(out), "apis": len(watch),
                      "consent_apis": len(consent), "data_types": len(data_types),
                      "rules_sha256": meta["rules_sha256"][:16]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
