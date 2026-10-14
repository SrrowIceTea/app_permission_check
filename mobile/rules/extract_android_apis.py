#!/usr/bin/env python3
"""从本机 android.jar 抽取敏感 API 签名 —— 本规则库 source_verified 的唯一来源。

仅用于授权测试（已获授权的样本与设备）。

做法：对 seed/api_targets.json 里每个 (类名, 方法名) 目标执行
    javap -classpath <android.jar> -public -s <类名>
并解析 javap 输出的 (声明行, descriptor 行) 对。**描述符逐字取自 javap，不手写、不推断。**
抽不到的目标准确落到 build/api_missing.json（探测 TODO），绝不编造签名。

输出（均在 mobile/rules/build/ 下，可重复生成、字节稳定）：
    api_facts.jsonl    —— 可直接入 dangerous_apis 表的事实行
    api_missing.json   —— 未抽到的目标（含 javap 报错原文）

用法：
    python extract_android_apis.py                 # 抽取（默认 jar = SDK platform 36）
    python extract_android_apis.py --verify        # 只核对：重算并与已有产物比对
    VSCAN_ANDROID_JAR=... python extract_android_apis.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = HERE / "seed" / "api_targets.json"
BUILD = HERE / "build"

# 本机默认值（旧开发机路径已失效，见根 CLAUDE.md 环境表与记忆）。
# 路径解析统一走 core/sdk_paths：VSCAN_SDK/VSCAN_JDK → ANDROID_SDK_ROOT/JAVA_HOME →
# PATH 探测 → 历史候选表。不再在这里写死绝对路径（§8.2 B-4）。
sys.path.insert(0, str(HERE.parent.parent))
from core import sdk_paths  # noqa: E402

DEFAULT_JAR_CANDIDATES = [sdk_paths.sdk_dir("platforms", "android-36", "android.jar")]
DEFAULT_JAVAP_CANDIDATES = [Path(sdk_paths.jdk_tool("bin", "javap.exe"))]

DECL_RE = re.compile(r"^\s+(?:public|protected)\s.*;\s*$")
DESC_RE = re.compile(r"^\s+descriptor:\s*(\S+)\s*$")
NAME_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*\(")


def _first_existing(paths: list[Path]) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


def find_jar(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            sys.exit(f"[fatal] --android-jar 不存在: {p}")
        return p
    env = os.environ.get("VSCAN_ANDROID_JAR")
    if env:
        p = Path(env)
        if not p.exists():
            sys.exit(f"[fatal] VSCAN_ANDROID_JAR 指向不存在的路径: {p}")
        return p
    found = _first_existing(DEFAULT_JAR_CANDIDATES)
    if found is None:
        sys.exit("[fatal] 找不到 android.jar。用 --android-jar 或 VSCAN_ANDROID_JAR 指定。"
                 f" 已尝试: {[str(p) for p in DEFAULT_JAR_CANDIDATES]}")
    return found


def find_javap(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.exists():
            sys.exit(f"[fatal] --javap 不存在: {p}")
        return p
    env = os.environ.get("VSCAN_JAVAP")
    if env:
        p = Path(env)
        if not p.exists():
            sys.exit(f"[fatal] VSCAN_JAVAP 指向不存在的路径: {p}")
        return p
    found = _first_existing(DEFAULT_JAVAP_CANDIDATES)
    if found is None:
        which = shutil.which("javap")
        if which is None:
            sys.exit("[fatal] 找不到 javap。用 --javap 或 VSCAN_JAVAP 指定。")
        return Path(which)
    return found


def javap_version(javap: Path) -> str:
    try:
        out = subprocess.run([str(javap), "-version"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=60)
        text = (out.stdout or "") + (out.stderr or "")
        return text.strip().splitlines()[0] if text.strip() else "unknown"
    except Exception as e:  # noqa: BLE001 —— 版本取不到不影响抽取，如实记 unknown
        return f"unknown ({e.__class__.__name__})"


def dump_class(javap: Path, jar: Path, class_name: str) -> tuple[list[tuple[str, str]], str | None]:
    """返回 ([(声明行, descriptor), ...], 错误文本)。类不存在时返回 ([], 错误原文)。"""
    try:
        proc = subprocess.run(
            [str(javap), "-classpath", str(jar), "-public", "-s", class_name],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except subprocess.TimeoutExpired:
        return [], "javap timeout"
    if proc.returncode != 0:
        return [], (proc.stderr or proc.stdout or "javap non-zero").strip()[:500]

    pairs: list[tuple[str, str]] = []
    lines = proc.stdout.splitlines()
    for i, line in enumerate(lines):
        if not DECL_RE.match(line):
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            m = DESC_RE.match(lines[j])
            if m:
                pairs.append((line.strip(), m.group(1)))
                break
    return pairs, None


def method_name_of(decl: str) -> str | None:
    m = NAME_RE.search(decl)
    return m.group(1) if m else None


def select_ok(select: str, descriptor: str) -> bool:
    if select == "zero_arg":
        return descriptor.startswith("()")
    if select == "one_int_arg":
        return descriptor.startswith("(I)")
    if select == "all":
        return True
    raise ValueError(f"未知 select: {select}")


def ref_for(jar: Path, jar_sha: str, class_name: str, method: str, desc: str, tool_ver: str) -> dict:
    return {
        "kind": "android_jar_signature",
        "tool": "javap -s",
        "tool_version": tool_ver,
        "jar": str(jar),
        "jar_sha256": jar_sha,
        "class_name": class_name,
        "method_name": method,
        "jvm_descriptor": desc,
    }


def extract(jar: Path, javap: Path, seed: dict) -> tuple[list[dict], list[dict]]:
    jar_sha = hashlib.sha256(jar.read_bytes()).hexdigest()
    tool_ver = javap_version(javap)
    cache: dict[str, tuple[list[tuple[str, str]], str | None]] = {}

    facts: list[dict] = []
    missing: list[dict] = []
    for tgt in seed["targets"]:
        cls, meth = tgt["class_name"], tgt["method_name"]
        if cls not in cache:
            cache[cls] = dump_class(javap, jar, cls)
        pairs, err = cache[cls]
        if err:
            missing.append({"class_name": cls, "method_name": meth, "reason": "class_dump_failed",
                            "javap_error": err})
            continue
        hits = [(d, de) for (d, de) in pairs if method_name_of(d) == meth and select_ok(tgt["select"], de)]
        if not hits:
            declared = sorted({method_name_of(d) or "?" for (d, _de) in pairs})
            missing.append({"class_name": cls, "method_name": meth, "reason": "method_not_found",
                            "declared_methods_sample": declared[:40]})
            continue
        for decl, desc in sorted(hits, key=lambda x: x[1]):
            facts.append({
                "api_key": meth + desc,
                "class_name": cls,
                "method_name": meth,
                "jvm_descriptor": desc,
                "api_role": tgt["api_role"],
                "data_type_key": tgt.get("data_type_key"),
                "observation_spec_json": json.dumps(tgt.get("observation"), sort_keys=True,
                                                    ensure_ascii=False),
                "declaration": decl,
                "source_ref": ref_for(jar, jar_sha, cls, meth, desc, tool_ver),
                "note": tgt.get("note"),
            })
    facts.sort(key=lambda f: (f["class_name"], f["method_name"], f["jvm_descriptor"]))
    missing.sort(key=lambda m: (m["class_name"], m["method_name"], m["reason"]))
    return facts, missing


def render(facts: list[dict], missing: list[dict]) -> tuple[str, str]:
    facts_text = "".join(json.dumps(f, sort_keys=True, ensure_ascii=False) + "\n" for f in facts)
    missing_text = json.dumps({"count": len(missing), "items": missing},
                              indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    return facts_text, missing_text


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--android-jar", default=None)
    ap.add_argument("--javap", default=None)
    ap.add_argument("--seed", default=str(SEED), help="目标表 JSON（默认 seed/api_targets.json）")
    ap.add_argument("--out-prefix", default="api_",
                    help="产物前缀：<prefix>facts.jsonl / <prefix>missing.json")
    ap.add_argument("--verify", action="store_true", help="重算并与已有产物比对，不写文件")
    args = ap.parse_args()

    jar = find_jar(args.android_jar)
    javap = find_javap(args.javap)
    seed = json.loads(Path(args.seed).read_text(encoding="utf-8"))
    facts, missing = extract(jar, javap, seed)
    facts_text, missing_text = render(facts, missing)

    fpath = BUILD / f"{args.out_prefix}facts.jsonl"
    mpath = BUILD / f"{args.out_prefix}missing.json"
    if args.verify:
        problems = []
        if not fpath.exists():
            problems.append(f"缺少产物 {fpath}")
        elif fpath.read_text(encoding="utf-8") != facts_text:
            problems.append(f"{fpath} 与重算结果不一致（android.jar 或种子变过？）")
        if not mpath.exists():
            problems.append(f"缺少产物 {mpath}")
        elif mpath.read_text(encoding="utf-8") != missing_text:
            problems.append(f"{mpath} 与重算结果不一致")
        for p in problems:
            print(f"[verify] FAIL {p}", file=sys.stderr)
        if problems:
            return 1
        print(json.dumps({"status": "ok", "facts": len(facts), "missing": len(missing)},
                         ensure_ascii=False))
        return 0

    BUILD.mkdir(parents=True, exist_ok=True)
    fpath.write_text(facts_text, encoding="utf-8")
    mpath.write_text(missing_text, encoding="utf-8")
    print(json.dumps({"status": "extracted", "jar": str(jar), "javap": str(javap),
                      "facts": len(facts), "missing": len(missing),
                      "facts_path": str(fpath), "missing_path": str(mpath)},
                     ensure_ascii=False, indent=2))
    if missing:
        print("[warn] 有目标未抽到，见 api_missing.json —— 这些是探测 TODO，不得当成已存在。",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
