"""Bound, portable mobile evidence ZIPs and offline replay. 仅用于授权测试。"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from core.io_utils import load_jsonl
from mobile.analyze.replay_inputs import EVENTS, ROOT, SCALARS, digest, read_json, sessions
from mobile.lab import window_benchmark as benchmark
from mobile.workbench.store import write_json

INDEX = "manifest.json"
KINDS = ("mobile_correlation", "mobile_window_benchmark")
MAX_BYTES = 2 * 1024**3
MAX_FILES = 128
HEX = re.compile(r"[a-f0-9]{64}")
MEMBER = re.compile(r"[a-zA-Z0-9_-][a-zA-Z0-9._-]*")
VERSIONS = re.compile(r"[0-9]{1,3}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def member_name(name):
    return isinstance(name, str) and 0 < len(name) <= 200 and all(
        MEMBER.fullmatch(part) and not part.endswith(".")
        and part.split(".", 1)[0].upper() not in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)),
                                                 *(f"LPT{i}" for i in range(10))}
        for part in name.split("/"))


def sha_string(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def checked_files(root, names):
    root = root.resolve()
    require(len(names) <= MAX_FILES and len({n.casefold() for n in names}) == len(names),
            "证据文件过多或命名重复")
    files = {}
    for name in sorted(names):
        require(member_name(name) and name != INDEX, "证据文件名无效")
        original = root / name
        path = original.resolve()
        require(path == original and path.is_file(), f"证据文件不可用：{name}")
        files[name] = path
    require(sum(path.stat().st_size for path in files.values()) <= MAX_BYTES, "证据超过 ZIP 大小上限")
    return files


def stream_hash(reader, writer):
    checksum = hashlib.sha256()
    for block in iter(lambda: reader.read(1024 * 1024), b""):
        checksum.update(block)
        writer.write(block)
    return checksum.hexdigest()


def create(root, names, kind, apk_sha, target):
    require(kind in KINDS and sha_string(apk_sha), "缺少可核对的 APK 摘要")
    files = checked_files(root, names)
    with tempfile.TemporaryDirectory(dir=target.parent) as temp:
        staged = Path(temp) / "evidence.zip"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            hashes = {}
            for name, path in files.items():
                with path.open("rb") as reader, archive.open(name, "w", force_zip64=True) as writer:
                    hashes[name] = stream_hash(reader, writer)
            archive.writestr(INDEX, json.dumps({"version": 1, "kind": kind, "apk_sha256": apk_sha,
                                               "files": hashes}, sort_keys=True))
        # The provisional archive is verified before it is made available.
        with tempfile.TemporaryDirectory(dir=temp) as extracted:
            verify(staged, apk_sha, Path(extracted))
        if os.name == "nt":
            staged.rename(target)  # Windows rename fails when target already exists.
        else:
            os.link(staged, target)


def verify(archive_file, apk_sha, destination):
    require(sha_string(apk_sha), "请提供原始 APK 的 SHA-256")
    with zipfile.ZipFile(archive_file) as archive:
        members = archive.infolist()
        by_name = {row.filename: row for row in members}
        require(len(members) <= MAX_FILES + 1 and len({r.filename.casefold() for r in members}) == len(members)
                and all(member_name(r.filename) for r in members)
                and sum(r.file_size for r in members) <= MAX_BYTES + 1024**2,
                "证据 ZIP 含不安全的名称、重复项或超限文件")
        require(INDEX in by_name and by_name[INDEX].file_size <= 1024**2, "缺少有效的证据清单")
        manifest = json.loads(archive.read(INDEX))
        require(isinstance(manifest, dict) and manifest.get("version") == 1 and manifest.get("kind") in KINDS
                and manifest.get("apk_sha256") == apk_sha, "证据格式或原始 APK 摘要不一致")
        hashes = manifest.get("files")
        require(isinstance(hashes, dict) and set(hashes) == set(by_name) - {INDEX}
                and all(sha_string(value) for value in hashes.values()), "ZIP 文件集合与证据清单不一致")
        for name, checksum in hashes.items():
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(name) as reader, path.open("xb") as writer:
                require(stream_hash(reader, writer) == checksum, f"原始证据摘要不一致：{name}")
    if manifest["kind"] == "mobile_correlation":
        correlation_inputs(destination, apk_sha)
    else:
        spec = read_json(destination / "suite.json")
        require(spec.get("apk_sha256") == apk_sha and set(spec.get("cases", {})) == set(benchmark.STEPS),
                "四组对照清单与 APK 不一致")
        for case, token in spec["cases"].items():
            folder = destination / case
            seal = read_json(folder / "manifest.json")
            required = set(benchmark.INPUTS) | ({"body.bin"} if case != "read_only" else set())
            require(seal["apk_sha256"] == apk_sha and seal["session_id"] == token and seal.get("passed") is True
                    and seal["hook_sha256"] == spec["hook_sha256"] and set(seal["sha256"]) == required
                    and all(digest(folder / name) == checksum for name, checksum in seal["sha256"].items()),
                    "对照会话或其冻结原件不一致")
            benchmark.truth(folder, case, seal)
        require(digest(destination / "rules.db") == spec["rules_sha256"]
                and digest(destination / "hook.bundle.js") == spec["hook_sha256"], "对照规则库或 Hook 不一致")
    return manifest


def correlation_inputs(root, apk_sha):
    spec = read_json(root / "replay-inputs/inputs.json")
    require(spec["apk_sha256"] == apk_sha, "关联输入与原始 APK 摘要不一致")
    session = spec["session_dir"]
    options, files = spec["options"], spec["files"]
    require(member_name(session) and "/" not in session and set(options) == set(SCALARS), "重放参数无效")
    require(isinstance(options["package"], str) and re.fullmatch(r"[\w]+(?:\.[\w]+)+", options["package"])
            and isinstance(options["version"], str) and VERSIONS.fullmatch(options["version"]),
            "应用标识或规则版本无效")
    names = {"policy": "policy.json", "rules": "rules.db", "permissions": "permissions.txt",
             "dexfacts": "static/dexfacts.json", "line": f"session/{session}/pcap-line-egress.jsonl",
             **{key: f"session/{session}/{key}.jsonl" for key in EVENTS}}
    checksums = spec["sha256"]
    require({"policy", "rules"} <= set(files) <= set(names) and set(checksums) == set(files.values())
            and all(names[key] == value for key, value in files.items()), "重放输入清单无效")
    base = root / "replay-inputs"
    paths = {key: base / value for key, value in files.items()}
    for key, path in paths.items():
        require(path.is_file() and digest(path) == checksums[files[key]], f"关联输入已变化：{key}")
    found, unidentified = sessions(path for key, path in paths.items() if key in (*EVENTS, "line"))
    require(found and found == spec.get("session_id") and not unidentified, "原始记录缺少一致的会话标识")
    reference = read_json(root / "out/summary.json")
    require(reference.get("apk_sha256") == apk_sha and reference.get("rules_sha256") == digest(paths["rules"])
            and reference.get("package") == options["package"] and reference.get("android_version") == options["version"],
            "规则库、包名或 APK 与原始关联摘要不一致")
    return options, paths, session, found


def export_job(job, target):
    root = job.out
    require(job.state == "done", "仅完成的动态任务可导出")
    apk = root / "uploaded.apk"
    require(apk.is_file() and not apk.is_symlink(), "原始 APK 不可用")
    apk_sha = digest(apk)
    _, paths, _, _ = correlation_inputs(root, apk_sha)
    allowed = ["replay-inputs/inputs.json", "out/findings.jsonl", "out/summary.json",
               "out/bundle.json", "out/mobile-report.pdf", "events.jsonl", "verification.json",
               "finding-reviews.json"]
    names = [path.relative_to(root).as_posix() for path in paths.values()]
    names.extend(name for name in allowed if (root / name).is_file())
    require({"out/findings.jsonl", "out/summary.json"} <= set(names), "原始关联结果不完整")
    create(root, names, "mobile_correlation", apk_sha, target)


def export_benchmark(source, target):
    suite = read_json(source / "suite.json")
    names = ["suite.json", "rules.db", "hook.bundle.js"]
    for case in benchmark.STEPS:
        names.extend(f"{case}/{name}" for name in (*benchmark.INPUTS, "manifest.json"))
        if case != "read_only":
            names.append(f"{case}/body.bin")
    create(source, names, "mobile_window_benchmark", suite["apk_sha256"], target)


def replay_correlation(root, apk_sha, out):
    options, paths, session, capture_id = correlation_inputs(root, apk_sha)
    session_path = root / "replay-inputs/session" / session
    session_path.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True)
    findings, summary = out / "findings.jsonl", out / "summary.json"
    command = [sys.executable, str(ROOT / "mobile/analyze/correlate_mobile.py"), "--session", str(session_path),
               "--apk-sha256", apk_sha, "--out", str(findings), "--summary", str(summary)]
    for key, value in options.items():
        if value is not None:
            command.extend(("--" + key.replace("_", "-"), str(value)))
    command.extend(("--rules", str(paths["rules"]), "--frozen-policy", str(paths["policy"])))
    if "permissions" in paths:
        command.extend(("--permissions", str(paths["permissions"])))
    if "dexfacts" in paths:
        command.extend(("--static-dir", str(paths["dexfacts"].parent)))
    run = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
    (out / "correlate.log").write_bytes(run.stdout + run.stderr)
    require(run.returncode == 0, "离线关联失败，查看 correlate.log")
    actual = load_jsonl(findings)
    require(actual == load_jsonl(root / "out/findings.jsonl"), "重放结论与原始结论不一致")
    record = {"status": "passed", "kind": "mobile_correlation", "apk_sha256": apk_sha, "session_id": capture_id,
              "rules_sha256": digest(paths["rules"]), "findings": len(actual)}
    write_json(out / "verification.json", record)
    return record


def replay(archive_file, apk_sha, out):
    with tempfile.TemporaryDirectory(prefix="mobile-evidence-") as temporary:
        root = Path(temporary).resolve()
        manifest = verify(archive_file, apk_sha, root)
        if manifest["kind"] == "mobile_window_benchmark":
            return benchmark.replay(root, out)
        return replay_correlation(root, apk_sha, out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    export = modes.add_parser("export-benchmark")
    export.add_argument("--source", type=Path, required=True)
    export.add_argument("--out", type=Path, required=True)
    offline = modes.add_parser("replay")
    offline.add_argument("--archive", type=Path, required=True)
    offline.add_argument("--apk-sha256", required=True)
    offline.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "export-benchmark":
            export_benchmark(args.source.resolve(), args.out.resolve())
        else:
            replay(args.archive.resolve(), args.apk_sha256, args.out.resolve())
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError) as error:
        print(f"evidence_archive_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
