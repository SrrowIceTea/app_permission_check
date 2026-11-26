"""Freeze the inputs actually used by the mobile correlator. 仅用于授权测试。"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

from mobile.workbench.store import write_json

ROOT = Path(__file__).resolve().parents[2]
SCALARS = ("package", "version", "device_api", "version_code", "app_category", "window_override_ms")
EVENTS = ("reads", "consent", "flows", "egress")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy(args, line_name):
    from mobile.policy.policy_library import load_policy as select_policy

    policy = read_json(Path(args.frozen_policy)) if args.frozen_policy else select_policy(
        Path(args.policy_store) if args.policy_store else None,
        package=args.package, version_code=args.version_code, apk_sha256=args.apk_sha256,
        allow_legacy=bool(args.policy_store and args.package == "com.vscanner.privacydemo"))
    if args.replay_inputs:
        try:
            freeze(args, policy, line_name)
        except (OSError, ValueError) as error:
            print(f"replay_snapshot_failed: {error}", file=sys.stderr)
    return policy


def freeze(args, policy, line_name):
    target, source = Path(args.replay_inputs), Path(args.session)
    target.mkdir()
    paths = {"rules": Path(args.rules)}
    if args.permissions:
        paths["permissions"] = Path(args.permissions)
    if args.static_dir:
        paths["dexfacts"] = Path(args.static_dir) / "dexfacts.json"
    for stream in EVENTS:
        explicit = getattr(args, stream)
        paths[stream] = Path(explicit) if explicit else source / f"{stream}.jsonl"
    paths["line"] = source / line_name
    filenames = {"rules": "rules.db", "permissions": "permissions.txt", "dexfacts": "static/dexfacts.json",
                 "line": f"session/{source.name}/{line_name}", "policy": "policy.json",
                 **{key: f"session/{source.name}/{key}.jsonl" for key in EVENTS}}
    retained = {}
    for key, path in paths.items():
        if not path.is_file():
            continue
        name = filenames[key]
        copied = target / name
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, copied)
        retained[key] = name
    write_json(target / filenames["policy"], policy)
    retained["policy"] = filenames["policy"]
    (target / "session" / source.name).mkdir(parents=True, exist_ok=True)
    capture, unidentified = sessions(target / name for key, name in retained.items() if key in (*EVENTS, "line"))
    if not capture or unidentified:
        raise ValueError("原始记录缺少可唯一验证的会话标识")
    write_json(target / "inputs.json", {
        "options": {key: getattr(args, key) for key in SCALARS},
        "apk_sha256": args.apk_sha256, "session_dir": source.name, "session_id": capture, "files": retained,
        "sha256": {name: digest(target / name) for name in retained.values()},
    })


def sessions(paths):
    """Inspect wire identities, including line-protocol capture when present."""
    found, unidentified = set(), 0
    for path in paths:
        with path.open(encoding="utf-8", newline="\n") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError as error:
                    raise ValueError(f"无法解析会话流记录：{path.name}:{number}") from error
                if not isinstance(row, dict):
                    raise ValueError(f"会话流记录不是 JSON 对象：{path.name}:{number}")
                session = row.get("session_id")
                if isinstance(session, str) and session.strip():
                    found.add(session)
                else:
                    unidentified += 1
    if len(found) > 1:
        raise ValueError("原始证据混有不同的采集会话")
    return next(iter(found), None), unidentified
