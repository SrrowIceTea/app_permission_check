"""仅用于授权测试：脱敏的存储/加密 API 事实，不把写调用当磁盘或泄露证明。"""
from __future__ import annotations
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
import re

from mobile.audit.cipher_storage import complete_bytes, written_transform, explicit_symmetric_ecb

LIMITATIONS = [
    "存储观察仅覆盖 app dataDir 的 FileOutputStream 两类 write 和 SharedPreferences.putString；不覆盖所有磁盘/SQLite/native IO。",
    "successful_stream_write 只证明原调用成功，editor_staged 只证明编辑暂存；未验证 flush/commit、磁盘持久化或跨应用可读。",
    "加密观察仅覆盖 Cipher.init 与 doFinal(byte[])；不覆盖 update、其他重载或 native 加密。",
    "完整字节的精确相等和时间先后不是全链路污点因果证明；无敏感读取值绑定，不推断个人数据存储或泄露。",
    "provider-default AES 模式未知；未命中弱配置不证明安全，未验证密钥身份/管理、nonce 唯一性或标签校验。",
]
BEHAVIORS = {"FILE_OPEN", "FILE_WRITE", "PREF_PUT_STRING", "CIPHER_INIT", "CIPHER_FINAL"}


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _number(value):
    return value if type(value) is int and value >= 0 else None


def _bytes(value) -> dict:
    if not isinstance(value, dict):
        return {"available": False}
    raw = complete_bytes(value)
    return {"length": _number(value.get("len")), "captured": _number(value.get("captured")),
            "complete": raw is not None, "sha256": _hash(raw) if raw is not None else None}


def _text(value) -> dict:
    if not isinstance(value, dict):
        return {"available": False}
    text = value.get("text")
    complete = isinstance(text, str) and value.get("truncated") is False
    return {"chars": _number(value.get("chars")), "complete": complete,
            "sha256": _hash(text.encode()) if complete else None}


def _name(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_/-]{1,80}", value) else None


def weak_reasons(algorithm):
    parts = re.sub(r"\s+", "", algorithm or "").upper().split("/")
    reasons = []
    if parts[0].replace("-", "") in {"DES", "DESEDE", "TRIPLEDES", "3DES", "TDEA", "RC4", "ARC4", "ARCFOUR"}:
        reasons.append("legacy_cipher")
    if explicit_symmetric_ecb(algorithm or ""):
        reasons.append("explicit_ecb")
    return reasons


def build_storage_crypto(session: Path, package: str, gaps: list[str]) -> dict:
    path = session / "audit.jsonl"
    if not path.is_file():
        gaps.append("[storage_crypto] audit.jsonl 缺失：存储/加密未采集，不能推断安全。")
        return {"schema_version": 1, "available": False, "observations": [], "findings": [],
                "coverage_gaps": ["audit.jsonl 缺失：存储/加密未采集，不能推断安全。"]}
    indexed, malformed = [], 0
    for line, text in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
        if not text.strip():
            continue
        try:
            row = json.loads(text)
            if row.get("type") == "send":
                row = row.get("payload", {})
            if isinstance(row.get("line"), str):
                row = json.loads(row["line"])
            if not isinstance(row, dict):
                raise ValueError("event object required")
        except (ValueError, AttributeError, TypeError):
            malformed += 1
            continue
        if row.get("pkg") == package and row.get("src") == "storage_crypto":
            indexed.append((line, row))
    sessions = {e.get("session_id") for _, e in indexed if isinstance(e.get("session_id"), str)}
    valid_session = (len(sessions) == 1 and
                     re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", next(iter(sessions))) is not None)
    local_gaps = list(LIMITATIONS)
    if malformed:
        local_gaps.append(f"audit.jsonl 有 {malformed} 行不可解析，证据不完整。")
    if not valid_session:
        local_gaps.append("存储/加密缺少唯一有效 session_id；禁止混合或归并事件。")
        indexed = []
    else:
        sid = next(iter(sessions))
        invalid_owners = sum(not (e.get("session_id") == sid and type(e.get("pid")) is int and e["pid"] > 0)
                             for _, e in indexed)
        if invalid_owners:
            local_gaps.append(f"{invalid_owners} 条存储/加密事件缺少同会话进程身份，已排除。")
        indexed = [(n, e) for n, e in indexed if e.get("session_id") == sid
                   and type(e.get("pid")) is int and e["pid"] > 0]
    rows, originals = [], {}
    counts = Counter(e.get("ev") for _, e in indexed if isinstance(e.get("ev"), str)
                     and re.fullmatch(r"[A-Z_]{1,40}", e["ev"]))
    for line, event in indexed:
        if event.get("ev") not in BEHAVIORS:
            continue
        eid = f"SC{len(rows) + 1}"
        row = {"evidence_id": eid, "event": event["ev"], "package": package,
               "source": {"artifact": "audit.jsonl", "line": line, "evt_id": _number(event.get("evt_id")),
                          "session_id": event["session_id"], "pid": event["pid"]},
               "ts": _number(event.get("ts")), "success": event.get("success") is True,
               "disk_persistence_proven": False, "personal_data_binding": "not_established",
               "plaintext_leak_proven": False}
        for key in ("path", "key", "value"):
            if key in event:
                row[key + "_metadata"] = _text(event[key])
        for key in ("bytes", "input", "output"):
            if key in event:
                row[key + "_metadata"] = _bytes(event[key])
        for key in ("algorithm", "cipher_id", "stream_id", "input_role", "output_role"):
            if key in event:
                row[key] = _name(event[key])
        for key in ("opmode", "iv_len", "iv_sha256_16"):
            if key in event:
                value = event[key]
                row[key] = (value if (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{16}", value))
                            else None) if key == "iv_sha256_16" else (value if type(value) is int else None)
        row["observation_scope"] = ("editor_staged" if event["ev"] == "PREF_PUT_STRING" else
                                    "successful_stream_write" if event["ev"] == "FILE_WRITE" else "api_call")
        rows.append(row)
        originals[eid] = event
    findings = assess_storage_crypto(rows, originals)
    armed = [e for _, e in indexed if e.get("ev") == "ARMED"]
    errors = sum(counts.get(k, 0) for k in ("PROBE_ERROR", "OBSERVATION_ERROR", "HOOK_MISS", "NOT_READY"))
    healthy = bool(armed) and not errors and all(not e.get("missing") for e in armed)
    if not healthy:
        local_gaps.append("存储/加密钩子健康未通过，零观测不得作为无行为结论。")
    if not counts.get("CIPHER_INIT"):
        local_gaps.append("本窗口未观测到 Cipher.init；不代表应用未加密。")
    if not counts.get("FILE_WRITE") and not counts.get("PREF_PUT_STRING"):
        local_gaps.append("本窗口未观测到存储写 API；不代表没有存储行为。")
    gaps.extend("[storage_crypto] " + x for x in local_gaps)
    return {"schema_version": 1, "available": True, "package": package,
            "source_artifact": {"name": "audit.jsonl", "sha256": _hash(path.read_bytes())},
            "health": {"armed": bool(armed), "error_events": errors, "healthy": healthy},
            "event_counts": dict(counts), "observations": rows, "findings": findings,
            "risk_assessment": {"method": "VSCAN-STORAGE-1", "meaning": "技术复核优先级，非法律或通用安全评分",
                                "signal_score": max((f["signal_score"] for f in findings), default=None),
                                "no_signal_is_safety_proof": False},
            "masking": "文本/路径/字节仅含完整值哈希和长度，无文件内容、明文、密钥或原始文件名。",
            "coverage_gaps": local_gaps}


def assess_storage_crypto(rows, originals):
    findings = []

    def add(kind, refs, detail, score, likelihood, impact):
        findings.append({"evidence_id": f"SCF{len(findings) + 1}", "kind": kind,
                         "evidence_refs": refs, "detail": detail, "signal_score": score,
                         "likelihood": likelihood, "impact": impact,
                         "score_formula": "4*likelihood*impact", "basis_kind": "technical_observation",
                         "conclusion": "observed_but_inconclusive", "regulation_refs": [],
                         "disk_persistence_proven": False, "plaintext_leak_proven": False})

    crypto = [r for r in rows if r["success"] and r["event"] in {"CIPHER_INIT", "CIPHER_FINAL"}]
    for algorithm in sorted({r["algorithm"] for r in crypto if r.get("algorithm")}):
        matching = [r for r in crypto if r.get("algorithm") == algorithm]
        if weak_reasons(algorithm):
            add("explicit_weak_configuration", [r["evidence_id"] for r in matching],
                "显式弱加密配置：" + algorithm + "；未证明内容属于个人信息或已泄露。", 48, 3, 4)
        elif algorithm.upper() == "AES":
            add("provider_default_mode_unresolved", [r["evidence_id"] for r in matching],
                "观测到 provider-default AES；具体模式未知，不擅自标为 ECB。", 16, 2, 2)
    groups = defaultdict(list)
    for row in crypto:
        iv = row.get("iv_sha256_16")
        if (row["event"] == "CIPHER_INIT" and row.get("opmode") == 1 and
                "/CBC/" in (row.get("algorithm") or "").upper() and
                isinstance(iv, str) and re.fullmatch(r"[0-9a-f]{16}", iv) and
                type(row.get("iv_len")) is int and row["iv_len"] > 0):
            source = row["source"]
            groups[(source["session_id"], source["pid"], row["algorithm"], row["iv_len"], iv)].append(row)
    for group in groups.values():
        if len(group) > 1:
            add("repeated_iv_fingerprint", [r["evidence_id"] for r in group],
                "同进程/会话 CBC 初始化重复 IV 指纹；密钥身份和长期固定性未验证。", 36, 3, 3)
    writes = [r for r in rows if r["event"] == "FILE_WRITE" and r["success"]]
    for cipher in crypto:
        raw = originals[cipher["evidence_id"]]
        ciphertext = complete_bytes(raw.get("output"))
        if (cipher["event"] != "CIPHER_FINAL" or cipher.get("opmode") != 1 or
                cipher.get("input_role") != "plaintext" or cipher.get("output_role") != "ciphertext" or
                complete_bytes(raw.get("input")) is None or not ciphertext):
            continue
        refs = []
        for write in writes:
            other = originals[write["evidence_id"]]
            if (type(raw.get("ts")) is not int or type(other.get("ts")) is not int or
                    cipher["source"]["pid"] != write["source"]["pid"] or
                    cipher["source"]["session_id"] != write["source"]["session_id"] or
                    write["source"]["line"] <= cipher["source"]["line"] or not 0 <= other["ts"] - raw["ts"] <= 5000):
                continue
            written = complete_bytes(other.get("bytes"))
            if written is not None and written_transform(ciphertext, written):
                refs.append(write["evidence_id"])
        if refs:
            add("encrypted_stream_write_relation", [cipher["evidence_id"], *refs],
                "完整密文或 Base64.DEFAULT 编码与后续成功流写入精确相等（≤5000ms）；不证明持久化、污点因果或个人数据类别。", 0, 0, 0)
    return findings
