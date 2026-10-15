"""证据包中的原始观察事实与缺口；仅用于授权测试。"""
from __future__ import annotations
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from mobile.analyze.read_semantics import read_state, read_gaps
from core.io_utils import load_jsonl_counting


def read_jsonl(path: Path, gaps: list[str] | None = None) -> list[dict]:
    """统一走 core/io_utils（§8.2 B-2）。

    坏行**不再静默 `continue`**：给了 `gaps` 就写进 gaps（证据包本来就有这个清单），
    否则打到 stderr。"少了几条证据"必须看得见。
    """
    rows, skipped = load_jsonl_counting(path)
    if skipped:
        note = f"{path.name} 有 {skipped} 行无法解析的 JSONL，已跳过（证据不完整）"
        if gaps is not None:
            gaps.append("[jsonl] " + note)
        else:
            print(f"[warn] {note}", file=sys.stderr)
    return rows


def top_app_frame(stack: str | None) -> str | None:
    """栈里第一条应用帧的文本。整栈可达数百行，打包时只留第一帧做定位线索。"""
    if not stack:
        return None
    for line in stack.splitlines():
        s = line.strip()
        if s.startswith("at ") and "com.android" not in s and "android." not in s[:40]:
            return s[:200]
    return None


def build_reads(session: Path, gaps: list[str]) -> list[dict]:
    events = read_jsonl(session / "reads.jsonl", gaps)
    if not events:
        gaps.append("reads.jsonl 缺失或为空：无动态读取证据（不等于没有读取，"
                    "可能只是钩子没挂上或应用没运行）")
    gaps.extend(read_gaps(events))
    out = []
    n = 0
    for e in events:
        if e.get("ev") != "PRIVACY_READ":
            continue
        n += 1
        out.append({
            "evidence_id": f"R{n}",
            "data_type": (e.get("data_types") or [None])[0],
            "data_types": e.get("data_types"),
            "data_type_zh": (e.get("data_types_zh") or [None])[0],
            "sensitivity": e.get("max_sensitivity"),
            "api": e.get("api"),
            "outcome": e.get("outcome"),
            "collection_state": read_state(e),
            "non_empty": e.get("non_empty"),
            "count": e.get("count"),
            "value_len": e.get("value_len"),
            "arg_disc": e.get("arg_disc"),
            "value_kind": e.get("value_kind"),
            "value_hash": e.get("value_hash"),
            "value_preview": e["value_preview"][:6] if isinstance(e.get("value_preview"), str) else None,
            "value_count": e.get("value_count", e.get("count")),
            "column_count": e.get("column_count"),
            "ts": e.get("ts"),
            "host_received_ts": e.get("host_received_ts"),
            "app_frame": top_app_frame(e.get("stack")),
        })
    return out


def build_consent(session: Path, gaps: list[str]) -> list[dict]:
    events = read_jsonl(session / "consent.jsonl", gaps)
    gaps.append("政策同意状态未知：未观测到直接接受信号，权限结果和政策页打开不证明政策接受。")
    if not events:
        gaps.append("consent.jsonl 缺失或为空：**无法判定「同意前收集」**——"
                    "没有同意时序就没有「之前」这个基准")
        return []
    out = []
    n = 0
    for e in events:
        if e.get("ev") not in ("PERM_REQ", "PERM_RESULT", "PERM_CHECK", "POLICY_VIEW"):
            continue
        n += 1
        item = {"evidence_id": f"C{n}", "signal": e.get("ev"), "ts": e.get("ts"),
                "host_received_ts": e.get("host_received_ts")}
        for k in ("permissions", "granted", "denied", "permission",
                  "check_granted", "url", "request_code"):
            if e.get(k) is not None:
                item[k] = e[k]
        out.append(item)
    return out


def build_flows(session: Path, gaps: list[str], *, include_previews: bool) -> tuple[list, list]:
    flows = read_jsonl(session / "flows.jsonl", gaps)
    if not flows:
        gaps.append("flows.jsonl 缺失或为空：无网络流证据（不等于没有外发）")
    out, plaintext = [], []
    for i, f in enumerate(flows, 1):
        eid = f"F{i}"
        rec = {
            "evidence_id": eid,
            "host": f.get("host"), "path": f.get("path"), "method": f.get("method"),
            "scheme": f.get("scheme"), "intercepted_tls": f.get("intercepted_tls"),
            "status_code": f.get("status_code"),
            "attribution": f.get("attribution"),
            "attribution_ambiguous": f.get("attribution_ambiguous"),
            "attribution_delta_ms": f.get("attribution_delta_ms"),
            "attribution_runner_up": f.get("attribution_runner_up"),
            "attribution_candidates": f.get("attribution_candidates"),
            "request_tags": f.get("request_tags") or [],
            "request_tokens": f.get("request_tokens") or [],
            "response_tags": f.get("response_tags") or [],
            "request_bytes": f.get("request_bytes"),
            "ts": f.get("ts"),
        }
        if (rec["request_tags"] or rec["response_tags"]):
            rec["sensitive_payload"] = True
        # Reverse mode scheme is upstream: HTTPS clients can have scheme=http.
        if rec["intercepted_tls"] is False:
            plaintext.append(eid)
        elif rec["intercepted_tls"] is not True:
            gaps.append(f"{eid} 客户端 TLS 状态未知：不能仅凭上游 scheme 判定明文传输。")
        if include_previews:
            rec["request_preview"] = f.get("request_preview")
        out.append(rec)
    return out, plaintext
