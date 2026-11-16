"""Produce UID-scoped line evidence and verification checks. 仅用于授权测试。"""
import hashlib
import json

from core.io_utils import load_jsonl_counting
from mobile.analyze.http_attribution import attribute_lines
from mobile.analyze.line_egress_evidence import NAME, build_flows
from pcap_lines import extract, load


def _write(path, rows):
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
                    encoding="utf-8")


def process(ctx, stats, packets):
    if not stats.get("tshark"):
        return
    out = ctx.out / "line-messages.jsonl"
    try:
        decoded = extract(ctx.pcap_path, out, tshark=stats["tshark"])
        stats["line_decode"] = decoded
        if decoded.get("error") and not decoded["ok"]:
            stats["line_attribution"] = {"error": decoded["error"]}
            ctx.check("line_payload_attributed", 1, optional=True, note=decoded["error"])
            return
        rows = load(out)
        snapshots, skipped = load_jsonl_counting(ctx.session / "conns.jsonl")
        valid = [row for row in snapshots if isinstance(row, dict)]
        result = attribute_lines(rows, valid, ctx.uid, packets=packets)
        _write(out, rows)
        with ctx.pcap_path.open("rb") as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        flows = build_flows(rows, session=ctx.session.name, package=ctx.args.package,
                            uid=ctx.uid, pcap_sha256=digest)
        _write(ctx.session / NAME, flows)
        stats["line_messages"] = result["total"]
        stats["line_attribution"] = result | {"rule_input": len(flows),
                                             "malformed_snapshots": skipped + len(snapshots) - len(valid)}
        ctx.check("line_payload_attributed", 0 if result["from_app"] else 1, optional=True,
                  note=f"确认应用发出 {result['from_app']}/{result['total']} 行，"
                       f"监听端口候选 {result['candidate_from_app']} 行。")
    except (OSError, ValueError, RuntimeError) as error:
        message = f"{type(error).__name__}: {error}"
        stats["line_attribution"] = {"error": message}
        ctx.check("line_payload_attributed", 1, optional=True, note=message)
