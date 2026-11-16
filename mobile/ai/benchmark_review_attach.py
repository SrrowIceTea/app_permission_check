"""Attach a validated live AI run without altering evidence, scores, or source batches."""
from __future__ import annotations

import copy
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# 与 benchmark_review.save 用同一个原子写实现；cwd 为 mobile/ai 时也拿得到 core。
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark_review_data import build_input, map_output  # noqa: E402
from benchmark_review_validation import validate_output  # noqa: E402
from core.regression_output import atomic_write_text  # noqa: E402


def save(path: Path, value) -> None:
    """原子写 JSON；复用 core 的 Windows 有界重试（见 benchmark_review.save）。"""
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")


def attach(batch_path: Path, ai_dir: Path) -> dict:
    batch_path, ai_dir = batch_path.resolve(), ai_dir.resolve()
    if batch_path.is_dir():
        batch_path /= "batch.json"
    root = Path(__file__).resolve().parents[2]
    if not all(p.is_relative_to(root / "output") for p in (batch_path, ai_dir)):
        raise ValueError("Only derived artifacts under ignored output/ may be attached")
    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    metadata = json.loads((ai_dir / "status.json").read_text(encoding="utf-8"))
    validation = json.loads((ai_dir / "validation.json").read_text(encoding="utf-8"))
    ai = json.loads((ai_dir / "ai-review.json").read_text(encoding="utf-8"))
    parsed = json.loads((ai_dir / "parsed-unvalidated.json").read_text(encoding="utf-8"))
    payload, mapping = build_input(batch)
    original_input = json.loads((ai_dir / "evidence-input.json").read_text(encoding="utf-8"))
    if payload != original_input or not validate_output(parsed, mapping)["ok"]:
        raise ValueError("Evidence changed or AI output no longer validates")
    if map_output(parsed, mapping)["samples"] != ai.get("samples"):
        raise ValueError("Mapped AI artifact differs from validated response")
    if metadata.get("state") != "ok" or metadata.get("live") is not True or validation.get("ok") is not True:
        raise ValueError("Only validated live AI output can be attached")
    if ai.get("batch_id") != batch.get("batch_id") or Path(metadata["input_batch"]).resolve() != batch_path:
        raise ValueError("AI run belongs to a different batch")
    reviews = {item["sample_id"]: item for item in ai["samples"]}
    if set(reviews) != {item["sample_id"] for item in batch["samples"]}:
        raise ValueError("AI and batch samples differ")
    backup = ai_dir / "attachment-backup"
    if backup.exists():
        raise ValueError("This AI run has already been attached; retain the existing backup")
    now = datetime.now(timezone.utc).isoformat()
    risk_before = {item["sample_id"]: copy.deepcopy(item.get("risk_assessment")) for item in batch["samples"]}
    writes = []
    for sample in batch["samples"]:
        item = copy.deepcopy(reviews[sample["sample_id"]])
        item.update(status="ok", live=True, model=ai["model"], validation={"passed": True, "issues": []},
                    reviewed_at=now, score_modified_by_ai=False)
        sample["ai_review"] = item
        path = (batch_path.parent / sample["evidence_path"]).resolve()
        if not path.is_relative_to(batch_path.parent) or path == batch_path:
            raise ValueError("Sample result path escaped derived batch")
        result = json.loads(path.read_text(encoding="utf-8"))
        if result.get("sample_id") != sample["sample_id"] or result.get("risk_assessment") != risk_before[sample["sample_id"]]:
            raise ValueError("Sample result and batch risk assessment differ")
        result["ai_review"] = copy.deepcopy(item)
        writes.append((path, result))
    batch["ai_state"] = "ok"
    batch["ai_reviewed_at"] = now
    batch["ai_run"] = {key: ai.get(key) for key in ("model", "endpoint_host", "request_count", "max_retries",
                        "usage", "elapsed_ms", "http_status", "request_sha256")}
    batch["ai_run"].update(status="ok", sample_count=len(reviews), live=True,
                           validation={"passed": True, "issues": []},
                           artifact_directory=str(ai_dir.relative_to(root)).replace("\\", "/"))
    writes.append((batch_path, batch))
    backup.mkdir()
    for path, _ in writes:
        destination = backup / path.relative_to(batch_path.parent)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    for path, value in writes:
        save(path, value)
    summary = {"status": "ok", "attached_samples": len(reviews), "files_updated": len(writes),
               "risk_scores_unchanged": all(s.get("risk_assessment") == risk_before[s["sample_id"]]
                                            for s in batch["samples"]), "backup": str(backup)}
    save(ai_dir / "attachment.json", summary)
    return summary
