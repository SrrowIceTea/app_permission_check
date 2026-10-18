"""只读论文 APK 批次结果；仅用于授权测试，不启动设备或读取原始事件大文件。"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from mobile.workbench.store import ROOT

MAX_JSON_BYTES = 8 * 1024 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,160}$")
VERDICTS = ("observed", "not_observed", "unsupported", "failed", "not_run")


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError("批次和样本 ID 仅允许字母、数字、下划线和连字符")
    return value


def _read_object(path: Path) -> dict:
    with path.open("rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("批次或证据 JSON 超过 8 MiB 上限")
    try:
        value = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("批次或证据不是有效 UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("批次或证据 JSON 必须是对象")
    return value


def _batches(root: Path | None):
    output = ((ROOT if root is None else Path(root)) / "output").resolve()
    if not output.is_dir():
        return
    for path in sorted(output.glob("root-benchmark-*/batch.json"), reverse=True):
        resolved = path.resolve()
        if not resolved.is_relative_to(output):
            continue
        yield resolved.parent, resolved


def _load_batch(directory: Path, path: Path) -> dict:
    batch = _read_object(path)
    _identifier(batch.get("batch_id"))
    samples = batch.get("samples")
    if not isinstance(samples, list) or not all(isinstance(s, dict) for s in samples):
        raise ValueError("批次 samples 必须是对象数组")
    ids = [_identifier(sample.get("sample_id")) for sample in samples]
    if len(ids) != len(set(ids)):
        raise ValueError("批次含重复样本 ID")
    return batch


def _evidence_path(directory: Path, sample: dict) -> Path | None:
    sample_id = _identifier(sample.get("sample_id"))
    relative = sample.get("evidence_path")
    if not isinstance(relative, str):
        return None
    # 只允许运行器约定的样本 JSON；客户端不能选择文件名或系统路径。
    parts = relative.replace("\\", "/").split("/")
    if (len(parts) != 3 or parts[:2] != ["samples", sample_id]
            or parts[2] not in ("result.json", "evidence.json")):
        return None
    target = directory.joinpath(*parts).resolve()
    if not target.is_relative_to(directory) or not target.is_file():
        return None
    return target


def catalog(root: Path | None = None) -> dict:
    """只读小型 batch.json；统计保留原 verdict，未观察到不等于安全。"""
    batches, errors, seen = [], [], set()
    for directory, path in _batches(root):
        try:
            batch = _load_batch(directory, path)
            batch_id = batch["batch_id"]
            if batch_id in seen:
                raise ValueError("重复批次 ID")
            seen.add(batch_id)
            samples = []
            for sample in batch["samples"]:
                item = dict(sample)
                available = _evidence_path(directory, sample) is not None
                item["evidence_available"] = available
                item["evidence_url"] = (f"/api/benchmarks/{batch_id}/"
                                        f"{sample['sample_id']}/evidence") if available else None
                samples.append(item)
            value = dict(batch, samples=samples)
            counts = Counter(sample.get("verdict") for sample in samples)
            value["summary"] = {"sample_count": len(samples),
                                "verdict_counts": {v: counts[v] for v in VERDICTS},
                                "unclassified_count": sum(n for v, n in counts.items()
                                                          if v not in VERDICTS),
                                "finding_count": sum(len(s.get("findings") or [])
                                                     for s in samples)}
            batches.append(value)
        except (OSError, ValueError) as exc:
            errors.append({"batch": directory.name, "reason": str(exc)})
    # Enrichment is new evidence, not a rerun: preserve original runtime timestamps.
    batches.sort(key=lambda b: str(b.get("ai_reviewed_at") or b.get("assessed_at")
                                   or b.get("created_at") or ""), reverse=True)
    return {"batches": batches, "count": len(batches), "errors": errors}


def evidence(batch_id: str, sample_id: str, root: Path | None = None) -> dict | None:
    """通过已登记批次和样本 ID 查证据，不提供任意路径下载接口。"""
    _identifier(batch_id)
    _identifier(sample_id)
    for directory, path in _batches(root):
        try:
            batch = _load_batch(directory, path)
        except (OSError, ValueError):
            continue
        if batch["batch_id"] != batch_id:
            continue
        sample = next((s for s in batch["samples"] if s["sample_id"] == sample_id), None)
        if sample is None:
            return None
        target = _evidence_path(directory, sample)
        return _read_object(target) if target is not None else None
    return None
