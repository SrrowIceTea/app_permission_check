"""Derive a new risk-rated batch without rewriting historical evidence. 仅用于授权测试。"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
from mobile.analyze.risk_rating import assess_risk
from mobile.lab.root_cases import ROOT
from mobile.lab.root_runtime import save


def derive(source: Path, out: Path):
    source, out = source.resolve(), out.resolve()
    if not source.is_relative_to((ROOT / "output").resolve()):
        raise ValueError("source must be a project-owned batch")
    if out.exists() or not out.is_relative_to((ROOT / "output").resolve()) or not out.name.startswith("root-benchmark-"):
        raise ValueError("use a new root-benchmark-* output directory")
    batch = json.loads((source / "batch.json").read_text(encoding="utf-8"))
    out.mkdir(parents=True)
    batch.update(batch_id=out.name, assessed_at=datetime.now(timezone.utc).isoformat(),
                 source_batch_id=batch["batch_id"], source_evidence_directory=str(source),
                 enrichment="risk-rating", ai_state="not_run")
    for sample in batch["samples"]:
        sid = sample["sample_id"]
        original = (source / sample["evidence_path"]).resolve()
        if not original.is_relative_to(source):
            raise ValueError("source evidence path escaped the batch")
        result = json.loads(original.read_text(encoding="utf-8"))
        folder = out / "samples" / sid
        folder.mkdir(parents=True)
        result["risk_assessment"] = assess_risk(result)
        result["ai_review"] = {"status": "not_run", "reason": "尚未进行本轮真实模型调用"}
        result["source_evidence_path"] = str(original)
        for name in ("events.jsonl", "assessment.json", "oracle.json"):
            path = original.parent / name
            if path.is_file():
                shutil.copy2(path, folder / name)
        save(folder / "result.json", result)
        sample.update(risk_assessment=result["risk_assessment"], ai_review=result["ai_review"])
    save(out / "batch.json", batch)
    return batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = derive(args.source, args.out)
    print(json.dumps({"batch_id": result["batch_id"], "samples": len(result["samples"])}))


if __name__ == "__main__":
    main()
