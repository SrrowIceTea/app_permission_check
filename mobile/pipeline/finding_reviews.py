"""Store human decisions beside, and independently from, detector findings."""
import hashlib
import json

from mobile.pipeline.registry import JobError
from mobile.workbench.store import now, write_json

STATUSES = ("confirmed", "rejected", "needs_more_evidence")
FILE = "finding-reviews.json"


def rows_for(job):
    if job.state != "done":
        raise JobError(409, "review_unavailable", "动态审计完成后才可复核本任务。")
    path = job.out / "out/bundle.json"
    if not path.is_file():
        raise JobError(404, "review_bundle_missing", "本任务的发现证据不可用。")
    rows = json.loads(path.read_text(encoding="utf-8"))["findings"]
    keyed = {}
    for finding in rows:
        if not isinstance(finding.get("rule_id"), str) or not finding["rule_id"].startswith("MOB-"):
            continue
        raw = json.dumps([job.id, finding], sort_keys=True, ensure_ascii=False).encode()
        keyed[hashlib.sha256(raw).hexdigest()] = finding
    return keyed


def load(job):
    path = job.out / FILE
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw["version"] != 1 or raw["job_id"] != job.id or not isinstance(raw["reviews"], dict):
            raise ValueError("复核文件版本或任务不符")
        return raw["reviews"]
    except (ValueError, OSError, KeyError, TypeError) as error:
        raise JobError(409, "review_unreadable", "现有复核记录不可读，保留原文件。") from error


def listing(job):
    rows, records = rows_for(job), load(job)
    return {"findings": [{"finding_uid": uid, "finding": row, "review": records.get(uid)}
                         for uid, row in rows.items()]}


def save(job, body, lock):
    fields = {"finding_uid", "status", "reviewer_kind", "reviewer", "note"}
    if not isinstance(body, dict) or set(body) != fields or body["reviewer_kind"] != "human":
        raise JobError(400, "review_fields", "请人工提交复核人、状态和复核依据。")
    uid, reviewer, note = body["finding_uid"], body["reviewer"], body["note"]
    if not isinstance(uid, str) or uid not in rows_for(job):
        raise JobError(404, "finding_not_in_task", "本任务没有这条发现。请刷新任务。")
    if body["status"] not in STATUSES:
        raise JobError(400, "review_status", "请选择确认、驳回或待补证。")
    if not isinstance(reviewer, str) or not 1 <= len(reviewer.strip()) <= 100 or any(c < " " for c in reviewer):
        raise JobError(400, "reviewer_invalid", "请填写 1–100 字的复核人。")
    if not isinstance(note, str) or not 1 <= len(note.strip()) <= 500:
        raise JobError(400, "review_note_invalid", "请填写 1–500 字的复核依据。")
    record = {"status": body["status"], "reviewer_kind": "human", "reviewer": reviewer.strip(),
              "note": note.strip(), "reviewed_at": now()}
    with lock:
        records = load(job)
        records[uid] = record
        write_json(job.out / FILE, {"version": 1, "job_id": job.id, "reviews": records})
    return record
