"""AI 阶段硬门控及报告复核；仅用于授权测试，不执行模型调用。"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
try:
    from . import validate as vd
except ImportError:
    import validate as vd


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_stage(stage: str, output, bundle: dict) -> dict:
    if not isinstance(output, dict):
        result = {"ok": False, "problems": ["模型输出必须是 JSON 对象"], "warnings": []}
    else:
        try:
            if stage == "stage1":
                policy = bundle.get("policy") or {}
                req_ids = [c["req_id"] for c in (policy.get("lint") or {}).get("checks", [])]
                result = vd.validate_stage1(output, req_ids=req_ids, policy_text=policy.get("text") or "")
            else:
                result = vd.VALIDATORS[stage](output, bundle=bundle)
        except (TypeError, ValueError, KeyError, AttributeError) as exc:
            result = {"ok": False, "problems": [f"输出结构不可校验: {type(exc).__name__}: {exc}"],
                      "warnings": []}
    result.update({"bundle_sha256": digest(bundle), "output_sha256": digest(output)})
    return result


def load_checked_stages(ai_dir: Path | None, bundle: dict) -> tuple[dict, dict]:
    """校验记录不能代替重新校验；失效、缺失或换包的旧输出不进入正文。"""
    accepted, validation = {}, {}
    if ai_dir is None:
        return accepted, validation
    try:
        original = json.loads((ai_dir / "validation.json").read_text(encoding="utf-8"))
        if not isinstance(original, dict):
            original = {}
    except (OSError, ValueError):
        original = {}
    for num in (1, 2, 3):
        stage = f"stage{num}"
        path = ai_dir / f"{stage}.json"
        recorded = original.get(stage)
        if not path.exists() and recorded is None:
            continue
        try:
            output = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            output = None
        checked = validate_stage(stage, output, bundle)
        problems = list(checked["problems"])
        warnings = list(checked["warnings"])
        if not isinstance(recorded, dict):
            problems.append("缺少该阶段的校验记录；原始输出不得当作结论")
        else:
            problems.extend(recorded.get("problems") or [])
            warnings.extend(recorded.get("warnings") or [])
            if recorded.get("ok") is not True:
                problems.append("原始阶段校验未通过")
            for field in ("bundle_sha256", "output_sha256"):
                if recorded.get(field) != checked[field]:
                    problems.append(f"{field} 不匹配或缺失：旧产物需重新运行 AI 校验")
        if num > 1 and f"stage{num - 1}" not in accepted:
            problems.append("依赖的前一阶段未通过门控，禁止传播其输出")
        checked.update({"ok": not problems, "problems": list(dict.fromkeys(problems)),
                        "warnings": list(dict.fromkeys(warnings))})
        validation[stage] = checked
        if checked["ok"]:
            accepted[stage] = output
    return accepted, validation
