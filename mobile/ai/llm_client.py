#!/usr/bin/env python3
"""OpenAI 兼容的 LLM 客户端 —— 不引入任何新依赖（urllib 足够）。

仅用于授权测试（已获授权的样本与设备）。

两种运行方式：
    --dry-run   只渲染提示词并落盘，**不联网**。用来在没有 key 的情况下
                审阅将要发送的完整内容（也用来复核脱敏是否到位）。
    正常调用    读 config.local.json（或环境变量），POST /chat/completions。

调用记录必须落盘：每次请求存 model / prompt 的 sha256 / 响应原文 / 耗时，
**api_key 一律脱敏**。理由是报告要能回答"这个结论是哪次调用产生的"，
以及"当时用的哪个模型"——模型换版本会让同样的提示词给出不同结论。
"""
from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / "config.local.json"
PLACEHOLDER_KEYS = {"", "PUT-YOUR-KEY-HERE", "sk-xxx", "YOUR_API_KEY"}


class ConfigError(RuntimeError):
    pass


class LLMError(RuntimeError):
    pass


def load_config(path: Path | None = None) -> dict:
    """配置文件 → 环境变量兜底。**没有 key 就明确报错，不用匿名请求硬跑。**"""
    cfg: dict = {}
    p = path or DEFAULT_CONFIG
    if p.exists():
        cfg = json.loads(p.read_text(encoding="utf-8"))
    for key, env in (("base_url", "VSCAN_LLM_BASE_URL"), ("api_key", "VSCAN_LLM_API_KEY"),
                     ("model", "VSCAN_LLM_MODEL")):
        if os.environ.get(env):
            cfg[key] = os.environ[env]
    cfg.setdefault("temperature", 0.1)
    cfg.setdefault("max_tokens", 8192)
    cfg.setdefault("timeout_s", 240)
    cfg.setdefault("max_retries", 2)
    if not cfg.get("base_url") or not cfg.get("model"):
        raise ConfigError(
            f"缺少 base_url / model。复制 {HERE / 'config.example.json'} 为 "
            f"config.local.json 并填写（或用 VSCAN_LLM_* 环境变量）。")
    key = (cfg.get("api_key") or "").strip()
    if key in PLACEHOLDER_KEYS:
        raise ConfigError(
            "api_key 未填写。请编辑 config.local.json 填入密钥"
            "（或设 VSCAN_LLM_API_KEY）；只想看提示词内容请用 --dry-run。")
    cfg["api_key"] = key
    return cfg


def redact(cfg: dict) -> dict:
    out = dict(cfg)
    if out.get("api_key"):
        k = out["api_key"]
        out["api_key"] = f"{k[:4]}…{k[-4:]}（已脱敏）" if len(k) > 10 else "（已脱敏）"
    return out


def chat(cfg: dict, *, system: str, user: str, tag: str) -> dict:
    """一次对话补全。返回 {text, request_sha256, response_raw, elapsed_ms, http_status}。"""
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg["model"],
        "temperature": cfg.get("temperature", 0.1),
        "max_tokens": cfg.get("max_tokens", 8192),
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "stream": False,
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req_sha = hashlib.sha256(body).hexdigest()
    headers = {"Content-Type": "application/json; charset=utf-8",
               "Authorization": f"Bearer {cfg['api_key']}"}

    last_err = None
    for attempt in range(int(cfg.get("max_retries", 2)) + 1):
        started = time.time()
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=cfg.get("timeout_s", 240),
                                         context=ctx) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                status = getattr(resp, "status", 200)
            elapsed = int((time.time() - started) * 1000)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                raise LLMError(f"响应不是 JSON（{e}）: {raw[:300]}")
            if "choices" not in data:
                raise LLMError(f"响应里没有 choices: {json.dumps(data, ensure_ascii=False)[:300]}")
            text = (data["choices"][0].get("message") or {}).get("content") or ""
            usage = data.get("usage") or {}
            return {"tag": tag, "text": text, "request_sha256": req_sha,
                    "response_raw": raw, "elapsed_ms": elapsed, "http_status": status,
                    "usage": usage, "model": data.get("model") or cfg["model"],
                    "attempt": attempt, "error": None}
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            last_err = f"HTTP {e.code} {e.reason} {detail}"
        except Exception as e:  # noqa: BLE001
            last_err = f"{e.__class__.__name__}: {e}"
        if attempt < int(cfg.get("max_retries", 2)):
            time.sleep(1.5 * (attempt + 1))
    raise LLMError(f"调用失败（已重试）: {last_err}")


def write_call_log(out_dir: Path, records: list[dict], cfg: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "llm-calls.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for r in records:
            rec = {k: v for k, v in r.items() if k != "response_raw"}
            rec["config"] = redact(cfg)
            rec["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    # 响应原文单独存：体积大，且是"模型到底说了什么"的原始证据。
    for r in records:
        if r.get("response_raw"):
            (out_dir / f"llm-response-{r['tag']}.raw.json").write_text(
                r["response_raw"], encoding="utf-8")
