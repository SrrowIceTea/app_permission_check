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
import http.client
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
    def __init__(self, message: str, records: list[dict] | None = None):
        super().__init__(message)
        self.records = records or []


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
    cfg.setdefault("validation_retries", 1)
    if type(cfg["validation_retries"]) is not int or cfg["validation_retries"] not in (0, 1):
        raise ConfigError("validation_retries 必须为 0 或 1；每阶段最多一次模型纠正")
    cfg.setdefault("use_system_proxy", True)
    if not isinstance(cfg["use_system_proxy"], bool):
        raise ConfigError("use_system_proxy 必须是 JSON 布尔值")
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
        out["api_key"] = "（已脱敏）"
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
    # Provider options are opt-in, never inferred for unrelated compatible endpoints.
    for option in ("thinking", "reasoning_effort"):
        if option in cfg:
            payload[option] = cfg[option]
    if cfg.get("response_format") is not None:
        payload["response_format"] = cfg["response_format"]
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req_sha = hashlib.sha256(body).hexdigest()
    headers = {"Content-Type": "application/json; charset=utf-8",
               "Authorization": f"Bearer {cfg['api_key']}"}

    last_err, failed = None, []
    for attempt in range(int(cfg.get("max_retries", 2)) + 1):
        started = time.time()
        raw_bytes, status, complete = b"", None, False
        record = {"tag": tag, "request_sha256": req_sha, "request_bytes": len(body),
                  "model": cfg["model"], "attempt": attempt,
                  "use_system_proxy": cfg.get("use_system_proxy", True)}
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            ctx = ssl.create_default_context()
            if cfg.get("use_system_proxy", True):
                response = urllib.request.urlopen(req, timeout=cfg.get("timeout_s", 240), context=ctx)
            else:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                    urllib.request.HTTPSHandler(context=ctx))
                response = opener.open(req, timeout=cfg.get("timeout_s", 240))
            with response as resp:
                status = getattr(resp, "status", 200)
                raw_bytes = resp.read()
                complete = True
            raw = raw_bytes.decode("utf-8", errors="replace")
            elapsed = int((time.time() - started) * 1000)
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as e:
                raise LLMError(f"响应不是 JSON（{e}）: {raw[:300]}")
            if "choices" not in data:
                raise LLMError(f"响应里没有 choices: {json.dumps(data, ensure_ascii=False)[:300]}")
            text = (data["choices"][0].get("message") or {}).get("content") or ""
            usage = data.get("usage") or {}
            return {**record, "text": text,
                    "response_raw": raw, "elapsed_ms": elapsed, "http_status": status,
                    "usage": usage, "model": data.get("model") or cfg["model"],
                    "response_complete": True, "response_bytes": len(raw_bytes),
                    "attempt_records": failed, "error": None,
                    "finish_reason": data["choices"][0].get("finish_reason")}
        except urllib.error.HTTPError as e:
            status = e.code
            detail = ""
            try:
                raw_bytes = e.read()
                complete = True
                detail = raw_bytes.decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            last_err = f"HTTP {e.code} {e.reason} {detail}"
        except http.client.IncompleteRead as e:
            # 保留已收到的残片供诊断，但绝不解析或接受截断正文。
            raw_bytes = e.partial
            last_err = f"IncompleteRead: {e}"
        except Exception as e:  # noqa: BLE001
            last_err = f"{e.__class__.__name__}: {e}"
        last_err = last_err.replace(cfg["api_key"], "（已脱敏）")
        failed.append({**record, "text": None, "http_status": status, "error": last_err,
            "elapsed_ms": int((time.time() - started) * 1000), "response_complete": complete,
            "response_bytes": len(raw_bytes), "response_raw": raw_bytes.decode("utf-8", errors="replace")})
        if attempt < int(cfg.get("max_retries", 2)):
            time.sleep(1.5 * (attempt + 1))
    raise LLMError(f"调用失败（共 {len(failed)} 次请求）: {last_err}", failed)


def write_call_log(out_dir: Path, records: list[dict], cfg: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    expanded = []
    for record in records:
        expanded.extend(record.get("attempt_records") or [])
        expanded.append({k: v for k, v in record.items() if k != "attempt_records"})
    path = out_dir / "llm-calls.jsonl"
    with path.open("a", encoding="utf-8") as fh:
        for r in expanded:
            rec = {k: v for k, v in r.items() if k != "response_raw"}
            rec["config"] = redact(cfg)
            rec["logged_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    # 响应原文单独存：体积大，且是"模型到底说了什么"的原始证据。
    for r in expanded:
        if r.get("response_raw"):
            suffix = (f".attempt-{r.get('attempt', 0) + 1}.incomplete.raw.txt"
                      if r.get("response_complete") is False else
                      f".attempt-{r.get('attempt', 0) + 1}.failed.raw.json" if r.get("error") else ".raw.json")
            (out_dir / f"llm-response-{r['tag']}{suffix}").write_text(
                r["response_raw"], encoding="utf-8")
