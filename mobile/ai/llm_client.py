"""Mobile compatibility entry for the shared LLM transport. Authorized tests only."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.ai.llm_client import (ConfigError, LLMError, PLACEHOLDER_KEYS,
    chat, redact, write_call_log, urllib, time, os)
from core.ai import llm_client as _shared

HERE = Path(__file__).resolve().parent
DEFAULT_CONFIG = HERE / 'config.local.json'


def load_config(path=None):
    return _shared.load_config(path if path is not None else DEFAULT_CONFIG)
