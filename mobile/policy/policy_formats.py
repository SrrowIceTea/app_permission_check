"""Compatibility import for shared document decoding. 仅用于授权测试。"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.policy.policy_formats import *  # noqa: F401,F403,E402
