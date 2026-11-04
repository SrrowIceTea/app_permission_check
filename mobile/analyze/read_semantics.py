"""仅用于授权测试。兼容导出；共享返回值语义。"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.privacy.semantics import read_state, obtained_reads, read_gaps
