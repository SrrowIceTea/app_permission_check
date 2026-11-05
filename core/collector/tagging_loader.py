"""Load the explicitly selected platform tagging module. 仅用于授权测试。"""
import importlib.util
import os
from pathlib import Path


def load_tagging(root):
    path = os.environ.get('VSCAN_TAGGING')
    if not path:
        raise SystemExit('VSCAN_TAGGING must select the platform tagging file.')
    src = Path(path)
    if not src.is_absolute():
        src = root / src
    if not src.is_file():
        raise SystemExit(f'VSCAN_TAGGING file missing: {src}')
    spec = importlib.util.spec_from_file_location('vscan_tagging', src)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, 'tag_sensitive'):
        raise SystemExit(f'{src} lacks tag_sensitive(text)')
    return module
