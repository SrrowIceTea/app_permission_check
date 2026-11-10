"""产物新鲜度闸：把「设备将执行哪份代码」钉成可验证的事实。

仅用于授权测试（自有设备与自有 APK）。

背景（2026-11-10）：`vehicle/hooks/dist/` 被 gitignore，设备上实际跑的是 11-06 的旧
bundle，而源码已经是 11-10，**没有任何环节会发现这件事**。对取证工具来说这是根本性
问题——那一轮所有"实测"描述的都是旧产物。本模块把 bundle 与它的源码集合绑定：

  * `core/frida_host/build.py` 每产出一个 bundle，就在旁边写 `<bundle>.sha256.json`；
  * 任何走设备采集的入口在起设备之前调用 `verify()`（`run.py` 是最后一道）。

三档判定（2026-11-10 收紧，见报告）：

  1. 产物与当前源码一致 + 源码干净（相对 HEAD 无未提交改动）→ `pass`；
  2. 产物与当前源码一致 + 源码 dirty（构建时或现在）→ `warn_dirty`：不拒绝，显著
     告警，并把 dirty 标记与未提交文件列表写进证据。dirty 构建本身不一定错
     （开发期常态），错的是**事后不知道它是 dirty 的**；
  3. 产物落后（指纹不符 / bundle 被改 / 没有清单）→ `refuse`，拒绝开跑。

判定只覆盖**参与该 bundle 的源码集合**（入口 + 其相对 import 闭包 + 构建脚本）；
仓库里其它文件的未提交改动不影响本轮结论。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SUFFIX = '.sha256.json'
REBUILD = 'python core/frida_host/build.py --platform vehicle'
# 只跟相对来源：`from './x.js'` / `import './x.js'` / `import('./x.js')`。
# 裸包名（frida-java-bridge 等）不入闭包——那是 node_modules，不是本仓源码。
IMPORT = re.compile(r"""(?:\bfrom|\bimport)\s*\(?\s*['"](\.[^'"]+)['"]""")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _rel(path: Path, root: Path) -> str:
    return str(Path(path).resolve().relative_to(Path(root).resolve())).replace('\\', '/')


def source_closure(entry: Path, root: Path = ROOT) -> list[Path]:
    """入口及其相对 import 的闭包。新增 import 会让闭包变化 → 闸会发现产物落后。"""
    root = Path(root).resolve()
    pending, seen = [Path(entry).resolve()], []
    while pending:
        current = pending.pop()
        try:
            current.relative_to(root)
        except ValueError:
            continue                     # 仓库外（例如 node_modules）不跟踪
        if current in seen or not current.is_file() or 'node_modules' in current.parts:
            continue
        seen.append(current)
        for spec in IMPORT.findall(current.read_text(encoding='utf-8', errors='replace')):
            target = (current.parent / spec).resolve()
            if not target.suffix:
                target = target.with_suffix('.js')
            if target.is_file():
                pending.append(target)
    return sorted(seen)


def _git_state(paths, root: Path) -> dict:
    """这些文件相对 HEAD 有没有未提交改动。git 不可用/不在仓库内时如实标 available=False。"""
    names = [_rel(path, root) for path in paths]
    try:
        result = subprocess.run(['git', '-C', str(root), 'status', '--porcelain', '--', *names],
                                capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        return {'available': False, 'dirty': None, 'files': [], 'error': type(error).__name__}
    if result.returncode:
        return {'available': False, 'dirty': None, 'files': [],
                'error': (result.stderr or '').strip()[:200] or f'exit {result.returncode}'}
    files = [line[3:].strip() for line in result.stdout.splitlines() if line.strip()]
    return {'available': True, 'dirty': bool(files), 'files': files}


def _fingerprint(sources: dict) -> str:
    payload = '\n'.join(f'{name}\0{digest}' for name, digest in sorted(sources.items()))
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def build_time() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')


def write_manifest(bundle: Path, entry: Path, platform: str, root: Path = ROOT) -> dict:
    """构建时调用：把 bundle 身份、源码指纹、dirty 标记与构建时间写到 bundle 旁边。"""
    bundle, entry, root = Path(bundle), Path(entry), Path(root)
    files = source_closure(entry, root)
    if not files:
        raise RuntimeError(f'源码闭包为空：{entry}')
    sources = {_rel(path, root): _sha256(path) for path in files}
    builder = root / 'core/frida_host/build.py'
    manifest = {'schema': 1, 'platform': platform,
                'bundle': bundle.name, 'bundle_sha256': _sha256(bundle),
                'bundle_bytes': bundle.stat().st_size,
                'entry': _rel(entry, root), 'built_at': build_time(),
                'builder': {'path': _rel(builder, root), 'sha256': _sha256(builder)}
                           if builder.is_file() else None,
                'source_fingerprint': _fingerprint(sources), 'sources': sources,
                'dirty_at_build': _git_state(files, root)}
    target = bundle.with_name(bundle.name + SUFFIX)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', newline='\n',
                                         prefix='.manifest-', suffix='.tmp',
                                         dir=target.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(manifest, handle, ensure_ascii=False, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return manifest


def read_manifest(bundle: Path):
    path = Path(bundle).with_name(Path(bundle).name + SUFFIX)
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except ValueError:
        return None


def _result(tier: str, code: str, detail: dict) -> dict:
    return {'tier': tier, 'code': code, **detail}


def verify(bundle, root: Path = ROOT) -> dict:
    """设备采集前的硬校验。返回 {tier: pass|warn_dirty|refuse, code, detail...}。"""
    bundle, root = Path(bundle).resolve(), Path(root).resolve()
    if not bundle.is_file():
        return _result('refuse', 'bundle_missing', {'bundle': str(bundle)})
    manifest = read_manifest(bundle)
    if manifest is None:
        return _result('refuse', 'no_manifest', {'bundle': str(bundle)})
    current_sha = _sha256(bundle)
    if current_sha != manifest.get('bundle_sha256'):
        return _result('refuse', 'bundle_modified',
                       {'bundle': str(bundle), 'manifest': manifest, 'sha256': current_sha})
    entry = root / str(manifest.get('entry') or '')
    files = source_closure(entry, root) if entry.is_file() else []
    sources = {_rel(path, root): _sha256(path) for path in files}
    recorded = dict(manifest.get('sources') or {})
    changed = sorted(name for name in set(recorded) | set(sources)
                     if recorded.get(name) != sources.get(name))
    builder = root / 'core/frida_host/build.py'
    builder_changed = bool(manifest.get('builder') and builder.is_file()
                           and _sha256(builder) != manifest['builder'].get('sha256'))
    now = _git_state([root / name for name in sources] if sources else [], root)
    detail = {'bundle': str(bundle), 'manifest': manifest, 'sha256': current_sha,
              'changed_sources': changed, 'builder_changed': builder_changed,
              'dirty_now': now, 'fingerprint_matches': not changed and not builder_changed}
    if changed or builder_changed:
        return _result('refuse', 'stale', detail)
    if (manifest.get('dirty_at_build') or {}).get('dirty') or now.get('dirty'):
        return _result('warn_dirty', 'dirty', detail)
    return _result('pass', 'clean', detail)


def identity(bundle, root: Path = ROOT) -> dict:
    """写进证据的身份块：bundle sha256 + 构建时间 + 源码指纹 + dirty 标记。"""
    bundle = Path(bundle)
    manifest = read_manifest(bundle) or {}
    return {'bundle': bundle.name, 'sha256': _sha256(bundle),
            'built_at': manifest.get('built_at'),
            'source_fingerprint': manifest.get('source_fingerprint'),
            'dirty_at_build': manifest.get('dirty_at_build'),
            'sources': len(manifest.get('sources') or {}),
            'manifest': str(bundle.name) + SUFFIX if manifest else None}


def refusal_text(gate: dict) -> str:
    bundle, manifest = gate.get('bundle'), gate.get('manifest') or {}
    if gate['code'] == 'bundle_missing':
        return f'钩子产物不存在：{bundle}。请先重建：{REBUILD}'
    if gate['code'] == 'no_manifest':
        return (f'{bundle} 没有构建清单（{SUFFIX}）——无法证明它就是当前源码的产物。\n'
                f'请先重建：{REBUILD}')
    if gate['code'] == 'bundle_modified':
        return (f'{bundle} 与构建清单记录的 sha256 不一致（产物被改过或清单过期）。\n'
                f'请先重建：{REBUILD}')
    changed = gate.get('changed_sources') or []
    return (f'产物是 {manifest.get("built_at") or "未知时间"} 时间的、源码已变'
            f'（{len(changed)} 个文件不一致：{", ".join(changed[:6]) or "-"}）。\n'
            f'请先重建：{REBUILD}')


def warning_text(gate: dict) -> str:
    manifest, dirty = gate.get('manifest') or {}, (gate.get('dirty_at_build') or {})
    files = (gate.get('dirty_now') or {}).get('files') or dirty.get('files') or []
    return (f'!! FRESHNESS_DIRTY：本轮钩子产物 {gate.get("bundle")} 是基于 dirty 源码构建的'
            f'（{len(files)} 个文件未提交：{", ".join(files[:6]) or "-"}）。\n'
            f'!! 这些证据的代码基线不是某个提交，报告会带 dirty 标记。'
            f'构建时间：{manifest.get("built_at") or "未知"}；'
            f'sha256={str(gate.get("sha256") or "")[:16]}…')


def announce(gate: dict) -> None:
    """dirty 档的显著告警（pass/refuse 由调用方处理）。"""
    if gate['tier'] == 'warn_dirty':
        print(warning_text(gate), flush=True)


def summary_line(gate: dict) -> str:
    manifest = gate.get('manifest') or {}
    return json.dumps({'freshness': gate['tier'], 'code': gate['code'],
                       'bundle': Path(gate.get('bundle') or '').name,
                       'sha256': gate.get('sha256'),
                       'built_at': manifest.get('built_at'),
                       'dirty_at_build': (manifest.get('dirty_at_build') or {}).get('dirty')},
                      ensure_ascii=False)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--write', type=Path, metavar='BUNDLE')
    parser.add_argument('--entry', type=Path, help='入口钩子源码（配合 --write）')
    parser.add_argument('--platform', default='vehicle')
    parser.add_argument('--verify', type=Path, metavar='BUNDLE')
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    if args.write:
        if not args.entry:
            parser.error('--write 需要 --entry')
        manifest = write_manifest(args.write, args.entry, args.platform, args.root)
        print(json.dumps({'manifest': str(args.write) + SUFFIX,
                          'bundle_sha256': manifest['bundle_sha256'],
                          'source_fingerprint': manifest['source_fingerprint'],
                          'dirty_at_build': manifest['dirty_at_build']}, ensure_ascii=False))
        return 0
    if args.verify:
        gate = verify(args.verify, args.root)
        print(summary_line(gate))
        if gate['tier'] == 'refuse':
            print(refusal_text(gate), file=sys.stderr)
            return 1
        if gate['tier'] == 'warn_dirty':
            print(warning_text(gate), file=sys.stderr)
        return 0
    parser.error('需要 --write 或 --verify')


if __name__ == '__main__':
    raise SystemExit(main())
