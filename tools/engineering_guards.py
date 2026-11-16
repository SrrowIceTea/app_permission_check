#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工程守卫：单文件行数 / 抓包授权声明 / 静默吞异常 / Python 语法。

仅用标准库，离线可跑，CI 与本地共用同一份判据（AGENTS.md 第 1/8/26 条约束）。

存量违规逐条登记在 engineering_guard_baseline.json 里豁免，但**不允许恶化**：
行数不得继续增长、授权缺口不得新增、静默异常数量不得增加、基线登记的文件不得
被搬出扫描面；拆分/补声明/改落盘让数字变小一律放行，新增文件没有豁免额度。

基线纪律（2026-11-12 五路 subagent 复核后的修复）：
- 基线缺失 = 门禁失效，直接判红，**绝不自动重建**（否则干净检出的 CI 恒绿）。
- `--update` 只允许收紧（条目变少/数值变小）；判定规则升级必须 bump
  RULE_VERSION，是一次可审计的显式动作，不能用它洗白新增违规。
- 基线带 registered_at 与每个超限文件的 split_plan 标记。
- 扫描用 os.walk 遍历整棵树（提前剪掉 output/ 等产物目录），不再限定 5 个目录；
  声明必须在文件头/docstring，AST 判定按「有无可观测副作用」而非字面 pass。

用法：
    python tools/engineering_guards.py             # 只读校验，违规返回 1
    python tools/engineering_guards.py --show     # 打印当前扫描结果
    python tools/engineering_guards.py --update   # 收紧基线（规则升级时重建）
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = Path(__file__).with_name('engineering_guard_baseline.json')
# 判定规则版本：收紧扫描/判定后 +1，旧基线必须显式 --update 重建，避免静默放宽。
# v2 = 语义 AST + 全树扫描 + 文件头声明；v3 = 读取改 utf-8-sig（剥 BOM，消除伪语法错误）。
RULE_VERSION = 3
SKIP_PARTS = {'__pycache__', 'node_modules', 'output', '.git', '.venv', '.workbuddy',
              'archive', 'dist', '_TRASH_'}
TEXT_SUFFIXES = {'.py', '.pyw', '.pyi', '.js', '.cjs', '.mjs', '.jsx', '.ts',
                 '.tsx', '.css', '.html'}
PY_SUFFIXES = {'.py', '.pyw', '.pyi'}
LINE_LIMIT = 300
AUTH_MARKERS = ('仅用于授权测试', '仅授权测试', '授权测试专用',
                'authorized testing', 'authorized tests only')
AUTH_SCOPES = (
    ('vehicle/hooks', ('.js', '.cjs', '.mjs')),
    ('vehicle/traffic', ('.py',)),
    ('mobile/hooks', ('.js', '.cjs', '.mjs')),
    ('mobile/traffic', ('.py',)),
    ('core/frida_host', ('.py', '.js')),
    ('core/collector', ('.py',)),
)
AUTH_GLOBS = (('mobile/tools', 'pcap_*.py'),)
AUTH_EXTRA = ('mobile/tools/pcap_http.py', 'mobile/tools/pcap_capture.py',
              'mobile/tools/device_capture.py', 'mobile/tools/verify_force_proxy.py',
              'core/collector/addon.py')
GENERATED_PREFIXES = ('.core-', '.entry.')


def iter_source_files():
    """产出 (相对路径, 绝对路径)。全树遍历但提前剪枝，避免扫 37GB 的 output/。"""
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_PARTS)
        base = Path(dirpath)
        for name in sorted(filenames):
            path = base / name
            if path.suffix not in TEXT_SUFFIXES:
                continue
            if name.startswith(GENERATED_PREFIXES) or name.endswith('.bundle.js'):
                continue
            relative = path.relative_to(ROOT)
            if any(part in SKIP_PARTS for part in relative.parts):
                continue
            yield relative.as_posix(), path


def line_counts() -> dict[str, int]:
    """超过 300 行的源码文件（含前端 .js/.css/.html，pre-commit 守卫只管 .py）。"""
    oversized = {}
    for rel, path in iter_source_files():
        count = len(path.read_text(encoding='utf-8-sig', errors='replace').splitlines())
        if count > LINE_LIMIT:
            oversized[rel] = count
    return oversized


def _declares_authorization(text: str) -> bool:
    """声明必须在文件头 30 行或模块 docstring 里；全文任意子串不算（防注释伪造）。"""
    if any(marker in '\n'.join(text.splitlines()[:30]).lower() for marker in AUTH_MARKERS):
        return True
    try:
        doc = ast.get_docstring(ast.parse(text), clean=False) or ''
    except (SyntaxError, ValueError):
        return False
    return any(marker in doc.lower() for marker in AUTH_MARKERS)


def authorization_gaps() -> list[str]:
    """抓包/Hook/采集相关文件里没有授权声明的；测试文件不算生产抓包代码。"""
    candidates = []
    for dirname, suffixes in AUTH_SCOPES:
        base = ROOT / dirname
        if not base.is_dir():
            continue
        for path in base.rglob('*'):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            relative = path.relative_to(ROOT)
            if any(part in SKIP_PARTS for part in relative.parts):
                continue
            if path.name.startswith(GENERATED_PREFIXES) or path.name.endswith('.bundle.js'):
                continue
            if path.name.startswith('test_'):
                continue
            candidates.append(path)
    for dirname, pattern in AUTH_GLOBS:
        candidates.extend((ROOT / dirname).glob(pattern))
    for extra in AUTH_EXTRA:
        path = ROOT / extra
        if path.is_file():
            candidates.append(path)
    gaps = []
    for path in sorted({p for p in candidates if p.is_file()}):
        text = path.read_text(encoding='utf-8-sig', errors='replace')
        if not _declares_authorization(text):
            gaps.append(path.relative_to(ROOT).as_posix())
    return gaps


def _observable(node: ast.AST) -> bool:
    """except 块里是否有可观测副作用：重抛 / 日志落盘 / 状态变更 / 带值返回。"""
    for stmt in ast.walk(node):
        if isinstance(stmt, (ast.Raise, ast.AugAssign, ast.Global, ast.Nonlocal)):
            return True
        if isinstance(stmt, ast.Return):
            value = stmt.value
            if value is None or (isinstance(value, ast.Constant) and value.value is None):
                continue  # return None 仍然是吞异常
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
            call = stmt.value
            name = getattr(call.func, 'attr', None) or getattr(call.func, 'id', None)
            if name in {'print', 'write', 'writelines', 'append', 'extend', 'emit',
                        'save', 'flush', 'log', 'debug', 'info', 'warning', 'error',
                        'exception', 'critical', 'add', 'put', 'send'}:
                return True
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, (ast.Attribute, ast.Subscript)):
                    return True
                if isinstance(target, ast.Name) and target.id not in {'_', 'exc', 'e', 'err'}:
                    return True
    return False


def python_ast_scan() -> tuple[list[tuple[str, int, str]], list[str]]:
    """返回 (静默吞异常位置, 语法错误位置)。按语义判定，不只认字面 `pass`。"""
    sites: list[tuple[str, int, str]] = []
    syntax_errors: list[str] = []
    for rel, path in iter_source_files():
        if path.suffix not in PY_SUFFIXES:
            continue
        text = path.read_text(encoding='utf-8-sig', errors='replace')
        try:
            tree = ast.parse(text, filename=rel)
        except SyntaxError as exc:
            # 语法错误文件必须判红，不能靠「解析失败就跳过」绕过守卫。
            syntax_errors.append(f'{rel}:{exc.lineno}')
            continue
        lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler) or _observable(node):
                continue
            line = lines[node.lineno - 1] if node.lineno <= len(lines) else ''
            if '# noqa: BLE001' in line:
                reason = line.split('#', 1)[1].replace('noqa: BLE001', '').strip()
                if len(reason) >= 8 and len(set(reason)) > 3:
                    continue  # 写明了理由的收尾代码，算显式允许忽略
            sites.append((rel, node.lineno, line.strip()))
    return sites, sorted(syntax_errors)


def silent_except_sites() -> list[tuple[str, int, str]]:
    return python_ast_scan()[0]


def snapshot() -> dict:
    sites, syntax_errors = python_ast_scan()
    counts: dict[str, int] = {}
    for rel, _, _ in sites:
        counts[rel] = counts.get(rel, 0) + 1
    return {'rule_version': RULE_VERSION, 'max_lines': line_counts(),
            'authorization_gaps': sorted(authorization_gaps()),
            'silent_except_counts': counts, 'syntax_errors': syntax_errors}


def violations(current: dict, baseline: dict) -> list[str]:
    """只判「新增或恶化」，存量豁免见模块 docstring。"""
    bad = []
    if baseline.get('rule_version') != RULE_VERSION:
        bad.append(f'基线规则版本 {baseline.get("rule_version")} != {RULE_VERSION}，'
                   f'判定已变更，需显式 --update 重建（不得静默沿用旧基线）')
    for rel, count in current.get('max_lines', {}).items():
        allowed = baseline.get('max_lines', {}).get(rel)
        if allowed is None or count > allowed:
            bad.append(f'单文件 >{LINE_LIMIT} 行且未登记/继续变长: {rel} = {count} 行（基线 {allowed}）')
    for rel in sorted(set(current.get('authorization_gaps', []))
                      - set(baseline.get('authorization_gaps', []))):
        bad.append(f'抓包/Hook 文件缺「仅用于授权测试」声明: {rel}')
    for rel, count in current.get('silent_except_counts', {}).items():
        allowed = baseline.get('silent_except_counts', {}).get(rel, 0)
        if count > allowed:
            bad.append(f'新增静默吞异常: {rel} 当前 {count} 处 > 基线 {allowed} 处')
    for item in sorted(set(current.get('syntax_errors', []))
                       - set(baseline.get('syntax_errors', []))):
        bad.append(f'Python 语法错误（不再静默跳过）: {item}')
    # 把登记过的文件搬出扫描面不应洗白：原路径消失且不再超限时才允许自然移除。
    for rel in baseline.get('max_lines', {}):
        if rel not in current.get('max_lines', {}) and not (ROOT / rel).is_file():
            bad.append(f'基线登记的文件已不在原路径: {rel}（移动/删除需显式更新基线）')
    return bad


def baseline_regressions(old: dict, new: dict) -> list[str]:
    """--update 只允许收紧；新增条目或数值上调必须判红，防止洗白。"""
    bad = []
    for key in ('max_lines', 'silent_except_counts'):
        old_map, new_map = old.get(key, {}), new.get(key, {})
        for rel, value in new_map.items():
            if rel not in old_map:
                bad.append(f'{key} 新增条目 {rel}={value}（--update 只记录改善）')
            elif value > old_map[rel]:
                bad.append(f'{key} {rel} 从 {old_map[rel]} 上调到 {value}')
    for key in ('authorization_gaps', 'syntax_errors'):
        for rel in sorted(set(new.get(key, [])) - set(old.get(key, []))):
            bad.append(f'{key} 新增条目 {rel}（--update 只记录改善）')
    return bad


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--update', action='store_true', help='收紧基线（规则升级时重建）')
    parser.add_argument('--show', action='store_true', help='只打印当前扫描结果')
    args = parser.parse_args()
    current = snapshot()
    if args.show:
        print(json.dumps(current, ensure_ascii=False, indent=2))
        return 0
    baseline = None
    if BASELINE.is_file():
        baseline = json.loads(BASELINE.read_text(encoding='utf-8'))
    elif not args.update:
        print('[guards] 基线文件缺失：门禁失效，拒绝自动重建。'
              '请提交 tools/engineering_guard_baseline.json，或显式用 --update 初始化。',
              file=sys.stderr)
        return 1
    if args.update:
        if baseline is not None and baseline.get('rule_version') == RULE_VERSION:
            bad = baseline_regressions(baseline, current)
            if bad:
                print('--update 被拒绝（只允许收紧基线）：\n  - ' + '\n  - '.join(bad),
                      file=sys.stderr)
                return 1
        payload = {'registered_at': date.today().isoformat(),
                   'note': '存量违规基线；只允许改善，不允许恶化。用 --update 收紧。',
                   'split_plan': {rel: 'pending_split' for rel in current['max_lines']},
                   **current}
        BASELINE.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n',
                            encoding='utf-8')
        print(f'基线已写入 {BASELINE.name}（rule_version={RULE_VERSION}）：'
              f'{len(current["max_lines"])} 个超限文件 / '
              f'{len(current["authorization_gaps"])} 个声明缺口 / '
              f'{sum(current["silent_except_counts"].values())} 处静默吞异常')
        return 0
    bad = violations(current, baseline)
    if bad:
        print('工程守卫未通过：\n  - ' + '\n  - '.join(bad), file=sys.stderr)
        return 1
    print(f'工程守卫通过：{len(current["max_lines"])} 个存量超限文件、'
          f'{len(current["authorization_gaps"])} 个存量声明缺口、'
          f'{sum(current["silent_except_counts"].values())} 处存量静默异常均未恶化。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
