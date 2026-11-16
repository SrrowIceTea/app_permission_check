"""回归入口的解释器前置检查：把「环境缺库」与「代码回归失败」分开。

背景（实测两次误判）：本机默认 `python` 是 WindowsApps 的 3.15，未装
frida / mitmproxy / cryptography / jsonschema 等；用它跑回归会出现成片
`ModuleNotFoundError`，看起来像代码坏了。入口先做一次 import 探测：
缺包就打印缺哪些、该用哪个解释器，并以独立退出码 3 退出；不缺则什么都不做。

约束：
- 只用标准库；探测自身失败一律按"缺包"记录并说明，不额外抛异常。
- 不自动切换解释器、不改 PATH、不安装任何包。
- 退出码：3 = 环境缺库（本模块），1 = 测试失败（各回归入口），两者不混用。
"""
import os
import sys
from importlib.util import find_spec
from pathlib import Path

EXIT_ENV_MISSING = 3

# 各入口真正 import 的第三方包：import 名 -> requirements.txt 里的包名。
# maxminddb 虽在 requirements.txt 里，但仓库没有任何 import，故意不要求。
BASE_DEPS = {
    'frida': 'frida',
    'mitmproxy': 'mitmproxy',
    'cryptography': 'cryptography',
}
MOBILE_DEPS = {
    **BASE_DEPS,
    'jsonschema': 'jsonschema',
    'PIL': 'Pillow',
    'pypdf': 'pypdf',
    'reportlab': 'reportlab',
}


def missing_packages(modules):
    """返回缺失的 import 名列表；探测异常按缺失处理，避免检查本身假绿。"""
    missing = []
    for name in modules:
        try:
            available = find_spec(name) is not None
        except Exception as exc:  # 坏安装/半安装的包不能当成"存在"
            print(f'[env-guard] 探测 {name} 时出错，按缺失处理：{exc!r}', file=sys.stderr)
            available = False
        if not available:
            missing.append(name)
    return missing


def project_interpreters():
    """按 environment.ps1 的口径给出候选解释器：(路径, 来源说明)。"""
    root = Path(__file__).resolve().parents[1]
    candidates = []
    override = os.environ.get('VSCAN_PYTHON')
    if override:
        candidates.append((Path(override), 'VSCAN_PYTHON'))
    candidates.append((root / '.venv' / 'Scripts' / 'python.exe', '项目 .venv'))
    local = os.environ.get('LOCALAPPDATA')
    if local:
        candidates.append(
            (Path(local) / 'Programs' / 'Python' / 'Python313' / 'python.exe',
             'Python 3.13 安装目录'))
    return [(path, label) for path, label in candidates if path.is_file()]


def _command_line(args):
    parts = []
    for arg in args:
        parts.append(f'"{arg}"' if (' ' in arg or '\t' in arg) else arg)
    return ' '.join(parts)


def _report(entry, modules, missing, argv):
    lines = [
        '',
        '=' * 72,
        '[env-guard] 环境检查未通过：当前解释器缺少第三方依赖。',
        '这是环境缺库，不是代码回归失败——测试尚未开始，也没有任何结论。',
        '-' * 72,
        f'  入口脚本  : {entry}',
        f'  当前解释器: {sys.executable}',
        f'  版本      : {sys.version.split()[0]}',
        f'  缺少依赖  : {", ".join(missing)}',
    ]
    pip_names = [modules[name] for name in missing if modules[name] != name]
    if pip_names:
        lines.append(f'  对应 pip 包: {", ".join(pip_names)}')
    lines.append('=' * 72)

    chosen = project_interpreters()
    same_as_suggested = chosen and Path(sys.executable).resolve() == chosen[0][0].resolve()
    if same_as_suggested:
        lines += [
            '解释器选对了，但这个解释器没装依赖。在它下面安装即可（不碰系统默认 python）：',
            f'    & "{sys.executable}" -m pip install -r requirements.txt',
        ]
    elif chosen:
        path, label = chosen[0]
        command = _command_line(argv or sys.argv[1:])
        lines += [
            f'请改用项目解释器（{label}）重跑：',
            f'    .\\tools\\python313.ps1 {entry} {command}',
            '等价写法：',
            f'    & "{path}" {entry} {command}',
            f'    . .\\environment.ps1; & $VSCAN_PYTHON {entry} {command}',
        ]
    else:
        lines += [
            '没有找到项目解释器（依次尝试 VSCAN_PYTHON、.venv、%LOCALAPPDATA%\\Programs\\'
            'Python\\Python313）。请先按 requirements.txt 准备解释器。',
        ]

    lines += [
        '-' * 72,
        '依赖清单见 requirements.txt；退出码 3 专指环境缺库，1 才是测试失败。',
        '=' * 72,
        '',
    ]
    print('\n'.join(lines), file=sys.stderr)


def enforce_dependencies(entry, modules, argv=None):
    """缺依赖时打印可操作报告并以退出码 3 结束；不缺则直接返回。"""
    missing = missing_packages(modules)
    if not missing:
        return
    _report(entry, modules, missing, argv)
    raise SystemExit(EXIT_ENV_MISSING)


def diagnose_apk_dir(path, only=None):
    """把跑批前的「0 个样本」拆成三种互斥原因，返回 (status, message)。

    status ∈ ok / missing / empty / filtered。只做只读判断：不建目录、不下载样本、
    不改 PATH，也不要求用户做环境探测（AGENTS.md 约束 7）。

    背景：`D:/数据集/数据集/F-Droid-60` 在部分主机上不存在，旧入口只报
    「目录不存在」或「没有 .apk」，`--only` 写错时同样报「没有 .apk」，
    三者混在一起会让人以为是数据集空了。
    """
    path = Path(path)
    if not path.is_dir():
        return 'missing', (f'APK 目录不存在：{path}'
                           f'（本机可能没有该数据集；先确认路径，别当成「0 个样本」）。'
                           f'样本获取见 apk/README.md')
    apks = sorted(p for p in path.glob('*.apk'))
    if not apks:
        return 'empty', f'APK 目录存在但没有 .apk：{path}（样本获取见 apk/README.md）'
    if only:
        # 公共 API 也可能被直接传字符串；不归一化会把包名拆成字符集合（set('abc')）。
        if isinstance(only, str):
            only = [only]
        selected = [p for p in apks if p.stem in set(only)]
        if not selected:
            return 'filtered', (f'--only={list(only)!r} 把 {len(apks)} 个 APK 全部过滤掉了；'
                                f'--only 匹配的是文件名 stem（不含 .apk）')
        return 'ok', f'选中 {len(selected)}/{len(apks)} 个 APK'
    return 'ok', f'{len(apks)} 个 APK'
