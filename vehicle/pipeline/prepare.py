"""Reproduce local Hook artifacts with the current interpreter. 授权测试专用。"""
import importlib
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from core.frida_host import freshness
from vehicle.pipeline.contracts import ROOT, AuditError, digest, write_json


def new_output(prefix):
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    return ROOT / 'output' / f'{prefix}-{stamp}-{uuid.uuid4().hex[:6]}'


def gated_hook_bundle(scope='all', sample_mode=None):
    """解析采集要用的 bundle，并先过产物新鲜度闸（2026-11-10）。

    在任何设备动作（建目录、起 mitm、adb reverse）之前失败——否则取证产物描述的
    是旧代码，事后无法分辨。返回 (bundle 路径, 写进证据的身份块)。
    """
    name = 'hook_vehicle_general.bundle.js' if scope == 'general' else 'hook_vehicle_all.bundle.js'
    if sample_mode:
        name = sample_mode.BUNDLE
    bundle = ROOT / 'vehicle/hooks/dist' / name
    gate = freshness.verify(bundle)
    if gate['tier'] == 'refuse':
        raise AuditError('stale_hook_bundle', freshness.refusal_text(gate),
                         '先运行 ' + freshness.REBUILD + ' 再重试。')
    freshness.announce(gate)
    return bundle, freshness.identity(bundle)


def prepare(output=None, install_deps=False):
    output = Path(output or new_output('vehicle-prepare'))
    output.mkdir(parents=True, exist_ok=False)
    result = {'status': 'running', 'python': sys.executable, 'steps': []}
    try:
        for name in ('frida', 'mitmproxy', 'reportlab', 'PIL', 'cryptography', 'pypdf'):
            try:
                importlib.import_module(name)
            except ImportError as error:
                raise AuditError('python_dependency_missing', f'当前解释器缺少依赖：{name}',
                                 '用当前解释器 -m pip install -r requirements.txt；不要切换到别名 python。',
                                 interpreter=sys.executable) from error
        bridge = ROOT / 'vehicle/hooks/node_modules/frida-java-bridge/index.js'
        from vehicle.privacy.catalog import generate
        generate(ROOT / 'vehicle/hooks/privacy_targets.generated.js')
        commands = []
        if not bridge.is_file():
            if not install_deps:
                raise AuditError('hook_dependencies_missing', '缺少锁文件对应的 Hook 构建依赖。',
                                 '运行 vehicle.ps1 prepare --install-deps；安装脚本默认跳过。')
            npm = shutil.which('npm.cmd') or shutil.which('npm')
            if not npm:
                raise AuditError('npm_missing', '未找到 npm。', '安装 Node 后重试。')
            commands.append(('npm', [npm, 'ci', '--ignore-scripts', '--cache', str(ROOT / 'output/npm-cache')],
                             ROOT / 'vehicle/hooks'))
        commands += [(platform, [sys.executable, str(ROOT / 'core/frida_host/build.py'),
                      '--platform', platform], ROOT) for platform in ('vehicle', 'shared')]
        for name, command, cwd in commands:
            with (output / f'{name}.log').open('w', encoding='utf-8') as log:
                code = subprocess.run(command, cwd=cwd, stdout=log, stderr=log, timeout=300).returncode
            result['steps'].append({'name': name, 'exit_code': code})
            if code:
                raise AuditError('prepare_failed', f'{name} 构建阶段失败。', f'查看 {output / (name + ".log")}。')
        result['status'] = 'completed'
        result['lock_sha256'] = digest(ROOT / 'vehicle/hooks/package-lock.json')
        result['bundles'] = {str(p.relative_to(ROOT)): digest(p)
            for folder in ('vehicle/hooks/dist', 'core/frida_host/dist')
            for p in (ROOT / folder).glob('*.bundle.js')}
    except Exception as error:
        result['status'] = 'failed'
        result['error'] = error.record() if isinstance(error, AuditError) else {'message': str(error)}
        raise
    finally:
        write_json(output / 'verification.json', result)
    return result
