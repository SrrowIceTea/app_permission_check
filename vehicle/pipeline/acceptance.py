"""Serial fixture acceptance through the common CLI. 仅用于授权测试。"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from vehicle.pipeline.capture_device import Device
from vehicle.pipeline.contracts import ROOT, AuditError, write_json
from vehicle.pipeline.prepare import new_output

SUITES = {'baseline': 'device_acceptance.py', 'scenarios': 'vehicle_scenario_acceptance.py',
          'context': 'vehicle_context_acceptance.py', 'users': 'vehicle_user_acceptance.py',
          'privacy': 'vehicle_privacy_acceptance.py'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=[*SUITES, 'all'], default='all')
    parser.add_argument('--serial', default=os.environ.get('VSCAN_SERIAL', 'emulator-5554'))
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    out = args.out or new_output('vehicle-acceptance')
    out.mkdir(parents=True, exist_ok=False)
    result = {'passed': False, 'steps': [], 'scope': 'owned_fixture_only'}
    try:
        device = Device(args.serial)
        if (not args.serial.startswith('emulator-') or
                'automotive' not in device.call('shell', 'pm', 'list', 'features')):
            raise AuditError('fixture_requires_owned_aaos', '夹具验收仅在自有 AAOS 模拟器运行。', '使用独立 AAOS 测试实例。')
        apk = ROOT / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'
        if not apk.is_file():
            raise AuditError('fixture_not_built', '自有 debug 夹具尚未构建。',
                             '先按 vehicle/README.md 执行 Gradle :app:assembleDebug。')
        device.call('install', '-r', apk)
        env = dict(os.environ, VSCAN_SERIAL=args.serial, PYTHONUTF8='1')
        selected = list(SUITES) if args.suite == 'all' else [args.suite]
        for name in selected:
            with (out / (name + '.log')).open('w', encoding='utf-8') as log:
                proc = subprocess.run([sys.executable, str(ROOT / 'tools' / SUITES[name])],
                    cwd=ROOT, env=env, stdout=log, stderr=log, timeout=600)
            result['steps'].append({'suite': name, 'exit_code': proc.returncode})
            print(json.dumps(result['steps'][-1]), flush=True)
            if proc.returncode:
                raise AuditError('fixture_acceptance_failed', f'{name} 验收失败。',
                                 f'查看 {out / (name + ".log")}；失败后停止依赖设备状态的后续验收。')
        result['passed'] = bool(result['steps']) and all(s['exit_code'] == 0 for s in result['steps'])
    except Exception as error:
        result['error'] = error.record() if isinstance(error, AuditError) else {'message': str(error)}
    finally:
        write_json(out / 'verification.json', result)
    print(json.dumps({'passed': result['passed'], 'out': str(out)}, ensure_ascii=False))
    return 0 if result['passed'] else 1
