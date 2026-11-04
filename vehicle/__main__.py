"""Ordinary third-party AAOS audit entry point. 仅用于授权测试。"""
import argparse
import json
import sys
from pathlib import Path
from vehicle.pipeline.contracts import AuditError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('prepare', help='校验依赖并重建车载及共享 Hook')
    setup.add_argument('--out', type=Path)
    setup.add_argument('--install-deps', action='store_true')
    coverage = commands.add_parser('coverage', help='从实际规则库生成覆盖链')
    coverage.add_argument('--out', type=Path, default=Path('vehicle/coverage/generated'))
    coverage.add_argument('--android-version', default='15')
    coverage.add_argument('--vhal-capture', type=Path, help='附加已封存的自有 API 35 夹具设备观测')
    commands.add_parser('profiles', help='查看版本能力与验证状态')
    for name in ('audit', 'capture', 'samples', 'benchmark', 'overhead', 'scenarios'):
        commands.add_parser(name, add_help=False, help=f'{name} --help 查看参数')
    args, remaining = parser.parse_known_args()
    if args.command in ('prepare', 'coverage', 'profiles') and remaining:
        parser.error('unrecognized arguments: ' + ' '.join(remaining))
    try:
        if args.command == 'prepare':
            from vehicle.pipeline.prepare import prepare
            result = prepare(args.out, args.install_deps)
        elif args.command == 'coverage':
            from vehicle.coverage.export import export_coverage
            result = export_coverage(args.out, args.android_version, args.vhal_capture)
            result = {'rows': len(result['rows']), 'out': str(args.out), 'profile': result['profile']}
        elif args.command == 'profiles':
            from vehicle.compatibility import PROFILES, profile
            result = {version: profile(version) for version in PROFILES}
        else:
            import importlib
            module = {'audit': 'vehicle.pipeline.audit', 'capture': 'vehicle.pipeline.capture',
                      'samples': 'vehicle.bench.samples', 'benchmark': 'vehicle.bench.evaluate',
                      'overhead': 'vehicle.bench.overhead',
                      'scenarios': 'vehicle.pipeline.acceptance'}[args.command]
            return importlib.import_module(module).main(remaining)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except AuditError as error:
        print(json.dumps({'status': 'failed', 'error': error.record()}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
