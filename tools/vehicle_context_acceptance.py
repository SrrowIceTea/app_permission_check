"""Owned consent UI and persistent cache scenarios. 仅用于授权测试。

Requires an AAOS emulator and the freshly built repository debug APK. Missing
devices produce an explicit failed verification, never a synthetic device pass.
"""
import json
import sys
from vehicle_scenario_acceptance import adb, run_case
from device_acceptance import ROOT, SERIAL
from vehicle.pipeline.prepare import new_output
from vehicle.pipeline.contracts import write_json


def main():
    out = new_output('vehicle-context')
    out.mkdir(parents=True)
    (ROOT / 'output/latest-vehicle-context.txt').write_text(str(out), encoding='utf-8')
    result = {'passed': False, 'cases': [], 'scope': 'owned_fixture_consent_ui_and_cache',
              'uncovered': ['real third-party consent UI', 'real vehicle/power state',
                            'carrier/cellular reconnect', 'long-duration upload distribution']}
    try:
        if not SERIAL.startswith('emulator-') or 'automotive' not in adb('shell', 'pm', 'list', 'features'):
            raise RuntimeError('Owned AAOS emulator required')
        user = adb('shell', 'am', 'get-current-user')
        adb('install', '-r', str(ROOT / 'vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk'))
        modes = ('consent-stop', 'consent-ignored', 'cache-after-revoke', 'cache-cleared',
                 'offline-reconnect', 'vehicle-transition')
        for mode in modes:
            result['cases'].append(run_case(out, mode, mode, user))
        result['passed'] = len(result['cases']) == len(modes) and all(r['passed'] for r in result['cases'])
    except Exception as error:
        result['error'] = f'{type(error).__name__}: {error}'
    finally:
        write_json(out / 'verification.json', result)
        print(json.dumps({'passed': result['passed'], 'out': str(out), 'error': result.get('error')},
                         ensure_ascii=False))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
