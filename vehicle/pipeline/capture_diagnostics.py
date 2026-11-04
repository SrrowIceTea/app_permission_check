"""Retain the primary failure when optional diagnostics/ADB cleanup also fail.

仅用于授权测试。 The caller owns process/device cleanup; this function owns the
final evidence status. A missing/incomplete capture manifest cannot be a pass.
"""
import time

from vehicle.pipeline.contracts import read_json, write_json


def finalize_case(output, session, serial, adb, manifest_writer, params, result):
    gaps = result.setdefault('diagnostic_gaps', [])
    # Capture identity is mandatory; optional logcat must not delay its snapshot.
    # One bounded retry covers a transient ADB timeout right after a user switch;
    # the first failure is still recorded.
    complete = False
    for attempt in range(2):
        try:
            manifest_writer(output, session, serial, adb, params)
            manifest = read_json(output / 'session-manifest.json')
            complete = bool(manifest.get('installed_apk_sha256') and manifest.get('rules_sha256')
                            and manifest.get('hook_bundles'))
            if not complete:
                gaps.append({'operation': 'manifest', 'attempt': attempt + 1,
                             'message': 'Capture-time APK/rules/Hook identity incomplete'})
            break
        except Exception as error:
            gaps.append({'operation': 'manifest', 'attempt': attempt + 1,
                         'exception': type(error).__name__, 'message': str(error)})
            if attempt == 0:
                time.sleep(2)
    result['checks']['capture_manifest_complete'] = complete
    result['passed'] = result['passed'] and complete
    write_json(output / 'verification.json', result)
    try:
        (output / 'logcat.txt').write_text(adb('logcat', '-d', '-t', '1000'), encoding='utf-8')
    except Exception as error:
        gaps.append({'operation': 'logcat', 'exception': type(error).__name__, 'message': str(error)})
    write_json(output / 'verification.json', result)
