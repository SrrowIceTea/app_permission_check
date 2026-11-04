"""Read historical sample evidence without importing it into the AAOS benchmark."""
import argparse
from collections import Counter
from pathlib import Path

from PIL import Image

from core.io_utils import load_jsonl
from core.privacy.semantics import read_state
from core.static.apkmeta import permissions
from core.static.toolchain import android_build_tool
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

FOLDERS = {'com.mendhak.gpslogger': 'gpslogger', 'com.kylecorry.trail_sense': 'trail-sense',
    'org.owntracks.android': 'owntracks', 'de.dennisguse.opentracks': 'opentracks',
    'org.fossify.contacts': 'fossify-contacts', 'com.dimowner.audiorecorder': 'audi-recorder',
    'org.fossify.phone': 'fossify-phone', 'org.fossify.gallery': 'fossify-gallery',
    'me.zhanghai.android.files': 'material-files', 'org.eu.exodus_privacy.exodusprivacy': 'exodus',
    'org.glpi.inventory.agent': 'glpi-agent'}


def screenshot_status(path):
    try:
        with Image.open(path) as image:
            image.verify()
        return 'verified_png'
    except (OSError, SyntaxError):
        return 'invalid_png'


def states(events):
    counts = Counter()
    for event in events:
        if event.get('ev') != 'PRIVACY_READ':
            continue
        state = read_state(event)
        if state == 'empty' and str(event.get('api', '')).endswith(')V'):
            state = 'call_only'
        counts[state] += 1
    return dict(counts)


def review(catalog, runtime):
    aapt = android_build_tool('aapt2')
    result = []
    for sample in read_json(catalog)['samples']:
        pkg = sample['package']
        apk = catalog.parent / pkg / 'sample.apk'
        if digest(apk) != sample['apk_sha256'] or apk.stat().st_size != sample['apk_bytes']:
            raise ValueError('sample APK identity mismatch: ' + pkg)
        folder = runtime / FOLDERS[pkg]
        summary = folder / 'result.json'
        report = read_json(summary)
        passes = []
        for path in sorted(folder.glob('*.jsonl')):
            events = load_jsonl(path)
            starts = [row for row in events if row.get('ev') == 'START' and row.get('src') == 'privacy']
            implementation = ('mobile' if any('watch_limit_raw' in row and 'rules_sha256' in row for row in starts)
                              else 'unverified')
            passes.append({'name': path.name, 'sha256': digest(path), 'hook_implementation': implementation,
                           'read_states': states(events)})
        result.append({'package': pkg, 'apk_sha256': sample['apk_sha256'],
                       'internet_permission': 'android.permission.INTERNET' in permissions(aapt, apk),
                       'historical_report_sha256': digest(summary), 'historical_device_label': report.get('device'),
                       'historical_install_reported': report.get('installed') is True,
                       'passes': passes,
                       'screenshots': [{'name': path.name, 'status': screenshot_status(path), 'sha256': digest(path)}
                                       for path in sorted(folder.glob('*.png'))],
                       'aaos_acceptance': 'not_established_by_historical_mobile_hook'})
    return {'scope': 'historical_runtime_evidence_inventory', 'sample_count': len(result),
            'historical_actions_sha256': digest(runtime / 'actions.log'), 'samples': result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'output/sample-acquisition-20261103/manifest.json')
    parser.add_argument('--runtime', type=Path, default=ROOT / 'output/sample-runtime-20261103')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    write_json(args.out, review(args.catalog, args.runtime))


if __name__ == '__main__':
    main()
