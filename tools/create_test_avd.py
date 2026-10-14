"""Create an isolated headless AAOS AVD without touching existing AVDs.

Uses the downloaded SDK system image directly; old avdmanager 12 cannot parse its multi-tag metadata.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402

root = ROOT / '.tools/avd'
avd = root / 'VScanner_AAOS_35.avd'
avd.mkdir(parents=True, exist_ok=False)
config = {
    'AvdId': 'VScanner_AAOS_35', 'avd.ini.displayname': 'VScanner AAOS 35 (authorized test)',
    'abi.type': 'x86_64', 'hw.cpu.arch': 'x86_64', 'hw.cpu.ncore': '4',
    'hw.ramSize': '2048', 'hw.lcd.width': '1408', 'hw.lcd.height': '792',
    'hw.lcd.density': '160', 'hw.keyboard': 'yes', 'hw.mainKeys': 'no',
    'hw.gpu.enabled': 'yes', 'hw.gpu.mode': 'swiftshader_indirect',
    'hw.audioInput': 'no', 'hw.audioOutput': 'no', 'hw.camera.back': 'none',
    'hw.camera.front': 'none', 'disk.dataPartition.size': '4G',
    # SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
    # sysdir 必须以分隔符结尾，avdmanager 才认。
    'image.sysdir.1': str(sdk_paths.sdk_dir('system-images', 'android-35-ext15',
                                            'android-automotive', 'x86_64')) + '/',
    'tag.id': 'android-automotive', 'tag.display': 'Automotive',
    'fastboot.forceColdBoot': 'yes', 'showDeviceFrame': 'no',
}
(avd / 'config.ini').write_text(''.join(f'{k}={v}\n' for k, v in config.items()), encoding='utf-8')
(root / 'VScanner_AAOS_35.ini').write_text(
    f'avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-35\n', encoding='utf-8')
print(avd)
