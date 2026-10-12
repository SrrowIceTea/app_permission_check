"""Create an isolated headless AAOS AVD without touching existing AVDs.

Uses the downloaded SDK system image directly; old avdmanager 12 cannot parse its multi-tag metadata.
"""
from pathlib import Path

root = Path(__file__).resolve().parents[1] / '.tools/avd'
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
    'image.sysdir.1': 'D:/Anroid/SDK/system-images/android-35-ext15/android-automotive/x86_64/',
    'tag.id': 'android-automotive', 'tag.display': 'Automotive',
    'fastboot.forceColdBoot': 'yes', 'showDeviceFrame': 'no',
}
(avd / 'config.ini').write_text(''.join(f'{k}={v}\n' for k, v in config.items()), encoding='utf-8')
(root / 'VScanner_AAOS_35.ini').write_text(
    f'avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-35\n', encoding='utf-8')
print(avd)
