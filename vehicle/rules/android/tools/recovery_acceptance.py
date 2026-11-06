"""AAOS process-death/reboot recovery acceptance. 仅用于授权测试（自有设备/夹具）。"""
import argparse
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
import traceback
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
APP = 'com.vscanner.rules'
DRIVER = APP + '.RulesDbRecoveryDeviceTest'
RUNNER = APP + '.test/androidx.test.runner.AndroidJUnitRunner'
POINTS = ('STAGING_WRITE', 'STAGED', 'BACKUP_READY', 'JOURNALED', 'RENAMED', 'META_WRITTEN')


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


class Acceptance:
    def __init__(self, args):
        self.args, self.out = args, args.out.resolve()
        self.out.mkdir(parents=True, exist_ok=False)
        sdk = os.environ.get('ANDROID_SDK_ROOT') or os.environ.get('VSCAN_SDK')
        self.command = [str(Path(sdk) / 'platform-tools/adb.exe'), '-s', args.serial]
        self.user, self.original_user = None, None
        self.original_apks, self.before_db = {}, None
        self.result = {'passed': False, 'stages': [], 'scope': 'owned AAOS rules fixture only'}

    def adb(self, *args, check=True, timeout=100):
        result = subprocess.run([*self.command, *map(str, args)], capture_output=True, timeout=timeout)
        with (self.out / 'adb.log').open('a', encoding='utf-8') as log:
            log.write(f'{datetime.now().astimezone().isoformat()} {args} rc={result.returncode}\n')
            if not args or args[0] != 'exec-out':
                log.write((result.stdout + result.stderr).decode('utf-8', errors='replace'))
        if check and result.returncode:
            raise RuntimeError(f'ADB {args}: {(result.stdout + result.stderr).decode(errors="replace")}')
        return result

    def shell(self, *args, **kwargs):
        return self.adb('shell', *args, **kwargs).stdout.decode('utf-8', errors='replace').strip()

    def wait(self, label, condition, seconds=150):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            value = condition()
            if value:
                return value
            time.sleep(2)
        raise TimeoutError(label)

    def user_file(self, path, check=True, user=None):
        result = self.adb('exec-out', 'run-as', APP, '--user', self.user if user is None else user,
                          'cat', path, check=check)
        return result.stdout if result.returncode == 0 else b''

    def json_file(self, path):
        return json.loads(self.user_file('files/' + path))

    def switch(self, user):
        self.shell('am', 'switch-user', user)
        self.wait('user unlocked', lambda: self.shell('am', 'get-current-user', check=False) == str(user)
                  and self.shell('am', 'get-started-user-state', user, check=False).endswith('RUNNING_UNLOCKED'))

    def instrument(self, method, *, extra=(), background=False, log_name=None):
        command = [*self.command, 'shell', 'am', 'instrument', '--user', str(self.user), '-w',
                   '-e', 'host_driver', 'true', '-e', 'class', DRIVER + '#' + method, *extra, RUNNER]
        log_path = self.out / (log_name or (method + '.log'))
        if background:
            log = log_path.open('wb')
            try:
                return subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            finally:
                log.close()
        result = subprocess.run(command, capture_output=True, timeout=160)
        log_path.write_bytes(result.stdout + result.stderr)
        text = log_path.read_text(encoding='utf-8', errors='replace')
        if result.returncode or not re.search(r'OK \(\d+ tests?\)', text):
            raise RuntimeError(f'instrumentation failed: {log_path.name}')

    def setup(self):
        fingerprint = self.shell('getprop', 'ro.build.fingerprint')
        assert '/sdk_gcar_' in fingerprint and self.shell('getprop', 'ro.build.version.sdk') == '35', fingerprint
        self.result['fingerprint'] = fingerprint
        self.original_user = int(self.shell('am', 'get-current-user'))
        for package in (APP, APP + '.test'):
            paths = self.shell('pm', 'path', '--user', self.original_user, package, check=False).splitlines()
            if paths and paths[0].startswith('package:'):
                assert len(paths) == 1, paths
                original = self.out / (package + '-original.apk')
                original.write_bytes(self.adb('exec-out', 'cat', paths[0][8:]).stdout)
                self.original_apks[package] = original
        if APP in self.original_apks:
            result = self.adb('exec-out', 'run-as', APP, '--user', self.original_user,
                              'cat', 'databases/vscanner-rules.db', check=False)
            self.before_db = result.stdout if result.returncode == 0 else None
        text = self.shell('pm', 'create-user', 'VScannerRecovery' + datetime.now().strftime('%H%M%S'))
        self.user = int(re.search(r'created user id (\d+)', text).group(1))
        self.result['test_user'] = self.user
        self.switch(self.user)
        for apk in (self.args.apk, self.args.test_apk):
            assert b'Success' in self.adb('install', '-r', '--user', self.user, apk).stdout

    def units(self):
        names = ('RulesDbUpgradeTest', 'RulesDbRecoveryTest', 'RulesVerifierStateTest', 'RulesSchemaValidationTest')
        expected = set()
        for name in names:
            source = ROOT / f'vehicle/rules/android/app/src/androidTest/java/com/vscanner/rules/{name}.kt'
            methods = re.findall(r'@Test\s+fun\s+(\w+)', source.read_text(encoding='utf-8-sig'))
            assert methods, 'missing expected test methods: ' + name
            expected.update((APP + '.' + name, method) for method in methods)
        classes = ','.join(APP + '.' + name for name in names)
        result = self.adb('shell', 'am', 'instrument', '--user', self.user, '-r', '-w', '-e', 'class', classes,
                          RUNNER, timeout=220)
        (self.out / 'android-tests.log').write_bytes(result.stdout + result.stderr)
        text = result.stdout.decode('utf-8', errors='replace')
        completed, fields = set(), {}
        for line in text.splitlines():
            match = re.match(r'INSTRUMENTATION_STATUS: (class|test)=(.+)', line)
            if match:
                fields[match[1]] = match[2].strip()
            elif line.startswith('INSTRUMENTATION_STATUS_CODE:'):
                code = int(line.rsplit(':', 1)[1])
                if code == 0:
                    completed.add((fields.get('class'), fields.get('test')))
                elif code != 1:
                    raise AssertionError('Android test failed/skipped: ' + str(fields))
                fields = {}
        assert completed == expected, f'missing/extra tests: {expected - completed}; {completed - expected}'
        self.result['android_tests'] = len(completed)
        self.result['android_test_methods'] = sorted(completed)

    def phase(self, point, reboot):
        name = ('reboot-' if reboot else 'kill-') + point.lower()
        self.instrument('reset', log_name=name + '-reset.log')
        before = self.json_file('recovery-before.json')
        boot_before = self.shell('cat', '/proc/sys/kernel/random/boot_id')
        child = self.instrument('interrupt', extra=('-e', 'fault_point', point, '-e', 'fault_action',
                                                   'pause' if reboot else 'kill'),
                                background=True, log_name=name + '-interrupted.log')
        try:
            def reached():
                raw = self.user_file('files/recovery-fault.json', False)
                try:
                    value = json.loads(raw)
                except (ValueError, TypeError):
                    return None
                return value if value.get('point') == point else None
            fault = self.wait('fault point ' + point, reached, 45)
            assert fault['point'] == point
            if reboot:
                self.adb('reboot')
                self.wait('new boot', lambda: self.shell('getprop', 'sys.boot_completed', check=False) == '1'
                          and self.shell('cat', '/proc/sys/kernel/random/boot_id', check=False) != boot_before)
                self.switch(self.user)
            child.wait(timeout=30)
            self.instrument('reopen', log_name=name + '-reopen.log')
            after = self.json_file('recovery-after.json')
            payload = self.user_file('databases/recovery-device.db')
            db_path = self.out / (name + '.db')
            db_path.write_bytes(payload)
            with sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True) as db:
                assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
                assert db.execute('SELECT count(*) FROM risk_rules').fetchone()[0] > 0
                schema = db.execute('PRAGMA user_version').fetchone()[0]
            new_sha = hashlib.sha256(self.user_file('files/recovery-next.db')).hexdigest()
            assert after['effectiveSha256'] in (before['effectiveSha256'], new_sha)
            assert after['contentMatch'] and after['schemaVersion'] == schema and after['readable']
            assert after['pid'] != fault['pid']
            assert (after['boot_id'] != boot_before) == reboot
            row = {'passed': True, 'point': point, 'action': 'reboot' if reboot else 'kill',
                   'fault': fault, 'before': before, 'after': after, 'database_sha256': hashlib.sha256(payload).hexdigest()}
            save(self.out / (name + '.json'), row)
            self.result['stages'].append(row)
            print(name, 'passed', flush=True)
        finally:
            if child.poll() is None:
                self.shell('am', 'force-stop', '--user', self.user, APP, check=False)
                child.wait(timeout=30)

    def cleanup(self):
        errors = []
        def attempt(label, operation):
            try:
                operation()
            except Exception as error:
                errors.append(f'{label}: {type(error).__name__}: {error}')
        if self.original_user is not None:
            attempt('original_user', lambda: self.switch(self.original_user))
        for package in (APP, APP + '.test'):
            if package in self.original_apks:
                attempt(package, lambda package=package:
                    self.adb('install', '-r', '--user', self.original_user, self.original_apks[package]))
            elif self.user is not None:
                attempt(package, lambda package=package: self.adb('uninstall', '--user', self.user, package, check=False))
        if self.before_db is not None:
            def verify_original():
                after = self.user_file('databases/vscanner-rules.db', user=self.original_user)
                self.result['original_user_database_unchanged'] = after == self.before_db
                assert after == self.before_db, 'original database changed'
            attempt('original_database', verify_original)
        if self.user is not None:
            def remove_user():
                value = self.shell('pm', 'remove-user', self.user)
                assert 'Success' in value, value
                self.result['test_user_removed'] = True
            attempt('remove_test_user', remove_user)
        if errors:
            raise RuntimeError('; '.join(errors))

    def run(self):
        try:
            self.setup()
            self.units()
            for point in POINTS:
                self.phase(point, False)
            for point in ('JOURNALED', 'RENAMED'):
                self.phase(point, True)
            self.result['passed'] = True
        except Exception:
            self.result['error'] = traceback.format_exc()
        finally:
            try:
                self.cleanup()
            except Exception:
                self.result.update(passed=False, cleanup_error=traceback.format_exc())
            save(self.out / 'verification.json', self.result)
        return 0 if self.result['passed'] else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--apk', type=Path, default=ROOT / 'vehicle/rules/android/app/build/outputs/apk/debug/app-debug.apk')
    parser.add_argument('--test-apk', type=Path, default=ROOT / 'vehicle/rules/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk')
    raise SystemExit(Acceptance(parser.parse_args()).run())
