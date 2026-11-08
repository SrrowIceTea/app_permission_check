"""Real same-UID, separate-process lease contention. 仅用于授权测试（自有AAOS夹具）。"""
import argparse
import hashlib
import json
import re
import secrets
import sqlite3
import time
import traceback
from pathlib import Path

from vehicle.rules.android.tools.crossprocess_checks import identity_pair, waiting_lock
from vehicle.rules.android.tools.recovery_acceptance import Acceptance, APP, ROOT, RUNNER, save

DRIVER = APP + '.RulesCrossProcessDeviceTest'


class CrossAcceptance(Acceptance):
    def __init__(self, args):
        super().__init__(args)
        self.result.update(acceptance_kind='same_uid_separate_process', cases=[])
        self.case = None

    def invoke(self, method):
        result = self.adb('shell', 'am', 'instrument', '--user', self.user, '-r', '-w', '-e',
            'host_driver', 'true', '-e', 'class', DRIVER + '#' + method, RUNNER, timeout=100)
        text = (result.stdout + result.stderr).decode('utf-8', errors='replace')
        (self.out / (self.case['name'] + '-' + method + '.log')).write_text(text, encoding='utf-8')
        completed, fields = [], {}
        for line in text.splitlines():
            value = re.match(r'INSTRUMENTATION_STATUS: (class|test)=(.+)', line)
            if value:
                fields[value[1]] = value[2].strip()
            elif line.startswith('INSTRUMENTATION_STATUS_CODE:'):
                code = int(line.rsplit(':', 1)[1])
                if code == 0:
                    completed.append((fields.get('class'), fields.get('test')))
                elif code != 1:
                    raise RuntimeError('driver failed/skipped: ' + str(fields))
                fields = {}
        assert completed == [(DRIVER, method)], completed

    def event(self, actor, phase):
        relative = f'files/lease-crossprocess/{self.case["run"]}/{actor}-{phase}.json'
        result = self.adb('shell', 'run-as', APP, '--user', self.user, 'cat', relative, check=False)
        if result.returncode != 0:
            return None
        try:
            value = json.loads(result.stdout)
        except ValueError:
            (self.out / (self.case['name'] + '-' + actor + '-' + phase + '-read-error.txt')).write_bytes(
                result.stdout + result.stderr)
            raise
        assert value['actor'] == actor and value['phase'] == phase
        assert value['user_id'] == self.user and value['uid'] // 100000 == self.user
        assert value['database_path'] == f'/data/user/{self.user}/{APP}/databases/lease-crossprocess.db'
        self.case['events'][actor + '-' + phase] = value
        save(self.out / (self.case['name'] + '-events.json'), self.case['events'])
        return value

    def await_event(self, actor, phase):
        def ready():
            failure = self.event(actor, 'failed')
            if failure:
                raise RuntimeError('peer failure: ' + str(failure))
            return self.event(actor, phase)
        return self.wait(actor + ' ' + phase, ready, 30)

    def signal(self, filename):
        assert re.fullmatch(r'(release-[ABC]|continue-[ABC])', filename)
        self.shell('run-as', APP, '--user', self.user, 'touch',
                   f'files/lease-crossprocess/{self.case["run"]}/{filename}')

    def start(self, actor, mode, *, pause=False):
        component = '.RulesLeasePeerA' if actor == 'A' else '.RulesLeasePeerB'
        text = self.shell('am', 'startservice', '--user', self.user, '-n', APP + '/' + component,
            '--es', 'run', self.case['run'], '--es', 'actor', actor, '--es', 'mode', mode,
            '--ez', 'pause_inside', str(pause).lower())
        assert 'Starting service' in text and 'Error' not in text, text
        row = self.await_event(actor, 'started')
        assert row['process_name'] == APP + (':rulesLeaseA' if actor == 'A' else ':rulesLeaseB')
        return row

    def blocked(self, owner, waiter):
        assert identity_pair(owner, waiter, self.user), (owner, waiter)
        inode = self.shell('stat', '-c', '%i', owner['database_path'] + '.lock')
        assert inode.isdigit(), inode
        self.case['lock_file_inode'] = int(inode)
        def pending():
            raw = self.shell('cat', '/proc/locks')
            (self.out / (self.case['name'] + '-kernel-locks.txt')).write_text(raw, encoding='utf-8')
            pair = waiting_lock(raw, owner['pid'], waiter['pid'])
            if pair and pair['owner']['inode'].rsplit(':', 1)[-1] != inode:
                return None
            if pair:
                save(self.out / (self.case['name'] + '-kernel-wait.json'), pair)
            return pair
        pair = self.wait('kernel confirms blocked POSIX lock', pending, 12)
        assert not self.event(waiter['actor'], 'done') and not self.event(waiter['actor'], 'install_entered')
        self.case['kernel_wait'] = pair

    def kill(self, identity):
        pid = identity['pid']
        assert type(pid) is int and pid > 1 and identity['user_id'] == self.user
        self.shell('kill', '-9', pid)
        self.wait('actual peer death', lambda: self.adb('shell', 'kill', '-0', pid, check=False).returncode != 0, 10)
        self.case.setdefault('killed', []).append(identity)

    def begin(self, name):
        self.case = {'name': name, 'run': secrets.token_hex(8), 'passed': False, 'events': {}}
        self.result['cases'].append(self.case)
        self.invoke('seed')
        self.case['expected_asset_sha256'] = hashlib.sha256(self.user_file('files/lease-crossprocess-next.db')).hexdigest()
        self.shell('am', 'start', '--user', self.user, '-W', '-n', APP + '/.MainActivity')

    def finish(self):
        self.invoke('inspect')
        report = self.json_file('lease-crossprocess-final.json')
        payload = self.user_file('databases/lease-crossprocess.db')
        file = self.out / (self.case['name'] + '.db')
        file.write_bytes(payload)
        with sqlite3.connect(file.as_uri() + '?mode=ro', uri=True) as db:
            assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
            assert db.execute('PRAGMA user_version').fetchone()[0] == report['schemaVersion']
            assert db.execute('SELECT count(*) FROM risk_rules').fetchone()[0] > 0
        assert report['contentSha256'] == report['expectedContentSha256']
        assert report['effectiveSha256'] == self.case['expected_asset_sha256']
        assert hashlib.sha256(payload).hexdigest() == report['activeFileSha256']
        self.case.update(passed=True, final=report)
        save(self.out / (self.case['name'] + '.json'), self.case)
        print(self.case['name'], 'passed', flush=True)

    def reader_then_writer(self, kill_owner=False, kill_waiter=False):
        name = 'owner-killed' if kill_owner else 'waiter-killed' if kill_waiter else 'reader-blocks-writer'
        self.begin(name)
        a = self.start('A', 'hold')
        held = self.await_event('A', 'acquired')
        b = self.start('B', 'install')
        self.await_event('B', 'attempting')
        self.blocked(a, b)
        if kill_owner:
            self.kill(a)
        else:
            if kill_waiter:
                self.kill(b)
                assert self.adb('shell', 'kill', '-0', a['pid']).returncode == 0
            self.signal('release-A')
            leaving = self.await_event('A', 'leaving')
            checked = self.await_event('A', 'read_checked')
            assert checked['content_after'] == held['content_before']
            self.await_event('A', 'done')
            if kill_waiter:
                restarted = self.start('C', 'install')
                assert identity_pair(a, restarted, self.user) and restarted['pid'] != b['pid']
                b = restarted
        actor = b['actor']
        completed = self.await_event(actor, 'done')
        assert completed['install']['state'] == 'UPGRADED'
        if not kill_owner:
            entered = self.await_event(actor, 'install_entered')
            assert entered['elapsed_ns'] >= leaving['elapsed_ns']
        self.finish()

    def two_writers(self):
        self.begin('two-writers')
        a = self.start('A', 'install', pause=True)
        self.await_event('A', 'install_entered')
        b = self.start('B', 'install')
        self.await_event('B', 'attempting')
        self.blocked(a, b)
        self.signal('continue-A')
        first, second = self.await_event('A', 'done'), self.await_event('B', 'done')
        assert first['install']['state'] == 'UPGRADED' and second['install']['state'] == 'UNCHANGED'
        assert first['install']['effectiveSha256'] == second['install']['effectiveSha256']
        self.finish()

    def run(self):
        try:
            self.result['input_apks'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in (self.args.apk, self.args.test_apk)}
            assert self.shell('id', '-u') == '0', 'owned userdebug root shell required for process-death controls'
            self.setup()
            self.units()
            self.reader_then_writer()
            self.two_writers()
            self.reader_then_writer(kill_owner=True)
            self.reader_then_writer(kill_waiter=True)
            self.result['passed'] = True
        except Exception:
            self.result['error'] = traceback.format_exc()
        finally:
            if self.user is not None:
                try:
                    self.shell('am', 'force-stop', '--user', self.user, APP)
                except Exception:
                    self.result.update(passed=False, stop_error=traceback.format_exc())
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
    raise SystemExit(CrossAcceptance(parser.parse_args()).run())
