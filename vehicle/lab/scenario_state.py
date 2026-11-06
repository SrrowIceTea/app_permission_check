"""Foreground/background evidence and real HTTP rejection. 仅用于授权测试。"""
import time
import re

from vehicle.pipeline.contracts import digest, write_json


class Scenarios:
    def __init__(self, ui, package, out):
        self.ui, self.package, self.out = ui, package, out
        self.observations = []
        self.activity = None

    def observe(self, label, expected):
        device = self.ui.device
        raw = device.call('shell', 'dumpsys', 'activity', 'activities')
        resumed = [line.strip() for line in raw.splitlines()
                   if 'topResumedActivity=' in line or 'mResumedActivity:' in line]
        if not resumed:
            raise ValueError('foreground state unavailable; cannot infer background from missing text')
        active = any(self.package + '/' in line for line in resumed)
        if active != (expected == 'foreground'):
            raise ValueError('foreground state does not match scenario: ' + label)
        stamp = int(time.time() * 1000)
        path = self.out / (label + '-activity.txt')
        path.write_text('\n'.join(resumed) + '\n', encoding='utf-8')
        row = {'label': label, 'ts_ms': stamp, 'state': expected,
               'activity_file': path.name, 'activity_sha256': digest(path)}
        self.observations.append(row)
        write_json(self.out / 'scenario-observations.json', self.observations)
        return row

    def background(self):
        self.ui.device.call('shell', 'input', 'keyevent', 3)
        time.sleep(1)
        return self.observe('background-start', 'background')

    def resolve(self):
        raw = self.ui.device.call('shell', 'dumpsys', 'activity', 'activities')
        rows = [line for line in raw.splitlines() if 'topResumedActivity=' in line or 'mResumedActivity:' in line]
        found = re.findall(re.escape(self.package) + r'/[A-Za-z0-9_.$]+', '\n'.join(rows))
        if len(set(found)) != 1:
            raise ValueError('unable to identify the actual foreground activity')
        activity = found[0]
        self.activity = activity

    def restore(self):
        if self.activity:
            self.ui.device.call('shell', 'am', 'start', '--user', '10', '-W', '-a', 'android.intent.action.MAIN',
                                '-c', 'android.intent.category.LAUNCHER', '-n', self.activity)
            time.sleep(1)


def check_rejection(reads, flows, receipts, session, endpoint, step, matcher):
    """A device-originated 503 is a transport rejection, not a permission denial."""
    rejected = matcher(reads, flows, receipts, session, endpoint, step, response_status=503)
    accepted = matcher(reads, flows, receipts, session, endpoint, step)
    return {'kind': 'http_503', 'permission_result': 'not_tested',
            'passed': len(rejected) == 1 and not accepted,
            'rejected_pairs': rejected, 'successful_pairs': accepted}
