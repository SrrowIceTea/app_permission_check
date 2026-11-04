"""Owned debug fixture sequence/consent UI driver. 仅用于授权测试。

UI control is restricted to the repository's fixture. It is never injected into
or substituted for an independent application's actual consent workflow.
"""
import hashlib
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from tools.vehicle_environment_actions import ACTIONS, EnvironmentActions

PACKAGE = 'com.vscanner.targetapp'
SEQUENCES = {
    'consent-stop': ['cache_clear', 'grant_consent', 'consent_respected',
                     'revoke_consent', 'consent_respected'],
    'consent-ignored': ['cache_clear', 'revoke_consent', 'consent_ignored'],
    'cache-after-revoke': ['cache_clear', 'grant_consent', 'cache_collect', 'cache_collect',
                           'revoke_consent', 'cache_flush'],
    'cache-cleared': ['cache_clear', 'cache_collect', 'cache_clear', 'cache_flush'],
    'cache-isolation-seed': ['cache_clear', 'cache_collect'],
    'offline-reconnect': ['cache_clear', 'wifi_off', 'network_enqueue', 'wifi_on', 'cache_flush'],
    'vehicle-transition': ['vehicle_park', 'plain', 'vehicle_drive', 'plain', 'vehicle_park'],
}


def consent_button(xml, label):
    for node in ET.fromstring(xml).iter('node'):
        if node.get('text') == label:
            values = list(map(int, re.findall(r'\d+', node.get('bounds', ''))))
            if len(values) == 4:
                return (values[0] + values[2]) // 2, (values[1] + values[3]) // 2
    raise AssertionError('Owned consent button not found: ' + label)


def set_consent_ui(adb, out, user, token, state):
    label = 'Grant audit consent' if state == 'granted' else 'Withdraw audit consent'
    remote = '/sdcard/vscan-owned-consent.xml'
    adb('shell', 'am', 'start', '--user', user, '-W', '-n', PACKAGE + '/.AuditConsentActivity')
    adb('shell', 'uiautomator', 'dump', remote)
    x, y = consent_button(adb('shell', 'cat', remote), label)
    adb('shell', 'input', 'tap', str(x), str(y))
    adb('shell', 'uiautomator', 'dump', remote)
    xml = adb('shell', 'cat', remote)
    if not any(n.get('text') == 'Audit consent: ' + state for n in ET.fromstring(xml).iter('node')):
        raise AssertionError('Consent UI state was not established')
    artifact = out / (token + '-consent-ui.xml')
    artifact.write_text(xml, encoding='utf-8')
    return {'file': artifact.name, 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
            'kind': 'ui_observation'}


def execute_fixture(adb, out, user, mode, token, session, foreground=True):
    environment = EnvironmentActions(adb, out)
    try:
        return _execute_fixture(adb, out, user, mode, token, session, foreground, environment)
    finally:
        environment.close()


def _execute_fixture(adb, out, user, mode, token, session, foreground, environment):
    actions = SEQUENCES.get(mode, [mode])
    journal, receipts = [], []
    consent, consent_ref = 'unknown', None
    for index, action in enumerate(actions):
        step = f'{token}_{index}'
        start = int(time.time() * 1000)
        if action in ('grant_consent', 'revoke_consent'):
            consent = 'granted' if action == 'grant_consent' else 'revoked'
            consent_ref = set_consent_ui(adb, out, user, step, consent)
        receipt = environment.apply(action, step) if action in ACTIONS else None
        if action not in ACTIONS:
            arguments = ['shell', 'am', 'broadcast', '--user', user, '-n', PACKAGE + '/.AuditScenarioReceiver',
                '--es', 'mode', action, '--es', 'token', step]
            if mode == 'offline-reconnect':
                arguments += ['--es', 'endpoint', 'http://10.0.2.2:8888/collect']
            adb(*arguments)
            remote = f'/data/user/{user}/{PACKAGE}/files/audit-scenario-{step}.json'
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    receipt = json.loads(adb('shell', 'cat', remote))
                    break
                except (ValueError, RuntimeError, subprocess.SubprocessError):
                    time.sleep(.3)
        if not receipt or receipt.get('completed') is not True:
            raise AssertionError('Fixture action failed: ' + str(receipt))
        artifact = out / (step + '-receipt.json')
        artifact.write_text(json.dumps(receipt, indent=2), encoding='utf-8')
        # Allow in-flight host event delivery before closing this action window.
        time.sleep(.4)
        end = int(time.time() * 1000)
        context = {'foreground': foreground, 'consent': consent, 'vehicle_state': 'not_injected'}
        context.update(environment.context)
        refs = {'consent': consent_ref} if consent_ref else {}
        refs.update(environment.references)
        foreground_file = out / 'foreground.txt'
        if environment.vehicle_modified:
            activity = adb('shell', 'dumpsys', 'activity', 'activities')
            resumed = '\n'.join(line for line in activity.splitlines() if any(field in line
                for field in ('mResumedActivity', 'topResumedActivity=', 'Resumed: ActivityRecord')))
            context['foreground'] = PACKAGE in resumed
            foreground_file = out / (step + '-foreground.txt')
            foreground_file.write_text(resumed, encoding='utf-8')
        if foreground_file.exists():
            refs['foreground'] = {'file': foreground_file.name,
                'sha256': hashlib.sha256(foreground_file.read_bytes()).hexdigest(), 'kind': 'adb_state'}
        journal.append({'id': step, 'action': action, 'package': PACKAGE, 'session_id': session,
            'start_ms': start, 'end_ms': end, 'source': 'owned_debug_fixture',
            'context': context, 'context_evidence': refs,
            'action_receipt': {'file': artifact.name, 'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest()}})
        receipts.append(receipt)
    return journal, receipts
