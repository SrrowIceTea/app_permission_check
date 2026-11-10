// 仅用于授权测试。Mock execution is safety/semantics evidence, not device proof.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { describe, sha256hex16 } from '../../core/privacy/values.js';
import { describeException } from '../../core/privacy/dispatch.js';
import { locationEvidence } from './privacy_location.js';
import { WATCH, META } from './privacy_targets.generated.js';
import { webhookSummary } from './ha_webhook_body.js';
import { syncBody } from './abs_sync_body.js';

const methods = new Map(), events = [];
let returnValue = 'abcdef1234567890', originalError = null, calls = 0, observerFails = false;
let adIdPermission = 0;
const context = {
  WATCH, META, describe, sha256hex16, describeException, locationEvidence,
  packages: () => ['test.owned'], procName: () => 'test.owned',
  makeLogger: () => (ev, extra) => events.push({ev, ...extra}),
  contactTracker: () => () => {},
  withStack: value => { if (observerFails) throw Error('observer failed'); return value; },
  Java: {perform: fn => fn(), use: name => {
    if (name === 'android.os.Process') return {myUid: () => 1012345};
    if (name === 'android.os.Build$VERSION') return {SDK_INT: {value: 35}};
    if (name === 'android.app.ActivityThread') return {currentApplication: () => ({
      getApplicationInfo: () => ({targetSdkVersion: {value: 35}}),
      checkSelfPermission: () => adIdPermission
    })};
    return new Proxy({}, {get: (_, method) => ({overload: (...types) => {
      const key = name + '.' + method + JSON.stringify(types);
      if (!methods.has(key)) methods.set(key, {apply() {
        calls++;
        if (originalError) throw originalError;
        return returnValue;
      }});
      return methods.get(key);
    }})});
  }},
};
vm.createContext(context);
const source = fs.readFileSync(new URL('./hook_privacy.js', import.meta.url), 'utf8')
  .replace(/^import .*;\r?\n/gm, '').replace(/export function/g, 'function');
vm.runInContext(source, context);
assert.equal(events.find(e => e.ev === 'ARMED').hooks, WATCH.length);
const target = WATCH.find(t => t.data_type === 'android_id');
const method = methods.get(target.cls + '.' + target.method + JSON.stringify(target.types));
const invoke = key => method.implementation.call({}, {}, key);

assert.equal(invoke('android_id'), returnValue);
assert.equal(events.at(-1).collection_state, 'obtained');
const before = events.length;
assert.equal(invoke('enabled_input_methods'), returnValue);
assert.equal(events.length, before, 'other secure settings must not become Android ID');
observerFails = true;
assert.equal(invoke('android_id'), returnValue, 'observer failure cannot change original return');
assert.equal(events.at(-1).ev, 'ERROR');
observerFails = false;
originalError = {$className: 'java.lang.SecurityException', message: 'denied'};
assert.throws(() => invoke('android_id'), error => error === originalError,
  'original exception object must propagate unchanged');
assert.equal(events.at(-1).outcome, 'denied');
assert.equal(calls, 4, 'original method called exactly once in all four paths');
originalError = null; returnValue = -3;
const audio = WATCH.find(t => t.capture === 'audio_count');
const audioMethod = methods.get(audio.cls + '.' + audio.method + JSON.stringify(audio.types));
assert.equal(audioMethod.implementation.call({}, [], 0, 320), -3);
assert.equal(events.at(-1).outcome, 'error', 'negative AudioRecord status is an API error, not empty data');

const {matches, returned} = context;
const contact = WATCH.find(t => t.data_type === 'contacts');
assert.equal(matches(contact, ['content://com.android.contacts/data']), true);
assert.equal(matches(contact, ['content://com.android.contacts.attacker/data']), false);
assert.equal(matches(contact, ['content://other/contacts']), false);
assert.equal(returned({capture: 'cursor'}, {}).collection_state, 'call_only');
assert.equal(returned({capture: 'call_only'}, undefined).collection_state, 'call_only');
assert.equal(returned({capture: 'audio_count'}, 0).collection_state, 'empty');
assert.equal(returned({capture: 'audio_count'}, -3).collection_state, 'error');
assert.equal(returned({capture: 'audio_count'}, 320).collection_state, 'obtained');
assert.equal(returned({capture: 'location'}, null).collection_state, 'empty');
const located = returned({capture: 'location'}, {getLatitude: () => 31.2, getLongitude: () => 121.4});
assert.equal(located.collection_state, 'obtained');
// 求值器有 value_len >= 8 的硬门槛：规范形态必须自己带长度，且不得泄露坐标原文。
assert.ok(located.value_len >= 8 && /^[0-9a-f]{16}$/.test(located.value_hash), '定位须带可匹配哈希与长度');
assert.ok(!JSON.stringify(located).includes('31.2'), '定位事件不得带坐标原文');
const noFix = returned({capture: 'location'}, {getLatitude: () => 0, getLongitude: () => 0});
assert.equal(noFix.collection_state, 'obtained');
assert.ok(!noFix.value_hash && noFix.location_fix === 'zero_pair_unverified', '零坐标不得产出哈希');
const idTarget = WATCH.find(t => t.capture === 'aaid');
const idMethod = methods.get(idTarget.cls + '.getId[]');
returnValue = '00000000-0000-0000-0000-000000000000';
assert.equal(idMethod.implementation.call({}), returnValue);
assert.equal(events.at(-1).collection_state, 'empty');
adIdPermission = -1;
assert.equal(idMethod.implementation.call({}), returnValue);
assert.equal(events.at(-1).outcome, 'denied');
returnValue = 'c937834d-ed38-47cc-b34f-ab37b8aac2ba';
assert.equal(idMethod.implementation.call({}), returnValue);
assert.equal(events.at(-1).collection_state, 'obtained');
assert.ok(!JSON.stringify(events.at(-1)).includes(returnValue) && !events.at(-1).value_hash);
const infoTarget = WATCH.find(t => t.data_type === 'advertising_id' && t.capture === 'call_only');
const infoMethod = methods.get(infoTarget.cls + '.getAdvertisingIdInfo["android.content.Context"]');
originalError = new Error('com.google.android.gms.common.GooglePlayServicesNotAvailableException: 9');
assert.throws(() => infoMethod.implementation.call({}, {}), error => error === originalError);
assert.equal(events.at(-1).outcome, 'unavailable');
originalError = new Error('java.io.IOException: Google Play services not available');
assert.throws(() => infoMethod.implementation.call({}, {}), error => error === originalError);
assert.equal(events.at(-1).outcome, 'unavailable');
originalError = new Error('java.io.IOException: Connection failure');
assert.throws(() => infoMethod.implementation.call({}, {}), error => error === originalError);
assert.equal(events.at(-1).outcome, 'error');
const noGms = {getPackageManager: () => ({getApplicationInfo: () => {
  throw new Error('android.content.pm.PackageManager$NameNotFoundException: com.google.android.gms');
}})};
assert.throws(() => infoMethod.implementation.call({}, noGms), error => error === originalError);
assert.equal(events.at(-1).outcome, 'unavailable');
assert.equal(events.at(-1).aaid_reason, 'gms_not_visible_to_caller');
originalError = null;
const webhook = (data) => webhookSummary(JSON.stringify({type: 'update_sensor_states', data}));
const battery = {unique_id: 'battery_level', state: 73, attributes: {private: 'discard'}};
assert.deepEqual(webhook([battery, {unique_id: 'another_sensor', state: 'discard'}]), {kind: 'sensor', state: 73});
assert.deepEqual(webhook([{unique_id: 'different_sensor', state: 73}]), {});
assert.equal(webhook([battery, battery]).gap, 'ambiguous_or_invalid_battery_state');
assert.equal(webhook([{...battery, state: '73'}]).gap, 'ambiguous_or_invalid_battery_state');
assert.equal(webhookSummary('{"type":').gap, 'invalid_json');
const control = (service, entity = 'input_boolean.audit_test_light') => webhookSummary(
  JSON.stringify({type: 'call_service', data: {domain: 'input_boolean', service,
    service_data: {entity_id: entity}}}));
assert.deepEqual(control('turn_on'), {kind: 'control', payload_type: 'call_service',
  domain: 'input_boolean', service: 'turn_on', operation: 'input_boolean.turn_on',
  entity_id: 'input_boolean.audit_test_light'});
assert.deepEqual(control('turn_on', 'input_boolean.other'), {});
assert.equal(control('light_on').gap, 'unexpected_control_schema');
const absBody = '{"currentTime":6,"timeListened":2.5,"duration":45}';
const absSession = 'a71cc095-ef24-431c-abc1-4b0f13a01ecc';
const absHead = `POST /api/session/${absSession}/sync HTTP/1.1\r\nAuthorization: Bearer omit\r\n`;
assert.deepEqual(syncBody(absBody), {text: absBody, session: null});
assert.deepEqual(syncBody(absHead + `Content-Length: ${absBody.length}\r\n\r\n` + absBody),
  {text: absBody, session: absSession});
assert.equal(syncBody(absHead + 'Content-Length: 1\r\n\r\n' + absBody), null);
assert.equal(syncBody(absBody.slice(0, -1)), null);
assert.equal(syncBody(absBody.replace('"duration":45', '"token":"omit"')), null);
assert.equal(syncBody(absBody.replace('"duration":45', '"currentTime":45')), null);
console.log('privacy observation: return/exception preservation, discriminator and collection controls passed');
