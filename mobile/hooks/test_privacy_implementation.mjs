// Offline runtime-class regression; these mock events are not device evidence.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { WATCH, DATA_TYPES, META } from './targets.generated.js';

const targets = WATCH.filter(e => e.cls === 'android.content.pm.PackageManager');
assert.ok(targets.length > 0);
const overloads = new Map();
const used = [];
const events = [];
const methodHolder = method => ({ overload(...types) {
  const key = method + JSON.stringify(types);
  if (!overloads.has(key)) overloads.set(key, { apply() { return [1, 2, 3]; } });
  return overloads.get(key);
} });
const context = {
  packages: () => ['com.example.audit'],
  makeLogger: () => (ev, extra) => events.push({ ev, ...extra }),
  procName: () => 'com.example.audit', threadName: () => 'unit-thread', stackStr: () => '',
  armRuntimeCache: () => true, armValueCache: () => true, argsOnly: () => false,
  matchBySpec: (_, __, dataType) => [dataType], describeException: () => ({}),
  discriminator: () => null, unmappedKey: () => null, preview: String,
  describe: (_, __, value) => ({ count: value.length, collection_state: 'obtained' }),
  WATCH: targets, DATA_TYPES, META,
  console: { log() {} }, Frida: { version: 'mock-unit-only' },
  Java: { perform(fn) { fn(); }, use(name) {
    used.push(name);
    if (name === 'android.os.Process') return { myUid: () => 1234 };
    assert.equal(name, 'android.app.ApplicationPackageManager');
    return new Proxy({}, { get: (_, method) => methodHolder(method) });
  } },
};
const source = fs.readFileSync(new URL('./hook_privacy.js', import.meta.url), 'utf8')
  .replace(/^import .*;\r?\n/gm, '');
vm.runInNewContext(source, context);
assert.ok(used.includes('android.app.ApplicationPackageManager'));
assert.ok(!used.includes('android.content.pm.PackageManager'));
assert.equal(events.find(e => e.ev === 'ARMED').hooks, targets.length);
for (const overload of overloads.values()) {
  assert.equal(overload.implementation.call({}).length, 3);
}
const reads = events.filter(e => e.ev === 'PRIVACY_READ');
assert.equal(reads.length, targets.length);
for (const read of reads) {
  assert.ok(read.api.startsWith('android.content.pm.PackageManager.'));
  assert.equal(read.hook_class, 'android.app.ApplicationPackageManager');
  assert.equal(read.count, 3);
}
console.log('PackageManager concrete implementation: passed; canonical rule API preserved');
