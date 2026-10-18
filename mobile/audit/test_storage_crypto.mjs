// Synthetic Frida/Java double only: verifies wrappers, not Android or ART behavior.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./storage_crypto.js', import.meta.url), 'utf8')
  .replace("import Java from 'frida-java-bridge';", '');
const pkg = 'com.vscanner.privacydemo';
const root = '/data/user/0/' + pkg;

function fixture(packageName = pkg, whitelist = undefined, early = false) {
  const records = [], overloads = new Map(), writes = [], prefs = [];
  const failure = new Error('SYNTHETIC app error');
  let appReady = !early;
  const callbacks = [];
  const method = (name, types, fn) => {
    const key = name + '(' + types.join(',') + ')';
    function ov(...args) { return fn.apply(this, args); }
    ov.argumentTypes = types.map(className => ({ className }));
    overloads.set(key, ov);
    return ov;
  };
  const appAttach = method('attach', ['android.content.Context'], function (_context) {
    if (this.fail) throw failure;
    appReady = true;
  });
  appAttach.returnType = { className: 'void' };
  const preference = method('putString', ['java.lang.String', 'java.lang.String'], function (key, value) {
    if (this.fail) throw failure;
    prefs.push([key, value]);
    return this;
  });
  const init = method('init', ['int', 'java.security.Key'], function (mode, _key) {
    if (this.fail) throw failure;
    this.mode = mode;
    return undefined;
  });
  const final = method('doFinal', ['[B'], function (_data) {
    if (this.fail) throw failure;
    return [0, 42, 255];
  });
  const constructors = new Map();
  for (const types of [['java.lang.String'], ['java.lang.String', 'boolean'],
    ['java.io.File'], ['java.io.File', 'boolean']]) {
    constructors.set(types.join(','), method('$init', types, function (path) {
      if (this.fail) throw failure;
      this.path = typeof path === 'string' ? path : path.getCanonicalPath();
      return undefined;
    }));
  }
  const sliced = method('write', ['[B', 'int', 'int'], function (value, offset, count) {
    if (this.fail) throw failure;
    writes.push(Array.from(value).slice(offset, offset + count));
  });
  const whole = method('write', ['[B'], function (value) {
    if (this.fail) throw failure;
    // Synthetic Java delegation: the inner hook must not generate a duplicate.
    return sliced.implementation.call(this, value, 0, value.length);
  });
  const pick = (items, types) => {
    const value = items.get(types.join(','));
    if (!value) throw new Error('synthetic missing overload ' + types);
    return value;
  };
  const application = {
    // Match attach timing: base Context works before outer ApplicationContext exists.
    getPackageName: () => { assert.ok(appReady, 'base Context must be attached'); return packageName; },
    getApplicationContext: () => early ? null : ({ getPackageName: () => packageName }),
    getApplicationInfo: () => ({ dataDir: { value: root } }) };
  const classes = {
    'android.app.ActivityThread': { currentApplication: () => appReady ? application : null },
    'android.app.Application': { attach: { overloads: [appAttach] } },
    'java.util.WeakHashMap': { $new: () => {
      const map = new Map();
      return { put: (key, value) => map.set(key, value), get: key => map.get(key) ?? null };
    } },
    'java.lang.String': { $new: value => value },
    'java.io.File': { $new: value => ({ getCanonicalPath: () => String(value) }) },
    'java.security.MessageDigest': { getInstance: () => ({ digest: value =>
      [...createHash('sha256').update(Buffer.from(value)).digest()] }) },
    'android.app.SharedPreferencesImpl$EditorImpl': { putString: { overload: () => preference } },
    'javax.crypto.Cipher': { init: { overloads: [init] }, doFinal: { overload: () => final } },
    'java.io.FileOutputStream': {
      $init: { overload: (...types) => pick(constructors, types) },
      write: { overload: (...types) => types.length === 1 ? whole : sliced }
    }
  };
  const context = { __VSCAN_AUDIT_PACKAGES__: whitelist, Java: { perform: fn => fn(), use: name => {
    assert.ok(classes[name], name);
    return classes[name];
  } }, Process: { id: 123, getCurrentThreadId: () => 1 },
  send: payload => {
    const record = JSON.parse(payload.line);
    assert.equal(record.ev, payload.ev);
    if (record.ev === 'FILE_WRITE') assert.ok(writes.length > 0, 'observe after original write');
    if (record.ev === 'PREF_PUT_STRING') assert.ok(prefs.length > 0, 'observe after original putString');
    records.push(record);
  }, setTimeout: fn => {
    if (!early) throw new Error('unexpected retry');
    callbacks.push(fn);
  } };
  if (early) context.Java.performNow = fn => fn();
  vm.runInNewContext(source, context);
  return { records, overloads, writes, prefs, failure, application, callbacks, appAttach };
}

function call(f, name, types, receiver, ...args) {
  const ov = f.overloads.get(name + '(' + types.join(',') + ')');
  assert.ok(ov.implementation, 'hook installed: ' + name);
  return ov.implementation.call(receiver, ...args);
}

{
  const f = fixture('com.other.app');
  assert.deepEqual(f.records.map(r => r.ev), ['SKIP']);
}
{
  const f = fixture();
  const armed = f.records.find(r => r.ev === 'ARMED');
  assert.ok(armed);
  assert.deepEqual(armed.missing, []);
  assert.equal(armed.pkg, pkg);
  const editor = {};
  assert.equal(call(f, 'putString', ['java.lang.String', 'java.lang.String'], editor, 'k', 'SYNTHETIC'), editor);
  const pref = f.records.find(r => r.ev === 'PREF_PUT_STRING');
  assert.equal(pref.value.text, 'SYNTHETIC');
  assert.equal(pref.observation_scope, 'editor_staged');
  const before = f.records.length;
  editor.fail = true;
  assert.throws(() => call(f, 'putString', ['java.lang.String', 'java.lang.String'], editor, 'k', 'v'),
    error => error === f.failure);
  assert.equal(f.records.length, before);
}
{
  const f = fixture();
  const cipher = { getAlgorithm: () => 'AES/GCM/NoPadding', getIV: () => [1, 2, 3] };
  for (const mode of [1, 2, 3]) {
    call(f, 'init', ['int', 'java.security.Key'], cipher, mode, { RAW_KEY_MUST_NEVER_APPEAR: true });
    const output = call(f, 'doFinal', ['[B'], cipher, [65, 66, 67]);
    assert.deepEqual(output, [0, 42, 255]);
    const row = f.records.at(-1);
    assert.equal(row.opmode, mode);
    assert.equal(row.input_role, mode === 1 ? 'plaintext' : mode === 2 ? 'ciphertext' : 'unknown');
    assert.equal(row.output_role, mode === 1 ? 'ciphertext' : mode === 2 ? 'plaintext' : 'unknown');
    assert.equal(row.input.hex, '414243');
    assert.equal(row.output.hex, '002aff');
  }
  const init = f.records.find(r => r.ev === 'CIPHER_INIT');
  assert.equal(init.iv_len, 3);
  assert.equal(init.iv_sha256_16, createHash('sha256').update(Buffer.from([1, 2, 3])).digest('hex').slice(0, 16));
  assert.ok(!JSON.stringify(f.records).includes('RAW_KEY'));
  const unseen = { getAlgorithm: () => 'AES' };
  call(f, 'doFinal', ['[B'], unseen, [65]);
  assert.equal(f.records.at(-1).input_role, 'unknown');
}
{
  const f = fixture(), stream = {};
  call(f, '$init', ['java.lang.String', 'boolean'], stream, root + '/files/synthetic.txt', false);
  call(f, 'write', ['[B', 'int', 'int'], stream, [0, 65, 66, 67, 255], 1, 3);
  let rows = f.records.filter(r => r.ev === 'FILE_WRITE');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].bytes.hex, '414243');
  assert.equal(rows[0].array_offset, 1);
  call(f, 'write', ['[B'], stream, [65, 66]);
  rows = f.records.filter(r => r.ev === 'FILE_WRITE');
  assert.equal(rows.length, 2, 'delegating overload emitted exactly one event');
  stream.fail = true;
  assert.throws(() => call(f, 'write', ['[B'], stream, [65]), error => error === f.failure);
  assert.equal(f.records.filter(r => r.ev === 'FILE_WRITE').length, 2);
  const external = {};
  call(f, '$init', ['java.lang.String'], external, '/sdcard/outside-scope.txt');
  call(f, 'write', ['[B'], external, [65]);
  assert.equal(f.records.filter(r => r.ev === 'FILE_WRITE').length, 2);
}
{
  const custom = 'edu.ksu.cs.benign';
  const f = fixture(custom, [custom]);
  assert.ok(f.records.some(r => r.ev === 'ARMED' && r.pkg === custom));
  assert.deepEqual(f.records.find(r => r.ev === 'START').whitelist, [custom]);
  assert.deepEqual(fixture(pkg, [custom]).records.map(r => r.ev), ['SKIP']);
  assert.ok(fixture(custom, [pkg, custom]).records.some(r => r.ev === 'ARMED'));
  for (const value of [[], null, custom, {}, [''], ['edu.*'], ['edu..ksu'],
    ['edu.ksu;bad'], [' edu.ksu'], ['edu.中文'], [custom, 42], Array(2)]) {
    const denied = fixture(custom, value);
    assert.deepEqual(denied.records.map(r => r.ev), ['PROBE_ERROR']);
    assert.ok(![...denied.overloads.values()].some(ov => ov.implementation));
  }
}
{
  const f = fixture(pkg, [pkg], true);
  assert.deepEqual(f.records.map(r => r.ev), ['BOOTSTRAP_ARMED']);
  assert.equal(f.application.getApplicationContext(), null, 'outer context still null at early attach');
  assert.equal(f.records[0].signature_source, 'runtime_enumerated_not_sdk_stub');
  assert.equal(f.appAttach.implementation.call(f.application, {}), undefined);
  assert.deepEqual(f.records.map(r => r.ev), ['BOOTSTRAP_ARMED', 'START', 'ARMED']);
  assert.ok(f.records.find(r => r.ev === 'START'));
  for (const callback of f.callbacks) callback();
  f.appAttach.implementation.call(f.application, {});
  assert.equal(f.records.filter(r => r.ev === 'ARMED').length, 1, 'bootstrap+boot install once');
  const before = f.records.length;
  f.application.fail = true;
  assert.throws(() => f.appAttach.implementation.call(f.application, {}), error => error === f.failure);
  assert.equal(f.records.length, before, 'original attach failure propagates without success record');
}
{
  // Regression for IT之家: Application.getPackageName() returned "" during attach.
  const f = fixture(pkg, [pkg], true);
  f.application.getPackageName = () => '';
  const context = { getPackageName: () => pkg, getApplicationInfo: f.application.getApplicationInfo };
  f.appAttach.implementation.call(f.application, context);
  assert.equal(f.records.find(r => r.ev === 'ARMED')?.pkg, pkg);
  assert.ok(!f.records.some(r => r.ev === 'SKIP'));
  for (const callback of f.callbacks) callback();
  assert.equal(f.records.filter(r => r.ev === 'ARMED').length, 1);
}
{
  const f = fixture(pkg, [pkg], true);
  f.application.getPackageName = () => '';
  f.application.getBaseContext = () => ({ getPackageName: () => pkg,
    getApplicationInfo: f.application.getApplicationInfo });
  f.appAttach.implementation.call(f.application, {});
  assert.equal(f.records.find(r => r.ev === 'ARMED')?.pkg, pkg, 'base Context fallback');
}
{
  const f = fixture(pkg, [pkg], true);
  f.application.getPackageName = () => '';
  f.appAttach.implementation.call(f.application, {});
  assert.deepEqual(f.records.map(r => r.ev), ['BOOTSTRAP_ARMED']);
  f.application.getPackageName = () => pkg;
  f.callbacks.shift()();
  assert.equal(f.records.find(r => r.ev === 'ARMED')?.pkg, pkg, 'empty identity remains retryable');
}
{
  const f = fixture(pkg, [pkg], true);
  f.application.getPackageName = () => '';
  f.appAttach.implementation.call(f.application, {});
  let attempts = 0;
  while (f.callbacks.length && ++attempts < 110) f.callbacks.shift()();
  assert.equal(attempts, 100, 'bounded 10-second identity resolution');
  assert.deepEqual(f.records.map(r => r.ev), ['BOOTSTRAP_ARMED', 'NOT_READY']);
  assert.equal(f.records.at(-1).pkg, null, 'never substitutes authorized package for unknown identity');
  assert.ok(![...f.overloads.values()].filter(ov => ov !== f.appAttach).some(ov => ov.implementation));
}
{
  const f = fixture(pkg, [pkg], true);
  f.appAttach.implementation.call(f.application, { getPackageName: () => 'org.outside.app' });
  assert.equal(f.records.at(-1).ev, 'SKIP');
  assert.equal(f.records.at(-1).pkg, 'org.outside.app', 'actual attach identity wins over wrapper');
  assert.ok(![...f.overloads.values()].filter(ov => ov !== f.appAttach).some(ov => ov.implementation));
}
console.log('PASS: synthetic hook wrappers, post-success semantics, exact whitelist, bounded Context identity bootstrap; NOT Android validation');
