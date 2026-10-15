// values.js 的纯离线测试；Java mock 只用于校验序列化，不注入设备。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../hooks/values.js', import.meta.url), 'utf8');
let hashedInput;
globalThis.Java = { use(name) {
  if (name === 'java.lang.String') return { $new(s) { return { getBytes() { return Buffer.from(s); } }; } };
  if (name === 'java.security.MessageDigest') return { getInstance() {
    let input;
    return { update(bytes) { input = bytes; hashedInput = bytes.toString(); },
             digest() { return Array.from(createHash('sha256').update(input).digest()); } };
  } };
  throw new Error('unexpected Java class ' + name);
} };
const { describe, armValueCache, argsOnly } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
assert.equal(argsOnly(), false);
assert.equal(armValueCache(), true);
// Resolved Java classes must be reused without Java.use in the event path.
globalThis.Java.use = () => { throw Error('event-time Java.use forbidden'); };
const scalar = { capture: 'return_or_exception' };
const count = { capture: 'count_only' };
for (const value of [null, undefined, '']) assert.equal(describe([], scalar, value).collection_state, 'empty');
for (const value of [[], { size() { return 0; } }, { getCount() { return 0; } }]) {
  const out = describe([], count, value);
  assert.equal(out.collection_state, 'empty');
  assert.equal(out.count, 0); assert.equal(out.value_count, 0);
}
for (const value of [[1, 2], { size() { return 3; } }, { getCount() { return 4; } }]) {
  assert.equal(describe([], count, value).collection_state, 'obtained');
}
assert.equal(describe([], count, {}).collection_state, 'unknown');
assert.equal(describe([], count, { size() { throw Error('unavailable'); } }).count, null);
assert.equal(describe([], { capture: 'args_only' }, 'sensitive').collection_state, 'call_only');
const long = '测试标识符'.repeat(100);
const out = describe([], scalar, long);
assert.equal(out.collection_state, 'obtained');
assert.equal(out.value_len, long.length);
assert.equal(out.value_preview, long.slice(0, 6) + '…');
assert.equal(hashedInput, long);
assert.equal(out.value_hash, createHash('sha256').update(long).digest('hex').slice(0, 16));
const diagnosticSource = source.replace('__VSCAN_ARGS_ONLY__', '1');
const diagnostic = await import('data:text/javascript;base64,' + Buffer.from(diagnosticSource).toString('base64'));
assert.equal(diagnostic.argsOnly(), true);
assert.deepEqual(diagnostic.describe([], count, [1]), { collection_state: 'call_only' });
assert.deepEqual(diagnostic.describe([], scalar, 'secret'), { collection_state: 'call_only' });
const noCacheSource = source + '\n// isolated cache failure test';
const noCache = await import('data:text/javascript;base64,' + Buffer.from(noCacheSource).toString('base64'));
assert.equal(noCache.armValueCache(), false);
assert.equal(noCache.describe([], scalar, 'secret').value_hash, null);
console.log('values: null/empty/list/unknown/call-only/full-UTF8-hash/6-char-preview passed');
