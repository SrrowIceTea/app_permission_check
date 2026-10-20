// values.js 的纯离线测试；不注入设备。
// 2026-10-19 起值哈希是**纯 JS SHA-256**：这个文件顺便守着"事件期绝不碰 Java"这条线——
// 下面把 globalThis.Java 定义成"一访问就抛"，任何 Java 调用都会立刻炸出来。
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const source = await readFile(new URL('../hooks/values.js', import.meta.url), 'utf8');

let javaTouched = 0;
Object.defineProperty(globalThis, 'Java', {
  configurable: true,
  get() { javaTouched += 1; throw new Error('event-time Java access forbidden'); },
});

const { describe, armValueCache, argsOnly } = await import(
  'data:text/javascript;base64,' + Buffer.from(source).toString('base64'));

assert.equal(argsOnly(), false);
assert.equal(armValueCache(), true, '不再需要解析 Java 类，挂载即就绪');

const sha = (s) => createHash('sha256').update(Buffer.from(s, 'utf8')).digest('hex').slice(0, 16);
const scalar = { capture: 'return_or_exception' };
const count = { capture: 'count_only' };

for (const value of [null, undefined, '']) {
  const out = describe([], scalar, value);
  assert.equal(out.collection_state, 'empty');
  assert.equal(out.value_hash ?? null, null, '空值不哈希');
}
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

// 长度/preview/hash 语义与旧实现（UTF-8 字节的 SHA-256 前 16 位）逐例对齐：
// 中文走 3 字节、emoji 走 4 字节（代理对）——旧实现把 String 转 bytes 再 digest，
// 纯 JS 版必须自己按 UTF-8 编码，这里是唯一能守住等价性的地方。
const cases = [
  ['测试标识符'.repeat(100), '长中文串'],
  ['+15551234567', '手机号'],
  ['中文测试', '短中文'],
  ['emoji😀x', 'emoji（4 字节码点）'],
  ['abc', 'ASCII'],
  ['a'.repeat(100), 'ASCII 长串'],
];
for (const [value, label] of cases) {
  const out = describe([], scalar, value);
  assert.equal(out.collection_state, 'obtained', label);
  assert.equal(out.value_len, value.length, label + '：value_len 仍按 UTF-16 单元计');
  assert.equal(out.value_hash, sha(value), label + '：哈希语义必须与旧实现一致');
}
const long = '测试标识符'.repeat(100);
assert.equal(describe([], scalar, long).value_preview, long.slice(0, 6) + '…');

const diagnosticSource = source.replace('__VSCAN_ARGS_ONLY__', '1');
const diagnostic = await import(
  'data:text/javascript;base64,' + Buffer.from(diagnosticSource).toString('base64'));
assert.equal(diagnostic.argsOnly(), true);
assert.deepEqual(diagnostic.describe([], count, [1]), { collection_state: 'call_only' });
assert.deepEqual(diagnostic.describe([], scalar, 'secret'), { collection_state: 'call_only' });

// armValueCache 的返回值不再因"缓存失败"变 false（已无缓存可失败），但要保证
// 重复挂载不炸、且挂载后哈希照常可用。
const noCache = await import(
  'data:text/javascript;base64,' + Buffer.from(source + '\n// re-import guard').toString('base64'));
assert.equal(noCache.armValueCache(), true);
assert.equal(noCache.describe([], scalar, 'secret').value_hash, sha('secret'));

assert.equal(javaTouched, 0, '事件路径里出现了 Java 访问——纯 JS 改造被破坏');
console.log('values: null/empty/list/unknown/call-only/UTF-8-hash/preview/no-Java passed');
