// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// F1 类加载归因的离线回归，**不需要设备、不需要 Frida**：
//   node test_classload.mjs
//
// 两部分：
//   1. classload_attribution.js 的纯函数——宿主边界、SDK 种子表、未知一律 unknown、
//      数组描述符/内部类归一化、调用方穿透反射帧；
//   2. hook_classload.js 的行为——返回值与异常原样透传、按类名去重、批量与截断、
//      findClass 与 defineClass 两条来源。
// 第二条用 vm + Java 桩跑真实钩子源码（同 test_privacy.mjs 的做法），
// 因为"钩子改写了被测应用行为"这种缺陷**没有任何一条日志会显示出来**。

import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import {
  attribute, callerClass, frameClass, normalizeClass, packageRoot,
  SDK_TABLE_SIZE
} from './classload_attribution.js';
import { withStack } from './stack_capture.js';

// ---- 1. 归因口径 ----------------------------------------------------------

assert.equal(SDK_TABLE_SIZE, 30, '种子表应保持 30 条（有界声明）');

const host = attribute('test.owned.MainActivity', 'test.owned');
assert.equal(host.origin, 'host');
assert.equal(host.class_kind, 'host');

// 前缀坑：targetapp 是 targetapp2 的前缀。子串匹配会把 B 算成 A。
assert.equal(attribute('test.owned2.Foo', 'test.owned').origin, 'unknown',
  '宿主判定必须按包边界，不能按子串');

const gms = attribute('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'test.owned');
assert.equal(gms.origin, 'third_party:com.google.android.gms');
assert.equal(gms.class_kind, 'sdk');
assert.equal(gms.sdk_name, 'Google Play services');

// 最长前缀：com.tencent.mm.opensdk 不能被更短的 com.tencent.* 抢走（表里没有后者，
// 但这条保证将来加进去时仍然按最长匹配）。
assert.equal(attribute('com.tencent.mm.opensdk.OpenSDK', 'test.owned').origin,
  'third_party:com.tencent.mm.opensdk');
assert.equal(attribute('com.facebook.ads.internal.Foo', 'test.owned').origin,
  'third_party:com.facebook');

// 未知一律 unknown——混淆后的类名不能被猜成某个 SDK。
const obf = attribute('a.b.c.d.E', 'test.owned');
assert.equal(obf.origin, 'unknown');
assert.equal(obf.class_kind, 'other');
assert.equal(obf.package_root, 'a.b.c', 'unknown 只报自己的包根这一事实');

// 支持库不是数据收集 SDK：origin 仍是 unknown，只是 kind 单列，便于解释噪声。
const androidx = attribute('androidx.core.app.ActivityCompat', 'test.owned');
assert.equal(androidx.origin, 'unknown');
assert.equal(androidx.class_kind, 'support_library');
assert.equal(attribute('java.lang.String', 'test.owned').class_kind, 'platform');

// 数组描述符与内部类：两种形态都会出现在 findClass 的入参里。
assert.equal(normalizeClass('[Lcom.google.firebase.Foo;'), 'com.google.firebase.Foo');
assert.equal(attribute('[Lcom.google.firebase.Foo;', 'test.owned').origin,
  'third_party:com.google.firebase');
assert.equal(attribute('com.google.firebase.Foo$Bar', 'test.owned').origin,
  'third_party:com.google.firebase');
assert.equal(packageRoot('com.google.firebase.Foo$Bar'), 'com.google.firebase');

// 构造器与 lambda 帧也要能取到类名。
assert.equal(frameClass('com.foo.Bar.baz(Bar.java:12)'), 'com.foo.Bar');
assert.equal(frameClass('com.foo.Bar.<init>(Bar.java:1)'), 'com.foo.Bar');
assert.equal(frameClass('com.foo.Bar.lambda$run$0(Bar.java:9)'), 'com.foo.Bar');

// 调用方穿透反射帧：否则每个反射读取都会被记成 java.lang.reflect.Method。
const frames = [
  'android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:1000)',
  'java.lang.reflect.Method.invoke(Method.java:500)',
  'com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo(AdvertisingIdClient.java:66)'
];
const caller = callerClass(frames, 'android.telephony.TelephonyManager', 'getDeviceId');
assert.equal(caller, 'com.google.android.gms.ads.identifier.AdvertisingIdClient');
assert.equal(attribute(caller, 'test.owned').origin, 'third_party:com.google.android.gms');
assert.equal(callerClass(['java.lang.reflect.Method.invoke(Method.java:1)'], null, null), null,
  '只有透明帧时必须返回 null，绝不能编一个调用方');

// stack_head：调用方归因的栈顶来源。默认不采集（不给不用的钩子增体积），
// 开启后必须跳过 VMStack 帧且不改变 app_frames 的宿主过滤。
const stackFrames = [
  'dalvik.system.VMStack.getThreadStackTrace(Native Method)',
  'android.telephony.TelephonyManager.getDeviceId(TelephonyManager.java:1)',
  'java.lang.reflect.Method.invoke(Method.java:500)',
  'com.google.android.gms.ads.identifier.AdvertisingIdClient.getAdvertisingIdInfo(AdvertisingIdClient.java:66)'
];
const previousJava = globalThis.Java;
globalThis.Java = {use: () => ({currentThread: () => ({getStackTrace: () => stackFrames})})};
try {
  const out = withStack({}, 'test.owned', 8, 8, 3);
  assert.equal(out.stack_head.length, 3, 'headLimit 应截到 3 帧');
  assert.ok(out.stack_head[0].includes('TelephonyManager'), 'VMStack 帧必须跳过');
  assert.equal(out.app_frames.length, 0, 'app_frames 仍只留宿主帧');
  assert.ok(!('stack_head' in withStack({}, 'test.owned', 8, 8)), '默认不采集 stack_head');
} finally { globalThis.Java = previousJava; }

// ---- 2. 钩子行为（vm + Java 桩）-------------------------------------------

const events = [];
let interval = null, originalError = null;
const sentinel = {ok: true};
const loaderStub = {
  hashCode: () => 4242,
  toString: () => 'dalvik.system.PathClassLoader[DexPathList[[zip file "/data/app/base.apk"]]]'
};
// apply 是钩子里 `ov.apply(this, args)` 的原实现桩：默认返回 sentinel；
// originalError 非空时抛它，用来验证异常原对象重抛。
const findOverloads = [{
  argumentTypes: [{className: 'java.lang.String'}],
  implementation: null,
  apply() { if (originalError) throw originalError; return sentinel; }
}];
const defineOverloads = [{
  argumentTypes: [{className: 'java.lang.String'}, {className: '[B'},
    {className: 'int'}, {className: 'int'}],
  implementation: null,
  apply() { return sentinel; }
}];

const context = {
  packages: () => ['test.owned'],
  procName: () => 'test.owned',
  // 钩子里这两个符号来自 import；vm 里剥掉了 import 行，必须显式注入真实现，
  // 否则测的就不是"真实归因模块 + 真实钩子"的组合。
  attribute, SDK_TABLE_SIZE,
  makeLogger: () => (ev, extra) => events.push({ev, ...extra}),
  Java: {
    perform: fn => fn(),
    use: name => {
      if (name === 'dalvik.system.BaseDexClassLoader') return {findClass: {overloads: findOverloads}};
      if (name === 'java.lang.ClassLoader') return {defineClass: {overloads: defineOverloads}};
      if (name === 'android.os.Process') return {myUid: () => 1012345};
      if (name === 'android.os.Build$VERSION') return {SDK_INT: {value: 35}};
      throw new Error('unexpected Java.use: ' + name);
    }
  },
  setInterval: (fn, ms) => { interval = {fn, ms}; return 1; },
  clearInterval: () => {},
  Process: {id: 99, getCurrentThreadId: () => 3},
  send: () => {},
  File: class { write() {} flush() {} close() {} },
  console: {log: () => {}}
};
vm.createContext(context);
const source = fs.readFileSync(new URL('./hook_classload.js', import.meta.url), 'utf8')
  .replace(/^import .*;\r?\n/gm, '');
vm.runInContext(source, context);

assert.ok(events.some(e => e.ev === 'ARMED' && e.find_class === 1 && e.define_class === 1),
  'ARMED 必须如实报告两条来源的挂载数');
assert.ok(interval && interval.ms === context.CFG.flushMs, '尾批定时器必须装上');

const find = findOverloads[0].implementation;
const define = defineOverloads[0].implementation;
const batches = () => events.filter(e => e.ev === 'CLASSLOAD_BATCH');

// findClass：返回值原样透传 + 归因字段
assert.equal(find.call(loaderStub, 'com.google.firebase.Foo'), sentinel, '返回值必须原样透传');
context.flush();
let batch = batches().at(-1);
assert.equal(batch.count, 1);
assert.deepEqual(Array.from(batch.items[0].slice(0, 5)),
  ['com.google.firebase.Foo', 'third_party:com.google.firebase', 'sdk',
    'com.google.firebase', 0]);
assert.equal(batch.items[0][5], 'find');

// 去重：同一个类第二次加载不再产出新批次
const before = batches().length;
find.call(loaderStub, 'com.google.firebase.Foo');
context.flush();
assert.equal(batches().length, before, '重复加载不得重复记录');

// 宿主与未知
find.call(loaderStub, 'test.owned.Secret');
find.call(loaderStub, 'x.y.Z');
context.flush();
batch = batches().at(-1);
assert.deepEqual(Array.from(batch.items.map(i => i[1])).sort(), ['host', 'unknown']);

// 异常：原对象重抛，且失败加载进入 CLASSLOAD_MISSING
const failure = new Error('ClassNotFoundException');
originalError = failure;
assert.throws(() => find.call(loaderStub, 'missing.Class'), e => e === failure,
  '异常必须原对象重抛');
originalError = null;
context.flush();
const miss = events.filter(e => e.ev === 'CLASSLOAD_MISSING').at(-1);
assert.equal(miss.missing, 1);
assert.equal(miss.samples[0][0], 'missing.Class');

// defineClass 来源
define.call(loaderStub, 'com.bytedance.sdk.Foo', new Uint8Array(0), 0, 0);
context.flush();
batch = batches().at(-1);
const defined = batch.items.find(i => i[0] === 'com.bytedance.sdk.Foo');
assert.equal(defined[5], 'define');
assert.equal(defined[1], 'third_party:com.bytedance');

// 批量上限：改小 batchSize 后应立即切批，不攒到定时器
context.CFG.batchSize = 2;
const seqBefore = batches().length;
find.call(loaderStub, 'a.one.A');
find.call(loaderStub, 'a.two.B');
assert.equal(batches().length, seqBefore + 1, '达到 batchSize 必须立即发送');
assert.equal(batches().at(-1).count, 2);

console.log('classload attribution: host boundary, 30-prefix seed table, unknown-stays-unknown, '
  + 'array/inner normalization, reflection-transparent caller, passthrough and batching passed');
