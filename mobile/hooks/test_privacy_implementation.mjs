// Offline runtime-class regression; these mock events are not device evidence.
//
// 覆盖两件事：
//  1) PackageManager 抽象声明被 ApplicationPackageManager 绕过的修法（原有断言）；
//  2) 类晚加载补挂（与 hook_privacy_native.js 的 RESCAN_STOPPED 同构）：
//     幂等 / 有界 / 可观测 / 全挂上时不起定时器。
//
// 夹具只证明"逻辑在有界轮次内补挂且不重复"，**不**证明真机上类确实晚到——
// 那需要设备（本项目无对应样本，见交付说明）。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { WATCH, DATA_TYPES, META } from './targets.generated.js';

const targets = WATCH.filter(e => e.cls === 'android.content.pm.PackageManager');
assert.ok(targets.length > 0);
const CONCRETE = 'android.app.ApplicationPackageManager';
// 与 hook_privacy.js 的 RESCAN 常量对齐；改了那边必须同步改这里。
const MAX_ROUNDS = 30;
const INTERVAL_MS = 2000;

const SOURCE = fs.readFileSync(new URL('./hook_privacy.js', import.meta.url), 'utf8')
  // 多行 import（本项目 L15-17 就是三条多行 import）必须整段剥掉，单行正则不够。
  .replace(/^import\s[\s\S]*?from\s+'[^']*';\r?\n/gm, '')
  .replace(/^export\s+/gm, '');
assert.ok(!/^import\s/m.test(SOURCE), 'import 未剥干净');
assert.ok(!/^export\s/m.test(SOURCE), 'export 未剥干净');

function makeHarness({ loadAfterTicks = 0, neverLoad = false, pkg = 'com.example.audit' } = {}) {
  const events = [];
  const used = [];
  const overloads = new Map();
  const implCount = new Map();
  const timers = new Map();
  let seq = 0;
  let ticks = 0;  // 定时器已触发的轮数；轮数到达 loadAfterTicks 时类才算加载完成

  const loaded = () => !neverLoad && ticks >= loadAfterTicks;
  const newOverload = () => {
    let impl = null;
    const obj = { apply() { return [1, 2, 3]; } };
    Object.defineProperty(obj, 'implementation', {
      get: () => impl,
      set(v) { impl = v; implCount.set(obj, (implCount.get(obj) || 0) + 1); },
    });
    return obj;
  };
  const methodHolder = method => ({ overload(...types) {
    const key = method + JSON.stringify(types);
    if (!overloads.has(key)) overloads.set(key, newOverload());
    return overloads.get(key);
  } });

  const context = {
    packages: () => ['com.example.audit'],
    makeLogger: () => (ev, extra) => events.push({ ev, ...extra }),
    procName: () => pkg, threadName: () => 'unit-thread', stackStr: () => '',
    armRuntimeCache: () => true, armValueCache: () => true, argsOnly: () => false,
    deoptimizeBeforeArm: () => false,
    matchBySpec: (_, __, dataType) => [dataType], describeException: () => ({}),
    discriminator: () => null, unmappedKey: () => null, preview: String,
    describe: (_, __, value) => ({ count: value.length, collection_state: 'obtained' }),
    WATCH: targets, DATA_TYPES, META,
    console: { log() {} }, Frida: { version: 'mock-unit-only' },
    setInterval(fn, ms) { const id = ++seq; timers.set(id, { fn, ms }); return id; },
    clearInterval(id) { timers.delete(id); },
    Java: {
      perform(fn) { fn(); },
      use(name) {
        used.push(name);
        if (name === 'android.os.Process') return { myUid: () => 1234 };
        assert.equal(name, CONCRETE);
        if (!loaded()) throw new Error('java.lang.ClassNotFoundException: ' + name);
        return new Proxy({}, { get: (_, method) => methodHolder(method) });
      },
    },
  };

  return {
    context, events, used, overloads, implCount,
    timerMs: () => [...timers.values()].map(t => t.ms),
    timerCount: () => timers.size,
    run() { vm.runInNewContext(SOURCE, context); context.Java.perform(context.main); },
    advance(n = 1) {
      for (let i = 0; i < n; i++) {
        ticks++;
        for (const [id, t] of [...timers]) if (timers.has(id)) t.fn();
      }
    },
  };
}

const pick = (events, ev) => events.filter(e => e.ev === ev);

// ---- 1) 类一开始就在：一次挂满，不启动定时器 ----
{
  const h = makeHarness({ loadAfterTicks: 0 });
  h.run();
  assert.ok(h.used.includes(CONCRETE));
  assert.ok(!h.used.includes('android.content.pm.PackageManager'));
  const armed = pick(h.events, 'ARMED')[0];
  assert.equal(armed.hooks, targets.length);
  assert.equal(armed.pending, 0);
  assert.equal(h.timerCount(), 0, '全挂上时不得起定时器');
  assert.equal(pick(h.events, 'JAVA_RESCAN_ROUND').length, 0);
  const stop = pick(h.events, 'JAVA_RESCAN_STOPPED')[0];
  assert.equal(stop.reason, 'all_armed_at_arm_time');
  for (const n of h.implCount.values()) assert.equal(n, 1);

  for (const ov of h.overloads.values()) assert.equal(ov.implementation.call({}).length, 3);
  const reads = pick(h.events, 'PRIVACY_READ');
  assert.equal(reads.length, targets.length);
  for (const read of reads) {
    assert.ok(read.api.startsWith('android.content.pm.PackageManager.'));
    assert.equal(read.hook_class, CONCRETE);
    assert.equal(read.count, 3);
  }
  console.log('PackageManager concrete implementation: passed; canonical rule API preserved');
}

// ---- 2) 类晚到：轮询补挂成功，且每个重载只挂一次 ----
{
  const h = makeHarness({ loadAfterTicks: 1 });
  h.run();
  const armed = pick(h.events, 'ARMED')[0];
  assert.equal(armed.hooks, 0);
  assert.equal(armed.pending, targets.length);
  assert.deepEqual(h.timerMs(), [INTERVAL_MS]);
  assert.equal(h.timerCount(), 1);

  h.advance(1);
  const round1 = pick(h.events, 'JAVA_RESCAN_ROUND');
  assert.equal(round1.length, 1);
  assert.equal(round1[0].round, 1);
  assert.equal(round1[0].attempted, targets.length);
  assert.equal(round1[0].added, targets.length);
  assert.equal(round1[0].pending, 0, 'pending 是本轮结束后的剩余数');
  assert.equal(round1[0].added_keys.length, targets.length);
  assert.equal(h.timerCount(), 0, 'pending 归零后必须停表');
  const stop = pick(h.events, 'JAVA_RESCAN_STOPPED').pop();
  assert.equal(stop.reason, 'all_armed');
  assert.equal(stop.hooks, targets.length);

  for (const n of h.implCount.values()) assert.equal(n, 1, '重复 implementation 会让事件翻倍');
  // TARGET_ABSENT 只记一次，不是每轮一条
  assert.equal(pick(h.events, 'TARGET_ABSENT').length, targets.length);
  for (const ov of h.overloads.values()) assert.equal(ov.implementation.call({}).length, 3);
  assert.equal(pick(h.events, 'PRIVACY_READ').length, targets.length);
}

// ---- 3) 类始终不到：有界收尾，每轮都有 0 补挂计数 ----
{
  const h = makeHarness({ neverLoad: true });
  h.run();
  assert.equal(h.timerCount(), 1);
  h.advance(MAX_ROUNDS + 10);
  const rounds = pick(h.events, 'JAVA_RESCAN_ROUND');
  assert.equal(rounds.length, MAX_ROUNDS, '超过上限必须停表，不能无限轮询');
  for (const r of rounds) {
    assert.equal(r.added, 0);
    assert.equal(r.pending, targets.length);
    // 跨 realm 的数组原型不同，deepEqual 会失败；只比内容。
    assert.equal(JSON.stringify(r.added_keys), '[]');
  }
  assert.equal(h.timerCount(), 0);
  const stop = pick(h.events, 'JAVA_RESCAN_STOPPED').pop();
  assert.equal(stop.reason, 'max_rounds');
  assert.equal(stop.round, MAX_ROUNDS);
  assert.equal(JSON.stringify(stop.unresolved),
               JSON.stringify(targets.map(t => t.cls + '.' + t.method + t.desc)));
  assert.equal(pick(h.events, 'PRIVACY_READ').length, 0);
  console.log('bounded rescan: ' + MAX_ROUNDS + ' rounds @' + INTERVAL_MS + 'ms then stopped');
}

// ---- 4) 不在白名单：不挂任何钩子，也不起定时器（零额外开销） ----
{
  const h = makeHarness({ pkg: 'com.other.app' });
  h.run();
  assert.deepEqual(h.used, ['android.os.Process']);
  assert.equal(h.timerCount(), 0);
  assert.equal(pick(h.events, 'NOT_TARGET').length, 1);
  assert.equal(pick(h.events, 'ARMED').length, 0);
  assert.equal(pick(h.events, 'JAVA_RESCAN_STOPPED').length, 0);
}

console.log('all offline cases passed (' + targets.length + ' PackageManager entries)');
