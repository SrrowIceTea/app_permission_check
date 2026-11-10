// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
//
// vscan_runtime.js 的离线回归，**不需要设备、不需要 Frida**。
//
//   node test_runtime.mjs
//
// 为什么这个文件值得存在：共享运行时抽出来的**首要理由**不是省代码，是修一个缺陷——
// `hook_vhal.js` / `recon_cpm.js` 原先那两份 vlog 没有外层 try/catch，
// 记录一失败就会把异常抛回被挂钩的 `CarPropertyManager.getProperty`，
// 也就是"观测失败改变了被测应用的行为"。项目原则是"只观察不改写"。
// 这个缺陷**没有任何一条日志会显示出来**，所以只能靠测试钉住。
//
// Frida 的全局（Process / send / File / console）在这里是桩，本文件在 Node 里跑。

const results = [];

function check(name, fn) {
  try {
    fn();
    results.push({ name, ok: true });
  } catch (e) {
    results.push({ name, ok: false, msg: String(e && e.message ? e.message : e) });
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// ---- Frida 全局的桩 -------------------------------------------------------
function installStubs({ fileThrows = false, sendThrows = false } = {}) {
  const sent = [];
  globalThis.Process = { id: 4242, getCurrentThreadId: () => 7 };
  globalThis.send = (m) => { if (sendThrows) throw new Error('no host'); sent.push(m); return undefined; };
  globalThis.File = class {
    constructor(path, mode) { this.path = path; this.mode = mode; this.written = ''; }
    write(s) { if (fileThrows) throw new Error('EACCES'); this.written += s; }
    flush() {}
    close() {}
  };
  return sent;
}

const { makeLogger, setTransport } = await import('./vscan_runtime.js');
const { createBufferedTransport } = await import('./buffered_transport.js');
const { createReadScope, recordDelegate } = await import('./vhal_read_scope.js');
const { propertyValue } = await import('./property_value.js');

// ---- 1. 记录形状 ----------------------------------------------------------

check('事件记录带齐 v/src/ev/evt_id/ts/pid/tid', () => {
  const sent = installStubs();
  const vlog = makeLogger('vhal', '/data/local/tmp/vscan.log');
  vlog('VHAL_READ', { prop_id: 289408000 });
  assert(sent.length === 1, '应当只发了一条');
  const rec = JSON.parse(sent[0].line);
  for (const k of ['v', 'src', 'ev', 'evt_id', 'ts', 'pid', 'tid']) {
    assert(k in rec, `记录里缺字段 ${k}`);
  }
  assert(rec.src === 'vhal', `src 应为 vhal，实际 ${rec.src}`);
  assert(rec.v === '1', 'v 应为字符串 "1"');
  assert(rec.pid === 4242 && rec.tid === 7, 'pid/tid 应来自 Process');
  assert(rec.prop_id === 289408000, 'extra 应被合并进记录');
});

check('extra 不会覆盖掉保留字段', () => {
  // 下游按 (src, evt_id) 定位事件。若 extra 里恰好有个 evt_id，把保留字段盖掉
  // 会让证据指向别的事件——**而且没有任何地方会报错**。
  const sent = installStubs();
  const vlog = makeLogger('tls', '/data/local/tmp/vscan.log');
  vlog('PINNING_BYPASS', { src: 'attacker', evt_id: 999, ts: 0 });
  const rec = JSON.parse(sent[0].line);
  assert(rec.src === 'tls', `src 被 extra 覆盖了：${rec.src}`);
  assert(rec.evt_id === 1, `evt_id 被 extra 覆盖了：${rec.evt_id}`);
});

check('序号按 logger 各自递增，且从 1 开始', () => {
  const sent = installStubs();
  const a = makeLogger('vhal', '/x');
  const b = makeLogger('egress', '/x');
  a('A'); a('A'); b('B');
  const ids = sent.map((m) => JSON.parse(m.line).evt_id);
  assert(JSON.stringify(ids) === JSON.stringify([1, 2, 1]), `序号错：${ids}`);
});

// ---- 2. 缺陷本身：记录失败绝不能影响被测进程 -------------------------------

check('extra 有循环引用时不抛（记录失败不得传回应用）', () => {
  const sent = installStubs();
  const vlog = makeLogger('vhal', '/data/local/tmp/vscan.log');
  const circular = { name: 'ctx' };
  circular.self = circular; // JSON.stringify 会抛 TypeError
  vlog('VHAL_READ', circular); // 不得抛出
  assert(sent.length === 0, '循环引用时应一条都发不出去');
});

check('设备端写入被拒时不抛（SELinux 拒绝是常态）', () => {
  const sent = installStubs({ fileThrows: true });
  const vlog = makeLogger('tls', '/data/local/tmp/vscan.log');
  vlog('START', {}); // 不得抛出
  assert(sent.length === 1, '设备端写失败不该影响回传主机');
});

check('send 失败时不抛（钩子掉线是常态）', () => {
  installStubs({ sendThrows: true });
  const vlog = makeLogger('egress', '/data/local/tmp/vscan.log');
  vlog('EGRESS_CONNECT', {}); // 不得抛出
});

check('未定义值也能记录，不抛', () => {
  installStubs();
  const vlog = makeLogger('vhal', '/data/local/tmp/vscan.log');
  vlog('X', undefined);
  vlog('X', null);
});

// ---- 3. 双通道：设备端副本失败也要如实标注 --------------------------------

check('设备端写失败时 console 行带 DEVICE_WRITE_DENIED', () => {
  installStubs({ fileThrows: true });
  const lines = [];
  const orig = console.log;
  console.log = (s) => lines.push(String(s));
  try {
    makeLogger('tls', '/data/local/tmp/vscan.log')('START', {});
  } finally { console.log = orig; }
  assert(lines.length === 1, '应有一行 console 输出');
  assert(lines[0].includes('DEVICE_WRITE_DENIED'), `未标注写入失败：${lines[0]}`);
  assert(!lines[0].includes('SEND_FAIL'), `回传成功不该标 SEND_FAIL：${lines[0]}`);
});

check('回传失败时 console 行带 SEND_FAIL', () => {
  installStubs({ sendThrows: true });
  const lines = [];
  const orig = console.log;
  console.log = (s) => lines.push(String(s));
  try {
    makeLogger('tls', '/data/local/tmp/vscan.log')('START', {});
  } finally { console.log = orig; }
  assert(lines[0].includes('SEND_FAIL'), `未标注回传失败：${lines[0]}`);
});

// ---- 4. 同一条事件里的字段只有一处定义（抽出来的真正目的） -----------------

check('四个 src 的记录形状逐字一致', () => {
  const sent = installStubs();
  const keys = [];
  for (const src of ['vhal', 'egress', 'tls', 'recon']) {
    makeLogger(src, '/x')('EV', {});
  }
  for (const m of sent) keys.push(Object.keys(JSON.parse(m.line)).sort().join(','));
  assert(new Set(keys).size === 1, `四个 src 的记录字段不一致：${JSON.stringify([...new Set(keys)])}`);
  assert(sent.map((m) => JSON.parse(m.line).src).join(',') === 'vhal,egress,tls,recon',
         'src 应各自如实记录');
});

check('车载批量记录先于出站事件，收尾刷盘后停止接收', () => {
  const sent = installStubs();
  const transport = createBufferedTransport();
  setTransport(transport);
  try {
    const read = makeLogger('vhal', '/x');
    const egress = makeLogger('egress', '/x');
    read('VHAL_READ', { value_raw: 4 });
    assert(sent.length === 0, '读取应先进入队列');
    egress('EGRESS_URL');
    assert(JSON.parse(sent[0].lines[0]).value_raw === 4, '读取应先于出站发送');
    assert(JSON.parse(sent[1].line).ev === 'EGRESS_URL', '出站应立即发送');
    read('VHAL_READ');
    const stats = transport.close();
    read('VHAL_READ');
    assert(stats.delivered === 3 && stats.buffered_events === 2 && sent.length === 3, '尾批对账失败');
    assert(JSON.parse(sent[2].lines[0]).evt_id === 2, '读取序号应保持');
  } finally { setTransport(null); }
});

check('批次上限和发送失败都计入回执', () => {
  const sent = installStubs();
  const transport = createBufferedTransport();
  for (let i = 0; i < 20; i++) transport.emit('vhal', 'VHAL_READ', '{}');
  assert(sent.length === 1 && sent[0].lines.length === 20, '批次上限失效');
  transport.emit('vhal', 'VHAL_READ', '{}');
  globalThis.send = () => { throw new Error('no host'); };
  const stats = transport.close();
  assert(stats.delivered === 20 && stats.failed === 1, '丢失事件必须可见');
});

check('嵌套合并限制在相同线程、属性、区域和已知委托链', () => {
  const scope = createReadScope();
  const outer = scope.enter(7, 'cpm.getFloatProperty(II)', 1, 0);
  const inner = scope.enter(7, 'cpm.getProperty(II)', 1, 0);
  assert(inner.merged && inner.outer === outer && outer.nested_suppressed === 1, '委托链未合并');
  recordDelegate(outer, 'cpm.getProperty(II)', 'unavailable');
  recordDelegate(outer, 'cpm.getProperty(Class,II)', 'ok');
  assert(outer.delegate === 'unavailable', '较外层返回值不能覆盖内层不可用');
  for (const [thread, property, area] of [[8, 1, 0], [7, 2, 0], [7, 1, 2], [7, 1, 0]]) {
    const separate = scope.enter(thread, 'cpm.getProperty(II)', property, area);
    assert(!separate.merged, '独立调用不得合并');
    scope.leave(separate);
  }
  scope.leave(outer);
  assert(!scope.enter(7, 'cpm.getProperty(II)', 1, 0).merged, '收尾必须清理线程上下文');
});

check('原始值和展示值共用一次读取；不可用属性不尝试取值', () => {
  let status = 0, statuses = 0, reads = 0;
  const value = { $className: 'android.car.hardware.CarPropertyValue',
    getStatus: () => { statuses++; return status; }, getValue: () => { reads++; return 0; } };
  const available = propertyValue(value, String);
  assert(available.value_raw === 0 && available.value === 'CarPropertyValue{status=0,value=0}', '数值零丢失');
  assert(statuses === 1 && reads === 1, '可用值应只探测一次');
  status = 1;
  const unavailable = propertyValue(value, String);
  assert(unavailable.value_raw === null && unavailable.value_status === 1 && reads === 1 &&
    unavailable.value === 'CarPropertyValue{status=1,value=null}', '不可用值不应再探测或展示');
});

// ---- 5. 定位规范形态（privacy_location.js）--------------------------------

const { locationEvidence, LOCATION_FORM_NAMES } = await import('./privacy_location.js');
const { sha256hex16 } = await import('../../core/privacy/values.js');

const fakeLocation = (lat, lon) => ({ getLatitude: () => lat, getLongitude: () => lon });

check('定位主形态是 6 位小数的 lat,lon 对，且带 value_len', () => {
  const out = locationEvidence(fakeLocation(30.2741, 120.1551));
  const canonical = '30.274100,120.155100';
  assert(out.collection_state === 'obtained' && out.non_empty === true, '应记为 obtained');
  assert(out.location_form === 'pair_d6', `主形态错：${out.location_form}`);
  assert(out.value_hash === sha256hex16(canonical), '主哈希与规范串不一致');
  assert(out.value_len === canonical.length, `value_len 错：${out.value_len}`);
  // 最弱的一环：求值器有 value_len >= 8 的硬门槛，规范形态必须自己越过它。
  assert(out.value_len >= 8, 'value_len 低于求值器门槛');
});

check('形态表顺序固定，主形态永远是第一项', () => {
  assert(LOCATION_FORM_NAMES[0] === 'pair_d6', `第一项应为 pair_d6：${LOCATION_FORM_NAMES[0]}`);
  const out = locationEvidence(fakeLocation(30.2741, 120.1551));
  assert(out.location_forms.length === LOCATION_FORM_NAMES.length, '形态数量与表不一致');
  assert(out.location_forms.map((f) => f.form).join(',') === LOCATION_FORM_NAMES.join(','),
         '返回顺序与形态表不一致');
  assert(out.location_forms[0].hash === out.value_hash, '主形态哈希应与 value_hash 相同');
  // 经纬度顺序不能混：交换后必须得到不同哈希，否则两种顺序会互相误配。
  const swapped = out.location_forms.find((f) => f.form === 'pair_d6_lonlat');
  assert(swapped.hash !== out.value_hash, 'lat,lon 与 lon,lat 不应同哈希');
});

check('定位证据不含经纬度原文（POLICY 不留样本）', () => {
  const out = locationEvidence(fakeLocation(30.2741, 120.1551));
  const text = JSON.stringify(out);
  for (const leak of ['30.2741', '120.1551', '30.274100', '120.155100']) {
    assert(!text.includes(leak), `事件里泄露了坐标原文：${leak}`);
  }
  assert(text.includes('"hash"'), '至少应保留哈希');
});

check('零坐标与越界坐标不出哈希（否则是高频误配源）', () => {
  const zero = locationEvidence(fakeLocation(0, 0));
  assert(zero.collection_state === 'obtained', '零坐标不应改写成 empty（语义保持不变）');
  assert(zero.location_fix === 'zero_pair_unverified', `零坐标标记错：${zero.location_fix}`);
  assert(!('value_hash' in zero) && !('value_len' in zero), '零坐标不得产出可匹配哈希');
  const far = locationEvidence(fakeLocation(91, 0));
  assert(far.location_fix === 'out_of_range' && !('value_hash' in far), '越界坐标不得产出哈希');
});

check('null 记 empty；字段读不到记 unknown 且不抛', () => {
  assert(locationEvidence(null).collection_state === 'empty', 'null 应为 empty');
  const broken = { getLatitude: () => { throw new Error('boom'); },
                   getLongitude: () => 1 };
  const out = locationEvidence(broken);  // 不得抛出
  assert(out.collection_state === 'unknown', `读不到字段应为 unknown：${out.collection_state}`);
  const nan = locationEvidence(fakeLocation(NaN, 1));
  assert(nan.collection_state === 'unknown' && !('value_hash' in nan), 'NaN 应为 unknown');
});

// ---- 汇总 -----------------------------------------------------------------

const failed = results.filter((r) => !r.ok);
for (const r of results) {
  console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}${r.ok ? '' : '  -- ' + r.msg}`);
}
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
