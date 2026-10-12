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

const { makeLogger } = await import('./vscan_runtime.js');

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

// ---- 汇总 -----------------------------------------------------------------

const failed = results.filter((r) => !r.ok);
for (const r of results) {
  console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}${r.ok ? '' : '  -- ' + r.msg}`);
}
console.log(`\n${results.length - failed.length}/${results.length} passed`);
process.exit(failed.length === 0 ? 0 : 1);
