/**
 * Flutter（`libflutter.so` 自带静态 BoringSSL）证书校验绕过。
 *
 * ## 为什么单独一个模块
 *
 * `hook_native_ssl.js` 靠**导出符号**找 `SSL_read`/`SSL_write`；`hook_tls_meta.js`
 * 靠导出符号找 `SSL_CTX_set_keylog_callback`。Flutter 把 BoringSSL **静态链接进
 * libflutter.so 并剥掉符号**，实测本地样本（LocalSend 1.18.2 x86_64）的 `.dynsym`
 * 里连 `SSL_read` 这个字符串都不存在——两个模块对它都是**零挂载**，且是静默的。
 *
 * 所以这里换一条路：**不找符号，找代码形状**。
 *
 *     ssl_crypto_x509_session_verify_cert_chain(hs, out_alert) {
 *         *out_alert = SSL_AD_INTERNAL_ERROR;   // 80 = 0x50，函数第一条语句
 *         ...
 *     }
 *
 * x86_64:  `c6 02 50`（mov byte [rdx], 0x50）紧跟 `48 8b af ?? ?? ?? ??`
 * arm64 :  `08 0a 80 52`（mov w8, #0x50）紧跟 `48 00 00 39`（strb w8, [x2]）
 *
 * 这两个常量组合**跟版本无关**：栈帧大小、SSL 结构体偏移都会变（实测本地样本
 * `48 83 ec 38` + `[rdi+0xa0]`，而 NVISO 2019 那份是 `a8`），但"先写 0x50 再解引用
 * ssl"这个形状不变。从锚点往回扫 10 字节的序言，就得到函数入口。
 *
 * ## 局限（不要读成"Flutter 都能解"）
 *
 * 1. **绕过的是证书校验，不是加密本身。** 打完补丁后握手会成功，但明文要能看到
 *    还得有流量入口：Dart 的 `HttpClient` **不读 Android 系统代理**，所以
 *    "装系统 CA + 设 http_proxy" 那套对 Flutter 天然无效——必须再用
 *    iptables REDIRECT/DNAT 把 443 引到 mitmproxy（透明模式）。
 * 2. 若 App 用**自定义 `HttpOverrides` / 自签证书固定**（Dio + badCertificateCallback），
 *    本补丁照样有效（它拦的是 BoringSSL 的链校验），但这也意味着"补丁命中"≠"必然拿到明文"。
 * 3. `libflutter.so` 被加固/改名时扫不到；`FLUTTER_SCAN_MISS` 里带模块列表，别当成
 *    "这个 App 没有 Flutter"。
 *
 * 仅用于授权测试。
 */
import { makeLogger, procName } from './runtime.js';

var vlog = makeLogger('flutter', '/data/local/tmp/vscan-mobile.log');

var CFG = {
  module: 'libflutter.so',
  // 锚点 = `*out_alert = SSL_AD_INTERNAL_ERROR` 及其后的 ssl 解引用
  anchors: { x64: 'c6 02 50 48 8b af', arm64: '08 0a 80 52 48 00 00 39' },
  // 序言：x64 push rbp/r15/r14/r13/r12/rbx；arm64 sub sp, sp, #0x70
  prologues: { x64: '55 41 57 41 56 41 55 41 54 53', arm64: 'ff c3 01 d1' },
  maxLookback: 24,
  maxGap: 16,
  maxLog: 8
};

var STATE = { done: false, hits: 0, allowed: 0, patched: null };

function archKey() {
  var a = Process.arch;                     // 'x64' | 'arm64' | 'ia32' | 'arm'
  if (a === 'x64' || a === 'arm64') return a;
  return null;
}

/** 把序言字节串在 [from, to) 里找出来；返回偏移或 -1。 */
function findBytes(block, pattern, from, to) {
  var n = pattern.length;
  for (var i = from; i + n <= to; i++) {
    var ok = true;
    for (var j = 0; j < n; j++) {
      if (block[i + j] !== pattern[j]) { ok = false; break; }
    }
    if (ok) return i;
  }
  return -1;
}

/**
 * 取模块里**实际映射为可执行**的区间。
 *
 * 不能直接 `Memory.scanSync(mod.base, mod.size, ...)`：模块的 size 是"从 base 到最后一个
 * 段结束"的跨度，中间夹着未映射的空洞（实测 libflutter.so 12.7MB 的跨度里在
 * 0x7639a640c000 处就没有页），scanSync 会在那里抛 access violation，然后**整次扫描
 * 归零**——表现出来就是 FLUTTER_SCAN_MISS，看起来像"没有这个函数"。
 */
function execRanges(mod) {
  var out = [];
  var lo = mod.base;
  var hi = mod.base.add(mod.size);
  var ranges = [];
  try { ranges = Process.enumerateRanges('r-x'); } catch (e) { return out; }
  for (var i = 0; i < ranges.length; i++) {
    var r = ranges[i];
    if (r.base.compare(lo) >= 0 && r.base.compare(hi) < 0) {
      out.push(r);
    }
  }
  return out;
}

function scan(mod, key) {
  var anchorHex = CFG.anchors[key];
  var proHex = CFG.prologues[key];
  var pro = [];
  proHex.split(' ').forEach(function (h) { pro.push(parseInt(h, 16)); });
  var found = [];
  var ranges = execRanges(mod);
  for (var k = 0; k < ranges.length; k++) {
    var r = ranges[k];
    var results = [];
    try {
      results = Memory.scanSync(r.base, r.size, anchorHex.replace(/ /g, ''));
    } catch (e) {
      // 单个区间失败不能拖垮整次扫描：记下来继续扫下一段。
      vlog('ERROR', { where: 'Memory.scanSync range', base: r.base.toString(),
                      size: r.size, msg: String(e) });
      continue;
    }
    for (var i = 0; i < results.length; i++) {
      var anchorAddr = results[i].address;
      var off = anchorAddr.sub(mod.base).toInt32();
      var lo = Math.max(0, off - CFG.maxLookback);
      var win = null;
      try { win = new Uint8Array(mod.base.add(lo).readByteArray(off - lo)); } catch (e) { continue; }
      var p = findBytes(win, pro, 0, win.length);
      while (p >= 0) {
        var startOff = lo + p;
        var gap = off - (startOff + pro.length);
        if (gap >= 0 && gap <= CFG.maxGap) {
          found.push({ start: mod.base.add(startOff), anchor: anchorAddr, gap: gap });
          break;
        }
        p = findBytes(win, pro, p + 1, win.length);
      }
    }
  }
  return found;
}

function patch(mod, hit) {
  try {
    Interceptor.attach(hit.start, {
      onEnter: function () { this.t = Date.now(); },
      onLeave: function (retval) {
        // 返回值是 bool：直接改成 1（true）。**不 replace 整个函数**——
        // replace 会丢掉函数体里其它副作用（如写 out_alert），而这里只需要"校验通过"。
        var was = retval.toInt32();      // 先取值再改，否则日志里的 was 永远是 1
        retval.replace(1);
        STATE.allowed++;
        if (STATE.allowed <= CFG.maxLog) {
          vlog('FLUTTER_VERIFY_ALLOWED', {
            n: STATE.allowed,
            module: mod.name,
            offset: hit.start.sub(mod.base).toString(),
            was: was
          });
        }
      }
    });
    STATE.patched = hit.start.sub(mod.base).toString();
    vlog('FLUTTER_VERIFY_PATCHED', {
      module: mod.name,
      base: mod.base.toString(),
      offset: STATE.patched,
      anchor_offset: hit.anchor.sub(mod.base).toString(),
      gap: hit.gap,
      note: '已把 ssl_crypto_x509_session_verify_cert_chain 的返回值强制为 true。' +
            '注意：这只绕过证书校验；Dart 不读系统代理，要拿明文还需把 443 引到 mitmproxy。'
    });
    return true;
  } catch (e) {
    vlog('ERROR', { where: 'Interceptor.attach(flutter)', msg: String(e) });
    return false;
  }
}

export function main() {
  if (STATE.done) return;
  var key = archKey();
  if (key === null) {
    vlog('FLUTTER_UNSUPPORTED_ARCH', { arch: Process.arch });
    STATE.done = true;
    return;
  }
  var mod = null;
  try { mod = Process.findModuleByName(CFG.module); } catch (e) { mod = null; }
  if (mod === null) {
    // 绝大多数 App 没有这个库——静默返回，别把日志刷满。
    STATE.done = true;
    return;
  }
  var hits = scan(mod, key);
  if (hits.length === 0) {
    vlog('FLUTTER_SCAN_MISS', {
      module: mod.name, arch: Process.arch, base: mod.base.toString(), size: mod.size,
      note: '锚点没命中。可能是加固/改名/非常规构建——这只说明本模块定位失败，' +
            '不等于该 App 没有证书校验。'
    });
    STATE.done = true;
    return;
  }
  patch(mod, hits[0]);
  STATE.done = true;
  // 库可能晚加载：2s 轮询兜底，直到 patch 成功或满 15 轮。
  var rounds = 0;
  var timer = setInterval(function () {
    rounds++;
    if (STATE.patched !== null || rounds >= 15) { clearInterval(timer); return; }
    var m = null;
    try { m = Process.findModuleByName(CFG.module); } catch (e) { m = null; }
    if (m === null) return;
    var h = scan(m, key);
    if (h.length) patch(m, h[0]);
  }, 2000);
}
