// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。
// V-Scanner Mobile — values.js：按数据类别格式化返回值。
//
// hook_privacy.js 在每条 API 调用完成后调 describe(dataTypes, spec, ret)
// 拿到要附加到 PRIVACY_READ 事件上的字段（值哈希、预览、计数等）。
//
// 三种 capture 模式（与 observation_spec_json 一致）：
//   count_only          → { count: N }              （列表/集合类 API）
//   return_or_exception → { value_hash, value_preview, non_empty } （标量 API）
//   args_only           → { collection_state: 'call_only' }                        （只记调用行为，不记返回值）
//
// 值哈希：SHA-256 前 16 hex。下游 correlate_mobile.py 用它与流量令牌比对，
// 是"值级匹配"的证据基础。不落原文：报告与 LLM 不该再拿到一份个人信息副本。
// ============================================================================
'use strict';

// Preserve upstream ARMED-phase caches: event handlers never call Java.use.
var FORCE_ARGS_ONLY = parseInt("__VSCAN_ARGS_ONLY__", 10) === 1;

// 2026-10-19：值哈希改为**纯 JS**，事件期不再 `Java.use(...)`、不再分配 Java 对象。
// 动机是"减少 trampoline 里的额外风险"，**不是**已证实的解药——实机对照：
// `--args-only`（完全绕开本文件）1 活 1 死，纯 JS 版（A1 型崩溃）也是 1 死 1 活，
// 每组 n=2，统计上什么也证明不了。根因在 ART JIT 编译线程与 ArtMethod 克隆的竞态，
// 与这里是否调 Java 无关（见 mobile/A1_RESIDUAL_20261019.md §2、§3.5）。
// 原实现每次命中要 `MessageDigest.getInstance` + `new java.lang.String(bytes)` +
// `getBytes` + update/digest。现在只剩：
//   - `String(ret)`：bridge 读 jstring（return_or_exception 路径才会走到）；
//   - `ret.length/size()/getCount()`：count_only 路径对 Java 集合取计数，仍要过一次 bridge。
// 哈希语义不变：UTF-8 字节的 SHA-256 前 16 hex（良构字符串与旧实现逐字节可比；
// 孤立代理项这类畸形串，JS 走 WTF-8，Java getBytes 会替换成 '?'，两者不同）。
var K256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

function utf8Bytes (s) {
  var out = [];
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x80) {
      out.push(c);
    } else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    } else if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      var c2 = s.charCodeAt(i + 1);
      if (c2 >= 0xdc00 && c2 <= 0xdfff) {
        var cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
        out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
                 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
        i++;
      } else {
        out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
      }
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    }
  }
  return out;
}

function sha256hex16 (s) {
  try {
    var bytes = utf8Bytes(String(s));
    var l = bytes.length;
    var hi = Math.floor(l / 536870912);            // (l*8) 的高 32 位
    var lo = (l * 8) >>> 0;
    var msg = bytes.slice();
    msg.push(0x80);
    while (msg.length % 64 !== 56) msg.push(0);
    msg.push((hi >>> 24) & 255, (hi >>> 16) & 255, (hi >>> 8) & 255, hi & 255,
             (lo >>> 24) & 255, (lo >>> 16) & 255, (lo >>> 8) & 255, lo & 255);
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64);
    for (var off = 0; off < msg.length; off += 64) {
      for (var i = 0; i < 16; i++) {
        w[i] = ((msg[off + i * 4] << 24) | (msg[off + i * 4 + 1] << 16) |
                (msg[off + i * 4 + 2] << 8) | msg[off + i * 4 + 3]) >>> 0;
      }
      for (var j = 16; j < 64; j++) {
        var s0 = ((w[j - 15] >>> 7) | (w[j - 15] << 25)) ^
                 ((w[j - 15] >>> 18) | (w[j - 15] << 14)) ^ (w[j - 15] >>> 3);
        var s1 = ((w[j - 2] >>> 17) | (w[j - 2] << 15)) ^
                 ((w[j - 2] >>> 19) | (w[j - 2] << 13)) ^ (w[j - 2] >>> 10);
        w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3],
          e = H[4], f = H[5], g = H[6], h = H[7];
      for (var k = 0; k < 64; k++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^
                 ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K256[k] + w[k]) >>> 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^
                 ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    var hex = '';
    for (var n = 0; n < 8; n++) hex += ('00000000' + H[n].toString(16)).slice(-8);
    return hex.slice(0, 16);
  } catch (e) {
    return null;
  }
}

// 兼容旧调用点：不再解析任何 Java 类，值哈希就绪是纯 JS 的事。
export function armValueCache () {
  return true;
}

export function argsOnly () {
  return FORCE_ARGS_ONLY;
}

function safeStringify(v, maxLen) {
  if (v === null || v === undefined) return null;
  var s;
  try { s = String(v); } catch (e) { return null; }
  if (!maxLen) maxLen = 200;
  return s.length <= maxLen ? s : s.slice(0, maxLen) + '…';
}

function resultCount(ret) {
  var readers = [function () { return ret.length; },
                 function () { return ret.size(); },
                 function () { return ret.getCount(); }];
  for (var i = 0; i < readers.length; i++) {
    try {
      var raw = readers[i]();
      if (raw === null || raw === undefined) continue;
      var n = Number(raw);
      if (Number.isFinite(n) && n >= 0 && Number.isInteger(n)) return n;
    } catch (e) {}  // 不能把不支持/失败的计数读成空列表
  }
  return null;
}

export function describe(dataTypes, spec, ret) {
  var capture = (spec && spec.capture) || 'return_or_exception';
  // Diagnostic args-only still records a call, never claims data collection.
  if (FORCE_ARGS_ONLY || capture === 'args_only') return { collection_state: 'call_only' };
  if (ret === null || ret === undefined) {
    return { collection_state: 'empty', non_empty: false, value_kind: 'null' };
  }
  if (capture === 'count_only') {
    var count = resultCount(ret);
    return { count: count, value_count: count,
             collection_state: count === null ? 'unknown' : count > 0 ? 'obtained' : 'empty',
             non_empty: count === null ? null : count > 0 };
  }
  var s;
  try { s = String(ret); }
  catch (e) { return { collection_state: 'unknown' }; }
  var nonEmpty = s.length > 0;
  var out = { non_empty: nonEmpty, value_len: s.length,
              collection_state: nonEmpty ? 'obtained' : 'empty' };
  if (nonEmpty) {
    out.value_preview = safeStringify(s, 6);  // 展示截断不改变值哈希输入
    out.value_hash = sha256hex16(s);
  }
  return out;
}
