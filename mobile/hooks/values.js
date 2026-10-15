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
var MD_CLS = null, STRING_CLS = null;
var FORCE_ARGS_ONLY = parseInt("__VSCAN_ARGS_ONLY__", 10) === 1;

export function armValueCache() {
  try {
    MD_CLS = Java.use('java.security.MessageDigest');
    STRING_CLS = Java.use('java.lang.String');
    return MD_CLS !== null && STRING_CLS !== null;
  } catch (e) { MD_CLS = null; STRING_CLS = null; return false; }
}

export function argsOnly() {
  return FORCE_ARGS_ONLY;
}

function sha256hex16(s) {
  if (MD_CLS === null || STRING_CLS === null) return null;
  try {
    var md = MD_CLS.getInstance('SHA-256');
    var bytes = STRING_CLS.$new(s).getBytes('UTF-8');
    md.update(bytes);
    var digest = md.digest();
    var hex = '';
    for (var i = 0; i < digest.length; i++) {
      var b = (digest[i] & 0xff);
      hex += ('0' + b.toString(16)).slice(-2);
    }
    return hex.slice(0, 16);
  } catch (e) { return null; }
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
