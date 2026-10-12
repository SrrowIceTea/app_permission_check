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
//   args_only           → {}                        （只记调用行为，不记返回值）
//
// 值哈希：SHA-256 前 16 hex。下游 correlate_mobile.py 用它与流量令牌比对，
// 是"值级匹配"的证据基础。不落原文：报告与 LLM 不该再拿到一份个人信息副本。
// ============================================================================
'use strict';

function sha256hex16(s) {
  try {
    var md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
    var bytes = new java.lang.String(s).getBytes('UTF-8');
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

function javaArrayLength(ret) {
  try {
    if (ret === null || ret === undefined) return 0;
    return Number(ret.length) | 0;
  } catch (e) { return 0; }
}

function javaListSize(ret) {
  try {
    if (ret === null || ret === undefined) return 0;
    return Number(ret.size()) | 0;
  } catch (e) { return 0; }
}

function javaCursorCount(ret) {
  try {
    if (ret === null || ret === undefined) return 0;
    return Number(ret.getCount()) | 0;
  } catch (e) { return 0; }
}

export function describe(dataTypes, spec, ret) {
  var capture = (spec && spec.capture) || 'return_or_exception';

  if (capture === 'args_only') return {};

  if (capture === 'count_only') {
    var count = 0;
    if (ret !== null && ret !== undefined) {
      count = javaArrayLength(ret);
      if (count === 0) count = javaListSize(ret);
      if (count === 0) count = javaCursorCount(ret);
    }
    return { count: count };
  }

  var s = safeStringify(ret, 200);
  var nonEmpty = s !== null && s.length > 0;
  var out = { non_empty: nonEmpty };
  if (nonEmpty) {
    out.value_preview = safeStringify(s, 80);
    out.value_hash = sha256hex16(s);
  }
  return out;
}
