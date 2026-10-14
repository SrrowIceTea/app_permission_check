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

// ---- 事件期缓存（批次 4 · A1 假设 H1，见 DEV_FIX_REPORT §5.1）----
// 假设：崩点在被替换的 ArtMethod 内做 Java.use()。MessageDigest 的 Java.use
// 收敛到 ARMED 阶段解析一次（armValueCache）；缓存缺失时 value_hash 退化为
// null（下游本来就允许 null，见 correlate 对 value_hash 的处理），事件照发。
var MD_CLS = null;

export function armValueCache() {
  try {
    MD_CLS = Java.use('java.security.MessageDigest');
    return MD_CLS !== null;
  } catch (e) { MD_CLS = null; return false; }
}

function sha256hex16(s) {
  if (MD_CLS === null) return null;
  try {
    var md = MD_CLS.getInstance('SHA-256');
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

// ---- H5 开关：整轮强制 args_only（批次 4 · A1 假设 H5，见 DEV_FIX_REPORT §5.1）----
// H5：崩点也许不是"替换 ArtMethod"本身，而是**事件期构造 Java 对象**——
// `new java.lang.String(s)` + `MessageDigest.update/digest`。打开这个开关后
// describe() 一律返回 {}，事件里只剩"这个 API 被调用了"：不 String()、不哈希、
// 不数长度。于是"崩 / 不崩"的差异被隔离到**这一个**变量上。
// 它是 H1（事件期 Java.use）的更严格版本，也是 §8.6 第 1 条的用法示范：
// 诊断期临时降低观测面，**不改判据**——PRIVACY_READ 事件照样必须出现，
// 缺的是值字段，不是"有没有收集"的结论。
//
// **写法注意**：必须走 parseInt 消费——frida-compile 的压缩器会把直接的
// 字面量比较（`"__VSCAN_ARGS_ONLY__" === "1"`）常量折叠成 false，占位符就没了。
var FORCE_ARGS_ONLY = parseInt("__VSCAN_ARGS_ONLY__", 10) === 1;

export function argsOnly() {
  return FORCE_ARGS_ONLY;
}

export function describe(dataTypes, spec, ret) {
  var capture = (spec && spec.capture) || 'return_or_exception';

  if (FORCE_ARGS_ONLY) return {};          // H5：整轮不碰返回值（含 count_only）
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
