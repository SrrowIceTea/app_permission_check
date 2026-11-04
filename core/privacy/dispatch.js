// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。
// V-Scanner Mobile — dispatch.js：纯判断逻辑（可离线测试，不依赖 Frida）。
//
// 职责：
//   1) matchBySpec —— 按 observation_spec 分派数据类别（direct / provider_arg /
//      content_uri / string_key_arg）。钩子拿到实参后调它，返回要记的 data_type 列表。
//   2) 同意链辅助 —— looksLikePolicy / shortName / splitGrantResults / toJsArray。
//   3) 调试留痕 —— unmappedKey / discriminator / preview。
//
// 为什么单独拆出来：hook_privacy.js 与 hook_consent.js 的 Frida 装配逻辑各异，
// 但"这条调用属于哪个数据类别""这个 URL 像不像政策页"是纯函数，
// 抽出来可以写单元测试（test_dispatch.js，将来补）而不需要真机。
// ============================================================================
'use strict';

var DENIED_CLASSES = [
  'java.lang.SecurityException',
  'java.lang.PermissionDeniedException',
  'android.permission.PermissionDeniedException'
];

export function isDeniedClassName(name) {
  if (!name) return false;
  for (var i = 0; i < DENIED_CLASSES.length; i++) {
    if (name === DENIED_CLASSES[i] || name.indexOf(DENIED_CLASSES[i] + '$') === 0) return true;
  }
  return false;
}

function exceptionField(err, key) {
  try {
    var value = err && err[key];
    return value === null || value === undefined ? null : String(value);
  } catch (ignored) { return null; }
}

export function describeException(err) {
  // Frida 17 can wrap a thrown Java exception in JS Error, putting the Java class
  // at the *start* of message. Never infer denial from a mention in prose/stack.
  var javaClass = exceptionField(err, '$className');
  var wrapperClass = javaClass || exceptionField(err, 'name');
  var message = exceptionField(err, 'message');
  if (message === null) {
    try { message = String(err); } catch (ignored) { message = ''; }
  }
  var className = wrapperClass || '?';
  var source = javaClass ? 'java_class' : wrapperClass ? 'wrapper_class' : 'unknown';
  // An actual Java class always wins; TypeError and other typed JS errors also
  // cannot be reclassified based on text. Match only exact known denied prefixes.
  if (!javaClass && (!wrapperClass || wrapperClass === 'Error')) {
    for (var i = 0; i < DENIED_CLASSES.length; i++) {
      if (message.indexOf(DENIED_CLASSES[i] + ':') === 0) {
        className = DENIED_CLASSES[i];
        source = 'wrapper_message_prefix';
        break;
      }
    }
  }
  return { class_name: className, wrapper_class: wrapperClass,
           message: message, class_source: source, denied: isDeniedClassName(className) };
}

export function preview(value, maxLen) {
  if (value === null || value === undefined) return null;
  var s;
  try { s = String(value); } catch (e) { return null; }
  if (!maxLen || maxLen <= 0) maxLen = 200;
  return s.length <= maxLen ? s : s.slice(0, maxLen) + '…';
}

export function toJsArray(javaArr) {
  if (!javaArr) return [];
  try {
    var out = [];
    var len = javaArr.length;
    for (var i = 0; i < len; i++) out.push(javaArr[i]);
    return out;
  } catch (e) { return []; }
}

export function shortName(perm) {
  if (!perm) return perm;
  var idx = perm.lastIndexOf('.');
  return idx >= 0 ? perm.slice(idx + 1) : perm;
}

export function splitGrantResults(perms, results) {
  var granted = [], denied = [], other = [];
  for (var i = 0; i < perms.length; i++) {
    var p = perms[i];
    var s = shortName(p);
    var r = i < results.length ? results[i] : -1;
    if (r === 0) granted.push(s);
    else if (r === -1) denied.push(s);
    else other.push({ permission: s, result: r });
  }
  return { granted: granted, denied: denied, other: other };
}

export function looksLikePolicy(url) {
  if (!url) return false;
  var lower = url.toLowerCase();
  var keywords = ['privacy', 'policy', 'yinsi', 'zhengce', 'agreement', 'terms',
                  '隐私', '政策'];
  for (var i = 0; i < keywords.length; i++) {
    if (lower.indexOf(keywords[i]) >= 0) return true;
  }
  return false;
}

function javaStringToJs(v) {
  if (v === null || v === undefined) return null;
  try { return String(v); } catch (e) { return null; }
}

function matchDirect(spec, args, defaultDataType) {
  if (!defaultDataType) return [];
  return [defaultDataType];
}

function matchProviderArg(spec, args) {
  var idx = spec.arg_index || 0;
  var arg = javaStringToJs(args[idx]);
  if (!arg) return [];
  var lower = arg.toLowerCase();
  var map = spec.map || {};
  for (var key in map) {
    if (Object.prototype.hasOwnProperty.call(map, key) && lower.indexOf(key) >= 0) {
      return [map[key]];
    }
  }
  if (spec.unmapped === 'ignore') return [];
  return [];
}

function matchContentUri(spec, args) {
  var idx = spec.arg_index || 0;
  var uri = javaStringToJs(args[idx]);
  if (!uri) return [];
  var lower = uri.toLowerCase();
  var entries = spec.map || [];
  for (var i = 0; i < entries.length; i++) {
    var prefix = (entries[i].prefix || '').toLowerCase();
    if (prefix && lower.indexOf(prefix) === 0) {
      return [entries[i].data_type];
    }
  }
  if (spec.unmapped === 'ignore') return [];
  return [];
}

function matchStringKeyArg(spec, args) {
  var idx = spec.arg_index || 0;
  var key = javaStringToJs(args[idx]);
  if (!key) return [];
  var entries = spec.map || [];
  for (var i = 0; i < entries.length; i++) {
    if (entries[i].value === key) return [entries[i].data_type];
  }
  if (spec.unmapped === 'ignore') return [];
  return [];
}

export function matchBySpec(spec, args, defaultDataType) {
  if (!spec) return defaultDataType ? [defaultDataType] : [];
  var kind = spec.kind || 'direct';
  if (kind === 'direct') return matchDirect(spec, args, defaultDataType);
  if (kind === 'provider_arg') return matchProviderArg(spec, args);
  if (kind === 'content_uri') return matchContentUri(spec, args);
  if (kind === 'string_key_arg') return matchStringKeyArg(spec, args);
  if (kind === 'consent') return [];
  return defaultDataType ? [defaultDataType] : [];
}

export function discriminator(spec, args) {
  if (!spec || spec.kind === 'direct') return null;
  var idx = spec.arg_index;
  if (idx === undefined || idx === null) return null;
  return preview(args[idx], 200);
}

export function unmappedKey(entry, spec, args) {
  if (!spec) return null;
  var idx = spec.arg_index;
  if (idx === undefined || idx === null) return null;
  var raw = args[idx];
  if (raw === null || raw === undefined) return null;
  var s = String(raw);
  var q = s.indexOf('?');
  if (q >= 0) s = s.slice(0, q);
  var v = preview(s, 80);
  return entry.cls + '.' + entry.method + '|' + (spec.kind || '?') + '|' + String(v);
}
