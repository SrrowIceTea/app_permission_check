// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。观察模式：不改写、不阻断。
//
// V-Scanner Mobile — hook_consent.js：同意时序观测。
//
// 为什么单独一条链：「同意前就开始收集」是《认定方法》三.1 的第一条，
// 而它**只能由时序证明**——必须先有「用户同意」这个事件，才谈得上「之前」。
// 只记读取不记同意，这一条永远判不出来，且症状是"结论里没有这条"，
// 不是报错（静默失败）。
//
// 记什么：
//   PERM_REQ     应用发起权限请求（系统授权弹窗由此触发）
//   PERM_RESULT  用户在弹窗上的选择——**「同意」的权威时刻**
//   PERM_CHECK   应用自查权限状态（区分"检查后未读"与"未检查直读"）
//   POLICY_VIEW  打开疑似隐私政策页面（认定方法一.2 的线索，不是结论）
//
// 边界（必须保留）：本钩子看不到"用户点了隐私政策弹窗的同意按钮"——那是 UI 动作。
// PERM_RESULT 与 POLICY_VIEW 是**代理信号**，不得当成"已取得同意"的证明。
// ============================================================================
'use strict';

import { packages } from './scope.js';
import { makeLogger, procName, threadName, stackStr } from './runtime.js';
import { CONSENT_WATCH } from './targets.generated.js';
import { looksLikePolicy, preview, toJsArray, shortName, splitGrantResults } from './dispatch.js';

var vlog = makeLogger('consent', '/data/local/tmp/vscan-mobile.log');
var CFG = { whitelist: packages() };
var STATE = { pkg: null, uid: -1, armed: 0, failed: [] };

function base(api, extra) {
  extra.api = api;
  extra.pkg = STATE.pkg;
  extra.uid = STATE.uid;
  extra.thread_name = threadName();
  extra.stack = stackStr();
  return extra;
}

function handle(entry, args) {
  var spec = entry.spec || {};
  var sig = spec.signal;
  var idx = spec.args || {};
  var api = entry.cls + '.' + entry.method + entry.desc;

  if (sig === 'permission_request') {
    var perms = toJsArray(args[idx.permissions]).map(String);
    return { ev: 'PERM_REQ', extra: base(api, {
      permissions: perms, permissions_short: perms.map(shortName),
      request_code: Number(args[idx.request_code]) | 0,
      note: '权限请求发起；这不等于用户同意。' }) };
  }

  if (sig === 'permission_result') {
    var rp = toJsArray(args[idx.permissions]).map(String);
    var rr = toJsArray(args[idx.grant_results]).map(function (x) { return Number(x) | 0; });
    var split = splitGrantResults(rp, rr);
    return { ev: 'PERM_RESULT', extra: base(api, {
      request_code: Number(args[idx.request_code]) | 0,
      permissions: rp, grant_results: rr,
      granted: split.granted, denied: split.denied, other_results: split.other,
      note: split.denied.length > 0 && split.granted.length > 0
        ? '部分授权：granted/denied 必须按权限逐条使用，不得整体当作"已同意"。'
        : (split.granted.length ? '用户同意（本组权限）。' : '用户拒绝。') }) };
  }

  if (sig === 'permission_check') {
    var perm = String(args[idx.permission]);
    return { ev: 'PERM_CHECK', extra: base(api, {
      permission: perm, permission_short: shortName(perm),
      note: '自查权限；返回值由外层包装记为 check_result/check_granted。' }) };
  }

  if (sig === 'policy_view') {
    var url = String(args[idx.url]);
    if (!looksLikePolicy(url)) return null;
    return { ev: 'POLICY_VIEW', extra: base(api, {
      url: preview(url, 300),
      note: '疑似隐私政策页面被打开。这是线索，不是"已告知/已同意"的证明。' }) };
  }
  return null;
}

function armOne(entry) {
  var cls;
  try { cls = Java.use(entry.cls); }
  catch (e) {
    vlog('TARGET_ABSENT', { cls: entry.cls, api: entry.method });
    STATE.failed.push(entry.cls + '.' + entry.method);
    return;
  }
  try {
    var holder = cls[entry.method];
    var ov = holder.overload.apply(holder, entry.types);
    ov.implementation = function () {
      var args = Array.prototype.slice.call(arguments);
      if (CFG.whitelist.indexOf(STATE.pkg) < 0) return ov.apply(this, args);
      var ret = null, err = null;
      try { ret = ov.apply(this, args); }
      catch (e) { err = e; }
      try {
        var h = handle(entry, args);
        if (h) {
          if (h.ev === 'PERM_CHECK') {
            h.extra.check_result = err ? null : (Number(ret) | 0);
            h.extra.check_granted = err ? null : ((Number(ret) | 0) === 0);
          }
          vlog(h.ev, h.extra);
        }
      } catch (e2) {}
      if (err) throw err;
      return ret;
    };
    STATE.armed++;
  } catch (e) {
    vlog('ARM_FAIL', { cls: entry.cls, api: entry.method, desc: entry.desc,
                       types: entry.types, msg: String(e).slice(0, 300) });
    STATE.failed.push(entry.cls + '.' + entry.method);
  }
}

function main() {
  try {
    STATE.pkg = procName();
    STATE.uid = Java.use('android.os.Process').myUid();
    vlog('START', { script: 'hook_consent', pkg: STATE.pkg, uid: STATE.uid,
                   whitelist: CFG.whitelist, consent_apis: CONSENT_WATCH.length,
                   frida: Frida.version,
                   boundary: '权限结果与政策页打开是同意状态的代理信号，不是同意的直接证明。' });
    if (CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg, whitelist: CFG.whitelist });
      return;
    }
    for (var i = 0; i < CONSENT_WATCH.length; i++) armOne(CONSENT_WATCH[i]);
    vlog('ARMED', { hooks: STATE.armed, failed: STATE.failed });
    console.log('[consent] armed ' + STATE.armed + '/' + CONSENT_WATCH.length +
                ' apis; failed=' + STATE.failed.length);
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String((e && e.stack) || e) });
  }
}

Java.perform(main);
