// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。观察模式：不改写返回值、不阻断调用。
//
// V-Scanner Mobile — hook_privacy.js：敏感数据读取观测。
//
// 监视表来自 targets.generated.js，而它由 rules_mobile.db 生成——
// **API 清单只有一个真源（规则库）**；规则库改了重新生成即可，钩子不手抄。
// 纯判断逻辑在 dispatch.js（可离线测试），本文件只做 Frida 装配与事件拼装。
//
// 与 vehicle/hooks/hook_vhal.js 的差异：移动侧直接 attach 应用进程，
// 不需要 system_server 模式与 Binder.getCallingUid 归因；其余契约一致。
// ============================================================================
'use strict';

import { packages } from './scope.js';
import { makeLogger, procName, threadName, stackStr, armRuntimeCache } from './runtime.js';
import { WATCH, DATA_TYPES, META } from './targets.generated.js';
import { describe, armValueCache, argsOnly } from './values.js';
import { matchBySpec, describeException, discriminator, unmappedKey, preview } from './dispatch.js';

var vlog = makeLogger('privacy', '/data/local/tmp/vscan-mobile.log');
var CFG = { whitelist: packages() };
// 分档定位（批次 4 · A1 假设 H2，见 DEV_FIX_REPORT §5.1）：宿主在注入前把字面量替换为
// 档位数字（`VSCAN_WATCH_LIMIT=8` → run.py → bundle_config.configure）。未替换时
// parseInt 得到 NaN → 全量挂载，保持旧行为；0 = 一条也不挂（attach 对照组）。
var RAW_WATCH_LIMIT = "__VSCAN_WATCH_LIMIT__";
var STATE = { pkg: null, uid: -1, failed: [] };
var ARMED = [];
var unmappedSeen = {};
var SENS_RANK = { personal: 0, sensitive_personal: 1, children: 2 };

function noteUnmapped(entry, args) {
  try {
    var spec = entry.spec || {};
    if (!spec.kind || spec.kind === 'direct') return;
    var key = unmappedKey(entry, spec, args);
    if (!key || unmappedSeen[key]) return;
    unmappedSeen[key] = true;
    vlog('UNMAPPED_ARG', { api: entry.cls + '.' + entry.method,
                           arg_preview: preview(args[spec.arg_index], 60),
                           spec_kind: spec.kind,
                           note: '判别值不匹配任何已知映射；本条不计入任何数据类别。' });
  } catch (e) {}
}

function maxSensitivity(dts) {
  var best = null;
  for (var i = 0; i < dts.length; i++) {
    var s = DATA_TYPES[dts[i]] && DATA_TYPES[dts[i]].sensitivity;
    if (s && (best === null || SENS_RANK[s] > SENS_RANK[best])) best = s;
  }
  return best;
}

function buildExtra(entry, dts, args, ret, outcome, err) {
  var extra = {
    api: entry.cls + '.' + entry.method + entry.desc,
    api_role: entry.role,
    data_types: dts,
    data_types_zh: dts.map(function (d) { return (DATA_TYPES[d] && DATA_TYPES[d].name_zh) || d; }),
    max_sensitivity: maxSensitivity(dts),
    outcome: outcome,
    arg_disc: discriminator(entry.spec || {}, args),
    thread_name: threadName(),
    stack: stackStr(),
    rules_sha256: META.rules_sha256,
  };
  if (outcome === 'ok') {
    var desc = describe(dts, entry.spec || {}, ret);
    for (var k in desc) if (Object.prototype.hasOwnProperty.call(desc, k)) extra[k] = desc[k];
  } else if (err) {
    extra.exc_class = err.class_name;
    extra.exc_wrapper_class = err.wrapper_class;
    extra.exc_class_source = err.class_source;
    extra.exc_msg = preview(err.message, 200);
    extra.exc_msg_truncated = err.message.length > 200;
  }
  return extra;
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
      var dts = matchBySpec(entry.spec, args, entry.dataType);
      if (dts.length === 0) { noteUnmapped(entry, args); return ov.apply(this, args); }
      var ret = null, err = null, errInfo = null, outcome = 'ok';
      try { ret = ov.apply(this, args); }
      catch (e) {
        err = e;
        errInfo = describeException(e);
        outcome = errInfo.denied ? 'denied' : 'error';
      }
      try { vlog('PRIVACY_READ', buildExtra(entry, dts, args, ret, outcome, errInfo)); }
      catch (e2) {}
      if (err) throw err;
      return ret;
    };
    ARMED.push(entry.cls + '.' + entry.method + entry.desc);
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
    // A1：事件期不再 Java.use——缓存与分档都在 ARMED 阶段一次定妥。
    var cacheOk = armRuntimeCache();
    var valueCacheOk = armValueCache();
    var limit = parseInt(RAW_WATCH_LIMIT, 10);
    if (!isFinite(limit) || limit < 0 || limit > WATCH.length) limit = WATCH.length;
    vlog('START', { script: 'hook_privacy', pkg: STATE.pkg, uid: STATE.uid,
                    whitelist: CFG.whitelist, watch_apis: WATCH.length,
                    watch_limit_raw: RAW_WATCH_LIMIT, watch_limit: limit,
                    runtime_cache: cacheOk, value_cache: valueCacheOk,
                    args_only: argsOnly(),
                    data_types: Object.keys(DATA_TYPES).length,
                    rules_sha256: META.rules_sha256, frida: Frida.version });
    if (CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg, whitelist: CFG.whitelist,
                           note: '不在白名单：不挂任何钩子。' });
      return;
    }
    for (var i = 0; i < limit; i++) armOne(WATCH[i]);
    vlog('ARMED', { hooks: ARMED.length, failed: STATE.failed.length,
                    watch_limit: limit,
                    failed_apis: STATE.failed, apis: ARMED });
    console.log('[privacy] armed ' + ARMED.length + '/' + limit +
                ' apis; failed=' + STATE.failed.length);
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String((e && e.stack) || e) });
  }
}

Java.perform(main);
