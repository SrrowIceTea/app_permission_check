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
import { makeLogger, procName, threadName, stackStr, armRuntimeCache,
         deoptimizeBeforeArm } from './runtime.js';
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
// 幂等：同一个 cls.method.desc 只能成功挂一次。重复 Java.use + implementation 会让
// 事件翻倍（甚至递归），所以用显式集合去重，不靠"应该不会重复"。
var ARMED_KEYS = {};
var FAILED_KEYS = {};    // TARGET_ABSENT 只记一次，但每轮仍继续重试
var MIGRATED_KEYS = {};  // native 已接管：永久跳过，不计入 pending
// 类晚加载兜底（与 hook_privacy_native.js 的 RESCAN_STOPPED 对齐）：
// 初始 Java.use 失败的类每 2s 重试，最多 30 轮；到点必须收尾，不把开销堆在采样窗口。
var RESCAN = { intervalMs: 2000, maxRounds: 30 };
var RESCAN_TIMER = null;
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

// 导出给 hook_privacy_native.js 复用：native 迁移点的事件与 Java 层同格式同字段，
// 只多 hook='native'/symbol/module/nat_* 附加字段（见该文件头注释）。
export function buildExtra(entry, dts, args, ret, outcome, err) {
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

// ----------------------------------------------------------------------------
// i2 Native 迁移（2026-10-21）：下列高频 API 已迁到 hook_privacy_native.js
// （Interceptor.attach 挂 JNI/native 实现，**不替换 ArtMethod**——A1 崩点随替换面
// 收窄）。armed 标记由 native 模块先装配时写入 globalThis.__vscanNat；
// 标记存在 → 本层跳过并把证据写成 SKIPPED_JAVA。符号未命中（未导出/被剥）时
// 标记不存在 → 自动回退 Java 层接管，覆盖率不丢（NATIVE_SYMBOL_MISS 留痕）。
// 键名与 hook_privacy_native.js 的 TARGETS[].key 一一对应。
// ----------------------------------------------------------------------------
var NATIVE_KEY_BY_API = {
  'android.hardware.SensorManager.registerListener': 'sensor_registerListener',
  'android.hardware.Camera.open': 'camera_open',
  'android.media.AudioRecord.startRecording': 'audiorecord_start'
  // java.net.NetworkInterface.getHardwareAddress 不在此列：API 37 实测纯 Java
  // 实现（无 JNI），留在 Java 层。
};

function keyOf(entry) {
  return entry.cls + '.' + entry.method + entry.desc;
}

function markFailed(entry) {
  var key = keyOf(entry);
  if (FAILED_KEYS[key]) return false;
  FAILED_KEYS[key] = true;
  STATE.failed.push(entry.cls + '.' + entry.method);
  return true;
}

function armOne(entry) {
  var key = keyOf(entry);
  if (ARMED_KEYS[key]) return 'already';
  var migrate = NATIVE_KEY_BY_API[entry.cls + '.' + entry.method];
  var natArmed = globalThis.__vscanNat || {};
  if (migrate && natArmed[migrate]) {
    MIGRATED_KEYS[key] = true;
    vlog('SKIPPED_JAVA', { cls: entry.cls, api: entry.method, desc: entry.desc,
                           migrated_key: migrate,
                           note: '已由 hook_privacy_native 接管（NATIVE_MIGRATED）。' });
    return 'migrated';
  }
  var cls;
  // PackageManager is abstract: hooking its declaration reports ARMED but
  // ApplicationPackageManager overrides bypass it (fixture + LibChecker API 36).
  // Keep the SDK/rules identity in `api`; expose the observed implementation.
  var hookClass = entry.cls === 'android.content.pm.PackageManager'
    ? 'android.app.ApplicationPackageManager' : entry.cls;
  try { cls = Java.use(hookClass); }
  catch (e) {
    // 只记一次（30 轮重试不等于 30 条失败），但每轮仍会重试：类可能稍后才加载。
    if (markFailed(entry)) {
      vlog('TARGET_ABSENT', { cls: entry.cls, api: entry.method,
                              note: '类尚未加载；进入补挂轮询（最多 ' +
                                    RESCAN.maxRounds + ' 轮）。' });
    }
    return 'absent';
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
      try {
        var extra = buildExtra(entry, dts, args, ret, outcome, errInfo);
        extra.hook_class = hookClass;
        vlog('PRIVACY_READ', extra);
      }
      catch (e2) {}
      if (err) throw err;
      return ret;
    };
    ARMED.push(key);
    ARMED_KEYS[key] = true;
    return 'armed';
  } catch (e) {
    if (markFailed(entry)) {
      vlog('ARM_FAIL', { cls: entry.cls, api: entry.method, desc: entry.desc,
                         types: entry.types, msg: String(e).slice(0, 300) });
    }
    return 'failed';
  }
}

// ----------------------------------------------------------------------------
// 类晚加载兜底（与 hook_privacy_native.js 的 RESCAN_STOPPED 同构）。
// 初始 Java.use 失败的类不会自己出现——SDK 懒加载、插件化、ClassLoader 延迟
// 解析都属这类。每 RESCAN.intervalMs 重试一轮，最多 RESCAN.maxRounds 轮。
// 幂等由 ARMED_KEYS 保证（已在 armOne 入口返回 'already'，不会重复 implementation）；
// 每轮都落 JAVA_RESCAN_ROUND——**0 个补挂也记**，否则事后无法区分
// "这个类一直没加载" 与 "补挂根本没跑"。
// ----------------------------------------------------------------------------
function pendingEntries(limit) {
  var out = [];
  for (var i = 0; i < limit; i++) {
    var key = keyOf(WATCH[i]);
    if (ARMED_KEYS[key] || MIGRATED_KEYS[key]) continue;
    out.push(WATCH[i]);
  }
  return out;
}

function rescanRound(limit) {
  var pending = pendingEntries(limit);
  var added = [];
  for (var i = 0; i < pending.length; i++) {
    if (armOne(pending[i]) === 'armed') added.push(keyOf(pending[i]));
  }
  // remaining 是本轮**结束后**仍未挂上的数量：用它做终止判据，补上的那轮就能停表，
  // 不必空转一轮。
  return { attempted: pending.length, added: added,
           remaining: pendingEntries(limit).length };
}

function stopRescan(reason, round, limit) {
  if (RESCAN_TIMER !== null) clearInterval(RESCAN_TIMER);
  RESCAN_TIMER = null;
  vlog('JAVA_RESCAN_STOPPED', {
    round: round, reason: reason, hooks: ARMED.length,
    unresolved: pendingEntries(limit).map(function (e) { return keyOf(e); }),
  });
}

function startJavaRescan(limit) {
  var rounds = 0;
  RESCAN_TIMER = setInterval(function () {
    rounds++;
    var r = rescanRound(limit);
    vlog('JAVA_RESCAN_ROUND', { round: rounds, attempted: r.attempted,
                                added: r.added.length, added_keys: r.added,
                                pending: r.remaining, hooks: ARMED.length });
    if (r.remaining === 0) stopRescan('all_armed', rounds, limit);
    else if (rounds >= RESCAN.maxRounds) stopRescan('max_rounds', rounds, limit);
  }, RESCAN.intervalMs);
}

export function main() {
  try {
    STATE.pkg = procName();
    STATE.uid = Java.use('android.os.Process').myUid();
    // A1 尝试（2026-10-16，**未消除**）：替换 ArtMethod 前先把已编译方法退回解释器。
    // 实测无效（deopt 默认 off）；崩点在 JIT 编译线程，不在替换入口。见 A1_RESIDUAL_20261019.md。
    var deopt = deoptimizeBeforeArm();
    // A1：事件期不再 Java.use——缓存与分档都在 ARMED 阶段一次定妥。
    var cacheOk = armRuntimeCache();
    var valueCacheOk = armValueCache();
    var limit = parseInt(RAW_WATCH_LIMIT, 10);
    if (!isFinite(limit) || limit < 0 || limit > WATCH.length) limit = WATCH.length;
    vlog('START', { script: 'hook_privacy', pkg: STATE.pkg, uid: STATE.uid,
                    whitelist: CFG.whitelist, watch_apis: WATCH.length,
                    watch_limit_raw: RAW_WATCH_LIMIT, watch_limit: limit,
                    runtime_cache: cacheOk, value_cache: valueCacheOk,
                    deoptimize: deopt,
                    args_only: argsOnly(),
                    data_types: Object.keys(DATA_TYPES).length,
                    rules_sha256: META.rules_sha256, frida: Frida.version });
    if (CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg, whitelist: CFG.whitelist,
                           note: '不在白名单：不挂任何钩子。' });
      return;
    }
    var absent = 0;
    for (var i = 0; i < limit; i++) {
      var how = armOne(WATCH[i]);
      if (how === 'absent' || how === 'failed') absent++;
    }
    vlog('ARMED', { hooks: ARMED.length, failed: STATE.failed.length,
                    watch_limit: limit, pending: absent,
                    failed_apis: STATE.failed, apis: ARMED });
    console.log('[privacy] armed ' + ARMED.length + '/' + limit +
                ' apis; failed=' + STATE.failed.length + '; pending=' + absent);
    // 有未挂上的才启动轮询——全部一次挂上时不起定时器，零额外开销。
    if (absent > 0) startJavaRescan(limit);
    else stopRescan('all_armed_at_arm_time', 0, limit);
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String((e && e.stack) || e) });
  }
}

// 独立入口由构建提供（build.mjs 的薄入口先 import 本模块再 Java.perform(main)）：
// 本文件导出 main 而**不**在顶层自执行——这样它既能被独立 bundle 使用，也能被
// hook_all（单 agent 合并入口）与其他模块一起装配。背景：frida-java-bridge 不支持
// "多脚本各自替换"（见 bridge 的 ensureArtKnowsHowToHandleReplacementMethods 注释），
// 多个 run.py（=多个 agent）各自 attach 同一进程时偶发 ART FATAL（2026-10-16 实测，
// 双脚本 ~50% vs 单脚本 5/5）——故 production 统一收敛为单 bundle。
