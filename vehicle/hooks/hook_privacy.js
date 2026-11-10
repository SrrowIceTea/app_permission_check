// 仅用于授权测试。Observe ordinary Android sources without modifying calls/results.
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { withStack } from './stack_capture.js';
import { describe } from '../../core/privacy/values.js';
import { locationEvidence } from './privacy_location.js';
import { describeException } from '../../core/privacy/dispatch.js';
import { contactTracker } from './privacy_contacts.js';
import { WATCH, META } from './privacy_targets.generated.js';
import { REGISTER, armRegistration } from './privacy_registration.js';

const log = makeLogger('privacy', '/data/local/tmp/vscan-vehicle-privacy.log');
const AD_ID = 'com.google.android.gms.permission.AD_ID';
const ZERO_ID = '00000000-0000-0000-0000-000000000000';
const GMS_UNAVAILABLE = [
  'com.google.android.gms.common.GooglePlayServicesNotAvailableException',
  'com.google.android.gms.common.GooglePlayServicesRepairableException'
];

export function matches(entry, args) {
  if (entry.data_type === 'android_id') return String(args[1]) === 'android_id';
  if (entry.data_type === 'contacts') return /^content:\/\/com\.android\.contacts(?:\/|$)/i.test(String(args[0]));
  return true;
}

export function returned(entry, ret) {
  if (entry.capture === 'aaid') {
    const id = ret === null || ret === undefined ? '' : String(ret);
    if (id === ZERO_ID) {
      const app = Java.use('android.app.ActivityThread').currentApplication();
      if (!app) return {collection_state: 'unknown', aaid_reason: 'application_context_missing'};
      if (Number(app.getApplicationInfo().targetSdkVersion.value) >= 33 && app.checkSelfPermission(AD_ID) !== 0)
        return {collection_state: 'denied', aaid_reason: 'ad_id_permission_missing_zero_return'};
      return {collection_state: 'empty', non_empty: false, aaid_reason: 'zero_id'};
    }
    if (!id) return {collection_state: 'empty', non_empty: false, aaid_reason: 'empty_id'};
    return {collection_state: 'obtained', non_empty: true, value_len: id.length};
  }
  if (entry.capture === 'call_only' || entry.capture === 'cursor') return {collection_state: 'call_only'};
  if (entry.capture === 'audio_count') {
    const count = Number(ret);
    return {collection_state: count > 0 ? 'obtained' : count === 0 ? 'empty' : 'error',
      non_empty: count > 0, count: Math.max(0, count), audio_result_code: count,
      value_capture_gap: 'audio samples intentionally not retained; no audio egress value matching'};
  }
  if (entry.capture === 'location') {
    // 规范形态在 privacy_location.js：只读已返回 Location 的字段，含 value_len。
    return locationEvidence(ret);
  }
  return describe([entry.data_type], {}, ret);
}

function gmsAvailabilityGap(context) {
  try {
    const app = context.getPackageManager().getApplicationInfo('com.google.android.gms', 0);
    return app.enabled.value ? null : 'gms_disabled_for_caller';
  } catch (error) {
    const info = describeException(error);
    const name = 'android.content.pm.PackageManager$NameNotFoundException';
    if (info.class_name === name ||
        (info.class_name === 'Error' && (info.message === name || info.message.startsWith(name + ':'))))
      return 'gms_not_visible_to_caller';
    return null;
  }
}

function callOutcome(entry, info, values, args) {
  if (info) {
    if (info.denied) return 'denied';
    if (entry.data_type === 'advertising_id') {
      const unavailable = GMS_UNAVAILABLE.find(name => info.class_name === name ||
        (info.class_name === 'Error' && (info.message === name || info.message.startsWith(name + ':'))));
      if (unavailable) {
        info.class_name = unavailable;
        return 'unavailable';
      }
      // play-services-ads-identifier 18.2.0 also uses this exact message after
      // its GMS availability check. Other IOException messages stay errors.
      if ((info.class_name === 'java.io.IOException' && info.message === 'Google Play services not available') ||
          (info.class_name === 'Error' && info.message === 'java.io.IOException: Google Play services not available')) {
        info.class_name = 'java.io.IOException';
        values.aaid_reason = 'gms_sdk_reported_unavailable';
        return 'unavailable';
      }
      const io = info.class_name === 'java.io.IOException' || (info.class_name === 'Error' &&
        (info.message === 'java.io.IOException' || info.message.startsWith('java.io.IOException:')));
      if (io && entry.method === 'getAdvertisingIdInfo' && args[0]) {
        const gap = gmsAvailabilityGap(args[0]);
        if (gap) {
          info.class_name = 'java.io.IOException';
          values.aaid_reason = gap;
          return 'unavailable';
        }
      }
    }
    return 'error';
  }
  return ['denied', 'error'].includes(values.collection_state) ? values.collection_state : 'ok';
}

function main() {
  try {
    const pkg = procName(), allowed = packages();
    if (!allowed.includes(pkg)) { log('NOT_TARGET', {pkg}); return; }
    const uid = Number(Java.use('android.os.Process').myUid());
    const sdk = Number(Java.use('android.os.Build$VERSION').SDK_INT.value);
    if (!META.api_levels.includes(sdk)) {
      log('ERROR', {where: 'platform', pkg, sdk, message: 'general-source API level outside contract'}); return;
    }
    const gap = (where, message) => log('PRIVACY_GAP', {pkg, uid, user_id: Math.floor(uid / 100000), where, message});
    const emit = (entry, ret, outcome, error, values) => {
      const extra = {pkg, uid, user_id: Math.floor(uid / 100000),
        data_types: [entry.data_type], api: entry.api || entry.cls + '.' + entry.method + entry.desc,
        outcome, privacy_catalog_sha256: META.sha256, ...values};
      if (error) extra.exc_class = error.class_name;
      log('PRIVACY_READ', withStack(extra, pkg, 8, 48));
    };
    const track = contactTracker(emit, gap);
    const armed = [], failed = [];
    for (const entry of WATCH) {
      try {
        const cls = Java.use(entry.cls), holder = cls[entry.method];
        const method = holder.overload(...entry.types);
        method.implementation = function () {
          const args = Array.from(arguments);
          let selected = false;
          try { selected = matches(entry, args); } catch (e) { gap('argument_classification', String(e)); }
          if (!selected) return method.apply(this, args);
          let ret, error;
          try { ret = method.apply(this, args); } catch (e) { error = e; }
          try {
            const info = error ? describeException(error) : null;
            if (!error && entry.capture === 'cursor') track(ret);
            const values = error ? {} : returned(entry, ret);
            emit(entry, ret, callOutcome(entry, info, values, args), info, values);
          } catch (e) { log('ERROR', {where: 'privacy_observation', pkg, message: String(e)}); }
          if (error) throw error;
          return ret;
        };
        armed.push(entry.cls + '.' + entry.method + entry.desc);
      } catch (e) {
        failed.push(entry.cls + '.' + entry.method + entry.desc);
        gap('api_unavailable', failed[failed.length - 1] + ': ' + String(e));
      }
    }
    log('ARMED', {pkg, uid, user_id: Math.floor(uid / 100000), sdk,
      privacy_catalog_sha256: META.sha256, hooks: armed.length, apis: armed, failed_apis: failed});
    if (!armed.length) log('ERROR', {where: 'privacy_arm', pkg, message: 'No general-source hooks installed'});
    // 注册/异步接口单独记：只说明"调用过"，永远不升级为读取。
    const emitRegister = (entry, outcome, error) => {
      const extra = {pkg, uid, user_id: Math.floor(uid / 100000), data_types: [entry.data_type],
        api: entry.cls + '.' + entry.method + entry.desc, outcome,
        collection_state: 'call_only', registration_kind: entry.registration_kind,
        value_capture_gap: 'registration_or_async_no_return_value',
        privacy_catalog_sha256: META.sha256};
      if (error) extra.exc_class = error.class_name;
      log('PRIVACY_REGISTER', withStack(extra, pkg, 8, 48));
    };
    const reg = armRegistration(REGISTER, emitRegister, gap);
    log('ARMED', {pkg, uid, user_id: Math.floor(uid / 100000), sdk,
      kind: 'registration', hooks: reg.armed.length, apis: reg.armed, failed_apis: reg.failed});
  } catch (e) { log('ERROR', {where: 'privacy_main', message: String(e)}); }
}

Java.perform(main);
