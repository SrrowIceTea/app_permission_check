// 仅用于授权测试。 Pinned YAABSA 1.16.0; yc.d.S()J verified in this APK's DEX.
import {packages} from './scope.js';
import {makeLogger, procName} from './vscan_runtime.js';
const PKG = 'de.vito0912.yaabsa';
const log = makeLogger('abs_progress', '/data/local/tmp/vscan-abs-progress.log');
Java.perform(() => {
  try {
    if (procName() !== PKG || !packages().includes(PKG)) return;
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {pkg: PKG, uid, user_id: Math.floor(uid / 100000)};
    const position = Java.use('yc.d').S.overload();
    let previous = null;
    let stamp = 0;
    position.implementation = function() {
      const result = position.call(this);
      try {
        const value = Number(result);
        const now = Date.now();
        if (Number.isSafeInteger(value) && value >= 0 && value <= 86400000
            && (previous === null || now - stamp >= 250)) {
          log('ABS_POSITION', {...identity, position_ms: value, api: 'yc.d.S()J'});
          previous = value;
          stamp = now;
        }
      } catch (_) { log('ERROR', {...identity, where: 'position_observation'}); }
      return result;
    };
    log('ARMED', {...identity, api: 'yc.d.S()J', semantics: 'just_audio current position milliseconds'});
  } catch (_) { log('ERROR', {pkg: PKG, where: 'position_arm'}); }
});
