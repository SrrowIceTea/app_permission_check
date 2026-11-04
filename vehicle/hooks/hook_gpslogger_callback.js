// 仅用于授权测试。 Fixed GPSLogger 138, actual listener inspected in the pinned APK.
import './java_bootstrap.js';
import {packages} from './scope.js';
import {makeLogger, procName} from './vscan_runtime.js';
import {sha256hex16} from '../../core/privacy/values.js';
const PKG = 'com.mendhak.gpslogger';
const log = makeLogger('gpslogger_location', '/data/local/tmp/vscan-gpslogger.log');
Java.perform(() => {
  try {
    if (procName() !== PKG || !packages().includes(PKG)) return;
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {pkg: PKG, uid, user_id: Math.floor(uid / 100000)};
    const callback = Java.use('com.mendhak.gpslogger.GeneralLocationListener')
      .onLocationChanged.overload('android.location.Location');
    callback.implementation = function(location) {
      try {
        if (location === null) log('LOCATION_EMPTY', identity);
        else {
          const values = [Number(location.getLatitude()), Number(location.getLongitude())];
          if (values.every(Number.isFinite) && Math.abs(values[0]) <= 90 && Math.abs(values[1]) <= 180)
            log('GPSLOGGER_LOCATION', {...identity,
              coordinate_sha256_16: sha256hex16(JSON.stringify(values.map(n => Number(n.toFixed(6))))),
              location_time_ms: Number(location.getTime()), provider: String(location.getProvider())});
        }
      } catch (_) { log('ERROR', {...identity, where: 'callback_observation'}); }
      return callback.call(this, location);
    };
    log('ARMED', {...identity, api: 'GeneralLocationListener.onLocationChanged(android.location.Location)'});
  } catch (_) { log('ERROR', {where: 'callback_arm'}); }
});
