// 仅用于授权测试。 Observe the received Location without modifying the coroutine.
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { sha256hex16 } from '../../core/privacy/values.js';

const PKG = 'org.owntracks.android';
const CLASS = 'org.owntracks.android.services.LocationProcessor';
const ARGS = ['android.location.Location', 'org.owntracks.android.model.messages.MessageLocation$ReportType',
  'kotlin.coroutines.Continuation'];
const log = makeLogger('owntracks_location', '/data/local/tmp/vscan-owntracks.log');

Java.perform(() => {
  try {
    if (procName() !== PKG || !packages().includes(PKG)) return;
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {pkg: PKG, uid, user_id: Math.floor(uid / 100000)};
    // Verified against the pinned APK's services/LocationProcessor.java decompilation.
    const method = Java.use(CLASS).onLocationChanged.overload(...ARGS);
    method.implementation = function (location, type, continuation) {
      try {
        if (location !== null) {
          const pair = [Number(location.getLatitude()), Number(location.getLongitude())];
          if (pair.every(Number.isFinite) && Math.abs(pair[0]) <= 90 && Math.abs(pair[1]) <= 180)
            log('OWNTRACKS_LOCATION', {...identity, coordinate_sha256_16:
              sha256hex16(JSON.stringify(pair.map(n => Number(n.toFixed(6))))),
              location_time_ms: Number(location.getTime())});
        }
      } catch (error) {
        log('ERROR', {...identity, where: 'owntracks_location_observation', error_type: String(error.name || 'Error')});
      }
      return method.call(this, location, type, continuation);
    };
    log('ARMED', {...identity, api: CLASS + '.onLocationChanged(' + ARGS.join(',') + ')'});
  } catch (error) {
    log('ERROR', {where: 'owntracks_location_arm', message: String(error)});
  }
});
