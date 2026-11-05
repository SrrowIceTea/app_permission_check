// 仅用于授权测试。 This pinned APK renames OkHttp Builder.build.
import { packages } from './scope.js';
import { procName } from './vscan_runtime.js';
import { logEgress } from './hook_egress.js';

const PKG = 'org.owntracks.android';
const HTTP = 'org.owntracks.android.net.http.';
const CLASS = HTTP + 'HttpMessageProcessorEndpoint';

Java.perform(() => {
  try {
    if (procName() !== PKG || !packages().includes(PKG)) return;
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {package: PKG, uid, user_id: Math.floor(uid / 100000)};
    const original = Java.use(CLASS).getRequest.overload(
      HTTP + 'HttpConfiguration', 'org.owntracks.android.model.messages.MessageBase');
    original.implementation = function (configuration, message) {
      const result = original.call(this, configuration, message);
      try {
        const url = String(configuration.getUrl());
        const match = /^http:\/\/(198\.18\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}):18145\/owntracks\/[a-f0-9]{16}$/.exec(url);
        if (match && match[1].split('.').every(x => Number(x) <= 255))
          logEgress('EGRESS_URL', {...identity, outcome: 'candidate',
            target_host: match[1], target_port: 18145, via: CLASS + '.getRequest',
            evidence_role: 'request_target_candidate'});
      } catch (_) {
        logEgress('ERROR', {...identity, where: 'owntracks_request_target'});
      }
      return result;
    };
    logEgress('OWNTRACKS_TARGET_ARMED', identity);
  } catch (error) {
    logEgress('ERROR', {where: 'owntracks_request_arm', message: String(error)});
  }
});
