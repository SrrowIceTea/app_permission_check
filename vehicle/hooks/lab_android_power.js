// 仅用于授权测试。Observe values already returned to the explicitly allowed app.
import './java_bootstrap.js';
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { withStack } from './stack_capture.js';

const log = makeLogger('lab_power', '/data/local/tmp/vscan-lab-power.log');
Java.perform(() => {
  const pkg = procName();
  if (!packages().includes(pkg)) return;
  try {
    const uid = Number(Java.use('android.os.Process').myUid());
    const fields = new Set(['level', 'scale', 'status', 'plugged']);
    const read = Java.use('android.content.Intent').getIntExtra.overload('java.lang.String', 'int');
    read.implementation = function (key, fallback) {
      const value = read.call(this, key, fallback);
      try {
        if (fields.has(String(key)) && String(this.getAction()) === 'android.intent.action.BATTERY_CHANGED') {
          log('ANDROID_POWER_EXTRA', withStack({pkg, uid, user_id: Math.floor(uid / 100000),
            field: String(key), value, fallback, rule_id: 'VSC-LAB-ANDROID-POWER-001'}, pkg, 6, 36));
        }
      } catch (e) {
        log('ERROR', {pkg, where: 'power_extra_observation', message: String(e)});
      }
      return value;
    };
    log('ARMED', {pkg, uid, api: 'android.content.Intent.getIntExtra(java.lang.String,int)'});
  } catch (e) {
    log('ERROR', {pkg, where: 'power_arm', message: String(e)});
  }
});
