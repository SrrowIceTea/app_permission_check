// 仅用于授权测试。只观察回调，不替换 callback，不改变注册或回调返回值。
// 两条注册路径的语义不同，分别计数、不混算：
//   subscribePropertyEvents —— 持续接收某个属性的变化（订阅）
//   registerCallback        —— 把回调对象交给系统，按 rate 接收（回调注册）
// 名称与重载来源：device_calibration/cpm-signatures-device35.json
//   + javap -s platforms/android-36/optional/android.car.jar（双源核对）。
// registerCallback 在 android-36 公开 stub 上只有 1 个重载：
//   registerCallback(CarPropertyEventCallback, int, float) -> boolean
import { propertyValue } from './property_value.js';

const CB_CLASS =
  'android.car.hardware.property.CarPropertyManager$CarPropertyEventCallback';

export function hookSubscriptions(CPM, vlog, watch, callerInfo, stackStr) {
  const armedClasses = new Set();      // 已挂 onChangeEvent 的回调类
  const sourcesByClass = new Map();    // 回调类名 -> 该回调的注册来源集合

  function recordSource(name, source) {
    const set = sourcesByClass.get(name) || new Set();
    set.add(source);
    sourcesByClass.set(name, set);
    return Array.from(set).sort();
  }

  function armCallback(callback, source) {
    // 参数静态类型是接口，Frida 不一定暴露 Object.getClass；先显式向上转型。
    const object = Java.cast(callback, Java.use('java.lang.Object'));
    const name = String(object.getClass().getName());
    const sources = recordSource(name, source);
    if (armedClasses.has(name)) {
      // 同一回调被第二条路径再次注册：只更新来源，不重复挂载。
      vlog('SUBSCRIPTION_CALLBACK_ARMED', { target: name, sources, already_armed: true });
      return;
    }
    const cls = Java.use(name);
    const holder = cls.onChangeEvent;
    for (const original of holder.overloads) {
      if (original.argumentTypes.length !== 1 ||
          original.argumentTypes[0].className !== 'android.car.hardware.CarPropertyValue') continue;
      original.implementation = function (value) {
        try {
          const v = Java.cast(value, Java.use('android.car.hardware.CarPropertyValue'));
          const id = v.getPropertyId();
          if (watch[id]) {
            const caller = callerInfo();
            const registered = sourcesByClass.get(name);
            vlog('VHAL_READ', { ...caller, api: 'subscription.onChangeEvent',
              // 区分「订阅」与「回调注册」：同一回调可能被两条路径注册过。
              registration_source: registered ? Array.from(registered).sort() : ['unknown'],
              callback_target: name,
              user_id: caller.uid >= 0 ? Math.floor(caller.uid / 100000) : null,
              prop_id: id, prop_name: watch[id], area_id: v.getAreaId(),
              outcome: v.getStatus() === 0 && v.getValue() !== null ? 'ok' : 'unavailable',
              value: String(v.getValue()), ...propertyValue(v), stack: stackStr() });
          }
        } catch (e) { vlog('ERROR', { where: 'subscription callback observation', msg: String(e) }); }
        return original.call(this, value);
      };
    }
    armedClasses.add(name);
    vlog('SUBSCRIPTION_CALLBACK_ARMED', { target: name, sources });
  }

  // 挂一个注册方法上的全部重载。返回值与异常语义原样保留（只观测）。
  function hookRegistration(methodName, source, eventName) {
    let holder;
    try {
      holder = CPM[methodName];
      if (!holder) throw new Error('method absent on this API level');
    } catch (e) {
      vlog(eventName + '_ABSENT', { source, method: methodName, msg: String(e) });
      return null;
    }
    let count = 0;
    for (const original of holder.overloads) {
      const index = original.argumentTypes.findIndex(t => t.className === CB_CLASS);
      if (index < 0) continue;
      original.implementation = function () {
        const args = Array.from(arguments);
        try { armCallback(args[index], source); }
        catch (e) {
          vlog('ERROR', { where: 'arm callback via ' + methodName, msg: String(e.stack || e) });
        }
        try {
          const result = original.apply(this, args);
          vlog(eventName, { source, method: methodName, accepted: Boolean(result),
            ...callerInfo() });
          return result;
        } catch (e) {
          vlog(eventName + '_ERROR', { source, method: methodName, msg: String(e),
            ...callerInfo() });
          throw e;
        }
      };
      count += 1;
    }
    if (!count) vlog(eventName + '_ABSENT', { source, method: methodName,
      msg: 'no overload with CarPropertyEventCallback argument' });
    return count;
  }

  const hooked = [];
  try {
    const a = hookRegistration('subscribePropertyEvents', 'subscribe', 'SUBSCRIPTION_REGISTER');
    if (a) hooked.push('subscribePropertyEvents x' + a);
    const b = hookRegistration('registerCallback', 'registerCallback', 'CALLBACK_REGISTER');
    if (b) hooked.push('registerCallback x' + b);
    return hooked;
  } catch (e) {
    vlog('ERROR', { where: 'hook subscription/registration', msg: String(e) });
    return hooked;
  }
}
