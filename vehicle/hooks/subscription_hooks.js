// 仅用于授权测试。只观察回调，不替换 callback，不改变注册或回调返回值。
// subscribePropertyEvents 名称与重载来自 device_calibration/cpm-signatures-device35.json。
export function hookSubscriptions(CPM, vlog, watch, callerInfo, stackStr) {
  const callbacks = new Set();
  function armCallback(callback) {
    // 参数静态类型是接口，Frida 不一定暴露 Object.getClass；先显式向上转型。
    const object = Java.cast(callback, Java.use('java.lang.Object'));
    const name = String(object.getClass().getName());
    if (callbacks.has(name)) return;
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
            vlog('VHAL_READ', { ...caller, api: 'subscription.onChangeEvent',
              prop_id: id, prop_name: watch[id], area_id: v.getAreaId(),
              outcome: v.getStatus() === 0 && v.getValue() !== null ? 'ok' : 'unavailable',
              value: String(v.getValue()), stack: stackStr() });
          }
        } catch (e) { vlog('ERROR', { where: 'subscription callback observation', msg: String(e) }); }
        return original.call(this, value);
      };
    }
    callbacks.add(name);
    vlog('SUBSCRIPTION_CALLBACK_ARMED', { target: name });
  }
  try {
    for (const original of CPM.subscribePropertyEvents.overloads) {
      const index = original.argumentTypes.findIndex(t =>
        t.className === 'android.car.hardware.property.CarPropertyManager$CarPropertyEventCallback');
      if (index < 0) continue;
      original.implementation = function () {
        const args = Array.from(arguments);
        try { armCallback(args[index]); }
        catch (e) { vlog('ERROR', { where: 'arm subscription callback', msg: String(e.stack || e) }); }
        try {
          const result = original.apply(this, args);
          vlog('SUBSCRIPTION_REGISTER', { accepted: Boolean(result), ...callerInfo() });
          return result;
        } catch (e) {
          vlog('SUBSCRIPTION_REGISTER_ERROR', { msg: String(e), ...callerInfo() });
          throw e;
        }
      };
    }
    return ['subscribePropertyEvents (runtime overloads)'];
  } catch (e) {
    vlog('ERROR', { where: 'hook subscribePropertyEvents', msg: String(e) });
    return [];
  }
}
