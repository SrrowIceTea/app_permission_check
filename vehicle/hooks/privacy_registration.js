// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices only.
// privacy_registration.js —— 定位"注册/异步"接口的调用观测（不含取值判定）
//
// 为什么单独一份：真实样本（OwnTracks / GPSLogger / Organic Maps）实际调用的
// 是 requestLocationUpdates / getCurrentLocation，现有 watch 集只有
// LocationManager.getLastKnownLocation，于是这些样本在报告里表现为**零隐私事件**。
// "没看到"不能读成"没采集"——这里补的是那一段可见性。
//
// 语义红线：这些接口返回 void，位置是异步回调交出去的。回调交付值不等于
// 被调方法的返回值，按项目判据**不计入 obtained**。所以本文件只发
// PRIVACY_REGISTER（collection_state=call_only），永远不产生读取结论。
// 判据：注册 ≠ 取值。注册事件带 collection_state=call_only 与
// value_capture_gap=registration_or_async_no_return_value，下游只统计不升级。
// ============================================================================
import { describeException } from '../../core/privacy/dispatch.js';

export const REGISTER = [
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'long', 'float', 'android.location.LocationListener'],
    desc: '(Ljava/lang/String;JFLandroid/location/LocationListener;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 1},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'long', 'float', 'android.location.LocationListener', 'android.os.Looper'],
    desc: '(Ljava/lang/String;JFLandroid/location/LocationListener;Landroid/os/Looper;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 1},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'long', 'float', 'java.util.concurrent.Executor', 'android.location.LocationListener'],
    desc: '(Ljava/lang/String;JFLjava/util/concurrent/Executor;Landroid/location/LocationListener;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 30},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'long', 'float', 'android.app.PendingIntent'],
    desc: '(Ljava/lang/String;JFLandroid/app/PendingIntent;)V',
    data_type: 'location', registration_kind: 'pending_intent_registration', added_api: 1},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'android.location.LocationRequest', 'java.util.concurrent.Executor', 'android.location.LocationListener'],
    desc: '(Ljava/lang/String;Landroid/location/LocationRequest;Ljava/util/concurrent/Executor;Landroid/location/LocationListener;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 31},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['java.lang.String', 'android.location.LocationRequest', 'android.app.PendingIntent'],
    desc: '(Ljava/lang/String;Landroid/location/LocationRequest;Landroid/app/PendingIntent;)V',
    data_type: 'location', registration_kind: 'pending_intent_registration', added_api: 31},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['long', 'float', 'android.location.Criteria', 'android.location.LocationListener', 'android.os.Looper'],
    desc: '(JFLandroid/location/Criteria;Landroid/location/LocationListener;Landroid/os/Looper;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 1},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['long', 'float', 'android.location.Criteria', 'java.util.concurrent.Executor', 'android.location.LocationListener'],
    desc: '(JFLandroid/location/Criteria;Ljava/util/concurrent/Executor;Landroid/location/LocationListener;)V',
    data_type: 'location', registration_kind: 'listener_registration', added_api: 30},
  {cls: 'android.location.LocationManager', method: 'requestLocationUpdates',
    types: ['long', 'float', 'android.location.Criteria', 'android.app.PendingIntent'],
    desc: '(JFLandroid/location/Criteria;Landroid/app/PendingIntent;)V',
    data_type: 'location', registration_kind: 'pending_intent_registration', added_api: 1},
  {cls: 'android.location.LocationManager', method: 'getCurrentLocation',
    types: ['java.lang.String', 'android.os.CancellationSignal', 'java.util.concurrent.Executor', 'java.util.function.Consumer'],
    desc: '(Ljava/lang/String;Landroid/os/CancellationSignal;Ljava/util/concurrent/Executor;Ljava/util/function/Consumer;)V',
    data_type: 'location', registration_kind: 'async_current_location', added_api: 30},
];

// 只记录"调用了注册/异步接口"，绝不触碰返回值与回调参数：注册不等于取值。
export function armRegistration(entries, emit, gap) {
  const armed = [], failed = [];
  for (const entry of entries) {
    const label = entry.cls + '.' + entry.method + entry.desc;
    try {
      const method = Java.use(entry.cls)[entry.method].overload(...entry.types);
      method.implementation = function () {
        const args = Array.from(arguments);
        let error = null;
        try { method.apply(this, args); } catch (e) { error = e; }
        try {
          let info = null;
          try { info = error ? describeException(error) : null; } catch (e2) { info = null; }
          emit(entry, info ? (info.denied ? 'denied' : 'error') : 'ok', info);
        } catch (e3) { gap('registration_observation', String(e3)); }
        if (error) throw error;
      };
      armed.push(label);
    } catch (e) {
      failed.push(label);
      gap('api_unavailable', label + ': ' + String(e));
    }
  }
  return {armed, failed};
}
