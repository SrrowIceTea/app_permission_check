// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Mobile — fixture_trigger.js：夹具验证用的纯触发编排（i2 迁移验证）。
//
// 只做一件事：在应用进程内**调用**敏感 API（传感器注册 / Camera.open /
// AudioRecord.startRecording / loopback socket connect），让已挂的 hook_all
// 观测到这些调用。与 hook 模块的差别：
//   - 不做任何 Interceptor.attach、不做任何 ov.implementation——纯调用，零替换。
//   - 它自己打包 frida-java-bridge（独立 bundle），由 validate_native_migration.py
//     以第二个脚本方式加载。第二个脚本本身不替换方法，不触发 A1 的
//     "多脚本各自替换"约束（那只约束 ArtMethod 替换，见 hook_all 注释）。
//
// 为什么需要它：夹具 UI 只有 btnDeviceId/location/contacts/http 等按钮，
// 没有传感器/相机/录音按钮；而 i2 迁移验证必须触发 native 迁移点。
// 触发器在 app 主线程上同步执行，每次调用 1 次，不循环。
// ============================================================================
'use strict';

function tlog(msg) {
  try { console.log('[fixture_trigger] ' + msg); } catch (e) {}
}

function triggerSensor() {
  try {
    var AT = Java.use('android.app.ActivityThread');
    var ctx = AT.currentApplication().getApplicationContext();
    var SM = Java.use('android.hardware.SensorManager');
    var sm = Java.cast(ctx.getSystemService('sensor'), SM);
    if (sm === null) { tlog('sensor: no service'); return; }
    var s = sm.getDefaultSensor(1);   // TYPE_ACCELEROMETER
    if (s === null) {
      var lst = sm.getSensorList(-1);  // 全部传感器
      s = lst && lst.size() > 0 ? Java.cast(lst.get(0), Java.use('android.hardware.Sensor')) : null;
    }
    if (s === null) { tlog('sensor: none present'); return; }
    var Listener = Java.registerClass({
      name: 'com.vscanner.fixturetrigger.SensorL',
      implements: [Java.use('android.hardware.SensorEventListener')],
      methods: {
        onSensorChanged: function (e) {},
        onAccuracyChanged: function (s2, a) {}
      }
    });
    var l = Listener.$new();
    sm.registerListener(l, s, 3);      // SENSOR_DELAY_NORMAL
    Java.use('java.lang.Thread').sleep(300);
    sm.unregisterListener(l);
    tlog('sensor: registered+unregistered');
  } catch (e) { tlog('sensor: ' + String(e).slice(0, 120)); }
}

function triggerCamera() {
  try {
    var Cam = Java.use('android.hardware.Camera');
    var c = Cam.open(0);               // 后摄；native_setup(weakThis, cameraId, ...)
    if (c !== null) c.release();
    tlog('camera: open(0)+release');
  } catch (e) { tlog('camera: ' + String(e).slice(0, 120)); }
}

function triggerAudioRecord() {
  try {
    var AR = Java.use('android.media.AudioRecord');
    var min = AR.getMinBufferSize(16000, 16, 2);
    if (min <= 0) { tlog('audio: getMinBufferSize failed'); return; }
    var ar = AR.$new(1, 16000, 16, 2, min);   // MIC
    ar.startRecording();
    Java.use('java.lang.Thread').sleep(300);
    ar.stop();
    ar.release();
    tlog('audio: start+stop');
  } catch (e) { tlog('audio: ' + String(e).slice(0, 120)); }
}

function triggerLoopback() {
  try {
    var IA = Java.use('java.net.InetAddress');
    var Sock = Java.use('java.net.Socket');
    var sock = Sock.$new();
    sock.connect(Java.use('java.net.InetSocketAddress').$new(IA.getByName('127.0.0.1'), 80), 1000);
    sock.close();
    tlog('loopback: connected');
  } catch (e) { tlog('loopback: ' + String(e).slice(0, 80)); }
}

// 每个触发点放独立 Java 线程 + join 超时：模拟器上 Camera.open 可能长时间阻塞
// （虚拟场景初始化），单线程顺序执行会让后面的 audio/loopback 永远轮不到、
// DONE 也不打 —— inject 侧只能按失败取证。隔离后单个卡死不拖累整体。
// 两个实测教训（2026-10-21）：
//   1) 每次触发点各注册一个新类 → 太多合成类 run() 被 ART JIT 编译（HBasicBlockBuilder
//      崩在 Jit thread pool）——改为全程只注册一个共享 Runnable 类。
//   2) 回调载荷不能挂 Java wrapper 实例属性（r.__fn = fn）：run() 在执行线程上
//      `this` 是另一份线程本地 wrapper，属性读不到（全量 TypeError 空转）。
//      改为按 hashCode 索引的 PENDING 表，跨线程稳定。
var RUNNER_CLS = null;
var PENDING = {};
function runGuarded(name, fn, timeoutMs) {
  try {
    if (RUNNER_CLS === null) {
      RUNNER_CLS = Java.registerClass({
        name: 'com.vscanner.fixturetrigger.Runner',
        implements: [Java.use('java.lang.Runnable')],
        methods: { run: function () {
          var job = PENDING[this.hashCode()];
          if (job) {
            try { job.fn(); } catch (e) { tlog(job.name + ': ' + String(e).slice(0, 120)); }
          } else { tlog('runner: PENDING miss'); }
        } }
      });
    }
    var r = RUNNER_CLS.$new();
    PENDING[r.hashCode()] = { name: name, fn: fn };
    var t = Java.use('java.lang.Thread').$new(r);
    t.start();
    t.join(timeoutMs);
    tlog(name + (t.isAlive() ? ': TIMEOUT(thread still running)' : ': finished'));
  } catch (e) { tlog(name + ': guard failed ' + String(e).slice(0, 100)); }
}

export function main() {
  try {
    tlog('START pkg=' + procNameSafe());
    runGuarded('sensor', triggerSensor, 10000);
    runGuarded('camera', triggerCamera, 10000);
    runGuarded('audio', triggerAudioRecord, 10000);
    runGuarded('loopback', triggerLoopback, 8000);
    tlog('DONE');
  } catch (e) {
    tlog('ERROR ' + String((e && e.stack) || e));
  }
}

function procNameSafe() {
  try {
    var AT = Java.use('android.app.ActivityThread');
    return String(AT.currentApplication().getPackageName());
  } catch (e) { return 'unknown'; }
}