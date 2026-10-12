// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — vscan_runtime.js：四个钩子共用的观测运行时
//
// 这里只放**必须逐字一致**的东西：一条事件记录长什么样、走哪两个通道落盘、
// 进程名怎么取。各脚本的白名单、属性表、栈策略都留在自己的文件里——
// 那些是每个钩子各自的判断，共用会让一个钩子的改动波及另一个。
//
// **为什么非抽出来不可：这段代码原先在四个脚本里各有一份，而且已经漂移了。**
// `hook_vhal.js` / `recon_cpm.js` 那两份**没有外层 try/catch**——
// `JSON.stringify(rec)` 一旦抛（`extra` 里出现循环引用就会抛），异常就顺着
// `implementation` 传回被挂钩的 `CarPropertyManager.getProperty`，
// 也就是**观测失败会改变被测应用的行为**。项目原则是"只观察不改写"，
// 这条比省几行代码重要得多。另外 `hook_egress.js` 那份把日志路径写死，
// 不走 CFG.logPath，四份的 console 行格式也各不相同。
//
// 漂移本身就是理由：**这四份拷贝没有一处会报错**，只是慢慢长得不一样，
// 而下游是按这些字段做证据链的。合成一份之后，字段只有一个定义。
//
// 用法：
//   import { makeLogger } from './vscan_runtime.js';
//   var vlog = makeLogger('egress', '/data/local/tmp/vscan.log');
// ============================================================================

// 事件序号按 logger 各自计数。四个钩子是四个独立的 Frida 会话，本来就不共享
// JS 上下文；即便将来同进程加载两个，各记各的也比混在一起好——
// 下游按 (src, evt_id) 定位事件，串号会让结论指向错误的事件。
export function makeLogger(src, logPath) {
  var evtSeq = 0;
  return function vlog(ev, extra) {
    evtSeq++; // 放在 try 外：它不可能抛，且抛了也不该让序号停滞
    // 整个函数体都在 try 里。**观测绝不能因为记录失败而影响被测进程**，
    // 这是本文件存在的首要理由。
    try {
      // extra 先写、保留字段后写。原来的顺序是反的，于是 `vlog('X', {src: 'y'})`
      // 会把 src 改掉——下游按 (src, evt_id) 定位事件，改掉就等于让证据指向别的事件，
      // 而且**一个错都不会报**。当前没有调用点这么做，但顺序不该由调用者的自觉来保证。
      var rec = {};
      if (extra) {
        for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) rec[k] = extra[k];
      }
      rec.v = '1';
      rec.src = src;
      rec.ev = ev;
      rec.evt_id = evtSeq;
      rec.ts = Date.now();
      rec.pid = Process.id;
      rec.tid = Process.getCurrentThreadId();
      var line = JSON.stringify(rec);
      // 主通道：send() 回传，由宿主机落盘。
      // 设备端副本是尽力而为——实测本设备 SELinux 禁止 untrusted_app 追加写
      // shell_data_file (/data/local/tmp)，permissive=0；而读取观察只能发生在
      // 应用进程内，所以那条路靠不住，不能当主通道。
      var sent = false, persisted = false;
      try { send({ vscan: 1, line: line }); sent = true; } catch (e1) {}
      try {
        var f = new File(logPath, 'a');
        f.write(line + '\n');
        f.flush();
        f.close();
        persisted = true;
      } catch (e2) {}
      console.log('[' + src + '] ' + ev +
                  (sent ? '' : ' SEND_FAIL') + (persisted ? '' : ' DEVICE_WRITE_DENIED') +
                  ' ' + JSON.stringify(extra || {}).slice(0, 400));
    } catch (e) { console.log('[' + src + '] VLOG_FAIL: ' + e); }
  };
}

// 解析一个类引用，解不到就返回 null。
// **注意它解到了不代表那个类被加载、被使用**——`Java.use` 只要类引用能解析就返回非空。
// 这个区别害过我们一次：`tryUse(A) || tryUse(B)` 短路之后钩子全挂在一个死类上，
// 表现是"报告已挂载、运行期一次都不触发"。见 pinning_bypasses.js 的 TM_CANDIDATES。
export function tryUse(name) {
  try { return Java.use(name); } catch (e) { return null; }
}

// 进程名。两条路都要走，顺序有意义：
//   1) `ActivityThread.currentApplication()` 在应用进程里给出**权威包名**；
//   2) system_server 等系统进程里它是 null（Phase 0 实测），退回 /proc/self/cmdline。
// 调用方若还要 system_server 的 Context，得自己再走一次 systemMain().getSystemContext()——
// 那是各脚本自己的事（见 hook_vhal.js 的 detect()），不放在这里。
export function procName() {
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    if (app !== null) return String(app.getApplicationContext().getPackageName());
  } catch (e) {}
  try {
    var f = new File('/proc/self/cmdline', 'r');
    var ab = f.readBytes(512);
    f.close();
    var s = '';
    var u8 = new Uint8Array(ab);
    for (var i = 0; i < u8.length; i++) { if (u8[i] === 0) break; s += String.fromCharCode(u8[i]); }
    return s;
  } catch (e) { return 'unknown'; }
}
