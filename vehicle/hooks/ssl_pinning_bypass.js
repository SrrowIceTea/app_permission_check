// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — ssl_pinning_bypass.js：TLS 校验收宽的入口（交付物 3）
//
// 用途声明（重要）：本脚本是 V-Scanner"只观察"原则的唯一例外。它故意放宽 TLS 信任
// 校验，唯一目的是让审计工具能读取【白名单内】被测应用在【本自有设备】上的流量
// （配合宿主代理/抓包工具）。它不读取、不修改任何明文数据。
// 作用范围：仅 frida 附加到的那个进程（默认要求其包名在 CFG.whitelist 内，
// 不在白名单 → NOT_TARGET，拒绝挂载任何钩子）。默认白名单：['com.vscanner.targetapp']。
//
// 本文件只做**三件事**：判断该不该对当前进程动手、把绕过挂上去、如实报告挂到了什么。
// 绕过手法本身在 pinning_bypasses.js，事件记录格式在 vscan_runtime.js。
//
// 事件记录于 /data/local/tmp/vscan.log（JSONL，src=tls）。
// 显式开关（2026-11-10）：默认**关闭**——宿主不注入 __VSCAN_TLS_BYPASS__ 时只发一条
// TLS_SWITCH{tls_bypass:false} + TLS_BYPASS_DISABLED，不挂任何接缝；run.py 传
// --tls-bypass（或 VSCAN_TLS_BYPASS=1）才武装。车载流水线默认显式传该参数以保持
// 既有交付行为，开关值同时落 verification.json 与本文件的 TLS_SWITCH 事件，可 grep。
// 运行：frida -U -f <白名单包> -l ssl_pinning_bypass.js（见 vehicle/hooks/README.md）
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './vscan_runtime.js';
import { makeBypasses } from './pinning_bypasses.js';

var CFG = {
  logPath: '/data/local/tmp/vscan.log',
  whitelist: packages(), // 默认白名单
  // 显式开关（2026-11-10）：未注入占位符 = 保持字面量 = 关闭；注入 '1' 才武装。
  // 只允许出现**一次**字面量：宿主替换是全局的，再写一次比较字面量会被一起替换。
  // 车载流水线（vehicle/pipeline/capture.py）默认传 --tls-bypass 保持既有交付行为；
  // 直接手跑 core/frida_host/run.py 不给该开关即关闭（与移动侧同名语义）。
  tlsBypass: String('__VSCAN_TLS_BYPASS__') === '1'
};

var vlog = makeLogger('tls', CFG.logPath);
var bypasses = makeBypasses(vlog);

var STATE = { pkg: null, uid: -1 };

function detect() {
  STATE.uid = Java.use('android.os.Process').myUid();
  STATE.pkg = procName();
  return STATE;
}

function main() {
  try {
    detect();
    vlog('START', { script: 'ssl_pinning_bypass.js', pkg: STATE.pkg, uid: STATE.uid,
                    whitelist: CFG.whitelist, frida: Frida.version,
                    scope_note: 'process-local only; bypasses trust verification for audit traffic capture' });
    // 开关的**启动行**证据：不论开/关都先记一条，事后可 grep「本轮到底开没开」。
    // 不放进 START 是为了让两侧 START 保持同形（parity 守卫）。
    vlog('TLS_SWITCH', { tls_bypass: CFG.tlsBypass, source: 'run.py --tls-bypass' });
    if (CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg, note: 'package not in whitelist; no hooks armed (pinning bypass disabled)' });
      return;
    }
    if (!CFG.tlsBypass) {
      vlog('TLS_BYPASS_DISABLED', {
        pkg: STATE.pkg,
        note: '显式开关未开启：本轮不做 TLS 校验收宽（未传 --tls-bypass / VSCAN_TLS_BYPASS=1）；' +
              '隐私/流量采集不受影响'
      });
      console.log('ssl_pinning_bypass.js TLS_BYPASS_DISABLED in ' + STATE.pkg + ' — pass --tls-bypass to enable.');
      return;
    }
    vlog('PINNING_ARMED', { hooks: bypasses.arm(),
                            candidates: bypasses.candidates,
                            covered: 'conscrypt TrustManagerImpl (incl. NSC pin-set path), SSLContext custom TMs, okhttp CertificatePinner, HttpsURLConnection HostnameVerifier',
                            not_covered: 'native TLS (BoringSSL/libssl), hand-written fingerprint checks, WebView/Chromium-native checks, non-whitelisted processes' });
    console.log('ssl_pinning_bypass.js PINNING_ARMED in ' + STATE.pkg + ' — audit-traffic mode; Ctrl+C to exit.');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}
Java.perform(main);
