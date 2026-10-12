// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — ssl_pinning_tp.js：第三方样本的 TLS 校验收宽入口
//
// 与 phase3/ssl_pinning_bypass.js 是**同一份契约**（白名单判断 + PINNING_ARMED 事件 +
// try/catch 包住一切），差别只在绕过手法集合：本入口用 mobile/hooks/tls_bypasses_tp.js，
// 它裁掉了 phase3 版里会触发 ART abort 的 HttpsURLConnection 主机名钩子
// （完整裁剪记录与证据见该文件头部注释）。
//
// 事件记录于 /data/local/tmp/vscan.log（JSONL，src=tls），主通道是 send() 回宿主机。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './runtime.js';
import { makeBypasses } from './tls_bypasses_tp.js';

var CFG = {
  logPath: '/data/local/tmp/vscan.log',
  whitelist: packages() // 主机注入的显式白名单；空白名单不给默认全进程
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
    vlog('START', { script: 'ssl_pinning_tp.js', pkg: STATE.pkg, uid: STATE.uid,
                    whitelist: CFG.whitelist, frida: Frida.version,
                    scope_note: 'process-local only; relaxes TLS trust verification for audit traffic capture' });
    if (CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg,
                           note: 'package not in whitelist; no hooks armed (pinning bypass disabled)' });
      return;
    }
    vlog('PINNING_ARMED', { hooks: bypasses.arm(),
                            candidates: bypasses.candidates,
                            covered: 'conscrypt TrustManagerImpl (incl. NSC pin-set path), SSLContext custom TMs, okhttp CertificatePinner',
                            reduced: 'HttpsURLConnection default/instance HostnameVerifier was REMOVED for this sample: it aborted ART on the Glide source thread (see tls_bypasses_tp.js header) and buys nothing because this sample\'s HTTP client ignores the system proxy',
                            not_covered: 'native TLS (BoringSSL/libssl), hand-written fingerprint checks, WebView/Chromium-native checks, non-whitelisted processes' });
    console.log('ssl_pinning_tp.js PINNING_ARMED in ' + STATE.pkg + ' — audit-traffic mode; Ctrl+C to exit.');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}
Java.perform(main);
