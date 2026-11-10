// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — ssl_pinning_tp.js：第三方样本的 TLS 校验收宽入口
//
// 与 vehicle/hooks/ssl_pinning_bypass.js 是**同一份契约**（白名单判断 + PINNING_ARMED 事件 +
// try/catch 包住一切），差别只在绕过手法集合：本入口用 mobile/hooks/tls_bypasses_tp.js，
// 它裁掉了 vehicle/hooks 版里会触发 ART abort 的 HttpsURLConnection 主机名钩子
// （完整裁剪记录与证据见该文件头部注释）。
//
// 事件记录于 /data/local/tmp/vscan.log（JSONL，src=tls），主通道是 send() 回宿主机。
//
// 显式开关（2026-11-10）：
//   本脚本默认**不启用**。TLS 校验收宽会改变目标进程的校验结果，对有证书链一致性
//   依赖的 App 有行为风险（2026-11-10 Organic Maps + OkHttp 6 实证：早期 no-op 实现
//   返回 undefined，bridge 报 "expected return value compatible with java.util.List"，
//   Java 侧拿到 null，AndroidCertificateChainCleaner.clean() NPE 崩溃）。修复后仍需
//   由宿主逐样本显式开启，而不是对所有样本默认打开：
//       run.py --tls-bypass        （或环境变量 VSCAN_TLS_BYPASS=1）
//   适用边界：只放宽 **Java/TLS 层**（conscrypt TrustManagerImpl、SSLContext.init 注入
//   的自定义 TrustManager、okhttp CertificatePinner）。native BoringSSL 自定义
//   verify callback、应用手写指纹、WebView/Chromium 自带校验、非白名单进程都不覆盖。
//   对"把证书链本身当业务输入"的 App（自签证书校验器、证书固定+双向 TLS），开启后
//   可能改变其行为，需人工确认样本适用性。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './runtime.js';
import { makeBypasses } from './tls_bypasses_tp.js';

var CFG = {
  logPath: '/data/local/tmp/vscan.log',
  whitelist: packages(), // 主机注入的显式白名单；空白名单不给默认全进程
  // 未注入占位符 = 保持字面量 = 关闭；注入 '1' 才启用（见文件头"显式开关"）。
  // 只允许出现**一次**字面量：宿主替换是全局的，若再写一次比较字面量会被一起替换掉。
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

export function main() {
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
    if (!CFG.tlsBypass) {
      vlog('TLS_BYPASS_DISABLED', {
        pkg: STATE.pkg,
        note: '显式开关未开启：本轮不做 TLS 校验收宽（未传 --tls-bypass / VSCAN_TLS_BYPASS=1）；' +
              '隐私/流量采集不受影响'
      });
      console.log('ssl_pinning_tp.js TLS_BYPASS_DISABLED in ' + STATE.pkg + ' — pass --tls-bypass to enable.');
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
// 独立入口由构建提供（build.mjs 的薄入口）——本文件不自执行，见 hook_privacy.js
// 顶部关于"单 agent 合并"的注释（2026-10-16 A1 修复：多脚本各自替换不被 bridge 支持）。
