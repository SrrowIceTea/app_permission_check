// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — tls_relax.js：TLS 放松的公共语义层
//
// 2026-11-10 从 tls_bypasses_tp.js 拆出（该文件一度 309 行，越过"单文件 ≤300 行"）。
// 与 vehicle/hooks/tls_relax.js **同名同职责**，由 test_hooks_parity.py 的 tls_relax
// 配对守卫。这里只放与具体手法无关的三件事：
//   1) 异常分类：哪些异常算"证书校验失败"（loadExcTypes / isBypassable）
//   2) 返回值语义：按声明返回类型交出合适值（peerChainOf / defaultValueOf）
//   3) SSLContext.init 注入的自定义 TrustManager 整体放行（hookSslContextInit）
// 三条手法本身（conscrypt / okhttp；车载另有 HostnameVerifier）仍在主文件里。
// ============================================================================

import { tryUse } from './runtime.js';

// 校验失败实际抛的是 CertPathValidatorException（"Trust anchor for certification path
// not found"），它与 CertificateException **是兄弟**（同继承 GeneralSecurityException，
// 互不为 isInstance）。只匹配 CertificateException 会让 swallow 分支一次都进不去——
// 这是 vehicle/hooks 最初的根因（那边有完整记录）。
var EXC_CACHE = { cert: null, peer: null, genSec: null, certPath: null };

export function loadExcTypes() {
  try { EXC_CACHE.cert = Java.use('java.security.cert.CertificateException').class; } catch (e) {}
  try { EXC_CACHE.peer = Java.use('javax.net.ssl.SSLPeerUnverifiedException').class; } catch (e) {}
  try { EXC_CACHE.genSec = Java.use('java.security.GeneralSecurityException').class; } catch (e) {}
  try { EXC_CACHE.certPath = Java.use('java.security.cert.CertPathValidatorException').class; } catch (e) {}
}

export function isBypassable(e) {
  try {
    if (EXC_CACHE.cert !== null && EXC_CACHE.cert.isInstance(e)) return true;
    if (EXC_CACHE.peer !== null && EXC_CACHE.peer.isInstance(e)) return true;
    if (EXC_CACHE.certPath !== null && EXC_CACHE.certPath.isInstance(e)) return true;
    if (EXC_CACHE.genSec !== null && EXC_CACHE.genSec.isInstance(e)) return true;
    var n = String(e && e.$className ? e.$className : e);
    return /Cert|SSL|Trust|Handshake|PathValidator/i.test(n);
  } catch (x) { return false; }
}

// 从入参里找对端证书链：有的入口是 X509Certificate[]，有的是 List<X509Certificate>
// （Android 15 的 conscrypt TrustManagerImpl.checkServerTrusted 返回 List，入参仍是数组；
// 但自定义 TrustManager 也可能收 List，两种都要认）。
function peerChainOf(args) {
  var X509ARR = '[Ljava.security.cert.X509Certificate;';
  for (var i = 0; i < (args || []).length; i++) {
    var candidate = args[i];
    if (!candidate || candidate.$className !== X509ARR) continue;
    try {
      var arr = Java.cast(candidate, Java.use(X509ARR));
      var list = Java.use('java.util.ArrayList').$new();
      for (var j = 0; j < arr.length; j++) list.add(arr[j]);
      if (list.size() > 0) return list;
    } catch (e) { /* 继续找下一个 */ }
  }
  var LIST = null;
  try { LIST = Java.use('java.util.List'); } catch (e) { LIST = null; }
  if (LIST !== null) {
    for (var k = 0; k < (args || []).length; k++) {
      var c2 = args[k];
      if (!c2) continue;
      try {
        if (!LIST.class.isInstance(c2)) continue;
        var src = Java.cast(c2, LIST);
        var out = Java.use('java.util.ArrayList').$new();
        for (var m = 0; m < src.size(); m++) out.add(src.get(m));
        if (out.size() > 0) return out;
      } catch (e2) { /* 继续找下一个 */ }
    }
  }
  return null;
}

export function defaultValueOf(retName, args) {
  if (retName === 'java.util.List') {
    // checkTrusted*/checkServerTrusted 返回的是**已验证的链**。返回空表会让 TLS 栈
    // 拿不到对端链而再次失败——吞了异常却仍然握手失败，等于没绕过。把对端自己的
    // 证书当作已验证链返回。
    var list = peerChainOf(args);
    if (list !== null) return list;
    try { return Java.use('java.util.ArrayList').$new(); } catch (e) { return null; }
  }
  if (retName === '[Ljava.security.cert.X509Certificate;') {
    // 少数 TrustManager 直接返回证书数组；同样把对端链交回去，不给 null。
    for (var i = 0; i < (args || []).length; i++) {
      var candidate = args[i];
      if (candidate && candidate.$className === '[Ljava.security.cert.X509Certificate;') {
        try { return Java.cast(candidate, Java.use('[Ljava.security.cert.X509Certificate;')); } catch (e) {}
      }
    }
    return null;
  }
  if (retName === 'boolean') return true; // check* 的布尔语义：放行
  if (retName === 'void') return undefined;
  return null;
}

// ---- SSLContext.init 注入的自定义 TrustManager：按类放行其 check* 全部重载 ----
// 注意（2026-11-10 设备实证）：Android 15 的 conscrypt TrustManagerImpl.checkServerTrusted
// **返回 java.util.List<X509Certificate>**，不是 void。早期实现直接 `return undefined`
// 当 no-op，bridge 会抛 "Implementation for checkServerTrusted expected return value
// compatible with java.util.List"，Java 侧拿到 null，OkHttp 6 的
// AndroidCertificateChainCleaner.clean() 随即 NPE、进程崩溃（Organic Maps 实测）。
// 正确做法：先跑原校验；仅在证书类异常时按**真实返回类型**交出对端原始链。
export function hookSslContextInit(logCapped, vlog) {
  var hooked = [];
  try {
    var SC = Java.use('javax.net.ssl.SSLContext');
    var ov = SC.init.overload('[Ljavax.net.ssl.KeyManager;',
                              '[Ljavax.net.ssl.TrustManager;',
                              'java.security.SecureRandom');
    ov.implementation = function (kms, tms, sr) {
      var n = tms === null ? 0 : tms.length;
      for (var i = 0; i < n; i++) {
        var tm = tms[i];
        if (tm === null) continue;
        var cls = null;
        try { cls = tryUse(String(tm.$className)); } catch (e) {}
        if (cls === null) continue;
        ['checkServerTrusted', 'checkClientTrusted'].forEach(function (mn) {
          try {
            var ovs = cls[mn].overloads;
            for (var k = 0; k < ovs.length; k++) {
              (function (o) {
                if (o.__vscanTmHooked) return;
                o.__vscanTmHooked = true;
                var retName = String(o.returnType ? o.returnType.className : 'void');
                o.implementation = function () {
                  var args = Array.prototype.slice.call(arguments);
                  try {
                    return o.apply(this, args); // 校验通过 → 原样返回，不改变行为
                  } catch (e) {
                    if (!isBypassable(e)) throw e; // 非证书类异常不吞
                    logCapped('sslctx:' + mn, {
                      target: 'SSLContext.init custom TrustManager',
                      detail: mn + ' relaxed (return=' + retName + ', chain=' +
                              (peerChainOf(args) !== null) + ')'
                    });
                    return defaultValueOf(retName, args);
                  }
                };
              })(ovs[k]);
            }
          } catch (e) {}
        });
      }
      logCapped('sslctx:init', { target: 'SSLContext.init',
                                 detail: 'TrustManager checks relaxed for ' + n + ' TM(s)' });
      return ov.apply(this, arguments); // 原 init 照常执行
    };
    hooked.push('SSLContext.init(KM[],TM[],SecureRandom)');
  } catch (e) { vlog('ERROR', { where: 'hook SSLContext.init', msg: String(e) }); }
  return hooked;
}
