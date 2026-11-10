// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner — tls_relax.js：TLS 放松的公共语义层
//
// 2026-11-10 从 pinning_bypasses.js 拆出（与移动侧同时拆，切分点相同）。
// 与 mobile/hooks/tls_relax.js **同名同职责**，由 test_hooks_parity.py 的 tls_relax
// 配对守卫。这里只放与具体手法无关的三件事：
//   1) 异常分类：哪些异常算"证书校验失败"（loadExcTypes / isBypassable）
//   2) 返回值语义：按声明返回类型交出合适值（peerChainOf / defaultValueOf）
//   3) SSLContext.init 注入的自定义 TrustManager 整体放行（hookSslContextInit）
// 四条手法本身（conscrypt / okhttp / HostnameVerifier）仍在 pinning_bypasses.js 里。
// ============================================================================

import { tryUse } from './vscan_runtime.js';

// 异常类型的候选。**只匹配 CertificateException 是不够的**，这是本脚本最初
// "钩子挂上了却没绕过"的根因：校验失败实际抛的是 CertPathValidatorException
// （"Trust anchor for certification path not found"），而它与 CertificateException
// **是兄弟**——同继承 GeneralSecurityException，但互不为 isInstance。
// 异常因此被原样重抛，钩子里那个 swallow 分支一次都没进过。
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
    // checkTrusted / checkTrustedRecursive 返回的是**已验证的链**。返回空表会让 TLS 栈
    // 拿不到对端链而再次失败——吞了异常却仍然握手失败，等于没绕过。
    // 因此把**对端自己的证书**当作已验证链返回，这是各类 unpinning 脚本的标准做法。
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
  // 布尔语义**故意与移动侧相反**：车载侧保持 false。翻成 true 会让原本失败的握手变成功，
  // 现有车载验收证据立刻不可比；离交付近，不做这种只换"逐字一致"的行为翻转。
  if (retName === 'boolean') return false;
  if (retName === 'void') return undefined;
  return null;
}

// ---- SSLContext.init 注入的自定义 TrustManager：按类放行其 check* 全部重载 ----
// 车载侧当前语义：把 check* 全部置为 no-op 并 return undefined（恒放行）。
// 已知与移动侧不同源（移动侧按声明返回类型交回对端链），差异由 parity 白名单
// block «tls-sslctx-tm-impl» 显式登记，待同步。
export function hookSslContextInit(logCapped, vlog) {
  var hooked = [];
  try {
    var SC = Java.use('javax.net.ssl.SSLContext');
    var ov = SC.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
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
                if (o.__vscanNoop) return;
                o.__vscanNoop = true;
                o.implementation = function () {
                  logCapped('sslctx:' + mn, { target: 'SSLContext.init custom TrustManager',
                                              detail: String(o.returnType ? o.returnType.className : '?') + ' check relaxed' });
                  return undefined;
                };
              })(ovs[k]);
            }
          } catch (e) {}
        });
      }
      logCapped('sslctx:init', { target: 'SSLContext.init', detail: 'TrustManager checks relaxed for ' + n + ' TM(s)' });
      return ov.apply(this, arguments); // 原 init 照常执行（参数不变，TM 类已被放行）
    };
    hooked.push('SSLContext.init(KM[],TM[],SecureRandom)');
  } catch (e) { vlog('ERROR', { where: 'hook SSLContext.init', msg: String(e) }); }
  return hooked;
}
