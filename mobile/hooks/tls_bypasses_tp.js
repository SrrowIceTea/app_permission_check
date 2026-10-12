// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — tls_bypasses_tp.js：第三方样本专用的 TLS 校验收宽
//
// 与 phase3/pinning_bypasses.js 的关系：**同源、裁剪版**。
// phase3 的模块不能跨项目根被 import（frida-compile 按入口所在目录解析相对路径，
// 与 mobile/hooks/runtime.js 重复 phase3/vscan_runtime.js 是同一个原因），
// 所以这里放一份本地副本；但**不是逐行复制**——裁剪掉了一条已被证伪的路径（见下）。
//
// 裁剪记录（必须留痕，不许静默删除能力）：
//   phase3 版的第 4 条手法 `HttpsURLConnection` 默认主机名校验（getDefaultHostnameVerifier
//   / setDefaultHostnameVerifier / setHostnameVerifier 三个钩子）在本样本上被证实会触发
//   **ART 层 abort**：logcat 记录到
//     F/libc: Fatal signal 6 (SIGABRT) ... in tid <n> (glide-source-th), pid <p>
//     art_method.cc:696] javax.net.ssl.HostnameVerifier
//                        javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier() pc=0
//   线程是 Glide 的取图线程（Glide 的 HttpUrlConnection fetcher 会走 HttpsURLConnection），
//   进程随后 `has died: fg TOP`。A/B 对照：只挂 TLS 钩子即可复现，只挂出站钩子不复现。
//   同时，该路径对本样本的**收益为零**：样本的天气请求走 loopj/Apache HttpClient，
//   **不读 Android 系统代理**，mitmproxy 结构性看不到它的流量，因此放宽主机名校验
//   也不会换来任何可读流量。风险 > 收益，故裁掉。
//   这不是"覆盖不到就说没覆盖"：剩余三条手法的实际挂载结果逐条写进 PINNING_ARMED 事件。
//
// 保留的三条手法：
//   1) conscrypt.TrustManagerImpl (checkTrustedRecursive / verifyChain / checkTrusted)
//   2) javax.net.ssl.SSLContext.init 传入的自定义 TrustManager
//   3) okhttp3.CertificatePinner（类存在才钩）
// 不覆盖：HttpsURLConnection 主机名校验（本文件主动裁掉，见上）、native TLS
// （BoringSSL/libssl 自定义 verify callback）、应用手写指纹比对、WebView/Chromium
// 引擎自身的校验、非 Java 运行时（Flutter/RN）。
// ============================================================================

import { tryUse } from './runtime.js';

// 每类吞掉的校验最多记录多少条，防日志风暴。
var MAX_LOGS_PER_KIND = 50;

// 校验失败实际抛的是 CertPathValidatorException（"Trust anchor for certification path
// not found"），它与 CertificateException **是兄弟**（同继承 GeneralSecurityException，
// 互不为 isInstance）。只匹配 CertificateException 会让 swallow 分支一次都进不去——
// 这是 phase3 最初的根因（那边有完整记录）。
var EXC_CACHE = { cert: null, peer: null, genSec: null, certPath: null };

function loadExcTypes() {
  try { EXC_CACHE.cert = Java.use('java.security.cert.CertificateException').class; } catch (e) {}
  try { EXC_CACHE.peer = Java.use('javax.net.ssl.SSLPeerUnverifiedException').class; } catch (e) {}
  try { EXC_CACHE.genSec = Java.use('java.security.GeneralSecurityException').class; } catch (e) {}
  try { EXC_CACHE.certPath = Java.use('java.security.cert.CertPathValidatorException').class; } catch (e) {}
}

function isBypassable(e) {
  try {
    if (EXC_CACHE.cert !== null && EXC_CACHE.cert.isInstance(e)) return true;
    if (EXC_CACHE.peer !== null && EXC_CACHE.peer.isInstance(e)) return true;
    if (EXC_CACHE.certPath !== null && EXC_CACHE.certPath.isInstance(e)) return true;
    if (EXC_CACHE.genSec !== null && EXC_CACHE.genSec.isInstance(e)) return true;
    var n = String(e && e.$className ? e.$className : e);
    return /Cert|SSL|Trust|Handshake|PathValidator/i.test(n);
  } catch (x) { return false; }
}

function defaultValueOf(retName, args) {
  if (retName === 'java.util.List') {
    // checkTrusted* 返回的是**已验证的链**。返回空表会让 TLS 栈拿不到对端链而再次
    // 失败——吞了异常却仍然握手失败，等于没绕过。把对端自己的证书当作已验证链返回。
    try {
      var X509ARR = '[Ljava.security.cert.X509Certificate;';
      for (var i = 0; i < (args || []).length; i++) {
        var candidate = args[i];
        if (!candidate || candidate.$className !== X509ARR) continue;
        var arr = Java.cast(candidate, Java.use(X509ARR));
        var list = Java.use('java.util.ArrayList').$new();
        for (var j = 0; j < arr.length; j++) list.add(arr[j]);
        if (list.size() > 0) return list;
      }
    } catch (e) { /* 落到下面的空表 */ }
    try { return Java.use('java.util.ArrayList').$new(); } catch (e) { return null; }
  }
  if (retName === 'boolean') return false;
  if (retName === 'void') return undefined;
  return null;
}

// 两个类名都要钩，不能 `a || b`：Java.use 只要能解析类引用就返回非空，与类是否真的
// 被使用无关，而 `||` 会短路。实测设备上真正在用的是 com.android.org.conscrypt.*。
var TM_CANDIDATES = [
  'com.android.org.conscrypt.TrustManagerImpl',
  'org.conscrypt.TrustManagerImpl',
];

export function makeBypasses(vlog) {
  var counters = {};
  function logCapped(kind, extra) {
    counters[kind] = (counters[kind] || 0) + 1;
    if (counters[kind] <= MAX_LOGS_PER_KIND) vlog('PINNING_BYPASS', extra);
  }

  function hookOneTrustManagerImpl(className) {
    var cls = tryUse(className);
    if (cls === null) return null;
    var names = { checkTrustedRecursive: 1, verifyChain: 1, checkTrusted: 1 };
    var hooked = [];
    var methods = cls.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      var m = methods[i];
      if (!names[m.getName()]) continue;
      var types = [];
      var pts = m.getParameterTypes();
      for (var j = 0; j < pts.length; j++) types.push(pts[j].getName());
      (function (mName, typesArr, retName) {
        // 遍历 bridge 自己的 overloads，而不是按反射类型名去 overload('a.b.C')：
        // 后者要求每个类型名都精确解析，一旦解析不了会在 bridge 深处报
        // "cannot read property '_o' of null"，既不提方法也不提类型。
        var holder = null;
        try { holder = cls[mName]; } catch (e0) { holder = null; }
        if (!holder) {
          vlog('METHOD_NOT_EXPOSED', { where: 'conscrypt.' + mName,
                                      note: 'declared on the class but not exposed by the bridge' });
          return;
        }
        var overloads = [];
        try { overloads = holder.overloads || []; } catch (e1) { overloads = []; }
        if (overloads.length === 0) {
          vlog('METHOD_NOT_EXPOSED', { where: 'conscrypt.' + mName,
                                      note: 'exposed with no usable overloads',
                                      reflected_types: typesArr });
          return;
        }
        for (var k = 0; k < overloads.length; k++) {
          (function (ov, sig) {
            try {
              ov.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                try {
                  return ov.apply(this, args); // 原校验通过 → 原样返回
                } catch (e) {
                  if (!isBypassable(e)) throw e; // 非证书类异常不吞
                  logCapped('tm:' + mName, { target: 'conscrypt.' + mName, signature: sig,
                                             detail: 'swallowed ' + String(e.$className || e.name) +
                                                     ': ' + String(e.message) });
                  return defaultValueOf(retName, args);
                }
              };
              hooked.push('conscrypt.' + mName + '(' + sig + ')');
            } catch (e) { vlog('ERROR', { where: 'hook conscrypt.' + mName + '#' + k, msg: String(e) }); }
          })(overloads[k], typesArr.join(','));
        }
      })(m.getName(), types, m.getReturnType().getName());
    }
    return hooked;
  }

  function hookTrustManagerImpl() {
    var all = [];
    for (var i = 0; i < TM_CANDIDATES.length; i++) {
      var name = TM_CANDIDATES[i];
      var result = hookOneTrustManagerImpl(name);
      if (result === null) {
        vlog('TM_CLASS_ABSENT', { target: name, note: '解析不到该类，跳过' });
        continue;
      }
      vlog('TM_CLASS_HOOKED', { target: name, hooked: result.length, methods: result });
      all = all.concat(result);
    }
    if (all.length === 0) {
      vlog('NOT_PRESENT', { target: 'conscrypt.TrustManagerImpl',
                            note: '两个候选类名都没钩上；主绕过路径不可用' });
    }
    return all;
  }

  // ---- 2) SSLContext.init 注入的自定义 TrustManager：按类放行其 check* 全部重载 ----
  function hookSslContextInit() {
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
                  if (o.__vscanNoop) return;
                  o.__vscanNoop = true;
                  o.implementation = function () {
                    logCapped('sslctx:' + mn, { target: 'SSLContext.init custom TrustManager',
                                                detail: mn + ' relaxed' });
                    return undefined;
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

  // ---- 3) okhttp3.CertificatePinner：置为 no-op（类存在才钩） ----
  function hookOkhttpPinner() {
    var cls = tryUse('okhttp3.CertificatePinner');
    if (cls === null) {
      vlog('NOT_PRESENT', { target: 'okhttp3.CertificatePinner',
                            note: 'okhttp 不在本进程类路径' });
      return [];
    }
    var hooked = [];
    var methods = cls.class.getDeclaredMethods();
    for (var i = 0; i < methods.length; i++) {
      var m = methods[i];
      if (m.getName() !== 'check' && m.getName() !== 'check$okhttp') continue;
      var types = [];
      var pts = m.getParameterTypes();
      for (var j = 0; j < pts.length; j++) types.push(pts[j].getName());
      (function (mName, typesArr) {
        try {
          var target = typesArr.join(',');
          var ov = cls[mName].overloads.find(
            function (o) { return o.argumentTypes.map(function (t) { return t.className; }).join(',') === target; });
          ov.implementation = function () {
            logCapped('okhttp:' + mName, { target: 'okhttp3.CertificatePinner.' + mName,
                                           detail: 'pin check skipped (no-op)' });
            return undefined; // check() 返回 void
          };
          hooked.push('okhttp3.CertificatePinner.' + mName + '(' + target + ')');
        } catch (e) { vlog('ERROR', { where: 'hook okhttp3.CertificatePinner.' + mName, msg: String(e) }); }
      })(m.getName(), types);
    }
    return hooked;
  }

  return {
    arm: function () {
      loadExcTypes();
      var hooked = [];
      hooked = hooked.concat(hookTrustManagerImpl());
      hooked = hooked.concat(hookSslContextInit());
      hooked = hooked.concat(hookOkhttpPinner());
      return hooked;
    },
    candidates: TM_CANDIDATES
  };
}
