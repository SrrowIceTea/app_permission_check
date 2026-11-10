// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — pinning_bypasses.js：TLS 校验收宽的**技术本身**
//
// 本模块只管"怎么把校验放宽"，不管"什么时候该放宽、对哪个进程放宽"——
// 后者是入口脚本（ssl_pinning_bypass.js）的白名单判断。分开的理由：
// 入口脚本的职责随场景变（附加哪个进程、白名单是谁），
// 而这些绕过手法是固定的四条，改动它们的理由和改白名单的理由完全不同。
//
// 四条手法（覆盖范围同 ssl_pinning_bypass.js 的 PINNING_ARMED 事件，那里也逐条报）：
//   1) conscrypt.TrustManagerImpl 的 checkTrustedRecursive / verifyChain / checkTrusted
//      —— 吞掉证书类异常，覆盖：未知 CA / 自签证书、Network Security Config
//      <pin-set>（NSC 固定走 conscrypt 同一条校验路径）、主机名不匹配
//   2) javax.net.ssl.SSLContext.init(...) 传入的自定义 TrustManager：
//      checkServerTrusted/checkClientTrusted 全部重载置为放行（按类钩，进程内生效）
//   3) okhttp3.CertificatePinner（check / check$okhttp）：置为 no-op（若类存在）
//   4) javax.net.ssl.HttpsURLConnection 的默认/实例 HostnameVerifier：替换为恒真
// 不覆盖：native TLS（BoringSSL/libssl 自定义 verify callback）、应用手写的证书指纹
// 比对、WebView/Chromium 引擎自身（非 conscrypt）的校验、非 Java 运行时（Flutter/RN）。
//
// 本模块只放宽信任校验，不读取也不修改任何明文数据。
// ============================================================================

import { tryUse } from './vscan_runtime.js';
import { loadExcTypes, isBypassable, defaultValueOf, hookSslContextInit } from './tls_relax.js';

// 每类吞掉的校验最多记录多少条，防日志风暴。这是**绕过的日志策略**，
// 跟着绕过走，不跟着入口脚本走。
var MAX_LOGS_PER_KIND = 50;

// 异常分类、按声明返回类型交回对端链、SSLContext 自定义 TM 放行，已拆到
// tls_relax.js（2026-11-10：与移动侧同步拆分，保持同名同职责）。

// ---- 1) conscrypt TrustManagerImpl（主路径：默认信任管理器 / NSC 固定均经此处） ----
//
// **两个类名都要钩，不能 `a || b`。** Java.use 只要能解析类引用就返回非空，
// 与类是否真的被加载、被使用无关；而 `||` 会短路，于是钩到的是那个没被使用的类。
// 实测：设备上真正在用的是 com.android.org.conscrypt.TrustManagerImpl
// （enumerateLoadedClasses 里根本没有 org.conscrypt.*），
// 但 `tryUse('org.conscrypt.TrustManagerImpl')` 解析成功，把钩子全挂到了一个死类上——
// 表现就是"钩子报告已挂载、运行期一次都没触发"。
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
        // Enumerate the bridge's own overload list rather than matching by reflected
        // type names. `holder.overload('a.b.C', 'int')` has to have every name resolve
        // exactly, and when one does not, conscrypt's methods fail deep inside the
        // bridge with "cannot read property '_o' of null" - a message that names
        // neither the method nor the offending type. Iterating `.overloads` avoids the
        // lookup entirely and cannot mismatch.
        var holder = null;
        try { holder = cls[mName]; } catch (e0) { holder = null; }
        if (!holder) {
          vlog('METHOD_NOT_EXPOSED', { where: 'conscrypt.' + mName,
                                      note: 'declared on the class but not exposed by the Frida bridge; not hooked' });
          return;
        }
        var overloads = [];
        try { overloads = holder.overloads || []; } catch (e1) { overloads = []; }
        if (overloads.length === 0) {
          vlog('METHOD_NOT_EXPOSED', { where: 'conscrypt.' + mName,
                                      note: 'exposed with no usable overloads; not hooked',
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
                                             detail: 'swallowed ' + String(e.$className || e.name) + ': ' + String(e.message) });
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

  // 逐个候选类都钩一遍，并**分别报告**各自挂到了什么。这样才能看出
  // "报告已挂载但运行期不触发"是因为钩错了类。
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

  // ---- 2) SSLContext.init 注入的自定义 TrustManager：实现见 tls_relax.js ----
  // 为什么不在这里：与移动侧同源，放在 tls_relax.js 里由 parity 的 tls_relax 配对看守。

  // ---- 3) okhttp3.CertificatePinner：置为 no-op（类存在才钩） ----
  function hookOkhttpPinner() {
    var cls = tryUse('okhttp3.CertificatePinner');
    if (cls === null) {
      vlog('NOT_PRESENT', { target: 'okhttp3.CertificatePinner', note: 'okhttp 不在本进程类路径（本夹具不用 okhttp）' });
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
          var ov = cls[mName].overloads.find(o => o.argumentTypes.map(t => t.className).join(",") === typesArr.join(","));
          ov.implementation = function () {
            logCapped('okhttp:' + mName, { target: 'okhttp3.CertificatePinner.' + mName,
                                           detail: 'pin check skipped (no-op)' });
            return undefined; // check() 返回 void；no-op 即绕过固定校验
          };
          hooked.push('okhttp3.CertificatePinner.' + mName + '(' + typesArr.join(',') + ')');
        } catch (e) { vlog('ERROR', { where: 'hook okhttp3.CertificatePinner.' + mName, msg: String(e) }); }
      })(m.getName(), types);
    }
    return hooked;
  }

  // ---- 4) HttpsURLConnection HostnameVerifier：默认/实例 替换为恒真 ----
  function hookHostnameVerifier() {
    var hooked = [];
    try {
      var HV = Java.registerClass({
        name: 'com.vscanner.audit.AlwaysTrueHostnameVerifier',
        implements: [Java.use('javax.net.ssl.HostnameVerifier')],
        methods: {
          verify: function (hostname, session) {
            logCapped('hv:verify', { target: 'HostnameVerifier', host: String(hostname), detail: 'hostname check relaxed' });
            return true;
          }
        }
      });
      var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
      try { // getDefaultHostnameVerifier：静态
        HUC.getDefaultHostnameVerifier.implementation = function () {
          return HV.$new();
        };
        hooked.push('HttpsURLConnection.getDefaultHostnameVerifier');
      } catch (e) { vlog('ERROR', { where: 'hook getDefaultHostnameVerifier', msg: String(e) }); }
      try { // setDefaultHostnameVerifier：静态
        HUC.setDefaultHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (hv) {
          logCapped('hv:setDefault', { target: 'HttpsURLConnection.setDefaultHostnameVerifier', detail: 'replaced with always-true' });
          HUC.setDefaultHostnameVerifier(HV.$new());
        };
        hooked.push('HttpsURLConnection.setDefaultHostnameVerifier');
      } catch (e) { vlog('ERROR', { where: 'hook setDefaultHostnameVerifier', msg: String(e) }); }
      try { // setHostnameVerifier：实例（抽象基类声明，子类实现 —— 尽力而为）
        HUC.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier').implementation = function (hv) {
          logCapped('hv:set', { target: 'HttpsURLConnection.setHostnameVerifier', detail: 'replaced with always-true' });
          this.setHostnameVerifier(HV.$new());
        };
        hooked.push('HttpsURLConnection.setHostnameVerifier');
      } catch (e) { vlog('ERROR', { where: 'hook setHostnameVerifier', msg: String(e) }); }
    } catch (e) { vlog('ERROR', { where: 'hookHostnameVerifier', msg: String(e) }); }
    return hooked;
  }

  return {
    arm: function () {
      loadExcTypes();
      var hooked = [];
      hooked = hooked.concat(hookTrustManagerImpl());
      hooked = hooked.concat(hookSslContextInit(logCapped, vlog));
      hooked = hooked.concat(hookOkhttpPinner());
      hooked = hooked.concat(hookHostnameVerifier());
      return hooked;
    },
    candidates: TM_CANDIDATES
  };
}
