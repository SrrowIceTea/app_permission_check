// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — pinning_bypasses.js：TLS 校验收宽的**技术本身**
//
// 本模块只管"怎么把校验放宽"，不管"什么时候该放宽、对哪个进程放宽"——
// 后者是入口脚本（ssl_pinning_bypass.js）的白名单判断。分开的理由：
// 入口脚本的职责随场景变（附加哪个进程、白名单是谁），
// 而这些绕过手法是固定的五条，改动它们的理由和改白名单的理由完全不同。
//
// 五条手法（覆盖范围同 ssl_pinning_bypass.js 的 PINNING_ARMED 事件，那里也逐条报）：
//   1) conscrypt.TrustManagerImpl 的 checkTrustedRecursive / verifyChain / checkTrusted
//      —— 吞掉证书类异常，覆盖：未知 CA / 自签证书、主机名不匹配
//   2) javax.net.ssl.SSLContext.init(...) 传入的自定义 TrustManager：
//      checkServerTrusted/checkClientTrusted 全部重载置为放行（按类钩，进程内生效）
//   3) okhttp3.CertificatePinner（check / check$okhttp）：置为 no-op（若类存在）——**请求**层 pin
//   4) android.security.net.config.NetworkSecurityTrustManager.checkPins：
//      声明式 pin（network_security_config 的 <pin-set enforcePinning="true">）的**握手**层实施点，
//      置为 no-op。3) 与 4) 是两道独立的闸：只放行 3) 握手仍失败；只放行 4) 握手成功但请求 0 条
//      （Proton Mail 3.0.17 实测，2026-11-10）。4) 在类/方法不存在时发 SEAM_SKIP 跳过，不中断武装。
//      注意 1) 只吞"证书链校验"抛出的异常，声明式 pin 走的是 4) 这条独立路径（1) 对这类样本 0 命中）。
//   5) javax.net.ssl.HttpsURLConnection 的默认/实例 HostnameVerifier：替换为恒真
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
            var args = Array.prototype.slice.call(arguments);
            // host = 该签名的第一个字符串参数（check(host, chain) / check$okhttp(host, …)）。
            var host = '';
            for (var k = 0; k < args.length; k++) {
              if (typeof args[k] === 'string') { host = String(args[k]); break; }
            }
            logCapped('okhttp:' + mName, { seam: 'okhttp.CertificatePinner',
                                           target: 'okhttp3.CertificatePinner.' + mName,
                                           host: host, detail: 'pin check skipped (no-op)' });
            return undefined; // check() 返回 void；no-op 即绕过固定校验
          };
          hooked.push('okhttp3.CertificatePinner.' + mName + '(' + typesArr.join(',') + ')');
        } catch (e) { vlog('ERROR', { where: 'hook okhttp3.CertificatePinner.' + mName, msg: String(e) }); }
      })(m.getName(), types);
    }
    return hooked;
  }

  // ---- 4) NetworkSecurityTrustManager.checkPins：**声明式 pin 的握手闸** ----
  // 与 3) 的分工不许合并成一个判断：
  //   · 这里（checkPins）管**握手**：network_security_config 里
  //     <pin-set enforcePinning="true"> 的证书链 pin 校验在本方法内完成；
  //     不放行它，握手阶段就抛 CertificateException，连 HTTP 都发不出去；
  //   · 3) okhttp3.CertificatePinner 管**请求**：握手过了之后 OkHttp 再校一遍 pin。
  // 实测定性（Proton Mail 3.0.17，2026-11-10）：只放行 3) → 握手失败；只放行这里 →
  // 握手成功但 HTTP 请求 0 条；两条都放行才出流量。声明式 pin 是当前主流做法，
  // 而 1)/2) 对这类样本 0 命中，说明它走的是这条独立路径。
  // 运行期事件用 seam 字段区分两道闸：okhttp.CertificatePinner 带 host；
  // NetworkSecurityTrustManager.checkPins 的 host 恒为空串（签名里没有 host 参数）。
  var NSC_TM = 'android.security.net.config.NetworkSecurityTrustManager';

  function hookNscCheckPins() {
    var cls = tryUse(NSC_TM);
    // 老 API 没有声明式 pin 的实施点：静默跳过，不许因一条接缝缺席中断整包武装。
    if (cls === null) {
      vlog('SEAM_SKIP', { target: NSC_TM + '.checkPins',
                          note: '类不存在（该 API 无声明式 pin 实施点），跳过；其余手法照常' });
      return [];
    }
    var holder = null;
    try { holder = cls.checkPins; } catch (e0) { holder = null; }
    if (!holder) {
      vlog('SEAM_SKIP', { target: NSC_TM + '.checkPins',
                          note: '方法未被 bridge 暴露（可能被内联），跳过；其余手法照常' });
      return [];
    }
    var overloads = [];
    try { overloads = holder.overloads || []; } catch (e1) { overloads = []; }
    if (overloads.length === 0) {
      vlog('SEAM_SKIP', { target: NSC_TM + '.checkPins', note: '无可用的重载，跳过' });
      return [];
    }
    var hooked = [];
    for (var i = 0; i < overloads.length; i++) {
      (function (ov, idx) {
        try {
          ov.implementation = function () {
            // 平台签名是 checkPins(X509Certificate[])，argc=1 —— 物理上拿不到 host。
            // 不猜 host、也不用 SNI 反填：留空并写明原因，否则就是假证据。
            logCapped('nsc:checkPins#' + idx,
                      { seam: 'NetworkSecurityTrustManager.checkPins',
                        target: NSC_TM + '.checkPins', host: '',
                        host_absent: 'checkPins(X509Certificate[]) has no host argument',
                        detail: 'declarative <pin-set> handshake check relaxed' });
            return undefined; // void：不抛 CertificateException 即放行握手
          };
          hooked.push(NSC_TM + '.checkPins#' + idx);
        } catch (e2) {
          vlog('ERROR', { where: 'hook ' + NSC_TM + '.checkPins#' + idx, msg: String(e2) });
        }
      })(overloads[i], i);
    }
    // 可检索的武装标记（与 PINNING_ARMED 并列）：这里报接缝名与已挂重载；
    // 运行期 PINNING_BYPASS{seam=NetworkSecurityTrustManager.checkPins, host=''} 报"被走到没有"。
    // host 恒为空串且带 host_absent 原因，别按空串判定"没走到"。
    vlog('PIN_SET_ARMED', { target: NSC_TM + '.checkPins', hooked: hooked,
                            note: '声明式 <pin-set> 握手闸已武装；请求闸见 okhttp3.CertificatePinner' });
    return hooked;
  }

  // ---- 5) HttpsURLConnection HostnameVerifier：默认/实例 替换为恒真 ----
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
      hooked = hooked.concat(hookNscCheckPins());
      hooked = hooked.concat(hookHostnameVerifier());
      return hooked;
    },
    candidates: TM_CANDIDATES
  };
}
