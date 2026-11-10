// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — tls_bypasses_tp.js：第三方样本专用的 TLS 校验收宽
//
// 与 vehicle/hooks/pinning_bypasses.js 的关系：**同源、裁剪版**。
// vehicle/hooks 的模块不能跨项目根被 import（frida-compile 按入口所在目录解析相对路径，
// 与 mobile/hooks/runtime.js 重复 vehicle/hooks/vscan_runtime.js 是同一个原因），
// 所以这里放一份本地副本；但**不是逐行复制**——裁剪掉了一条已被证伪的路径（见下）。
//
// 裁剪记录（必须留痕，不许静默删除能力）：
//   vehicle/hooks 版的第 4 条手法 `HttpsURLConnection` 默认主机名校验（getDefaultHostnameVerifier
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
import { loadExcTypes, isBypassable, defaultValueOf, hookSslContextInit } from './tls_relax.js';

// 每类吞掉的校验最多记录多少条，防日志风暴。
var MAX_LOGS_PER_KIND = 50;

// 异常分类、按声明返回类型交回对端链、SSLContext 自定义 TM 放行，已拆到
// tls_relax.js（2026-11-10：本文件一度 309 行，越过"单文件 ≤300 行"）。

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

  // ---- 2) SSLContext.init 注入的自定义 TrustManager：实现见 tls_relax.js ----
  // 为什么不在这里：返回类型语义（Android 15 的 List 返回 + OkHttp 6 NPE 实证）与
  // 车载侧同源，放在 tls_relax.js 里由 parity 的 tls_relax 配对逐字看守。

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
      hooked = hooked.concat(hookSslContextInit(logCapped, vlog));
      hooked = hooked.concat(hookOkhttpPinner());
      return hooked;
    },
    candidates: TM_CANDIDATES
  };
}
