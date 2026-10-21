// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Mobile — keylog_trigger.js：i3 keylog 验证的纯触发（零替换零 attach）。
//
// 与 fixture_trigger.js 同类：只在应用进程内**调用** TLS，让已挂的 hook_all
// （tls_meta 模块）观测到一次完整握手并吐 keylog。
//
// 为什么是裸 SSLSocket 而不是 HttpsURLConnection/OkHttp（fix4 实测，2026-10-21）：
//   挂钩后的冷进程跑 OkHttp 全栈（dispatcher 线程池 + 连接池 + 海量首次 JIT）
//   4/4 死在 connect 系统调用**之前**——零 EGRESS_CONNECT（连 libc native.connect
//   的 onEnter 都没到），全 SIGSEGV@Jit thread pool（D-054b 残余崩）。
//   裸 SSLSocket 单线程、只走 conscrypt，JIT 面最小；注册类 2→1（裸 SSLSocket
//   不做 hostname 校验，HostnameVerifier 整个删掉）。字面 IP：不走 DNS。
// 为什么不用 UI 按钮：uiautomator dump→tap 几秒 + 弹窗遮挡，见 validate_keylog.py。
//
// 只调官方工厂/信任器：不跑任何 ov.implementation、不 attach 任何函数。
// 自签证书按 TrustManager 全放行：验证在授权测试的闭环内。
// ============================================================================
'use strict';

function tlog(msg) {
  try { console.log('[keylog_trigger] ' + msg); } catch (e) {}
}

function trustAllSslContext() {
  var X509 = Java.use('javax.net.ssl.X509TrustManager');
  var TM = Java.registerClass({
    name: 'com.vscanner.keylogtrigger.TrustAll',
    implements: [X509],
    methods: {
      checkClientTrusted: function (chain, auth) {},
      checkServerTrusted: function (chain, auth) {},
      getAcceptedIssuers: function () { return []; }
    }
  });
  var SC = Java.use('javax.net.ssl.SSLContext');
  var sc = SC.getInstance('TLS');
  sc.init(null, [TM.$new()], Java.use('java.security.SecureRandom').$new());
  return sc.getSocketFactory();
}

function triggerSsl() {
  tlog('phase:sslctx');
  var sf = trustAllSslContext();
  tlog('phase:connect');
  // 桥只能枚举到 conscrypt 工厂的两个抽象 createSocket 重载（fix5 attempt-2 实测
  // createSocket(InetAddress,int) 报 argument types do not match）——两层路径规避：
  // 裸 Socket.connect 先建 TCP（egress 钩子可观测、宿主服务器可计数），再包 SSL。
  var IA = Java.use('java.net.InetAddress');
  var plain = Java.use('java.net.Socket').$new();
  plain.connect(Java.use('java.net.InetSocketAddress').$new(IA.getByName('10.0.2.2'), 8888), 5000);
  tlog('phase:layered');
  var sslSock = Java.cast(sf.createSocket(plain, '10.0.2.2', 8888, true),
                          Java.use('javax.net.ssl.SSLSocket'));
  sslSock.setSoTimeout(5000);
  tlog('phase:handshake');
  sslSock.startHandshake();      // 握手在此完成 → tls_meta 的 keylog 回调在此发键
  tlog('phase:write');
  var body = Java.use('java.lang.String').$new('vscan-keylog-fixture').getBytes('UTF-8');
  sslSock.getOutputStream().write(body);
  sslSock.getOutputStream().flush();
  sslSock.close();
  tlog('ssl: sent');
}

export function main() {
  try {
    tlog('START');
    triggerSsl();
    tlog('DONE');
  } catch (e) {
    tlog('ERROR ' + String((e && e.stack) || e).slice(0, 400));
  }
}