// 仅用于授权测试。Observe only the pinned MG4 lab WebView, without rewriting its requests.
import './java_bootstrap.js';
import './hook_privacy.js';
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { armNativeForm } from './hook_mg4_send.js';

const PKG = 'com.tommasov.mg4browser';
const log = makeLogger('mg4_webview', '/data/local/tmp/vscan-mg4-webview.log');

Java.perform(() => {
  if (procName() !== PKG || !packages().includes(PKG)) return;
  try {
    const uid = Number(Java.use('android.os.Process').myUid());
    const identity = {pkg: PKG, uid, user_id: Math.floor(uid / 100000)};
    armNativeForm(identity);
    const observe = Java.use('android.webkit.WebViewClient').shouldInterceptRequest
      .overload('android.webkit.WebView', 'android.webkit.WebResourceRequest');
    observe.implementation = function (view, request) {
      try {
        if (request.isForMainFrame() && !request.isRedirect() && String(request.getMethod()) === 'POST') {
          const url = request.getUrl();
          const host = String(url.getHost());
          const marker = /^vscan_id=([a-f0-9]{16})$/.exec(String(url.getEncodedQuery()));
          if (String(url.getScheme()) === 'http' && /^\d{1,3}(\.\d{1,3}){3}$/.test(host)
              && Number(url.getPort()) === 18124 && String(url.getEncodedPath()) === '/submit' && marker) {
            log('WEBVIEW_POST_REQUEST', {...identity, host, port: 18124, path: '/submit', marker: marker[1]});
          }
        }
      } catch (_) {
        log('ERROR', {...identity, where: 'mg4_webview_request'});
      }
      return observe.call(this, view, request);
    };
    log('ARMED', identity);
  } catch (_) {
    log('ERROR', {pkg: PKG, where: 'mg4_webview_arm'});
  }
});
