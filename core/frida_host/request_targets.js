// 仅用于授权测试。 Observe request-target candidates without rewriting the app.
// Host-only records avoid copying URL query values. A candidate is not proof of
// sending: the collector still requires an actual request and target agreement.
export function hookRequestTargets(packageName, vlog, enrich) {
  const installed = [];
  function observe(host, via) {
    try {
      if (host && String(host) !== 'null') {
        vlog('EGRESS_URL', enrich({ package: packageName, target_host: String(host),
          via: via, outcome: 'candidate', evidence_role: 'request_target_candidate' }));
      }
    } catch (e) { vlog('REQUEST_TARGET_OBSERVATION_ERROR', { via: via, msg: String(e) }); }
  }
  try {
    const URL = Java.use('java.net.URL');
    for (const original of URL.openConnection.overloads) {
      original.implementation = function () {
        const result = original.apply(this, Array.prototype.slice.call(arguments));
        try { observe(this.getHost(), 'java.net.URL.openConnection'); } catch (e) {}
        return result;
      };
      installed.push('java.net.URL.openConnection');
    }
  } catch (e) { vlog('REQUEST_TARGET_GAP', { target: 'java.net.URL', msg: String(e) }); }
  try {
    const Builder = Java.use('okhttp3.Request$Builder');
    for (const original of Builder.build.overloads) {
      if (original.argumentTypes.length !== 0) continue;
      original.implementation = function () {
        const result = original.call(this);
        try { observe(result.url().host(), 'okhttp3.Request.Builder.build'); } catch (e) {}
        return result;
      };
      installed.push('okhttp3.Request.Builder.build');
    }
  } catch (e) { vlog('REQUEST_TARGET_GAP', { target: 'okhttp3.Request.Builder', msg: String(e) }); }
  return installed;
}
