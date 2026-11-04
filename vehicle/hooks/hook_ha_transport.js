// 仅用于授权测试。Observe the real OkHttp write and its response in the isolated HA lab.
import { packages } from './scope.js';
import { decodeUtf8, makeLogger, procName } from './vscan_runtime.js';
import { webhookSummary } from './ha_webhook_body.js';
import { withStack } from './stack_capture.js';

const PACKAGE = 'io.homeassistant.companion.android.minimal';
const MAX_BODY = 64 * 1024;
const log = makeLogger('ha_transport', '/data/local/tmp/vscan-ha-transport.log');

Java.perform(() => {
  if (procName() !== PACKAGE || !packages().includes(PACKAGE)) return;
  const identity = {pkg: PACKAGE};
  try {
    identity.uid = Number(Java.use('android.os.Process').myUid());
    identity.user_id = Math.floor(identity.uid / 100000);
    const call = Java.use('okhttp3.internal.http.CallServerInterceptor')
      .intercept.overload('okhttp3.Interceptor$Chain');
    const sink = Java.use('okio.RealBufferedSink');
    const bytes = sink.write.overload('[B', 'int', 'int');
    const byteString = sink.write.overload('okio.ByteString');
    const byteBody = Java.use('okhttp3.RequestBody$Companion$toRequestBody$3');
    const stringBody = Java.use('okhttp3.RequestBody$Companion$toRequestBody$1');
    const active = new Map();
    const onThread = () => active.get(Process.getCurrentThreadId());

    function record(sinkObject, length, read) {
      const entry = onThread();
      if (!entry?.sink || !entry.sink.$isSameObject(sinkObject)) return;
      entry.writes++;
      if (entry.writes !== 1 || length !== entry.length) {
        entry.body = {gap: 'unexpected_write_shape'};
        return;
      }
      const payload = new Uint8Array(length);
      for (let i = 0; i < length; i++) payload[i] = read(i) & 255;
      const text = decodeUtf8(payload);
      entry.body = text.includes('\uFFFD') ? {gap: 'invalid_utf8'} : webhookSummary(text);
    }

    bytes.implementation = function (array, offset, count) {
      const result = bytes.call(this, array, offset, count);
      try {
        record(this, count, i => array[offset + i]);
      } catch (_) {
        const entry = onThread();
        if (entry) entry.body = {gap: 'body_observation_failed'};
      }
      return result;
    };
    byteString.implementation = function (value) {
      const result = byteString.call(this, value);
      try {
        if (onThread()?.sink !== undefined) record(this, Number(value.size()), i => value.getByte(i));
      } catch (_) {
        const entry = onThread();
        if (entry) entry.body = {gap: 'body_observation_failed'};
      }
      return result;
    };
    for (const bodyClass of [byteBody, stringBody]) {
      const write = bodyClass.writeTo.overload('okio.BufferedSink');
      write.implementation = function (target) {
        const entry = onThread();
        let observing = false;
        try {
          observing = !!entry?.requestBody && entry.requestBody.$isSameObject(this);
          if (observing) entry.sink = target;
        } catch (_) {
          if (entry) entry.gap = 'request_body_identity_failed';
        }
        try {
          return write.call(this, target);
        } finally {
          if (observing) delete entry.sink;
        }
      };
    }
    call.implementation = function (chain) {
      let entry;
      const thread = Process.getCurrentThreadId();
      const previous = active.get(thread);
      try {
        const request = chain.request();
        const url = request.url();
        if (String(request.method()) === 'POST' && String(url.scheme()) === 'http' &&
            String(url.host()) === '127.0.0.1' && Number(url.port()) === 18123 &&
            /^\/api\/webhook\/[^/]+$/.test(String(url.encodedPath()))) {
          const body = request.body();
          const kind = body && String(body.getClass().getName());
          entry = {request_started_ts: Date.now(), writes: 0};
          if (kind !== byteBody.$className && kind !== stringBody.$className) {
            entry.gap = 'unsupported_body_type';
          } else if (body.contentType()?.subtype().toString() !== 'json') {
            entry.gap = 'unsupported_content_type';
          } else {
            entry.length = Number(body.contentLength());
            if (!Number.isInteger(entry.length) || entry.length <= 0 || entry.length > MAX_BODY) {
              entry.gap = 'body_size_outside_limit';
            } else {
              entry.requestBody = body;
            }
          }
        }
      } catch (_) {
        log('ERROR', {...identity, where: 'ha_request_metadata'});
      }
      if (entry) active.set(thread, entry);
      else active.delete(thread);
      let response;
      try {
        response = call.call(this, chain);
      } finally {
        if (previous) active.set(thread, previous);
        else active.delete(thread);
        if (entry && !response) log('HA_BODY_GAP', {...identity, reason: 'request_failed'});
      }
      if (entry) {
        try {
          const body = entry.body;
          const reason = entry.gap ?? body?.gap ?? (entry.writes === 1 ? null : 'write_not_observed');
          const status = Number(response.code());
          if (reason) log('HA_BODY_GAP', {...identity, reason, status});
          else if (body?.kind === 'sensor' && body.state !== undefined) {
            log('HA_SENSOR_HTTP', withStack({...identity, request_started_ts: entry.request_started_ts,
              method: 'POST', endpoint: 'isolated_ha_webhook', status, request_bytes: entry.length,
              body_complete: true, payload_type: 'update_sensor_states',
              sensor_id: 'battery_level', state: body.state}, PACKAGE, 12, 12));
          } else if (body?.kind === 'control') {
            // Metadata only: no webhook token, no service_data beyond the test entity.
            log('HA_CONTROL_HTTP', withStack({...identity, request_started_ts: entry.request_started_ts,
              method: 'POST', endpoint: 'isolated_ha_webhook', status, request_bytes: entry.length,
              body_complete: true, payload_type: body.payload_type, operation: body.operation,
              entity_id: body.entity_id}, PACKAGE, 12, 12));
          }
        } catch (_) {
          log('ERROR', {...identity, where: 'ha_response_observation'});
        }
      }
      return response;
    };
    log('ARMED', {...identity, transport: 'okhttp_call_server'});
  } catch (_) {
    log('ERROR', {...identity, where: 'ha_transport_arm'});
  }
});
