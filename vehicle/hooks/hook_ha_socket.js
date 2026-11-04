// 仅用于授权测试。Observe the isolated HA WebSocket without modifying messages.
import './java_bootstrap.js';
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { decodeSocketText, requestMetadata, resultMetadata, entityState } from './ha_socket_message.js';

const PACKAGE = 'io.homeassistant.companion.android.minimal';
const log = makeLogger('ha_socket', '/data/local/tmp/vscan-ha-socket.log');

Java.perform(() => {
  if (procName() !== PACKAGE || !packages().includes(PACKAGE)) return;
  const identity = {pkg: PACKAGE};
  try {
    identity.uid = Number(Java.use('android.os.Process').myUid());
    identity.user_id = Math.floor(identity.uid / 100000);
    const Socket = Java.use('okhttp3.internal.ws.RealWebSocket');
    const sendText = Socket.send.overload('java.lang.String');
    const readText = Socket.onReadMessage.overload('java.lang.String');
    // RealWebSocket inherits Object equality. Weak keys neither conflate object
    // hash collisions nor retain a closed connection.
    const ids = Java.use('java.util.WeakHashMap').$new();
    const Integer = Java.use('java.lang.Integer');
    const pending = new Map();
    let next = 0;

    function connection(socket) {
      const known = ids.get(socket);
      if (known) return Number(Java.cast(known, Integer).intValue());
      const url = socket.request().url();
      if (String(url.scheme()) !== 'http' || String(url.host()) !== '127.0.0.1' ||
          Number(url.port()) !== 18123 || String(url.encodedPath()) !== '/api/websocket') return null;
      ids.put(socket, Integer.valueOf(++next));
      return next;
    }

    sendText.implementation = function (text) {
      let entry, key;
      try {
        const connectionId = connection(this);
        const messages = connectionId && decodeSocketText(String(text));
        const metadata = messages?.length === 1 && requestMetadata(messages[0]);
        if (metadata) {
          entry = {...identity, ...metadata, connection_id: connectionId, send_started_ts: Date.now()};
          key = connectionId + ':' + metadata.message_id;
          if (pending.size >= 128) {
            pending.delete(pending.keys().next().value);
            log('HA_WS_GAP', {...identity, reason: 'pending_limit'});
          }
          pending.set(key, entry);
        }
      } catch (_) {
        log('ERROR', {...identity, where: 'ha_socket_send_observation'});
      }
      let accepted = false;
      try {
        accepted = sendText.call(this, text);
        return accepted;
      } finally {
        if (entry) {
          if (!accepted) pending.delete(key);
          log('HA_WS_SEND', {...entry, accepted: accepted === true});
        }
      }
    };

    readText.implementation = function (text) {
      try {
        const connectionId = connection(this);
        if (connectionId) {
          const messages = decodeSocketText(String(text));
          if (!messages) log('HA_WS_GAP', {...identity, connection_id: connectionId, reason: 'unsupported_text'});
          for (const message of messages || []) {
            const state = entityState(message);
            if (state) log('HA_WS_STATE', {...identity, ...state, connection_id: connectionId});
            const result = resultMetadata(message);
            if (!result) continue;
            const key = connectionId + ':' + result.message_id;
            if (pending.delete(key)) log('HA_WS_RESULT', {...identity, ...result, connection_id: connectionId});
          }
        }
      } catch (_) {
        log('ERROR', {...identity, where: 'ha_socket_receive_observation'});
      }
      return readText.call(this, text);
    };
    log('ARMED', {...identity, transport: 'okhttp_websocket_text'});
  } catch (_) {
    log('ERROR', {...identity, where: 'ha_socket_arm'});
  }
});
