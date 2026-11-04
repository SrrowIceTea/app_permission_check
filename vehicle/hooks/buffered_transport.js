// 仅用于授权测试。 Keep device timestamps and per-source event IDs intact.
export const TRANSPORT = 'vehicle_buffered_v1';
const MAX_LINES = 20;
const MAX_DELAY_MS = 50;

export function createBufferedTransport() {
  let pending = [], timer = null, closed = false;
  const stats = { delivered: 0, failed: 0, batches: 0, buffered_events: 0 };

  function sendPacket(payload, count, batched) {
    try {
      send({ vscan: 1, transport: TRANSPORT, ...payload });
      stats.delivered += count;
      if (batched) {
        stats.batches++;
        stats.buffered_events += count;
      }
    } catch (_) {
      stats.failed += count;
    }
  }

  function flush() {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
    if (pending.length === 0) return;
    const lines = pending;
    pending = [];
    sendPacket({ lines }, lines.length, true);
  }

  return {
    emit(src, ev, line) {
      if (closed) return;
      if (src === 'vhal' && ev === 'VHAL_READ') {
        pending.push(line);
        if (pending.length >= MAX_LINES) flush();
        else if (timer === null) timer = setTimeout(flush, MAX_DELAY_MS);
      } else {
        // An egress or error event must not overtake an earlier vehicle read.
        flush();
        sendPacket({ line }, 1, false);
      }
    },
    fail() {
      if (!closed) stats.failed++;
    },
    close() {
      closed = true;
      flush();
      return { ...stats };
    }
  };
}
