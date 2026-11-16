// 仅用于授权测试。保留每组首条读取，重复读取另记次数和时间范围。
const GETTERS = new Set(['getLatitude', 'getLongitude', 'getSpeed', 'getAccuracy']);

export function locationReads(log, now = Date.now, windowMs = 4000, limit = 128) {
  const groups = new Map();
  function flush(key) {
    const group = groups.get(key);
    groups.delete(key);
    if (group.count) log('PRIVACY_READ_REPEATS', {
      api: group.api, value_hash: group.hash, repeat_count: group.count,
      first_repeat_ts: group.first, last_repeat_ts: group.last
    });
  }
  return {
    emit(entry, extra) {
      if (entry.cls !== 'android.location.Location' || !GETTERS.has(entry.method) ||
          entry.desc !== '()F' && entry.desc !== '()D' ||
          extra.outcome !== 'ok' || !extra.value_hash || !extra.stack) {
        log('PRIVACY_READ', extra);
        return;
      }
      const ts = now();
      const key = JSON.stringify([extra.api, extra.value_hash, extra.thread_name, extra.stack]);
      let group = groups.get(key);
      if (group && ts - group.started >= windowMs) {
        flush(key);
        group = undefined;
      }
      if (!group) {
        if (groups.size >= limit) flush(groups.keys().next().value);
        groups.set(key, { api: extra.api, hash: extra.value_hash, started: ts, count: 0 });
        log('PRIVACY_READ', extra);
        return;
      }
      if (!group.count) group.first = ts;
      group.count++;
      group.last = ts;
    },
    flush() {
      for (const key of groups.keys()) flush(key);
    }
  };
}
