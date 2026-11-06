// 仅用于授权测试。Accept only one complete synthetic lab form, never general headers or bodies.
export function formWrite(text) {
  const split = text.indexOf('\r\n\r\n');
  if (split < 0 || text.length > 4096) return null;
  const lines = text.slice(0, split).split('\r\n');
  const request = /^POST http:\/\/(\d{1,3}(?:\.\d{1,3}){3}):18124(\/submit\?vscan_id=([a-f0-9]{16})) HTTP\/1\.[01]$/.exec(lines.shift());
  if (!request || request[1].split('.').some(x => Number(x) > 255)) return null;
  const headers = new Map();
  for (const line of lines) {
    const match = /^([A-Za-z0-9-]+):[ \t]*(.*)$/.exec(line);
    if (!match) return null;
    const key = match[1].toLowerCase();
    if (headers.has(key)) return null;
    headers.set(key, match[2]);
  }
  const body = text.slice(split + 4);
  if (headers.has('transfer-encoding') || headers.has('content-encoding')
      || headers.get('content-length') !== String(body.length)
      || headers.get('host') !== request[1] + ':18124'
      || !/^application\/x-www-form-urlencoded(?:;.*)?$/i.test(headers.get('content-type') || '')
      || body !== 'marker=' + request[3]) return null;
  return {host: request[1], port: 18124, path: request[2], body};
}
