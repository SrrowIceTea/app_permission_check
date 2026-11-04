// 仅用于授权测试。A bounded write can prove only a complete allowlisted ABS body.
const KEYS = ['currentTime', 'timeListened', 'duration'];
const FIELD = '"(?:currentTime|timeListened|duration)"\\s*:\\s*-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?';
const BODY = new RegExp('^\\s*\\{\\s*' + FIELD + '(?:\\s*,\\s*' + FIELD + '){2}\\s*\\}\\s*$');

export function syncBody(text) {
  let session = null;
  if (text.startsWith('POST ')) {
    const boundary = text.indexOf('\r\n\r\n');
    if (boundary < 0) return null;
    const lines = text.slice(0, boundary).split('\r\n');
    const route = /^POST \/api\/session\/([a-fA-F0-9-]{36})\/sync HTTP\/1\.[01]$/.exec(lines[0]);
    const lengths = lines.slice(1).filter(line => /^content-length:/i.test(line));
    if (!route || lengths.length !== 1 || lines.some(line => /^transfer-encoding:/i.test(line))) return null;
    text = text.slice(boundary + 4);
    const length = /^content-length:\s*(\d+)\s*$/i.exec(lengths[0]);
    if (!length || Number(length[1]) !== text.length) return null;
    session = route[1].toLowerCase();
  }
  // The lexical form also rules out extra string values and escaped field names.
  if (!BODY.test(text)) return null;
  try {
    const data = JSON.parse(text);
    if (!KEYS.every(key => Number.isFinite(data[key]) && data[key] >= 0 && data[key] <= 1e9)) return null;
    return {text, session};
  } catch (_) {
    return null;
  }
}
