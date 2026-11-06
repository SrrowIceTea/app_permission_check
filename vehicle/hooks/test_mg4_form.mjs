// 仅用于授权测试。Malformed HTTP and split/pipelined bodies cannot become write proof.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('./mg4_form_write.js', import.meta.url), 'utf8');
const { formWrite } = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const marker = '0123456789abcdef';
const head = `POST http://192.0.2.1:18124/submit?vscan_id=${marker} HTTP/1.1\r\nHost: 192.0.2.1:18124\r\nContent-Length: 23\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n`;
const raw = head + 'marker=' + marker;
assert.equal(formWrite(raw)?.body, 'marker=' + marker);
for (const bad of [raw.slice(0,-1), raw + 'x', raw.replace(marker, 'fedcba9876543210'),
    raw.replace('Content-Length: 23', 'Content-Length: 22'), raw.replace('18124','18125'),
    raw.replace('192.0.2.1','999.0.2.1'), raw.replace('Host:', 'Content-Length: 23\r\nHost:'),
    raw.replace('Host:', 'Transfer-Encoding: chunked\r\nHost:'), raw + raw]) {
  assert.equal(formWrite(bad), null);
}
console.log('MG4 complete synthetic form checks passed');
