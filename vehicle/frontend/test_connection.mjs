// 仅用于授权测试。Deterministic protocol checks, not device evidence.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const timers = new Map(), sources = [], completions = [], errors = [];
class Source {
  constructor(url) { this.url = url; this.listeners = {}; this.closed = false; sources.push(this); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  close() { this.closed = true; }
}
let pending, polls = 0;
const U = {base:'http://127.0.0.1:8773', get:async () => { polls++; return await pending; }};
const scope = {window:{VehicleUI:U}, EventSource:Source, Set, Map, JSON,
  setInterval(fn) { const id=timers.size+1; timers.set(id,fn); return id; },
  clearInterval(id) { timers.delete(id); }};
vm.runInNewContext(fs.readFileSync(new URL('./connection.js',import.meta.url),'utf8'),scope);
const hooks = {progress(){}, complete(j){completions.push(j.id);}, error(j,e){errors.push([j.id,e]);}};
const a={id:'a',state:'running'}, b={id:'b',state:'running'};
U.watch(a,hooks); U.watch(a,hooks); U.watch(b,hooks);
assert.equal(sources.length,2,'same job must not acquire a second subscription');
const record=JSON.stringify({stage:'static',status:'done',ts:1});
sources[0].onmessage({data:record}); sources[0].onmessage({data:record});
assert.equal(a._events.length,1,'replayed event must be deduplicated');
assert.equal(b._events.length,0,'one job cannot receive another job progress');
sources[0].onmessage({data:'broken'}); assert.equal(a._events.length,1);
let resolve;
pending=new Promise(r => {resolve=r;});
sources[0].onerror(); sources[0].onerror();
assert.equal(timers.size,1,'only one recovery poll per interrupted stream');
const tick=[...timers.values()][0];
const waiting=tick(); await tick();
assert.equal(polls,1,'pending recovery must not overlap itself');
resolve({state:'failed',result:{error:{code:'device_unavailable'}}}); await waiting;
assert.equal(a.state,'failed','recovery must preserve backend failure');
assert.equal(a._loaded,true); assert.equal(sources[0].closed,true);
assert.equal(timers.size,0); assert.equal(U.streams.size,1);
assert.deepEqual(completions,['a']);
U.watch(a,hooks); assert.equal(sources.length,2,'loaded terminal task must not reopen SSE');
U.streams.get('b').close(); assert.equal(U.streams.size,0);
assert.ok(errors.length>=2);
console.log('connection: duplicate/replay/independent jobs/error recovery/failure/cleanup passed');
