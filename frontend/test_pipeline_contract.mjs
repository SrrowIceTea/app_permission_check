// 仅用于授权测试（自有设备与自有 APK）。
// 一键审计前端的阶段契约：node test_pipeline_contract.mjs
// 不需要设备、服务或浏览器——用 vm + 极小 DOM 桩跑真实 app.js，把 /api/stages 当唯一来源。
//
// 钉住三件事（都会静默骗人）：
//   1. 时间线必须由 /api/stages 生成，前后端阶段数不能各写一份（17 阶段 vs 16 阶段那次就是这样漂的）；
//   2. 服务不可用/返回非数组时不能渲染出"假进度"，只能显示未连接；
//   3. app.js 里硬编码的动态阶段 id（liveDynamicStages / dynamicStageRows）必须是
//      stages.py STAGES 的子集——阶段改名后这两张表不跟着改，前端会静默少一行。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const APP = new URL('./app.js', import.meta.url);
const HTML = new URL('./app.html', import.meta.url);
const STAGES_PY = new URL('../mobile/pipeline/stages.py', import.meta.url);
const source = fs.readFileSync(APP, 'utf8');
const html = fs.readFileSync(HTML, 'utf8');

// ---------- 从后端契约文件里读真实阶段（唯一来源） ----------
const py = fs.readFileSync(STAGES_PY, 'utf8');
const block = py.slice(py.indexOf('STAGES: list'), py.indexOf('STAGE_ORDER'));
const STAGES = [...block.matchAll(/^\s*\("([a-z_]+)",\s*"([^"]+)"\),/gm)]
  .map(([, id, label]) => ({id, label}));

// 非设备阶段同样从后端契约抽：动态表的白名单必须是「13 个设备阶段」，
// 不能用全 17 个——否则把 'static'/'surface' 混进动态行也不会响。
// 注意用带 `=` 的字面量定位：注释里先出现过 DYNAMIC_STAGES 这个名字，按裸名切片会切反。
const nonDeviceBlock = py.slice(py.indexOf('NON_DEVICE_STAGES ='),
  py.indexOf('DYNAMIC_STAGES ='));
// 元组用的是双引号（写成单引号会抽空，然后 DYNAMIC 变成 17 个——本用例就是被这个咬过一次）。
const NON_DEVICE = [...nonDeviceBlock.matchAll(/["']([a-z_]+)["']/g)].map(m => m[1]);
const DYNAMIC = STAGES.map(s => s.id).filter(id => !NON_DEVICE.includes(id));
// app.js 里 liveDynamicStages / dynamicStageRows 两张表应有的内容（写死，不靠互相推导）。
const EXPECTED_ROWS = ['install', 'launch', 'conn_probe', 'mitm', 'hooks', 'explore',
  'death_probe', 'correlate', 'ai_review', 'report'];

const checks = [];
function check(name, fn) {
  try { fn(); checks.push({name, ok: true}); }
  catch (error) { checks.push({name, ok: false, msg: String((error && error.message) || error)}); }
}

// ---------- 极小 DOM 桩 ----------
function makeNode(tag = 'div') {
  let text = '';
  const n = {
    tagName: tag, nodeType: 1, innerHTML: '', className: '',
    dataset: {}, value: '', files: [], selectedIndex: -1, scrollTop: 0, scrollHeight: 0,
    children: [], listeners: {},
    style: {setProperty() {}, display: ''},
    classList: {add() {}, remove() {}, toggle() {}, contains() { return false; }},
    appendChild(c) { this.children.push(c); return c; },
    append(c) { this.children.push(c); return c; },
    addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
    removeEventListener() {}, setAttribute() {}, removeAttribute() {},
    querySelector() { return null; }, querySelectorAll() { return []; },
    focus() {}, click() {},
    get childNodes() { return this.children; },
    get firstChild() { return this.children[0] || null; }
  };
  // 真实 DOM 里 `textContent = ''` 会清空子节点；桩必须照做，否则"渲染前清屏"那行
  // 被删掉也测不出来（第二次渲染会把 17 行翻倍成 34 行，而浏览器里才是真 bug）。
  Object.defineProperty(n, 'textContent', {
    get() { return text; },
    set(value) {
      text = String(value);
      if (text === '') n.children.length = 0;
    }
  });
  return n;
}

function makeDom() {
  const byId = new Map(), bySelector = new Map(), docListeners = {};
  const document = {
    getElementById(id) {
      if (!byId.has(id)) byId.set(id, makeNode());
      return byId.get(id);
    },
    querySelector(sel) {
      if (!bySelector.has(sel)) bySelector.set(sel, makeNode());
      return bySelector.get(sel);
    },
    querySelectorAll() { return []; },
    createElement(tag) { return makeNode(tag); },
    createTextNode(text) { const n = makeNode('#text'); n.textContent = String(text); return n; },
    addEventListener(type, fn) { (docListeners[type] = docListeners[type] || []).push(fn); }
  };
  return {document, byId, bySelector, docListeners};
}

const tick = () => new Promise(resolve => setTimeout(resolve, 0));

// 起一份 app.js，触发 DOMContentLoaded，等 /api/stages 落地后把时间线节点交出来。
async function boot(stagesPayload) {
  const dom = makeDom();
  const location = {hash: '', protocol: 'http:'};
  const requests = [];
  const fetchStub = url => {
    requests.push(String(url));
    if (String(url).endsWith('/api/stages')) {
      return Promise.resolve({ok: true, json: () => Promise.resolve(stagesPayload)});
    }
    if (String(url).endsWith('/api/pipeline')) {
      return Promise.resolve({ok: true, json: () => Promise.resolve([])});
    }
    return Promise.resolve({ok: false, json: () => Promise.resolve({error: 'not stubbed'})});
  };
  const sandbox = {
    window: {location}, document: dom.document, location, fetch: fetchStub,
    alert() {}, console, setTimeout, EventSource: function () { this.close = () => {}; }
  };
  vm.runInNewContext(source, sandbox, {filename: 'app.js'});
  // 触发两次：第二次模拟"又有事件推动重绘"。真实 app.js 每次重绘前会清空时间线，
  // 桩若不清空就会数到 34 行——这条同时守住 `host.textContent = ''`。
  for (let round = 0; round < 2; round += 1) {
    (dom.docListeners.DOMContentLoaded || []).forEach(fn => fn());
    await tick(); await tick();
  }
  await tick();
  const timeline = dom.byId.get('pipeline-timeline');
  const rows = (timeline ? timeline.children : []).map(li => ({
    cls: li.className,
    label: li.children[1] && li.children[1].children[0]
      ? li.children[1].children[0].textContent : null
  }));
  return {dom, rows, requests};
}

// 时间线渲染只认 /api/stages：顺序、标签、条数全部来自后端。
await (async () => {
  const {rows, dom, requests} = await boot(STAGES.map(s => ({...s})));
  check('时间线条数与标签来自 /api/stages（17 阶段，顺序一致）', () => {
    assert.equal(STAGES.length, 17, 'stages.STAGES 应为 17 个阶段');
    assert.equal(rows.length, 17);
    assert.deepEqual(rows.map(r => r.label), STAGES.map(s => s.label));
    assert.ok(rows.every(r => r.cls === 'pl-pending'), '未开始的阶段只能是 pending');
  });
  check('确实向 /api/stages 发过请求，并在连上后标记在线', () => {
    assert.ok(requests.some(u => u.endsWith('/api/stages')));
    assert.match(dom.bySelector.get('.service-addr').textContent, /已连接/);
    assert.equal(dom.bySelector.get('.status-dot').dataset.online, 'true');
  });
})();

// 换成别的阶段表也要跟着变——否则"17"就是写死在前端的数字。
await (async () => {
  const fake = [{id: 'prepare', label: '甲'}, {id: 'static', label: '乙'}, {id: 'report', label: '丙'}];
  const {rows} = await boot(fake);
  check('后端改阶段表，前端跟着改（没有硬编码 17 条）', () => {
    assert.deepEqual(rows.map(r => r.label), ['甲', '乙', '丙']);
  });
})();

// 服务不可用：不许画出一条空进度假装在跑。
await (async () => {
  const {rows, dom} = await boot({error: '没有这个端点'});
  check('非数组响应不渲染假进度，只报未连接', () => {
    assert.equal(rows.length, 0);
    assert.match(dom.bySelector.get('.service-addr').textContent, /检测服务未连接/);
    assert.equal(dom.bySelector.get('.status-dot').dataset.online, 'false');
  });
})();

// 源码级契约：app.js 里那两张硬编码 id 表必须跟着 stages.py 走。
check('app.js 的动态阶段表与 stages.py 的 13 个设备阶段一致', () => {
  const dyn = source.slice(source.indexOf('function liveDynamicStages'),
    source.indexOf('function appendStageStatus'));
  // 抽两组：`[...].indexOf(`（liveDynamicStages）与 `[...].forEach(`（dynamicStageRows）。
  // 整段里的 'pending' 是状态值，不是阶段 id。
  const arrays = [...dyn.matchAll(/\[((?:\s*'[a-z_]+'\s*,?)+)\]\s*\.(?:indexOf|forEach)/g)]
    .map(m => [...m[1].matchAll(/'([a-z_]+)'/g)].map(x => x[1]));
  assert.equal(arrays.length, 2, `应抽出两张阶段表，实际 ${arrays.length}`);
  arrays.forEach((ids, index) => {
    assert.deepEqual([...ids].sort(), [...EXPECTED_ROWS].sort(),
      `第 ${index + 1} 张表与期望不一致（增减一项都算漂移）`);
    ids.forEach(id => {
      assert.ok(DYNAMIC.includes(id), `动态表引用了非设备阶段 ${id}`);
    });
  });
  assert.equal(DYNAMIC.length, 13, 'stages.py 的设备阶段应为 13 个');
});

check('阶段数只写在状态栏一处，且等于后端真实条数', () => {
  const label = /<span>(\d+) STAGES<\/span>/.exec(html);
  assert.ok(label, 'app.html 缺少 "N STAGES" 标注');
  assert.equal(Number(label[1]), STAGES.length);
});

check('app.html 里时间线与连接状态节点确实存在（桩会懒造，不能只看有没有渲染）', () => {
  ['id="pipeline-timeline"', 'class="service-addr', 'class="status-dot']
    .forEach(marker => assert.ok(html.includes(marker), `app.html 缺少 ${marker}`));
});

const failed = checks.filter(c => !c.ok);
checks.forEach(c => console.log((c.ok ? 'PASS ' : 'FAIL ') + c.name + (c.msg ? ' :: ' + c.msg : '')));
console.log(`pipeline contract: ${checks.length - failed.length}/${checks.length} passed`);
if (failed.length) process.exitCode = 1;
