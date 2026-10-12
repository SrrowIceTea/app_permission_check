// Local generated frontend only; isolated Chrome profile, no user browsing state.
import {spawn} from 'node:child_process';
import {readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
const out = path.resolve('output/frontend-review');
const profile = path.join(out, 'chrome-viewport-' + Date.now());
const child = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
  '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'
], {windowsHide: true, stdio: 'ignore'});
let ws;
try {
  let port;
  for (let i = 0; i < 60; i++) {
    try { port = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; break; }
    catch { await new Promise(r => setTimeout(r, 100)); }
  }
  if (!port) throw new Error('No Chrome debug port');
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  ws = new WebSocket(targets.find(x => x.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  let id = 0; const pending = new Map();
  ws.onmessage = e => { const m = JSON.parse(e.data); if (pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.reject(m.error) : p.resolve(m.result); } };
  const send = (method, params = {}) => new Promise((resolve, reject) => {
    const key = ++id; pending.set(key, {resolve, reject}); ws.send(JSON.stringify({id:key, method, params}));
  });
  const evaluate = async expression => (await send('Runtime.evaluate', {expression, returnByValue:true})).result.value;
  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', {width:390, height:844, deviceScaleFactor:1, mobile:true});
  await send('Page.navigate', {url:pathToFileURL(path.join(out, 'probe.html')).href + '#mobile'});
  for (let i=0;i<60;i++) {
    if (await evaluate("!!document.getElementById('frontend-qa')")) break;
    await new Promise(r => setTimeout(r,100));
  }
  const result = await evaluate(`({width:innerWidth, scroll:document.documentElement.scrollWidth, checks:JSON.parse(document.getElementById('frontend-qa').textContent)})`);
  if (result.width !== 390 || result.scroll > 390 || !Object.values(result.checks).every(Boolean)) throw new Error(JSON.stringify(result));
  await writeFile(path.join(out, 'mobile.png'), Buffer.from((await send('Page.captureScreenshot', {format:'png'})).data, 'base64'));
  await evaluate("document.getElementById('findings-card').scrollIntoView({behavior:'instant'});");
  await writeFile(path.join(out, 'mobile-findings.png'), Buffer.from((await send('Page.captureScreenshot', {format:'png'})).data, 'base64'));
  await send('Emulation.setDeviceMetricsOverride', {width:1440, height:1080, deviceScaleFactor:1, mobile:false});
  await evaluate("document.querySelector('.location-details').open=true; document.querySelector('.evidence-details').open=true; document.getElementById('findings-card').scrollIntoView({behavior:'instant'});");
  await writeFile(path.join(out, 'evidence.png'), Buffer.from((await send('Page.captureScreenshot', {format:'png'})).data, 'base64'));
  await writeFile(path.join(out, 'viewport-verification.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result));
  await send('Browser.close').catch(()=>{});
} finally { if(ws) ws.close(); child.kill(); }

