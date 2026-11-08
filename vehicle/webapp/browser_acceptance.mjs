// Real Chrome against the local service. Isolated profile; no personal browser state.
// Usage: node vehicle/webapp/browser_acceptance.mjs <apk> <capture-label-fragment>
import {spawn} from 'node:child_process';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';

const apk = path.resolve(process.argv[2]);
const captureLabel = process.argv[3];
const base = 'http://127.0.0.1:8773';
const out = path.resolve('output/vehicle-frontend-acceptance/browser-' + Date.now());
await mkdir(out, {recursive:true});
const profile = path.join(out, 'chrome');
const child = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
  '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'
], {windowsHide:true, stdio:'ignore'});
let ws, jobId;
const checks = {}, errors = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  let port;
  for (let i=0;i<100;i++) {
    try { port = (await readFile(path.join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]; break; }
    catch { await sleep(100); }
  }
  if (!port) throw new Error('Chrome did not start');
  const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  ws = new WebSocket(targets.find(x => x.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve,reject) => {ws.onopen=resolve;ws.onerror=reject;});
  let id = 0; const pending = new Map();
  ws.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
    if (pending.has(message.id)) {
      const p = pending.get(message.id); pending.delete(message.id);
      if (message.error) p.reject(message.error); else p.resolve(message.result);
    }
  };
  const send = (method,params={}) => new Promise((resolve,reject) => {
    const key=++id;pending.set(key,{resolve,reject});ws.send(JSON.stringify({id:key,method,params}));
  });
  const evaluate = async expression => {
    const result = await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result?.value;
  };
  const wait = async (expression,limit=1200) => {
    for(let i=0;i<limit;i++) {if(await evaluate(expression)) return;await sleep(250);}
    throw new Error('Timed out: '+expression);
  };
  const shot = async name => writeFile(path.join(out,name+'.png'),
    Buffer.from((await send('Page.captureScreenshot',{format:'png'})).data,'base64'));
  await send('Page.enable');await send('Runtime.enable');
  await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  await send('Page.navigate',{url:base});
  await wait("document.getElementById('service-state')?.textContent.includes('已连接')");
  checks.vehicle_title = await evaluate("document.title.includes('车载')");
  checks.seven_pages = await evaluate("document.querySelectorAll('.nav-item').length === 7");
  checks.authorization_default_off = await evaluate("!document.getElementById('authorized').checked");
  await shot('desktop-idle');
  await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
  await sleep(200);
  checks.mobile_no_horizontal_overflow = await evaluate('document.documentElement.scrollWidth <= innerWidth');
  await shot('mobile-idle');
  await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});
  const config = await (await fetch(base+'/api/config')).json();
  const capture = config.captures.find(c => c.label.includes(captureLabel));
  if (!capture) throw new Error('Capture not registered: '+captureLabel);
  await evaluate(`document.getElementById('authorized').checked=true;
    document.getElementById('audit-mode').value='replay';
    document.getElementById('audit-mode').dispatchEvent(new Event('change'));
    document.getElementById('capture-choice').value=${JSON.stringify(capture.id)};`);
  const doc = await send('DOM.getDocument');
  const input = await send('DOM.querySelector',{nodeId:doc.root.nodeId,selector:'#pipeline-apk-input'});
  const previousJob = await evaluate('window.VehicleUI.current || null');
  await send('DOM.setFileInputFiles',{nodeId:input.nodeId,files:[apk]});
  await wait(`!!window.VehicleUI?.current && window.VehicleUI.current !== ${JSON.stringify(previousJob)}`);
  jobId = await evaluate('window.VehicleUI.current');
  await shot('upload-running');
  console.log('Browser uploaded job '+jobId+'; waiting for real workflow');
  await wait("document.getElementById('audit-stage').dataset.state === 'done'");
  const row = await (await fetch(base+'/api/pipeline/'+jobId)).json();
  checks.real_replay_completed = row.state === 'done';
  checks.session_bound = !!row.result.session;
  await shot('completed');
  if(row.state !== 'done') throw new Error(JSON.stringify(row.result));
  const click = page => evaluate(`document.querySelector('[data-page="${page}"]').click()`);
  await click('static');await wait("document.querySelectorAll('#static-results .results-table').length > 0");
  checks.static_rows_loaded = true;await shot('static');
  await click('source');await wait("!!document.querySelector('#file-tree button')");
  await evaluate("document.querySelector('#file-tree button').click()");
  await wait("document.querySelector('#code-view .code-content')?.textContent.length > 0");
  checks.source_opened = true;await shot('source');
  await click('dynamic');await wait("document.querySelectorAll('#dynamic-results .results-table').length > 0");
  checks.evidence_details = await evaluate("document.querySelectorAll('#dynamic-results details').length > 1");
  await shot('dynamic');
  await click('ai-report');await wait("document.getElementById('ai-report').textContent.includes('未执行 AI')");
  checks.ai_skip_visible = true;
  await click('pdf-report');await wait("!!document.querySelector('#report-library button')");
  await evaluate("document.querySelector('#report-library button').click()");
  checks.pdf_link_is_current_job = await evaluate(`document.querySelector('#pdf-viewer-container iframe').src.includes(${JSON.stringify(jobId)})`);
  const pdf = await fetch(base+'/api/pipeline/'+jobId+'/report');
  checks.real_pdf = pdf.ok && Buffer.from(await pdf.arrayBuffer()).subarray(0,5).toString() === '%PDF-';
  await shot('report');
  await send('Page.reload');
  await wait(`window.VehicleUI?.current === ${JSON.stringify(jobId)}`);
  checks.history_restored_after_reload = true;
  await evaluate("document.getElementById('new-audit').click()");
  await click('static');
  checks.new_audit_clears_previous_results = await evaluate(
    "!document.querySelector('#static-results table') && document.getElementById('static-results').textContent.includes('请先')");
  checks.no_javascript_exceptions = errors.length === 0;
  await writeFile(path.join(out,'verification.json'),JSON.stringify({passed:Object.values(checks).every(Boolean),
    evidence_kind:'real_browser_upload_and_historical_capture_replay',jobId,capture,apk,checks,errors},null,2));
  console.log(JSON.stringify({out,jobId,checks,errors}));
  if (!Object.values(checks).every(Boolean)) process.exitCode=1;
  await send('Browser.close').catch(()=>{});
} catch(error) {
  await writeFile(path.join(out,'verification.json'),JSON.stringify({passed:false,jobId,checks,errors,error:String(error)},null,2));
  console.error(String(error));process.exitCode=1;
} finally {if(ws)ws.close();child.kill();}
