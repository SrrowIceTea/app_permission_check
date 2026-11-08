// Read-only real Chrome test. No upload, capture, task mutation or personal profile.
// Usage: node vehicle/webapp/review_acceptance.mjs <base-url> [--synthetic]
import {spawn} from 'node:child_process';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';

const base = process.argv[2] || 'http://127.0.0.1:8773';
if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)) throw new Error('Loopback URL required');
const synthetic = process.argv.includes('--synthetic');
const workflowLabels = {supported:'业务链有证据支持', insufficient:'证据不足', static_only:'仅静态完成'};
const reviewLabels = {signed:'已签核', pending:'待签核'};
const out = path.resolve('output/vehicle-review-browser', 'review-' + Date.now());
await mkdir(out, {recursive:true});
const profile = path.join(out, 'chrome');
const child = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new', '--disable-gpu', '--no-first-run', '--disable-background-networking',
  '--remote-debugging-port=0', '--user-data-dir=' + profile, 'about:blank'
], {windowsHide:true, stdio:'ignore'});
const checks = {}, errors = [], requests = [];
let ws;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  let port;
  for (let i=0;i<100;i++) {
    try {port=(await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}
    catch {await sleep(100);}
  }
  if (!port) throw new Error('Chrome did not start');
  const targets=await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  ws=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let seq=0; const pending=new Map();
  ws.onmessage=e=>{
    const m=JSON.parse(e.data);
    if(m.method==='Runtime.exceptionThrown') errors.push(m.params.exceptionDetails);
    if(m.method==='Network.requestWillBeSent') requests.push(m.params.request.url);
    const p=pending.get(m.id);
    if(p){pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(m.error):p.resolve(m.result);}
  };
  ws.onclose=()=>{
    for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error('Chrome connection closed'));}
    pending.clear();
  };
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++seq,timer=setTimeout(()=>{pending.delete(id);reject(new Error('Chrome command timed out: '+method));},10000);
    pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
  });
  const evaluate=async expression=>{
    const r=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
    return r.result?.value;
  };
  const wait=async expression=>{
    for(let i=0;i<100;i++){if(await evaluate(expression))return;await sleep(100);}
    throw new Error('Timed out: '+expression);
  };
  const data=await (await fetch(base+'/api/review-round')).json();
  if(data.error) throw new Error(data.error.message);
  await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
  for(const [width,height] of [[1440,1000],[390,844]]) {
    await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
    await send('Page.navigate',{url:base+'/#review'});
    await wait(`document.getElementById('review-round')?.dataset.round === ${JSON.stringify(data.round_id)}`);
    await evaluate('document.fonts.ready');
    checks[width+'_seven_pages']=await evaluate("document.querySelectorAll('.nav-item').length===7");
    checks[width+'_all_cases']=await evaluate(`document.querySelectorAll('.review-case').length===${data.cases.length}`);
    checks[width+'_separate_round']=await evaluate("document.querySelector('#page-review .page-head').textContent.includes('不随当前 APK')");
    checks[width+'_subagent_label']=await evaluate("document.getElementById('review-round').textContent.includes('不代表人工签核')");
    checks[width+'_no_overflow']=await evaluate("document.documentElement.scrollWidth<=innerWidth && document.querySelector('.page-container').scrollWidth<=document.querySelector('.page-container').clientWidth");
    checks[width+'_inert_findings']=await evaluate("!document.querySelector('#review-round img,#review-round script')");
    checks[width+'_counts']=await evaluate(`(()=>{const t=document.querySelector('.review-threshold').textContent;return t.includes('本轮新增证据（历史 HA 单列）')&&t.includes(${JSON.stringify('：' + data.counts.independent_apps + ' / ' + data.counts.required_independent_apps)})&&t.includes(${JSON.stringify('：' + data.counts.reference_pairs + ' / ' + data.counts.required_reference_pairs)});})()`);
    checks[width+'_bindings']=await evaluate(`${JSON.stringify(Object.values(data.bindings))}.every(value=>document.querySelector('#review-round .evidence-json').textContent.includes(value))`);
    for(const item of data.cases) {
      checks[width+'_case_'+item.id]=await evaluate(`(()=>{const n=Array.from(document.querySelectorAll('.review-case')).find(n=>n.dataset.case===${JSON.stringify(item.id)});return n.textContent.includes(${JSON.stringify(workflowLabels[item.workflow_status] || '状态未说明')})&&n.textContent.includes(${JSON.stringify(reviewLabels[item.review_status] || '未提供复核结论')});})()`);
      checks[width+'_findings_'+item.id]=await evaluate(`(()=>{const n=Array.from(document.querySelectorAll('.review-case')).find(n=>n.dataset.case===${JSON.stringify(item.id)});return ${JSON.stringify([...item.eligibility_reasons,...item.findings])}.every(text=>n.textContent.includes(text));})()`);
      checks[width+'_sessions_'+item.id]=await evaluate(`(()=>{const n=Array.from(document.querySelectorAll('.review-case')).find(n=>n.dataset.case===${JSON.stringify(item.id)});return ${JSON.stringify(item.session_ids)}.every(text=>n.textContent.includes(text));})()`);
      if(item.eligibility==='workflow_only') checks[width+'_workflow_only_'+item.id]=await evaluate(`Array.from(document.querySelectorAll('.review-case')).find(n=>n.dataset.case===${JSON.stringify(item.id)}).textContent.includes('仅验证工作流 · 不计分')`);
    }
    await writeFile(path.join(out,width+'.png'),Buffer.from((await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true})).data,'base64'));
    await evaluate("document.querySelector('#review-round details').open=true;document.querySelector('#review-round details').scrollIntoView({block:'end'})");
    await writeFile(path.join(out,width+'-bindings.png'),Buffer.from((await send('Page.captureScreenshot',{format:'png'})).data,'base64'));
    const before=await evaluate("document.getElementById('review-round').textContent");
    const switched=await evaluate("(()=>{const s=document.getElementById('apk-switch');if(s.options.length<2)return false;s.selectedIndex=s.selectedIndex===0?1:0;s.dispatchEvent(new Event('change'));return true;})()");
    if(switched){await wait("document.querySelectorAll('.review-case').length>0");checks[width+'_history_independent']=await evaluate(`document.getElementById('review-round').textContent===${JSON.stringify(before)}`);}
  }
  checks.no_exceptions=errors.length===0;
  checks.local_assets=requests.filter(url=>!url.startsWith('data:')).every(url=>url.startsWith(base+'/'));
  const result={passed:Object.values(checks).every(Boolean),
    evidence_kind:synthetic?'synthetic_browser_fixture_not_signoff':'read_only_published_review_browser',
    round_id:data.round_id,checks,errors};
  await writeFile(path.join(out,'verification.json'),JSON.stringify(result,null,2));
  console.log(JSON.stringify({out,...result}));
  if(!result.passed)process.exitCode=1;
  await send('Browser.close').catch(()=>{});
} catch(error) {
  await writeFile(path.join(out,'verification.json'),JSON.stringify({passed:false,synthetic,checks,errors,error:String(error)},null,2));
  console.error(String(error));process.exitCode=1;
} finally {if(ws)ws.close();child.kill();}
