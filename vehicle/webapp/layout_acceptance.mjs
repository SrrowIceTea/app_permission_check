// Visual geometry regression: real retained jobs plus explicitly synthetic running layout.
// Does not start captures, upload APKs or alter evidence/job state.
import {spawn} from 'node:child_process';
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';

const out = path.resolve(process.env.VSCAN_LAYOUT_OUT || 'output/vehicle-ui-redesign', 'layout-' + Date.now());
await mkdir(out, {recursive:true});
const profile = path.join(out, 'chrome');
const child = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe', [
  '--headless=new','--disable-gpu','--no-first-run','--disable-background-networking',
  '--remote-debugging-port=0','--user-data-dir=' + profile,'about:blank'
], {windowsHide:true,stdio:'ignore'});
const checks = {}, errors = [], geometry = {}, fontRequests = [];
let ws;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
try {
  let port;
  for(let i=0;i<100;i++) {
    try {port=(await readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}
    catch {await sleep(100);}
  }
  if(!port) throw new Error('Chrome did not start');
  const targets=await (await fetch(`http://127.0.0.1:${port}/json`)).json();
  ws=new WebSocket(targets.find(t=>t.type==='page').webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  let seq=0;const pending=new Map();
  ws.onmessage=e=>{
    const message=JSON.parse(e.data);
    if(message.method==='Runtime.exceptionThrown') errors.push(message.params.exceptionDetails);
    if(message.method==='Network.requestWillBeSent' && message.params.type==='Font') fontRequests.push(message.params.request.url);
    const promise=pending.get(message.id);
    if(promise){pending.delete(message.id);message.error?promise.reject(message.error):promise.resolve(message.result);}
  };
  const send=(method,params={})=>new Promise((resolve,reject)=>{
    const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));
  });
  const evaluate=async expression=>{
    const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
    return result.result?.value;
  };
  const wait=async expression=>{
    for(let i=0;i<150;i++){if(await evaluate(expression))return;await sleep(100);}
    throw new Error('Timed out: '+expression);
  };
  const shot=async name=>writeFile(path.join(out,name+'.png'),
    Buffer.from((await send('Page.captureScreenshot',{format:'png'})).data,'base64'));
  const dimensions=async()=>evaluate(`(()=>{
    const r=id=>{const n=document.getElementById(id),b=n.getBoundingClientRect();
      return {top:b.top,bottom:b.bottom,left:b.left,right:b.right,width:b.width,height:b.height,
        display:getComputedStyle(n).display,visibility:getComputedStyle(n).visibility,opacity:getComputedStyle(n).opacity};};
    const h=document.querySelector('.stage-brand').getBoundingClientRect();
    return {heading:{top:h.top,bottom:h.bottom},form:r('audit-options'),result:r('pipeline-result'),
      progress:r('pipeline-progress'),upload:r('pipeline-dropzone'),
      viewport:innerWidth,scroll:document.documentElement.scrollWidth,
      pane:document.querySelector('.page-container').clientWidth,paneScroll:document.querySelector('.page-container').scrollWidth};
  })()`);
  await send('Page.enable');await send('Runtime.enable');await send('Network.enable');
  const jobs=await (await fetch('http://127.0.0.1:8773/api/pipeline')).json();
  const complete=jobs.find(j=>j.state==='done'),failed=jobs.find(j=>j.state==='failed');
  if(!complete || !failed) throw new Error('Retained completed/failed jobs required');
  for(const [width,height] of [[1440,960],[1920,1080],[390,844]]){
    const label=String(width);
    await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<600});
    await send('Page.navigate',{url:'http://127.0.0.1:8773/'});
    await wait("document.getElementById('service-state')?.textContent.includes('已连接')");
    await evaluate('document.fonts.ready.then(()=>true)');
    await evaluate(`document.getElementById('apk-switch').value=${JSON.stringify(complete.id)};
      document.getElementById('apk-switch').dispatchEvent(new Event('change'));`);
    await wait("document.querySelectorAll('#pipeline-timeline .pl-done').length > 0");
    await sleep(250);
    const done=geometry[label+'-done']=await dimensions();
    checks[label+'_result_below_heading']=done.result.top>=done.heading.bottom+16;
    checks[label+'_progress_below_result']=done.progress.top>=done.result.bottom+16;
    checks[label+'_options_hidden_after_completion']=done.form.display==='none';
    checks[label+'_result_card_left_aligned']=await evaluate("Math.abs(document.querySelector('.pipeline-card').getBoundingClientRect().left-document.querySelector('.stage-brand').getBoundingClientRect().left)<1");
    checks[label+'_progress_visible']=done.progress.visibility==='visible' && done.progress.opacity==='1';
    checks[label+'_no_horizontal_overflow']=done.scroll<=width && done.paneScroll<=done.pane;
    checks[label+'_filename_uses_readable_ui_type']=await evaluate("getComputedStyle(document.getElementById('current-apk-name')).fontFamily.includes('Manrope') && parseFloat(getComputedStyle(document.getElementById('current-apk-name')).fontSize)>=12");
    checks[label+'_local_chinese_fonts_loaded']=await evaluate(`document.fonts.check('400 40px "Noto Serif SC"','车载应用审计') && document.fonts.check('400 14px "Noto Sans SC"','当前应用') && document.fonts.check('600 14px "Manrope"','authorized-fixture.apk')`);
    await shot(label+'-completed');
    await evaluate(`document.getElementById('apk-switch').value=${JSON.stringify(failed.id)};
      document.getElementById('apk-switch').dispatchEvent(new Event('change'));`);
    await sleep(200);
    const failure=geometry[label+'-failed']=await dimensions();
    checks[label+'_failure_keeps_flow']=failure.result.top>=failure.heading.bottom+16 && failure.progress.top>=failure.result.bottom+16;
    await shot(label+'-failed');
    await evaluate("document.getElementById('new-audit').click()");
    const idle=geometry[label+'-idle']=await dimensions();
    checks[label+'_form_below_heading']=idle.form.top>=idle.heading.bottom+16;
    checks[label+'_upload_below_form']=idle.upload.top>=idle.form.bottom+16;
    checks[label+'_upload_aligned_with_form']=Math.abs(idle.upload.left-idle.form.left)<1 && Math.abs(idle.upload.right-idle.form.right)<1;
    checks[label+'_new_audit_restores_options']=idle.form.display!=='none';
    await shot(label+'-idle');
    if(width===390){
      await evaluate("document.getElementById('audit-mode').value='live';document.getElementById('audit-mode').dispatchEvent(new Event('change'));");
      checks.mobile_live_form_fits=await evaluate("document.querySelector('.page-container').scrollWidth<=document.querySelector('.page-container').clientWidth");
      await shot('390-live-options');
    }
    await evaluate(`document.getElementById('audit-stage').dataset.state='running';
      document.getElementById('pipeline-progress').style.display='';
      document.getElementById('pipeline-job').textContent='布局检查 · 合成运行态';`);
    const running=geometry[label+'-synthetic-running']=await dimensions();
    checks[label+'_running_below_heading']=running.progress.top>=running.heading.bottom+16 && running.form.display==='none';
    await shot(label+'-running');
  }
  checks.background_http_ok=(await fetch('http://127.0.0.1:8773/assets/vehicle-studio.png')).ok;
  checks.background_loaded=await evaluate(`(async()=>{const image=new Image();image.src='/assets/vehicle-studio.png';await image.decode();return image.naturalWidth>1000;})()`);
  checks.no_javascript_exceptions=errors.length===0;
  checks.font_requests_stay_local=fontRequests.length>0 && fontRequests.every(url=>url.startsWith('http://127.0.0.1:8773/assets/fonts/'));
  const result={passed:Object.values(checks).every(Boolean),evidence_kind:'browser_layout_geometry_real_history_and_synthetic_running',checks,geometry,errors,fontRequests};
  await writeFile(path.join(out,'verification.json'),JSON.stringify(result,null,2));
  console.log(JSON.stringify({out,...result}));
  if(!result.passed)process.exitCode=1;
  await send('Browser.close').catch(()=>{});
} catch(error){
  await writeFile(path.join(out,'verification.json'),JSON.stringify({passed:false,checks,geometry,errors,error:String(error)},null,2));
  console.error(String(error));process.exitCode=1;
} finally {if(ws)ws.close();child.kill();}
