import {get,post,upload} from './api.js';
import {state,update,selectedTask,navigate} from './state.js';
import {h,icon,badge,empty,toast} from './ui.js';
import {renderTasks} from './tasks.js';
import {renderStatic} from './static.js';
import {renderEvidence} from './evidence.js';
import {renderPolicy} from './policy-ai.js';
import {renderReports} from './reports.js';
import {captureValidation,operationLabel} from './workflow-model.js';
const views={tasks:['任务总览','grid',renderTasks],static:['静态发现','scan',renderStatic],evidence:['动态证据','pulse',renderEvidence],policy:['政策与研判','book',renderPolicy],reports:['报告中心','report',renderReports]};
let renderSequence=0,pollTimer=null;
function identity(){
 const node=document.querySelector('#identity');const task=selectedTask();if(!task){node.replaceChildren();return;}
 const select=h('select',{class:'identity-select','aria-label':'选择当前检测任务',onchange:e=>update({selected:e.target.value})},state.tasks.map(t=>h('option',{value:t.id,selected:t.id===task.id},t.name||t.id)));
 const apk=task.apk||{};const digest=apk.sha256||apk.apk_sha256;
 node.replaceChildren(h('div',{class:'identity'},icon('file'),h('strong',{},task.name||apk.name||task.id),badge(task.mode==='static'?'neutral':'partial',task.mode==='static'?'静态任务':task.origin==='device_capture'?'夹具采集':'证据导入'),h('span',{class:'mono'},digest?`SHA256 ${digest.slice(0,16)}…`:'APK 摘要未提供'),h('span',{class:'muted'},`规则 ${task.rules?.version||'未提供'}`),select),h('div',{class:'context-stages'},[['static','静态扫描'],['decompile','源码反编译'],['dynamic','动态证据'],['ai','AI 研判'],['report','报告']].map(([key,label])=>h('div',{class:'stage-pill',title:task.stages?.[key]?.reason||''},label,badge(task.stages?.[key]?.state||'not_requested')))));
}
async function render(){
 const token=++renderSequence;
 const id=location.hash.slice(1);state.view=views[id]?id:'tasks';
 document.querySelector('#breadcrumb-title').textContent=views[state.view][0];
 const nav=document.querySelector('#navigation');nav.replaceChildren(...Object.entries(views).map(([key,[label,name]],index)=>h('button',{class:`nav-item ${key===state.view?'active':''}`,'aria-current':key===state.view?'page':null,onclick:()=>{navigate(key);closeMenu();}},icon(name),label,h('span',{class:'nav-number'},`0${index+1}`))));
 identity();const view=document.querySelector('#view');
 if(!['tasks','reports'].includes(state.view))view.replaceChildren(h('div',{class:'loading'},'读取本地证据…'));
 try{const content=await views[state.view][2]();if(token===renderSequence)view.replaceChildren(content);}catch(error){if(token===renderSequence)view.replaceChildren(empty('数据暂不可用',error.message,'link'));}
 document.title=`${views[state.view][0]} · Permission Lab`;
 const service=document.querySelector('#service-badge');service.textContent=state.health?'移动端服务在线':'本地服务未连接';service.className=`status-tag ${state.health?'online':'offline'}`;
}
async function refresh(){
 try{
  const [health,tasks,reports]=await Promise.all([get('/api/health'),get('/api/tasks'),get('/api/reports')]);
  if(health.platform!=='mobile')throw new Error('请启动 mobile/workbench/server.py，当前连接的不是移动端服务。');
  const all=Array.isArray(tasks.tasks)?tasks.tasks:[];const selected=all.some(t=>t.id===state.selected)?state.selected:all[0]?.id||null;
  update({health,tasks:all,reports:(reports.reports||[]).filter(r=>r.available),selected,error:null});
 }catch(error){update({health:null,error:`${error.message} 启动命令：.\.venv\Scripts\python.exe mobile/workbench/server.py --port 8770`});}
}
async function acceptApk(file){
 if(state.busy)return;if(!file.name.toLowerCase().endsWith('.apk')){toast('请选择 .apk 文件。',true);return;}
 if(!file.size){toast('APK 文件为空。',true);return;}
 update({busy:true,job:null});
 try{const result=await upload(file);state.selected=result.task_id;await refresh();toast(result.cached?'已建立任务，复用匹配的静态缓存。':'APK 已接收，后台分析已开始。');navigate('tasks');await poll(result.job_id||result.job?.id||result.job);}catch(error){toast(error.message,true);}finally{update({busy:false});}
}
async function importBundle(file){
 if(state.busy)return;if(file.size>16*1024*1024){toast('证据包超过 16 MB，请使用精简脱敏的 JSON。',true);return;}
 update({busy:true});
 try{const value=JSON.parse(await file.text());const result=await post('/api/evidence/import',value);state.selected=result.task_id;await refresh();toast('证据包已导入，计数按实际条目计算。');navigate('evidence');}catch(error){toast(error instanceof SyntaxError?'JSON 解析失败，请检查证据包格式。':error.message,true);}finally{update({busy:false});}
}
async function poll(id){
 clearTimeout(pollTimer);if(!id)return;
 try{const job=await get(`/api/jobs/${encodeURIComponent(id)}`);update({job});await refresh();
  if(['queued','running'].includes(job.state)){pollTimer=setTimeout(()=>poll(id),1500);}else{if(job.state==='failed')toast(job.error||'任务失败，原始产物已保留。',true);else if(job.state==='done'){
   toast(`${operationLabel(job.operation)}处理完成，请查看本轮结果与覆盖缺口。`);
   if(state.selected===job.task_id&&job.operation==='capture')navigate(selectedTask()?.stages?.report?.state==='done'?'reports':'evidence');
   if(state.selected===job.task_id&&job.operation==='report')navigate('reports');
  }}
 }catch(error){toast(`任务状态读取失败：${error.message}`,true);}
}
async function probeDevices(){
 if(state.deviceProbeBusy||state.busy)return;
 update({deviceProbeBusy:true,workflowError:null});
 try{const result=await get('/api/devices');const devices=Array.isArray(result.devices)?result.devices:[];
  if(!devices.some(d=>d.serial===state.captureOptions.serial&&d.state==='device'))state.captureOptions.serial='';
  state.captureOptions.authorized=false;
  update({devices,devicesObservedAt:result.observed_at,deviceReason:result.reason||null});
 }catch(error){update({devices:[],deviceReason:error.message,workflowError:error.message});}
 finally{update({deviceProbeBusy:false});}
}
async function runOperation(operation,options={}){
 const task=selectedTask();if(!task||state.busy)return;
 const error=operation==='capture'?captureValidation(options,state.devices):null;
 if(error){update({workflowError:error});return;}
 update({busy:true,workflowError:null,job:null});
 try{const result=await post(`/api/tasks/${encodeURIComponent(task.id)}/${operation}`,options);
  await refresh();toast(operation==='capture'?'已开始自有夹具采集，原始会话将保存在当前任务。':'报告生成已开始。');
  await poll(result.job_id);
 }catch(error){update({workflowError:error.message});toast(error.message,true);}
 finally{update({busy:false});}
}
function syncMenu(){const sidebar=document.querySelector('#sidebar');const hidden=matchMedia('(max-width:760px)').matches&&!sidebar.classList.contains('open');sidebar.inert=hidden;sidebar.setAttribute('aria-hidden',String(hidden));}
function closeMenu(){document.querySelector('#sidebar').classList.remove('open');document.querySelector('#menu-toggle').setAttribute('aria-expanded','false');syncMenu();}
window.addEventListener('hashchange',render);window.addEventListener('lab:change',render);
window.addEventListener('lab:upload',e=>acceptApk(e.detail));window.addEventListener('lab:import',e=>importBundle(e.detail));
window.addEventListener('lab:devices',probeDevices);
window.addEventListener('lab:capture',e=>runOperation('capture',e.detail));
window.addEventListener('lab:report',()=>runOperation('report'));
window.addEventListener('lab:cancel',async()=>{if(!state.job)return;try{const result=await post(`/api/jobs/${state.job.id}/cancel`,{});if(result.cancelled){update({job:{...state.job,cancellation_requested:true}});toast(result.note||'已请求取消，当前步骤结束后清理并停止。');}else toast('任务已结束或无法取消。',true);}catch(error){toast(error.message,true);}});
for(const [id,handler] of [['apk-input',acceptApk],['bundle-input',importBundle]])document.querySelector(`#${id}`).addEventListener('change',e=>{const file=e.target.files[0];e.target.value='';if(file)handler(file);});
document.querySelector('.skip-link').addEventListener('click',e=>{e.preventDefault();const workspace=document.querySelector('#workspace');workspace.focus();workspace.scrollIntoView({block:'start'});});
document.querySelector('#refresh').addEventListener('click',refresh);
document.querySelector('#menu-toggle').addEventListener('click',()=>{const open=document.querySelector('#sidebar').classList.toggle('open');document.querySelector('#menu-toggle').setAttribute('aria-expanded',String(open));syncMenu();});
document.addEventListener('click',e=>{if(!e.target.closest('#sidebar')&&!e.target.closest('#menu-toggle'))closeMenu();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeMenu();});
matchMedia('(max-width:760px)').addEventListener('change',syncMenu);syncMenu();
await render();await refresh();
const active=state.tasks.find(t=>['queued','running'].includes(t.state)&&t.job_id);if(active)poll(active.job_id);
