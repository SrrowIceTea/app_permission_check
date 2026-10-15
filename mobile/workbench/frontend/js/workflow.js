import {state,selectedTask,navigate} from './state.js';
import {h,icon,panel,button,badge,date,keyvalues} from './ui.js';
import {workflowState,captureValidation} from './workflow-model.js';
function emit(name,detail){window.dispatchEvent(new CustomEvent(name,{detail}));}
export function workflowPanel(){
 const task=selectedTask();const info=workflowState(task,state.health,state.busy);
 if(state.captureTask!==task?.id){state.captureTask=task?.id;state.captureOptions={serial:'',authorized:false,permission_response:'allow',generate_report:true};}
 const opts=state.captureOptions;
 const start=button('采集并生成报告',()=>emit('lab:capture',{...opts}),'primary','pulse');
 const generate=button('生成本轮报告',()=>emit('lab:report'),'secondary','report');
 const validation=h('p',{class:'workflow-hint',role:'status'});
 function sync(){
  start.textContent=opts.generate_report?'采集并生成报告':'开始设备采集';
  const error=captureValidation(opts,state.devices);
  start.disabled=!info.canCapture||!!error||state.deviceProbeBusy;
  generate.disabled=!info.canReport;
  validation.textContent=!info.canCapture?info.captureReason:error||'就绪：仅运行所选设备上的自有 Gadget 夹具。';
 }
 const probe=button(state.deviceProbeBusy?'正在检测…':'检测连接设备',()=>emit('lab:devices'),'secondary','link');
 probe.disabled=state.deviceProbeBusy||info.active||!state.health;
 const selector=h('select',{id:'capture-device',class:'workflow-select',value:opts.serial,disabled:info.active||state.deviceProbeBusy,onchange:e=>{opts.serial=e.target.value;opts.authorized=false;authorization.checked=false;sync();}},
  h('option',{value:''},state.devices===null?'先检测，再选择设备':'选择设备'),
  (state.devices||[]).map(d=>h('option',{value:d.serial,disabled:d.state!=='device',selected:opts.serial===d.serial},`${d.serial} · ${d.model||d.state}${d.state!=='device'?' · 不可用':''}`)));
 const permission=h('select',{id:'capture-permission',class:'workflow-select',value:opts.permission_response,disabled:info.active,onchange:e=>{opts.permission_response=e.target.value;sync();}},h('option',{value:'allow',selected:opts.permission_response==='allow'},'允许夹具请求的运行时权限'),h('option',{value:'deny',selected:opts.permission_response==='deny'},'拒绝夹具请求的运行时权限'));
 const authorization=h('input',{type:'checkbox',checked:opts.authorized,disabled:info.active,onchange:e=>{opts.authorized=e.target.checked;sync();}});
 const automatic=h('input',{type:'checkbox',checked:opts.generate_report,disabled:info.active,onchange:e=>{opts.generate_report=e.target.checked;sync();}});
 const steps=h('ol',{class:'workflow-steps'},[['01','静态发现',task?.stages?.static?.state],['02','设备采集',task?.stages?.dynamic?.state],['03','本轮报告',task?.stages?.report?.state]].map(([n,label,status])=>h('li',{},h('span',{class:'workflow-step-number'},n),h('div',{},h('strong',{},label),badge(status||'not_requested')))));
 const device=h('div',{class:'workflow-device'},h('div',{class:'workflow-section-title'},icon('pulse'),h('h3',{},'运行设备采集')),
  h('div',{class:'workflow-device-picker'},h('label',{for:'capture-device'},'目标设备',selector),probe),
  h('small',{class:'workflow-hint'},state.devices===null?'不会自动探测设备；点击后只读取连接状态。':`发现 ${state.devices.length} 台设备 · ${date(state.devicesObservedAt)} · ${state.deviceReason||''}`),
  h('label',{class:'workflow-field',for:'capture-permission'},'夹具权限弹窗响应',permission),
  h('label',{class:'workflow-check'},authorization,'我授权安装并运行自有测试夹具'),
  h('label',{class:'workflow-check'},automatic,'采集成功后自动生成本任务报告'),
  start,validation);
 const currentReport=state.reports.find(r=>r.task_id===task?.id&&r.kind==='task');
 const report=h('div',{class:'workflow-report'},h('div',{class:'workflow-section-title'},icon('report'),h('h3',{},'生成证据报告')),
  h('p',{},'使用当前任务的证据包生成 PDF；保留读取状态、流量依据与检测缺口。无需 AI Key。'),
  h('div',{class:'workflow-target'},h('span',{},'当前任务'),h('strong',{},task?.name||'尚未选择任务'),h('small',{class:'mono'},task?.id||'—')),
  generate,h('p',{class:'workflow-hint'},info.canReport?'已有本任务证据，可单独生成或重新生成报告。':info.reportReason),
  currentReport?button('查看本任务报告',()=>navigate('reports'),'ghost','arrow'):null,
  h('p',{class:'workflow-hint'},'自有 Debug 与 Gadget 构建摘要分别留存；本操作不支持任意第三方 APK 注入。'));
 const capture=task?.capture;
 if(capture)report.append(h('details',{class:'workflow-provenance'},h('summary',{},'查看采集来源与构建关系'),keyvalues([
  ['设备',capture.serial],['采集尝试',capture.attempt_id],['上传 APK SHA256',capture.source_apk_sha256],['采集 APK SHA256',capture.capture_apk_sha256],['字节是否相同',capture.same_apk_bytes===true?'是':capture.same_apk_bytes===false?'否':'未提供'],['关系声明',capture.relation_note]])));
 sync();
 const errors=state.workflowError?h('div',{class:'notice error',role:'alert'},icon('close'),state.workflowError):null;
 return panel('检测执行','选择任务 → 授权采集 → 生成本轮报告',h('div',{},steps,h('div',{class:'workflow-grid'},device,report),errors));
}
