import {state,selectedTask} from './state.js';
import {h,button,badge,panel} from './ui.js';
import {auditState,auditDefaults,auditDevices,auditValidation,auditStages,defaultScenario} from './audit-model.js';
const modeNames={'nonroot-gadget':'非 root · Gadget 重签衍生包','root-emulator':'Root 模拟器 · 原始 APK'};
const scenarioNames={launch:'启动与有限界面探索','launch-only':'仅启动观察',libchecker:'LibChecker 应用列表',readyou:'Read You 首次运行',fixture:'自有隐私正控','ghera-ecb':'Ghera ECB 对照','ghera-cbc':'Ghera CBC 对照','legacy-review':'旧版系统权限复核'};
function emit(name,detail){window.dispatchEvent(new CustomEvent(name,{detail}));}
export function auditPanel(){
 const task=selectedTask(),info=auditState(task,state.busy);
 if(state.auditTask!==task?.id){state.auditTask=task?.id;state.auditOptions=auditDefaults(task);}
 const opts=state.auditOptions||(state.auditOptions=auditDefaults(task));
 if(!opts.mode&&info.modes.length){opts.mode=info.modes[0];opts.scenario=defaultScenario(task);}
 const start=button('运行完整检测（含AI）',()=>emit('lab:audit',{...opts}),'primary','pulse');
 const message=h('p',{class:'workflow-hint',role:'status'});
 function revoke(){opts.authorized=false;authorization.checked=false;}
 function sync(){const error=auditValidation(opts,state.devices,task,state.busy);start.disabled=!!error||state.deviceProbeBusy;message.textContent=error||'就绪：原 APK 身份绑定、真实动态采集、三阶段 AI 及 PDF 将在当前任务中执行。';}
 const probe=button(state.deviceProbeBusy?'正在检测…':'检测连接设备',()=>emit('lab:devices'),'secondary','link');
 probe.disabled=info.active||state.deviceProbeBusy||!state.health;
 const mode=h('select',{id:'audit-mode',class:'workflow-select',disabled:info.active||!info.canAudit,onchange:e=>{opts.mode=e.target.value;opts.pcap_sidecar=false;vpn.checked=false;vpn.disabled=opts.mode!=='nonroot-gadget';revoke();sync();}},
  info.modes.length?null:h('option',{value:''},'服务尚未提供可用检测模式'),info.modes.map(m=>h('option',{value:m,selected:opts.mode===m},modeNames[m])));
 const available=auditDevices(task,state.devices);
 const device=h('select',{id:'audit-device',class:'workflow-select',disabled:info.active||state.deviceProbeBusy||!info.canAudit,onchange:e=>{opts.serial=e.target.value;revoke();sync();}},
  h('option',{value:'',selected:!opts.serial},state.devices===null?'先检测，再选择正控模拟器':available.length?'选择正控模拟器':'正控模拟器未在线'),available.map(d=>h('option',{value:d.serial,selected:opts.serial===d.serial},`${d.serial} · ${d.model||'在线'}`)));
 const scenario=h('select',{id:'audit-scenario',class:'workflow-select',disabled:info.active||!info.canAudit,onchange:e=>{opts.scenario=e.target.value;revoke();sync();}},info.scenarios.map(s=>h('option',{value:s,selected:opts.scenario===s},scenarioNames[s]||s)));
 const seconds=h('input',{id:'audit-seconds',type:'number',min:5,max:180,step:1,value:opts.seconds,disabled:info.active,onchange:e=>{opts.seconds=Number(e.target.value);revoke();sync();}});
 const vpn=h('input',{type:'checkbox',checked:opts.pcap_sidecar,disabled:info.active||opts.mode!=='nonroot-gadget',onchange:e=>{opts.pcap_sidecar=e.target.checked;revoke();sync();}});
 const authorization=h('input',{type:'checkbox',checked:opts.authorized,disabled:info.active,onchange:e=>{opts.authorized=e.target.checked;sync();}});
 const steps=h('ol',{class:'workflow-steps'},auditStages(task).map((s,i)=>h('li',{title:s.reason},h('span',{class:'workflow-step-number'},String(i+1).padStart(2,'0')),h('div',{},h('strong',{},s.label),badge(s.state)))));
 sync();
 return panel('真实 APK 完整检测','当前任务原始 APK → 实际采集 → 三阶段 AI → PDF',h('div',{},steps,
  h('p',{class:'workflow-hint'},info.reason),
  h('label',{class:'workflow-field',for:'audit-mode'},'检测模式',mode),
  h('div',{class:'workflow-device-picker'},h('label',{for:'audit-device'},'正控同设备',device),probe),
  h('p',{class:'workflow-hint'},info.serial?`仅可选择与本服务真实正控一致的 ${info.serial}；不会自动连接其他设备。`:'服务尚未提供已通过真实正控的设备。'),
  h('label',{class:'workflow-field',for:'audit-scenario'},'实际交互场景',scenario),
  h('label',{class:'workflow-field',for:'audit-seconds'},'场景完成后的观察秒数（5–180）',seconds),
  h('label',{class:'workflow-check'},vpn,'采集所选应用的 VPN 包（仅非 root；需在模拟器正常确认授权，最多等待 180 秒）'),
  h('p',{class:'workflow-hint'},'非 root 安装的是 Gadget 重签衍生包，可能影响签名校验与业务行为；不承诺任意 APK 兼容或所有协议解密。'),
  h('label',{class:'workflow-check'},authorization,'我已获此 APK 的检测授权，允许在所选模拟器安装、运行及必要的重签插桩，并允许把脱敏检测证据和政策文本发送至本机配置的 AI 服务'),
  start,message));
}
