import {workflowPanel} from './workflow.js';
import {get} from './api.js';
import {selectedTask} from './state.js';
import {h,badge,header,empty,panel,metric,keyvalues,json,safeList,tabs,date,button,icon} from './ui.js';
import {chooseBundle} from './tasks.js';
import {runtimePanel} from './runtime.js';
import {collectionState,evidenceGaps,clientTransport} from './evidence-model.js';
function readState(read){return collectionState(read);}
function readCard(read){return h('div',{class:'evidence-item'},h('div',{class:'evidence-title'},h('strong',{},`${read.evidence_id||'—'} · ${read.data_type||read.api||'敏感读取'}`),badge(readState(read))),keyvalues([['API',read.api],['调用结果',read.outcome],['返回数量',read.value_count??read.count],['值预览',read.value_preview],['应用栈',read.app_frame||null],['时间',read.ts!==null&&read.ts!==undefined?date(read.ts):null]]),h('details',{},h('summary',{},'原始读取证据'),json(read)));}
function consentCard(event){return h('div',{class:'evidence-item'},h('div',{class:'evidence-title'},h('strong',{},`${event.evidence_id||'—'} · ${event.signal||event.event||event.kind||event.type||'权限 / 政策事件'}`),badge('neutral',event.signal==='POLICY_VIEW'?'仅浏览（非同意）':event.signal==='PERM_RESULT'?'权限结果（非政策同意）':'无政策同意凭证')),keyvalues([['权限',event.permission||event.permissions],['结果',event.result||event.grants||((event.granted||event.denied)?{granted:event.granted,denied:event.denied}:null)],['数据类型',event.data_type],['时间',event.ts!==null&&event.ts!==undefined?date(event.ts):null]]),h('details',{},h('summary',{},'原始时序证据'),json(event)));}
function flowCard(flow){const transport=clientTransport(flow);return h('div',{class:'evidence-item'},h('div',{class:'evidence-title'},h('strong',{class:'mono'},`${flow.evidence_id||'—'} · ${flow.method||'—'} ${flow.host||'未知主机'}`),badge(transport.tone,transport.label)),keyvalues([['请求路径',flow.path],['敏感标签',flow.request_tags||flow.sensitive_tags],['归因',flow.attribution],['客户端传输',transport.label],['代理上游协议',flow.scheme],['响应码',flow.status_code],['时间',flow.ts!==null&&flow.ts!==undefined?date(flow.ts):null]]),h('details',{},h('summary',{},'原始流量证据'),json(flow)));}
export async function renderEvidence(){
 const root=h('div',{},header('DYNAMIC EVIDENCE','动态证据','只呈现实际采集或导入的结果；明确区分非空返回、空返回与未知状态。',[button('导入证据包',chooseBundle,'primary','book')]));
 const task=selectedTask();if(!task){root.append(panel('会话证据',null,empty('还没有动态证据','导入 mobile/ai 生成的 evidence bundle JSON，查看读取、权限时序和网络流量。','pulse')));return root;}
 root.append(h('div',{class:'section-gap'},workflowPanel()));
 const data=await get(`/api/tasks/${task.id}/evidence`);if(!data.available){root.append(panel('会话证据',null,empty('未采集 ≠ 未发生',data.reason||'当前任务仅有静态分析，没有提供动态采集证据。','pulse')));return root;}
 const bundle=data.bundle||{};const reads=safeList(bundle.dynamic?.reads),consent=safeList(bundle.dynamic?.consent_timeline),flows=safeList(bundle.traffic?.flows);
 root.append(h('div',{class:'metric-grid'},metric('敏感读取事件',reads.length,'含空返回与待核实事件','pulse'),metric('权限 / 政策事件',consent.length,'浏览政策不等于同意','book'),metric('网络流量',flows.length,'来源于此证据包的会话','link'),metric('证据缺口',evidenceGaps(data).length,'缺口需要补充实验，不推断安全','shield')));
 root.append(h('div',{class:'notice'},icon('shield'),task.origin==='imported_bundle'?'证据来自导入文件，未经独立真实性认证。POLICY_VIEW 只证明浏览，不是同意。':'证据来自本任务自有夹具运行；原始会话与摘要留存。POLICY_VIEW 只证明浏览，不是同意。'));
 root.append(runtimePanel(bundle.runtime));
 const content=h('div',{class:'tab-content'});let selected='reads';const choices=[['reads','敏感读取'],['consent','权限与同意时序'],['flows','网络流量'],['health','钩子与覆盖']];
 const tabholder=h('div');function draw(){tabholder.replaceChildren(tabs(choices,id=>{selected=id;draw();},selected));if(selected==='health'){content.replaceChildren(h('div',{class:'panel-body'},h('h3',{},'钩子健康记录'),json(bundle.dynamic?.hook_health||{}),h('ul',{class:'gaps section-gap'},evidenceGaps(data).map(x=>h('li',{},x)))));return;}
 const values=selected==='reads'?reads:selected==='consent'?consent:flows;const renderer=selected==='reads'?readCard:selected==='consent'?consentCard:flowCard;
 content.replaceChildren(values.length? h('div',{},values.map(renderer)):empty('本会话没有提供该类事件','当前包未记录对应数据。这不能证明实际行为不存在。',selected==='flows'?'link':'pulse'));}
 draw();root.append(h('div',{class:'section-gap'},panel('会话证据浏览',`包版本 ${bundle.bundle_version||'未提供'} · ${bundle.app?.package||'应用未标识'} · ${bundle.app?.device||'设备信息未提供'}`,h('div',{},tabholder,content))));return root;
}
