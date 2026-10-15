import {get} from './api.js';
import {state,selectedTask} from './state.js';
import {h,icon,button,badge,header,empty,panel,metric,keyvalues,json,safeList,table} from './ui.js';
import {chooseApk} from './tasks.js';
import {renderSource} from './source.js';
export async function renderStatic(){
 const task=selectedTask();const root=h('div',{},header('STATIC ANALYSIS','静态发现','规则命中提供可追溯线索；代码引用不证明运行时收集或违规。'));
 if(!task){root.append(panel('等待选择 APK',null,empty('还没有可分析的任务','回到总览上传 APK，或选择一个已有任务。','scan',button('上传 APK',chooseApk,'primary','upload'))));return root;}
 const data=await get(`/api/tasks/${task.id}/static`);
 if(!data.available){root.append(panel('静态结果尚不可用',null,empty('没有静态产物',data.reason||task.stages?.static?.reason||'此任务尚未完成 APK 静态分析。','scan')));return root;}
 const findings=safeList(data.findings);const high=findings.filter(f=>['high','critical'].includes(f.severity)).length;
 root.append(h('div',{class:'metric-grid'},metric('规则命中',findings.length,'全部作为候选线索查看','scan'),metric('高风险候选',high,'优先人工复核，不自动判违规','shield'),metric('已评估 / 已加载',data.rules_evaluated===undefined?'—':`${data.rules_evaluated} / ${data.rules_loaded??'—'}`,'仅静态阶段支持的规则，不是全覆盖','book'),metric('源码可用',task.stages?.decompile?.state==='done'?'是':task.stages?.decompile?.state==='partial'?'部分可用':'—','独立于静态扫描阶段','code')));
 root.append(h('div',{class:'notice'},icon('shield'),'判定边界：权限声明、API 引用与配置风险都是静态候选，必须结合运行时证据和上下文确认。'));
 const list=h('div',{class:'finding-list'});const detail=h('section',{class:'panel detail'},empty('选择一条发现','查看规则、证据来源与依据。','scan'));
 let query='',severity='all',selection=-1;
 function choose(f,index){selection=index;draw();detail.replaceChildren(h('h3',{},f.rule_id||'规则发现'),badge(f.conclusion_level||'candidate'),keyvalues([
  ['规则类型',f.rule_type||f.type],['风险级别',f.severity],['数据类型',f.data_type||f.data_type_key||f.condition?.data_type],['证据类型',f.evidence_kind||f.evidence_strength],['规则说明',f.note||f.description],['依据',safeList(f.basis_refs).map(r=>`${r.title||r.doc||'依据'} · ${r.clause||'未提供条款'}`).join('； ')],['关联事件',f.event_ids]]),h('details',{},h('summary',{},'查看原始规则证据'),json(f)));}
 function draw(){
  const filtered=findings.map((f,i)=>({f,i})).filter(({f})=>(severity==='all'||f.severity===severity)&&JSON.stringify(f).toLowerCase().includes(query.toLowerCase()));
  list.replaceChildren(filtered.length?table(['规则 / 信号','风险','判定级别',''],filtered,({f,i})=>h('tr',{class:i===selection?'selected':''},h('td',{},h('button',{class:'row-link rule-id',onclick:()=>choose(f,i)},f.rule_id||'未命名规则'),h('span',{class:'subtext'},f.note||f.rule_type||f.type||'静态线索')),h('td',{},badge(f.severity||'unknown')),h('td',{},badge(f.conclusion_level||'candidate')),h('td',{},button('证据',()=>choose(f,i),'ghost','arrow')))):empty(query||severity!=='all'?'没有匹配的发现':'本次扫描无规则命中','无命中只表示当前静态规则未发现候选，不等于应用安全。','scan'));
 }
 const toolbar=h('div',{class:'toolbar'},h('label',{class:'search-input'},icon('search'),h('input',{type:'search',placeholder:'搜索规则、数据类型或信号','aria-label':'搜索静态发现',oninput:e=>{query=e.target.value;draw();}})),h('select',{class:'filter','aria-label':'筛选风险等级',onchange:e=>{severity=e.target.value;draw();}},[['all','全部风险'],['critical','严重'],['high','高风险'],['medium','中风险'],['low','低风险']].map(([v,l])=>h('option',{value:v},l))));
 draw();const listPanel=panel('规则发现',`${findings.length} 条 · 可搜索、筛选并展开原始证据`,h('div',{},toolbar,list));root.append(h('div',{class:'split-detail'},listPanel,detail));
 const gaps=safeList(data.gaps);if(gaps.length)root.append(h('div',{class:'section-gap'},panel('覆盖缺口','仅展示服务端记录，不补造覆盖率',h('div',{class:'panel-body'},h('ul',{class:'gaps'},gaps.map(g=>h('li',{},typeof g==='object'?JSON.stringify(g):g)))))));
 root.append(h('div',{class:'section-gap'},await renderSource(task)));
 return root;
}
