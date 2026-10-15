import {workflowPanel} from './workflow.js';
import {operationLabel} from './workflow-model.js';
import {jobPresentation} from './job-model.js';
import {state,selectTask} from './state.js';
import {h,icon,button,badge,header,empty,panel,metric,table,date} from './ui.js';
export function chooseApk(){document.querySelector('#apk-input').click();}
export function chooseBundle(){document.querySelector('#bundle-input').click();}
function dropZone(title,desc,name,choose,eventName){
 const node=h('button',{class:`upload-zone ${name==='book'?'import':''}`,type:'button',onclick:choose},icon(name),h('strong',{},title),h('small',{},desc));
 if(eventName) {
  node.addEventListener('dragover',e=>{e.preventDefault();node.classList.add('drag');});
  node.addEventListener('dragleave',()=>node.classList.remove('drag'));
  node.addEventListener('drop',e=>{e.preventDefault();node.classList.remove('drag');const file=e.dataTransfer.files[0];if(file)window.dispatchEvent(new CustomEvent(eventName,{detail:file}));});
 }
 node.disabled=state.busy;return node;
}
function capabilities(){
 const health=state.health;const caps=health?.capabilities;
 const items=[['scan','静态分析',caps?.static,`aapt2 / dexdump · MOB-${health?.rules?.version||'—'}`],['code','源码反编译',caps?.decompile,'JADX / Java · 可独立降级'],['pulse','设备采集',caps?.device_capture,'授权后运行自有 Gadget 夹具'],['book','AI 研判','manual','导入产物后重验，本服务不调用模型']];
 return h('div',{class:'capabilities'},items.map(([name,title,cap,desc])=>h('div',{class:'capability'},h('span',{class:'capability-icon'},icon(name)),h('div',{class:'capability-text'},title,h('small',{},cap?.missing?.length?`未选定 ${cap.missing.join(' / ')}`:desc)),badge(!health?'unknown':cap==='manual'?'not_requested':cap?.available?'done':'blocked',!health?'未连接':cap==='manual'?'手动导入':cap?.available?'就绪':'缺少依赖'))));
}
function jobCard(){
 const job=state.job;if(!job)return null;
 const info=jobPresentation(job);
 return panel(info.active?'正在处理':'最近任务处理状态',`${operationLabel(job.operation)} · 分阶段留存原始产物`,h('div',{class:'progress-card'},h('div',{class:'progress-heading'},h('b',{},info.stage),badge(job.state)),info.percent!==null?h('div',{class:'progress-track'},h('div',{class:'progress-bar',style:`width:${info.percent}%`})):null,h('div',{class:'progress-meta'},h('span',{},info.message),h('span',{},info.progressLabel))),info.active?button('取消',()=>window.dispatchEvent(new Event('lab:cancel')),'danger'):null);
}
export function renderTasks(){
 const tasks=state.tasks;const completed=tasks.filter(t=>t.stages?.static?.state==='done').length;
 const imported=tasks.filter(t=>t.origin==='imported_bundle'||t.mode!=='static').length;
 const body=h('div',{},
  header('AUDIT OVERVIEW','任务总览','创建可复现的检测任务，串联权限、行为与政策证据。',[
   button('导入证据包',chooseBundle,'secondary','book'),button('新建检测任务',chooseApk,'primary','upload')]),
  h('div',{class:'intro-banner'},h('div',{},h('div',{class:'eyebrow'},'PRIVACY, WITH PROOF'),h('h2',{},'从一个 APK，开始一条证据链。'),h('p',{},'先发现静态候选，再以动态证据验证。不把未知包装成安全。')),h('div',{class:'intro-emblem'},icon('shield'))),
  h('div',{class:'metric-grid'},metric('检测任务',tasks.length,'本地工作空间内的真实任务','grid'),metric('静态分析完成',completed,'完成扫描，不等于违规确认','scan'),metric('动态证据任务',tasks.filter(t=>t.stages?.dynamic?.state==='done').length,'本地采集或已导入的会话证据','pulse'),metric('可浏览报告',state.reports.length,'包含明确标注的历史快照','report')),
  h('div',{class:'grid-2'},panel('开始检测','APK 或现有证据，两种入口',h('div',{class:'upload-grid'},dropZone('上传 APK 文件','点击或拖拽 · 静态扫描与源码反编译','upload',chooseApk,'lab:upload'),dropZone('导入证据包 JSON','已有动态采集与政策文本 · 原样留证','book',chooseBundle,'lab:import'))),panel('检测环境','依赖可用性来自本地服务，不推断设备状态',capabilities())));
 body.append(h('div',{class:'section-gap'},workflowPanel()));
 const job=jobCard();if(job)body.append(h('div',{class:'section-gap'},job));
 const rows=tasks.map(task=>h('tr',{},h('td',{},h('button',{class:'row-link',onclick:()=>selectTask(task.id,task.mode==='static'?'static':'evidence')},task.name||task.apk?.name||task.id),h('span',{class:'subtext mono'},task.apk?.package||task.id)),h('td',{},badge(task.state)),h('td',{},h('span',{class:'subtext'},task.origin==='device_capture'?'自有夹具采集':task.stages?.dynamic?.state==='done'&&task.mode==='static'?'静态 + 设备证据':task.mode==='static'?'APK 静态分析':'证据包导入')),h('td',{},badge(task.stages?.static?.state||'not_requested')),h('td',{},badge(task.stages?.dynamic?.state||'not_requested')),h('td',{},h('small',{},date(task.created_at))),h('td',{},button('查看',()=>selectTask(task.id,task.mode==='static'?'static':'evidence'),'ghost','arrow'))));
 body.append(h('div',{class:'section-gap'},panel('最近任务',tasks.length?`${tasks.length} 个真实任务 · 原始产物保存在本机`:'尚未创建任务，上传后将自动出现在这里',rows.length?table(['应用 / 任务','任务状态','检测模式','静态','动态','创建时间',''],rows,x=>x):empty('工作空间已就绪','上传 APK 进行静态分析，或导入现有 evidence bundle 查看动态证据。','scan'))));
 if(state.error)body.append(h('div',{class:'notice error section-gap'},icon('link'),state.error));
 return body;
}
