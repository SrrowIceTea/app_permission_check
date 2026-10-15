import {workflowPanel} from './workflow.js';
import {state} from './state.js';
import {h,icon,header,empty,panel} from './ui.js';
export function renderReports(){
 const root=h('div',{},header('REPORT LIBRARY','报告中心','本轮产物与历史快照分别标识，PDF 可在线预览或在独立窗口打开。'));
 root.append(h('div',{class:'section-gap'},workflowPanel()));
 const reports=state.reports;if(!reports.length){root.append(panel('报告库',null,empty('还没有可用报告','可浏览的 PDF 会由本地服务列出。静态任务不会凭空生成完整审计报告。','report')));return root;}
 const list=h('div',{class:'report-list'}),preview=h('div');let selected=(reports.find(r=>r.task_id===state.selected&&r.kind==='task')||reports[0]).id;
 function draw(){
  list.replaceChildren(...reports.map(r=>h('button',{class:`report-item ${r.id===selected?'active':''}`,onclick:()=>{selected=r.id;draw();}},icon('report'),h('div',{},h('strong',{},r.title),h('small',{},r.kind==='snapshot'?'历史快照 / 非本轮产物':`任务 ${r.task_id||'未标识'}`)))));
  const r=reports.find(r=>r.id===selected);const url=`/api/reports/${encodeURIComponent(r.id)}/file`;
  const actions=h('div',{class:'heading-actions'},h('a',{class:'button secondary',href:url,target:'_blank',rel:'noopener'},icon('link'),'打开 PDF'));
  const viewer=h('div',{},h('div',{class:'report-info'},'原生 PDF 阅读器依赖浏览器支持；若为空白，请使用“打开 PDF”。'),h('iframe',{class:'report-preview',src:url,title:r.title}));
  preview.replaceChildren(panel(r.title,null,h('div',{},h('div',{class:'report-info'},r.note||(r.kind==='snapshot'?'此 PDF 随源码提供，不代表当前工作台运行结果。':'此报告属于标识的任务。')),viewer),actions));
 }
 draw();root.append(h('div',{class:'notice warning'},icon('clock'),'历史快照只用于查看已有交付样式，其会话原始证据可能不随源代码分发。请勿将快照计为本轮检测结果。'),h('div',{class:'report-layout section-gap'},panel('报告目录',`${reports.length} 份可用文件`,list),preview));return root;
}
