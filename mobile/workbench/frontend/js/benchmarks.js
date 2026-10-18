import {get} from './api.js';
import {h,header,panel,metric,empty,table,icon,badge,date,keyvalues,json} from './ui.js';
import {normalizeCatalog,summarizeBatch,sampleMatches,stageLabels,verdictLabels,verdictTones,truthText,batchProgress} from './benchmark-model.js';
import {riskSummary,riskMatches,riskLabels,aiLabels} from './risk-model.js';
import {riskCell,aiCell,riskOverview,aiOverview,riskDetails} from './risk-view.js';
let selectedBatch=null;
const stageTone=state=>state==='done'?'done':state==='failed'?'failed':['unsupported','partial'].includes(state)?'partial':state;
function stageChart(summary){
 return h('div',{class:'benchmark-chart'},Object.entries(stageLabels).map(([key,label])=>{
  const values=summary.stages[key];
  return h('div',{class:'benchmark-stage'},h('div',{class:'benchmark-stage-label'},h('span',{},label),h('strong',{},values.done,h('small',{},` / ${summary.total}`))),
   h('div',{class:'benchmark-stage-track',role:'img','aria-label':`${label}：${values.done} / ${summary.total} 已完成`},h('span',{style:`width:${summary.total?values.done/summary.total*100:0}%` })),
   h('div',{class:'benchmark-stage-note'},[`失败 ${values.failed}`,`不支持 ${values.unsupported}`,`未执行 ${values.not_run}`,
    ...(values.running||values.queued?[`处理中 ${values.running+values.queued}`]:[]),...(values.partial?[`部分完成 ${values.partial}`]:[])].join(' · ')));
 }));
}
function verdictChart(summary){
 return h('div',{class:'benchmark-chart'},h('div',{class:'benchmark-distribution',role:'img','aria-label':Object.entries(verdictLabels).map(([key,label])=>`${label} ${summary.verdicts[key]}`).join('；')},
  Object.keys(verdictLabels).filter(key=>summary.verdicts[key]>0).map(key=>h('span',{class:`benchmark-tone-${verdictTones[key]}`,style:`width:${summary.total?summary.verdicts[key]/summary.total*100:0}%`,title:`${verdictLabels[key]} ${summary.verdicts[key]}`}))),
  h('div',{class:'benchmark-legend'},Object.entries(verdictLabels).map(([key,label])=>h('div',{},h('span',{class:`benchmark-dot benchmark-tone-${verdictTones[key]}`}),h('span',{},label),h('strong',{},summary.verdicts[key])))),
  h('p',{class:'benchmark-footnote'},'“已观察”仅表示本次触发记录到了目标事件，不等于违规结论。未观察、不支持和失败分开计数。'));
}
function sampleRow(sample){
 const stageStrip=h('div',{class:'benchmark-stage-chips'},Object.entries(stageLabels).map(([key,label])=>h('span',{title:sample.stages[key].reason||''},badge(stageTone(sample.stages[key].state),`${label} · ${sample.stages[key].state==='done'?'完成':sample.stages[key].state==='unsupported'?'不支持':sample.stages[key].state==='not_run'?'未执行':sample.stages[key].state==='failed'?'失败':sample.stages[key].state==='running'?'运行中':sample.stages[key].state==='queued'?'排队中':'部分完成'}`))));
 const metadata=h('div',{class:'benchmark-metadata'},keyvalues([
  [sample.dataset==='国内真实应用观察集'?'来源标签':'论文原标签',truthText(sample.original_truth)],['运行说明',sample.reason||'未提供'],['事件记录',sample.event_count??'未提供'],['APK SHA256',sample.apk_sha256||'未提供'],
  ['版本',sample.version_name||sample.variant||'未提供'],['来源',sample.source_url||'未提供'],
  ['静态候选',sample.static_summary?.candidate_count??'未报告'],['规则库遍历',sample.static_summary?.rules_evaluated??'未报告'],
  ['静态缺口',Array.isArray(sample.static_summary?.gaps)?sample.static_summary.gaps.map(gap=>gap.detail||gap.kind||'未标识').join(' / ')||'未报告缺口':'未报告'],
  ['显式清单配置',sample.manifest_flags?Object.entries(sample.manifest_flags).map(([key,value])=>`${key}: ${value===true?'是':value===false?'否':'未知'}`).join(' / '):'未报告'],
  ['检测记录',sample.findings.length?sample.findings.map(f=>f.kind||f.rule_id||'未分类').join(' / '):'本结果未提供条目']]),
  h('p',{class:'benchmark-footnote'},sample.dataset==='国内真实应用观察集'?'本观察集不提供风险真值标签，静态候选不等于实际泄露。':'论文原标签用于基准对照，不计入本次运行结论。'),sample.findings.length?h('details',{class:'benchmark-raw-findings'},h('summary',{},'原始规则候选 / 发现'),json(sample.findings)):null,
  sample.evidence_url?h('a',{class:'button secondary',href:sample.evidence_url,target:'_blank',rel:'noopener'},icon('file'),'查看运行证据 JSON'):null);
 const detailId=`benchmark-detail-${sample.sample_id}`,detailRow=h('tr',{class:'benchmark-detail-row',id:detailId,hidden:true},h('td',{colSpan:7},h('div',{class:'benchmark-expanded-details'},metadata,riskDetails(sample))));
 const toggle=h('button',{class:'button ghost benchmark-detail-toggle',type:'button','aria-expanded':'false','aria-controls':detailId,onclick:()=>{const open=detailRow.hidden;detailRow.hidden=!open;toggle.setAttribute('aria-expanded',String(open));toggle.textContent=open?'收起详情':'风险 / AI / 证据';}},'风险 / AI / 证据');
 const mainRow=h('tr',{},h('td',{},h('strong',{},sample.case_id),h('span',{class:'subtext'},`${sample.dataset}${sample.variant?` · ${sample.variant}`:''}`),h('span',{class:'subtext mono'},sample.package||sample.sample_id)),
  h('td',{},riskCell(sample)),h('td',{},aiCell(sample)),h('td',{},stageStrip),h('td',{},h('span',{class:`benchmark-verdict benchmark-ink-${verdictTones[sample.verdict]}`},verdictLabels[sample.verdict]),h('span',{class:'subtext'},sample.reason||'')),
  h('td',{class:'benchmark-event-cell'},sample.event_count??'—'),h('td',{},toggle));
 return [mainRow,detailRow];
}
function sampleTable(batch){
 let query='',verdict='all',risk='all',ai='all';const content=h('div'),counter=h('span',{class:'benchmark-result-count'});
 const search=h('input',{type:'search',placeholder:'搜索案例、包名或数据集','aria-label':'搜索基准样本',oninput:event=>{query=event.target.value;draw();}});
 const filter=h('select',{class:'filter','aria-label':'按运行结果筛选',onchange:event=>{verdict=event.target.value;draw();}},h('option',{value:'all'},'全部运行结果'),Object.entries(verdictLabels).map(([key,label])=>h('option',{value:key},label)));
 const riskFilter=h('select',{class:'filter','aria-label':'按风险等级筛选',onchange:event=>{risk=event.target.value;draw();}},h('option',{value:'all'},'全部风险等级'),Object.entries(riskLabels).map(([key,label])=>h('option',{value:key},label)));
 const aiFilter=h('select',{class:'filter','aria-label':'按AI研判状态筛选',onchange:event=>{ai=event.target.value;draw();}},h('option',{value:'all'},'全部 AI 状态'),Object.entries(aiLabels).map(([key,label])=>h('option',{value:key},label)));
 function draw(){const samples=batch.samples.filter(sample=>sampleMatches(sample,query,verdict)&&riskMatches(sample,risk,ai));counter.textContent=`${samples.length} / ${batch.samples.length} 个样本`;
  content.replaceChildren(samples.length?table(['样本 / 版本','证据风险分','AI 研判','执行阶段','本次运行结果','事件数','明细'],samples,sampleRow):empty('没有符合条件的样本','更换搜索词、风险等级或研判状态筛选条件。','search'));}
 draw();return h('div',{},h('div',{class:'toolbar'},h('label',{class:'search-input'},icon('search'),search),h('div',{class:'benchmark-result-filters'},filter,riskFilter,aiFilter),counter),content);
}
function batchContent(batch){
 const summary=summarizeBatch(batch),risk=riskSummary(batch.samples),env=batch.environment,progress=batchProgress(batch);
 const body=h('div',{},h('div',{class:'benchmark-environment'},h('div',{},h('span',{class:'eyebrow'},'EXECUTION ENVIRONMENT'),h('strong',{},env.device_execution===false?'主机静态分析 · 原始 APK':env.mode||'环境模式未提供'),h('p',{},env.device_execution===false?`未安装或运行应用 · 未启动 Android 检测环境 · 规则版本 ${env.rules_android_version||'未报告'}`:`${env.serial||'设备未提供'} · Android API ${env.android_api??'—'} · Root ${env.root===true?'已验证':env.root===false?'否':'未报告'}`)),
  h('div',{class:'benchmark-batch-meta'},badge(progress.tone,`批次${progress.label}`),h('span',{class:'mono'},batch.batch_id),h('small',{},progress.note),h('small',{},`开始 ${date(batch.created_at)}`),h('small',{},batch.completed_at?`结束 ${date(batch.completed_at)}`:'未报告结束时间'))),
  h('div',{class:'metric-grid'},metric('已写入样本',summary.total,progress.planned===null?'计划数量未报告':`计划 ${progress.planned} 个样本`,'file'),metric('完成事件采集',summary.stages.observe.done,'采集完成，不代表已观察到目标事件','pulse'),
   metric('已记录事件',summary.total&&summary.unknown_events===summary.total?'—':summary.event_count,summary.unknown_events?`${summary.unknown_events} 个样本未报告事件数`:'所有样本均报告事件数量','code'),metric('有评分风险信号',risk.signals,`已评估 ${risk.assessed} / ${summary.total}；运行通过不等于无风险`,'shield')),
  h('div',{class:'grid-2'},panel('执行覆盖','各阶段完成数 / 批次总样本数',summary.total?stageChart(summary):empty('批次尚无样本','等待实际运行结果写入。','clock')),panel('运行结果分布','未知、未触发与运行失败不会归入安全',summary.total?verdictChart(summary):empty('暂无结果分布','仅基于真实样本计算，不填充演示数据。','pulse'))),
  h('div',{class:'grid-2 section-gap'},panel('风险信号分布','按证据评估，独立于安装成功与来源标签',riskOverview(batch.samples)),panel('样本 AI 结果状态','按样本统计结果状态，不是模型请求次数',aiOverview(batch.samples))),
  h('div',{class:'section-gap'},panel('逐样本结果','原包身份、执行阶段和运行证据逐项保留',sampleTable(batch))));
 if(batch.dataset.name||batch.dataset.revision)body.append(h('div',{class:'benchmark-provenance'},h('span',{},batch.dataset.name||'数据集'),h('span',{class:'mono'},batch.dataset.revision||'修订信息未提供')));
 return body;
}
export async function renderBenchmarks(){
 const root=h('div',{},header('BENCHMARK OBSERVATORY','基准实验','查看真实 APK 的执行证据、风险评分与 AI 研判；来源与参考标签独立保留。'));
 const response=await get('/api/benchmarks'),batches=normalizeCatalog(response);
 if(Array.isArray(response.errors)&&response.errors.length)root.append(h('div',{class:'notice warning section-gap'},icon('link'),h('div',{},'部分批次无法读取：',response.errors.map(item=>h('p',{},`${item.batch||'未标识批次'} · ${item.reason||'格式无效'}`)))));
 if(!batches.length){root.append(panel('实验结果',null,empty('还没有可展示的真实批次','运行 root 模拟器基准测试后，此处展示实际样本、执行阶段与证据。','scan')));return root;}
 let batch=batches.find(value=>value.batch_id===selectedBatch)||batches[0];selectedBatch=batch.batch_id;
 const content=h('div'),select=h('select',{class:'filter','aria-label':'选择实验批次',onchange:event=>{selectedBatch=event.target.value;batch=batches.find(value=>value.batch_id===selectedBatch);draw();}},
  batches.map(value=>h('option',{value:value.batch_id,selected:value.batch_id===selectedBatch},`${value.batch_id} · ${value.samples.length} 个样本`)));
 function draw(){content.replaceChildren(batchContent(batch));}
 root.append(h('div',{class:'benchmark-selector'},h('label',{},'实验批次',select),h('span',{class:'muted'},'只读实验视图 · 刷新获取最新结果')),content);draw();return root;
}
