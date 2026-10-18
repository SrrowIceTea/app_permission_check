// Runtime results and author-provided labels deliberately remain separate.
export const stageLabels={static:'静态分析',install:'安装',launch:'启动',trigger:'触发',observe:'事件采集'};
export const verdictLabels={observed:'目标事件已观察',not_observed:'未观察到目标事件',unsupported:'当前环境不支持',failed:'运行失败',not_run:'未运行'};
export const verdictTones={observed:'teal',not_observed:'blue',unsupported:'amber',failed:'red',not_run:'gray'};
const allowedStates=new Set(['done','failed','unsupported','not_run','running','queued','partial']);
const object=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>typeof value==='string'?value:'';
const count=value=>typeof value==='number'&&Number.isFinite(value)&&value>=0?Math.floor(value):null;
export function normalizeSample(value,index=0){
 const raw=object(value),stages=object(raw.stages);
 return {...raw,sample_id:text(raw.sample_id)||`sample-${index+1}`,dataset:text(raw.dataset)||'未标识数据集',
  case_id:text(raw.case_id)||text(raw.sample_id)||`样本 ${index+1}`,variant:text(raw.variant),package:text(raw.package),
  stages:Object.fromEntries(Object.keys(stageLabels).map(key=>{
   const stage=object(stages[key]);return [key,{...stage,state:allowedStates.has(stage.state)?stage.state:'not_run'}];
  })),event_count:count(raw.event_count),findings:Array.isArray(raw.findings)?raw.findings.map(object):[],
  verdict:Object.hasOwn(verdictLabels,raw.verdict)?raw.verdict:'not_run',reason:text(raw.reason),
  evidence_url:typeof raw.evidence_url==='string'&&/^\/api\/benchmarks\/(?!\/)[^\r\n]*$/.test(raw.evidence_url)?raw.evidence_url:null};
}
export function normalizeBatch(value,index=0){
 const raw=object(value);
 return {...raw,batch_id:text(raw.batch_id)||`batch-${index+1}`,environment:object(raw.environment),dataset:object(raw.dataset),
  samples:(Array.isArray(raw.samples)?raw.samples:[]).map(normalizeSample)};
}
export function normalizeCatalog(value){return (Array.isArray(value?.batches)?value.batches:[]).map(normalizeBatch);}
export function summarizeBatch(batch){
 const samples=batch.samples||[],total=samples.length;
 const verdicts=Object.fromEntries(Object.keys(verdictLabels).map(key=>[key,samples.filter(s=>s.verdict===key).length]));
 const stages=Object.fromEntries(Object.keys(stageLabels).map(key=>[key,Object.fromEntries(
  [...allowedStates].map(state=>[state,samples.filter(s=>s.stages[key].state===state).length]))]));
 return {total,verdicts,stages,event_count:samples.reduce((sum,s)=>sum+(s.event_count??0),0),
  unknown_events:samples.filter(s=>s.event_count===null).length,
  finding_count:samples.reduce((sum,s)=>sum+s.findings.length,0)};
}
export function sampleMatches(sample,query='',verdict='all'){
 const haystack=[sample.sample_id,sample.case_id,sample.package,sample.dataset,sample.variant].join(' ').toLowerCase();
 return (verdict==='all'||sample.verdict===verdict)&&haystack.includes(query.trim().toLowerCase());
}
export function truthText(value){
 if(value===null||value===undefined||value==='')return '未提供';
 return typeof value==='string'?value:JSON.stringify(value);
}

export function batchProgress(batch){
 const labels={running:['running','运行中'],completed:['done','已结束'],failed:['failed','异常结束'],cancelled:['cancelled','已取消']};
 const [tone,label]=labels[batch.status]||['unknown','状态未报告'];
 const planned=count(batch.planned_sample_count),written=batch.samples.length;
 return {tone,label,planned,written,note:planned===null?`已写入 ${written} 个样本 · 计划数量未报告`:`计划 ${planned} 个样本 · 已写入 ${written} 个`};
}
