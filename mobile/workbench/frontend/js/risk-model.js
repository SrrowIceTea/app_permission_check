// Scores are supplied by the evidence evaluator; execution success is never risk.
export const riskLabels={high:'高风险信号',medium:'中风险信号',low:'低风险信号',none:'已测范围未检出评分风险',unknown:'证据不足 / 未评估'};
export const riskTones={high:'high',medium:'medium',low:'low',none:'none',unknown:'unknown'};
export const aiLabels={ok:'已完成 · 引用校验通过',failed:'调用失败',invalid:'输出校验未通过',not_run:'未运行'};
const object=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
const text=v=>typeof v==='string'?v:'';
const list=v=>Array.isArray(v)?v:[];
const score=v=>typeof v==='number'&&Number.isFinite(v)&&v>=0&&v<=100?v:null;
const refs=v=>list(v).filter(x=>typeof x==='string'&&x.length);
const knownStatus=new Set(['partial','insufficient_evidence','assessed']);
function finding(value){const raw=object(value);return {...raw,title:text(raw.title)||'风险信号',evidence_refs:refs(raw.evidence_refs)};}
export function normalizeRisk(sample){
 const raw=object(sample?.risk_assessment),status=knownStatus.has(raw.status)?raw.status:'insufficient_evidence';
 let value=status==='insufficient_evidence'?null:score(raw.score),level=Object.hasOwn(riskLabels,raw.level)?raw.level:'unknown';
 if(value===null||(value>0&&level==='none')||(value===0&&!['none','unknown'].includes(level)))level='unknown';
 if(level==='unknown')value=null;
 const coverage=object(raw.coverage),tested=Array.isArray(coverage.tested_domains)?coverage.tested_domains.length:coverage.tested_domains;
 return {...raw,status,score:value,level,summary:text(raw.summary)||'尚无可用的证据风险评估',method_version:text(raw.method_version),
  score_label:text(raw.score_label)||'已证据支持的风险信号分（非安全认证）',
  coverage:{...coverage,tested_domains:Number.isInteger(tested)&&tested>=0?tested:null,total_domains:Number.isInteger(coverage.total_domains)&&coverage.total_domains>0?coverage.total_domains:null,percent:score(coverage.percent)},
  findings:list(raw.findings).map(finding),dimensions:list(raw.dimensions).map(value=>{
   const dim=object(value),state=['observed','candidate','not_tested'].includes(dim.status)?dim.status:'not_tested';
   return {...dim,id:text(dim.id),label:text(dim.label)||text(dim.id)||'未标识维度',status:state,
    score:state==='not_tested'?null:score(dim.score),evidence_refs:refs(dim.evidence_refs)};
  })};
}
export function normalizeAI(sample){
 const raw=object(sample?.ai_review);let status=Object.hasOwn(aiLabels,raw.status)?raw.status:'not_run';
 if(status==='ok'&&object(raw.validation).passed!==true)status='invalid';
 return {...raw,status,model:text(raw.model),summary:status==='ok'?text(raw.summary):'',summary_evidence_refs:refs(raw.summary_evidence_refs),
  reason:text(raw.reason)||text(raw.error),validation:{...object(raw.validation),issues:list(object(raw.validation).issues).filter(v=>typeof v==='string')},
  concerns:status==='ok'?list(raw.concerns).map(finding):[],advice:status==='ok'?list(raw.advice).map(finding):[],
  limitations:status==='ok'?list(raw.limitations).map(finding):[],compliance_reason:status==='ok'?text(raw.compliance_reason):''};
}
export function riskSummary(samples=[]){
 const risks=samples.map(normalizeRisk),reviews=samples.map(normalizeAI);
 return {total:samples.length,levels:Object.fromEntries(Object.keys(riskLabels).map(key=>[key,risks.filter(r=>r.level===key).length])),
  assessed:risks.filter(r=>r.score!==null).length,signals:risks.filter(r=>r.score!==null&&r.score>0).length,
  findings:risks.reduce((sum,r)=>sum+r.findings.length,0),ai:Object.fromEntries(Object.keys(aiLabels).map(key=>[key,reviews.filter(r=>r.status===key).length]))};
}
export function riskMatches(sample,level='all',ai='all'){
 return (level==='all'||normalizeRisk(sample).level===level)&&(ai==='all'||normalizeAI(sample).status===ai);
}
