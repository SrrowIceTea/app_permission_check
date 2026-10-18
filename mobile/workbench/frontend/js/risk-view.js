import {h,icon,keyvalues} from './ui.js';
import {normalizeRisk,normalizeAI,riskSummary,riskLabels,aiLabels} from './risk-model.js';
const riskTag=risk=>h('span',{class:`risk-tag risk-${risk.level}`},riskLabels[risk.level]);
const evidenceRefs=values=>values.length?h('div',{class:'risk-evidence-refs'},h('span',{},'证据引用'),values.map(value=>h('code',{},value))):null;
const countText=risk=>risk.coverage.tested_domains===null?'覆盖未报告':`${risk.coverage.tested_domains} / ${risk.coverage.total_domains??'—'} 维已测`;
export function riskCell(sample){const risk=normalizeRisk(sample);return h('div',{class:'risk-cell'},
 h('div',{class:'risk-score-line'},h('strong',{class:`risk-score risk-text-${risk.level}`},risk.score===null?'—':risk.score),risk.score===null?null:h('small',{},'/ 100')),
 riskTag(risk),h('span',{class:'subtext'},countText(risk)));}
export function aiCell(sample){const ai=normalizeAI(sample);return h('div',{class:'risk-ai-cell'},
 h('span',{class:`risk-ai-state risk-ai-${ai.status}`},icon(ai.status==='ok'?'check':ai.status==='not_run'?'clock':'close'),aiLabels[ai.status]),
 h('span',{class:'subtext'},ai.model||'无模型调用记录'),ai.status==='failed'&&ai.reason?h('span',{class:'subtext',title:ai.reason},ai.reason):null);}
export function riskOverview(samples){const summary=riskSummary(samples);return h('div',{class:'risk-overview'},
 h('div',{class:'risk-overview-number'},h('strong',{},summary.signals),h('div',{},h('span',{},'个样本有评分风险信号'),h('small',{},`已评估 ${summary.assessed} / ${summary.total} · 风险条目 ${summary.findings}`))),
 h('div',{class:'risk-distribution',role:'img','aria-label':Object.entries(riskLabels).map(([key,label])=>`${label} ${summary.levels[key]}`).join('；')},
 Object.keys(riskLabels).filter(key=>summary.levels[key]).map(key=>h('span',{class:`risk-fill-${key}`,title:`${riskLabels[key]} ${summary.levels[key]}`,style:`width:${summary.total?summary.levels[key]/summary.total*100:0}%` }))),
 h('div',{class:'risk-legend'},Object.entries(riskLabels).map(([key,label])=>h('div',{},h('i',{class:`risk-fill-${key}`}),h('span',{},label),h('strong',{},summary.levels[key])))),
 h('p',{class:'benchmark-footnote'},'风险分来自证据支持的最严重单项。未测试维度不记零分；0 分仅表示已测范围未检出评分风险。'));}
export function aiOverview(samples){const summary=riskSummary(samples),reasons=[...new Set(samples.map(normalizeAI).filter(ai=>ai.status==='failed'&&ai.reason).map(ai=>ai.reason))];return h('div',{class:'risk-overview'},
 h('div',{class:'risk-overview-number'},h('strong',{},summary.ai.ok),h('div',{},h('span',{},'个样本有已校验 AI 研判'),h('small',{},'模型总结与评分规则分开呈现 · 按样本计数'))),
 h('div',{class:'risk-ai-overview'},Object.entries(aiLabels).map(([key,label])=>h('div',{},h('span',{class:`risk-ai-dot risk-ai-${key}`}),h('span',{},label),h('strong',{},summary.ai[key])))),
 reasons.length?h('div',{class:'risk-error-summary'},icon('link'),h('div',{},reasons.map(reason=>h('p',{},reason)))):null,
 h('p',{class:'benchmark-footnote'},'AI 以本轮证据解释风险、提出建议；没有政策正文和行为上下文时，不作合规通过判断。'));}
export function riskDetails(sample){const risk=normalizeRisk(sample),ai=normalizeAI(sample);
 return h('div',{class:'risk-detail'},h('div',{class:'risk-detail-heading'},h('h3',{},'风险评估'),riskTag(risk)),
 h('p',{class:'risk-detail-summary'},risk.summary),h('div',{class:'risk-score-method'},risk.score_label,risk.method_version?` · ${risk.method_version}`:''),
 risk.dimensions.length?h('div',{class:'risk-dimensions'},risk.dimensions.map(dim=>h('div',{class:'risk-dimension'},
  h('div',{class:'risk-dimension-label'},h('span',{},dim.label),h('strong',{},dim.score===null?'未测试':`${dim.score} / 100`)),
  h('div',{class:`risk-dimension-track ${dim.score===null?'risk-dimension-unknown':''}`,role:'img','aria-label':`${dim.label} ${dim.score===null?'未测试':dim.score+'分'}`},dim.score===null?null:h('span',{style:`width:${dim.score}%`})),evidenceRefs(dim.evidence_refs)))):null,
 risk.findings.length?h('div',{class:'risk-findings'},risk.findings.map(item=>h('article',{},h('strong',{},item.title),h('p',{},item.rationale||''),
  h('small',{},`${item.evidence_strength==='observed'?'运行证据':item.evidence_strength==='candidate'?'候选证据':'上下文信号'} · ${item.score??'—'} 分`),evidenceRefs(item.evidence_refs)))):null,
 h('div',{class:'risk-detail-heading'},h('h3',{},'AI 证据研判'),h('span',{class:`risk-ai-state risk-ai-${ai.status}`},aiLabels[ai.status])),
 ai.status==='ok'?h('div',{class:'risk-ai-summary'},h('p',{},ai.summary||'本次未提供摘要'),evidenceRefs(ai.summary_evidence_refs),
  ai.concerns.map(item=>h('article',{},h('strong',{},item.title),h('p',{},item.detail||item.assessment||''),evidenceRefs(item.evidence_refs))),
  ai.advice.length?h('div',{class:'risk-ai-list'},h('h4',{},'改进建议'),ai.advice.map(item=>h('div',{},h('p',{},item.text||item.title),evidenceRefs(item.evidence_refs)))):null,
  ai.limitations.length?h('div',{class:'risk-ai-list'},h('h4',{},'证据缺口'),ai.limitations.map(item=>h('div',{},h('p',{},item.text||item.title),evidenceRefs(item.evidence_refs)))):null,
  ai.compliance_reason?h('p',{class:'risk-compliance'},`合规判断：证据不足。${ai.compliance_reason}`):null):h('p',{class:'risk-detail-summary'},ai.reason||'本样本尚无可展示的有效 AI 研判。'),
 ai.status==='invalid'&&ai.validation.issues.length?h('ul',{class:'risk-validation'},ai.validation.issues.map(issue=>h('li',{},issue))):null,
 keyvalues([['模型',ai.model||'未调用'],['模型状态',aiLabels[ai.status]],['调用来源',ai.live===true?'本轮在线模型调用':ai.live===false?'离线 / 导入输出':'未报告']]));
}
