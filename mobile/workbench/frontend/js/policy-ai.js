import {get} from './api.js';
import {selectedTask} from './state.js';
import {h,badge,header,empty,panel,keyvalues,json,safeList,button,icon} from './ui.js';
import {chooseBundle} from './tasks.js';
export async function renderPolicy(){
 const root=h('div',{},header('POLICY & ASSESSMENT','政策与研判','将政策原文与行为事实分开呈现；AI 阶段只有通过校验后才能成为报告输入。',[button('导入证据包',chooseBundle,'secondary','book')]));
 const task=selectedTask();if(!task){root.append(panel('政策与 AI 输入',null,empty('先选择一个证据任务','导入带政策文本的证据包；不使用示例政策替代被测应用原文。','book')));return root;}
 const data=await get(`/api/tasks/${task.id}/evidence`);const policy=data.bundle?.policy;const ai=data.ai||{state:'not_run'};
 const policyBody=policy?.available&&policy.text?h('div',{},h('div',{class:'panel-body'},keyvalues([['标题',policy.title],['文本来源',policy.source_kind],['提取状态',policy.extract_status],['原文摘要',policy.raw_sha256],['文本摘要',policy.text_sha256]])),h('div',{class:'policy-text',tabIndex:0},policy.text)):empty('尚未取得政策原文','本任务未提供可读取的政策文本，政策一致性判断不可用。','book');
 const assessment=h('div',{class:'ai-stages'});
 const labels={not_run:'未运行',imported_validated:'导入内容通过校验',imported_partial:'部分阶段已校验',imported_rejected:'导入内容被拒绝'};
 assessment.append(h('div',{class:'notice'},icon('shield'),ai.reason||'本地工作台不会自动调用在线模型，AI 产物需显式导入并重新校验。'));
 for(const [key,label] of [['stage1','01 · 政策结构化'],['stage2','02 · 行为与政策对照'],['stage3','03 · 综合研判']]){
  const verdict=ai.validation?.[key];const stage=ai.stages?.[key];const status=verdict?verdict.ok?'done':'failed':'not_requested';
  const node=h('div',{class:'ai-stage'},h('div',{class:'evidence-title'},h('b',{},label),badge(status,verdict?verdict.ok?'引用校验通过':'校验失败':'未提供')));
  if(verdict?.problems?.length)node.append(h('ul',{class:'gaps'},verdict.problems.map(p=>h('li',{},p))));
  if(stage&&verdict?.ok)node.append(h('details',{},h('summary',{},'查看已接受的结构化内容'),json(stage)));
  else node.append(h('p',{},verdict&&!verdict.ok?'此阶段已阻断，不用于结论或后续阶段。':'没有已接受的阶段产物。'));
  assessment.append(node);
 }
 root.append(h('div',{class:'grid-equal'},panel(policy?.title||'隐私政策原文','仅展示导入文本 · 不自动抓取外部网址',policyBody),panel('AI 阶段状态',labels[ai.state]||ai.state,assessment,badge(ai.state==='imported_rejected'?'failed':ai.state==='imported_validated'?'done':'not_run',labels[ai.state]||'未运行'))));
 if(policy?.lint)root.append(h('div',{class:'section-gap'},panel('政策文本检查','关键词与结构检查只提供线索，不替代法律或人工判断',h('div',{class:'panel-body'},json(policy.lint)))));
 const gaps=safeList(data.gaps);if(gaps.length)root.append(h('div',{class:'section-gap'},panel('本轮不可判定事项',null,h('div',{class:'panel-body'},h('ul',{class:'gaps'},gaps.map(g=>h('li',{},g)))))));
 return root;
}
