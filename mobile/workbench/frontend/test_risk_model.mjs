import assert from 'node:assert/strict';
import {normalizeRisk,normalizeAI,riskSummary,riskMatches} from './js/risk-model.js';
const assessed={risk_assessment:{score:80,level:'high',status:'partial',summary:'有证据支持',method_version:'VSCAN-RISK-1',
 coverage:{tested_domains:['transport'],total_domains:5,percent:20},
 dimensions:[{id:'transport',label:'传输',score:80,status:'observed',evidence_refs:['net-1']},{id:'policy',label:'政策',score:0,status:'not_tested'}],
 findings:[{id:'net',title:'明文传输',score:80,evidence_refs:['net-1']}]},
 ai_review:{status:'ok',live:true,validation:{passed:true,issues:[]},summary:'依据网络证据',summary_evidence_refs:['net-1'],
 model:'actual-model',concerns:[{title:'明文',detail:'证据说明',evidence_refs:['net-1']}],advice:[{text:'使用TLS',evidence_refs:['net-1']}],limitations:[]}};
assert.equal(normalizeRisk(assessed).score,80);
assert.equal(normalizeRisk(assessed).coverage.tested_domains,1);
assert.equal(normalizeRisk(assessed).dimensions[1].score,null);
assert.equal(normalizeAI(assessed).status,'ok');
assert.equal(normalizeAI(assessed).summary,'依据网络证据');
assert.equal(normalizeAI(assessed).advice[0].text,'使用TLS');
assert.deepEqual(normalizeRisk(assessed).findings[0].evidence_refs,['net-1']);
for(const sample of [null,{}, {verdict:'observed',event_count:100,findings:[]},{original_truth:'author_corrected'}]){
 assert.equal(normalizeRisk(sample).score,null);assert.equal(normalizeRisk(sample).level,'unknown');assert.equal(normalizeAI(sample).status,'not_run');
}
const noSignal={risk_assessment:{score:0,level:'none',status:'partial',coverage:{tested_domains:2,total_domains:5,percent:40}}};
assert.equal(normalizeRisk(noSignal).score,0);
assert.equal(normalizeRisk(noSignal).level,'none');
assert.equal(normalizeRisk(noSignal).coverage.tested_domains,2);
for(const score of ['0',-1,101,NaN,null])assert.equal(normalizeRisk({risk_assessment:{score,level:'low',status:'assessed'}}).score,null);
assert.equal(normalizeRisk({risk_assessment:{score:0,level:'high',status:'assessed'}}).level,'unknown');
assert.equal(normalizeRisk({risk_assessment:{score:80,level:'none',status:'partial'}}).level,'unknown');
assert.equal(normalizeRisk({risk_assessment:{score:80,level:'high',status:'insufficient_evidence'}}).score,null);
assert.equal(normalizeAI({ai_review:{status:'ok',summary:'不可展示',validation:{passed:false}}}).summary,'');
assert.equal(normalizeAI({ai_review:{status:'ok',validation:{}}}).status,'invalid');
assert.equal(normalizeAI({ai_review:{status:'failed',summary:'不可展示'}}).summary,'');
assert.equal(normalizeAI({ai_review:{status:'invalid',summary:'不可展示',concerns:[{title:'不可展示'}]}}).concerns.length,0);
assert.equal(normalizeAI({ai_review:{status:'invalid',validation:{issues:['bad ref',{}]}}}).validation.issues.length,1);
assert.deepEqual(riskSummary([assessed,noSignal,{}]).levels,{high:1,medium:0,low:0,none:1,unknown:1});
assert.equal(riskSummary([assessed,noSignal,{}]).assessed,2);
assert.equal(riskSummary([assessed,noSignal,{}]).signals,1);
assert.equal(riskSummary([assessed,noSignal,{}]).ai.ok,1);
assert.equal(riskSummary([assessed,noSignal,{}]).ai.not_run,2);
assert.equal(riskSummary([]).assessed,0);
assert.equal(riskMatches(assessed,'high','ok'),true);
assert.equal(riskMatches(assessed,'unknown'),false);
assert.equal(riskMatches({},'unknown','not_run'),true);
console.log('PASS risk model: missing/invalid data remains unknown; observed events never imply risk or safety.');
