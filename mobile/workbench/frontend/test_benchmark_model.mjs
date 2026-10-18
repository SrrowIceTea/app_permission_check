import assert from 'node:assert/strict';
import {normalizeCatalog,normalizeBatch,summarizeBatch,sampleMatches,truthText,batchProgress} from './js/benchmark-model.js';
assert.deepEqual(normalizeCatalog(null),[]);
assert.deepEqual(normalizeCatalog({batches:'not-an-array'}),[]);
const batch=normalizeBatch({batch_id:'real-run',summary:{safe:999},samples:[
 {sample_id:'crypto-1',case_id:'ECB',dataset:'Ghera',package:'test.ecb',original_truth:'vulnerable',event_count:3,
  stages:{static:{state:'done'},install:{state:'done'},launch:{state:'done'},trigger:{state:'done'},observe:{state:'done'}},
  verdict:'observed',findings:[{kind:'weak_crypto',evidence_ids:['ev-1']}],evidence_url:'/api/benchmarks/real-run/crypto-1'},
 {sample_id:'storage-1',case_id:'Storage',dataset:'Ghera',original_truth:'secure',event_count:0,verdict:'not_observed',stages:{install:{state:'done'},observe:{state:'done'}}},
 {sample_id:'old-api',dataset:'DroidBench',original_truth:'leak',verdict:'unsupported',stages:{install:{state:'failed'}},evidence_url:'https://external.test/result'},
 {sample_id:'broken',event_count:-4,verdict:'failed',stages:{install:{state:'failed'}}},
 {sample_id:'missing',original_truth:'secure',event_count:'0',verdict:'safe',stages:{install:{state:'success'}},evidence_url:'javascript:alert(1)'},
]});
const summary=summarizeBatch(batch);
assert.equal(summary.total,5);
assert.equal(summary.event_count,3);
assert.equal(summary.unknown_events,3);
assert.equal(summary.finding_count,1);
assert.deepEqual(summary.verdicts,{observed:1,not_observed:1,unsupported:1,failed:1,not_run:1});
assert.equal(summary.stages.install.done,2);
assert.equal(summary.stages.install.failed,2);
assert.equal(summary.stages.install.not_run,1);
assert.equal(summary.stages.static.not_run,4);
assert.equal(summary.stages.observe.done,2);
assert.equal(batch.samples[4].verdict,'not_run');
assert.equal(batch.samples[1].original_truth,'secure');
assert.equal(batch.samples[0].evidence_url,'/api/benchmarks/real-run/crypto-1');
assert.equal(batch.samples[2].evidence_url,null);
assert.equal(batch.samples[4].evidence_url,null);
assert.equal(normalizeBatch({samples:[{evidence_url:'//evil.test'}]}).samples[0].evidence_url,null);
assert.equal(sampleMatches(batch.samples[0],'ECB'),true);
assert.equal(sampleMatches(batch.samples[0],' test.ecb ','observed'),true);
assert.equal(sampleMatches(batch.samples[0],'','unsupported'),false);
assert.equal(sampleMatches(batch.samples[2],'droidbench'),true);
assert.equal(truthText({label:'weak'}),'{"label":"weak"}');
assert.equal(truthText(null),'未提供');
assert.equal(summarizeBatch(normalizeBatch({})).event_count,0);
assert.equal(normalizeBatch({samples:[null]}).samples[0].event_count,null);
assert.equal(batchProgress(batch).planned,null);
assert.equal(batchProgress(batch).label,'状态未报告');
assert.equal(batchProgress({...batch,status:'completed'}).label,'已结束');
assert.equal(batchProgress({...batch,status:'running',planned_sample_count:10}).note,'计划 10 个样本 · 已写入 5 个');
assert.equal(batchProgress({...batch,planned_sample_count:'10'}).planned,null);
assert.equal(batchProgress({...batch,status:'failed'}).tone,'failed');
console.log('PASS benchmark model: 33 assertions; offline contract fixtures, not device evidence.');
