import assert from 'node:assert/strict';
import {collectionState,evidenceGaps,clientTransport} from './js/evidence-model.js';
const cases=[
 [{outcome:'ok'},'unknown'],[{outcome:'ok',count:0},'empty'],
 [{outcome:'ok',count:2},'obtained'],[{outcome:'ok',value_hash:'hash'},'obtained'],
 [{outcome:'ok',non_empty:false},'empty'],
 [{outcome:'ok',count:0,value_hash:'hash'},'unknown'],
 [{outcome:'denied',collection_state:'obtained',count:5},'denied'],
 [{outcome:'error',non_empty:true},'error'],
 [{outcome:'ok',collection_state:'call_only',value_hash:'hash'},'call_only'],
 [{outcome:'ok',collection_state:'unknown',count:3},'unknown'],
 [{outcome:'ok',collection_state:'empty',non_empty:true},'unknown'],
 [{outcome:'ok',value_count:true},'unknown'],
];
for(const [value,expected] of cases)assert.equal(collectionState(value),expected);
assert.deepEqual(evidenceGaps({bundle:{gaps:['A']},gaps:['A','B']}),['A','B']);
console.log(`PASS ${cases.length+1} evidence presentation assertions (synthetic fixtures, no device).`);

const transports=[
 [{scheme:'http',intercepted_tls:true},'tls'],
 [{scheme:'https',intercepted_tls:false},'plaintext'],
 [{scheme:'http',intercepted_tls:false},'plaintext'],
 [{scheme:'http'},'unknown'],[{scheme:'https'},'unknown'],
 [{scheme:'http',intercepted_tls:'false'},'unknown'],
];
for(const [flow,state] of transports)assert.equal(clientTransport(flow).state,state);
console.log(`PASS ${transports.length} client transport assertions (synthetic reverse-proxy regressions).`);
