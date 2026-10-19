import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const scope={};vm.runInNewContext(fs.readFileSync(new URL('./audit-results.js',import.meta.url),'utf8'),scope);
let view=scope.VScanResults.model({risk:{score:0,level:'none',dimensions:[{id:'network',score:0},{id:'storage',score:null}]}});
assert.equal(view.score,0);assert.equal(view.dimensions[0].unknown,false);assert.equal(view.dimensions[1].unknown,true);
view=scope.VScanResults.model({});assert.equal(view.score,null);assert.equal(view.level,'未知');
console.log('PASS risk unknown/zero separation; no fabricated default score');
