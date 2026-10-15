import assert from 'node:assert/strict';
import {runtimeSummary} from './js/evidence-model.js';

assert.equal(runtimeSummary(null).available,false);
assert.equal(runtimeSummary([]).available,false);
assert.equal(runtimeSummary({mode:'gadget',device_profile:{'ro.build.type':'userdebug','ro.debuggable':'1'}}).environment,'可调试 / 未知镜像 · 受限模拟');
assert.match(runtimeSummary({mode:'gadget'}).mode,/非 root 执行路径/);
assert.match(runtimeSummary({mode:'root'}).mode,/Root/);
assert.match(runtimeSummary({device_profile:{'ro.build.type':'user','ro.debuggable':'0'}}).environment,/未独立认证/);
assert.match(runtimeSummary({}).environment,/未知/);
assert.deepEqual(runtimeSummary({capture_checks:[{name:'one',exit_code:0},{name:'two',exit_code:1},{name:'three',exit_code:2,optional:true}]}).failed,['two']);
assert.deepEqual(runtimeSummary({capture_checks:[{name:'missing'}]}).failed,['missing']);
assert.equal(runtimeSummary({}).startup,'未提供覆盖声明');
console.log('PASS 10 runtime presentation assertions (offline declarations, no device).');
