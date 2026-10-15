// UI classification mirrors mobile/analyze/read_semantics.py, including legacy bundles.
export function collectionState(record){
 if(['denied','error'].includes(record.outcome))return record.outcome;
 if(record.outcome!=='ok')return 'unknown';
 const explicit=record.collection_state;if(['unknown','call_only'].includes(explicit))return explicit;
 let positive=explicit==='obtained',empty=explicit==='empty';
 if(typeof record.non_empty==='boolean'){positive ||= record.non_empty;empty ||= !record.non_empty;}
 for(const key of ['count','value_count','value_len']){const value=record[key];if(typeof value==='number'&&Number.isFinite(value)){positive ||= value>0;empty ||= value===0;}}
 positive ||= Boolean(record.value_hash);
 if(positive&&empty)return 'unknown';return positive?'obtained':empty?'empty':'unknown';
}
export function evidenceGaps(data){return [...new Set([...(Array.isArray(data.bundle?.gaps)?data.bundle.gaps:[]),...(Array.isArray(data.gaps)?data.gaps:[])])];}

// Imported runtime metadata is a declaration, never an independently certified result.
export function runtimeSummary(runtime){
 if(!runtime||typeof runtime!=='object'||Array.isArray(runtime))return {available:false};
 const profile=runtime.device_profile&&typeof runtime.device_profile==='object'?runtime.device_profile:{};
 const checks=Array.isArray(runtime.capture_checks)?runtime.capture_checks:[];
 const failed=checks.filter(check=>check?.exit_code!==0&&!check?.optional).map(check=>check?.name||'未命名检查');
 const debugImage=profile['ro.build.type']!=='user'||profile['ro.debuggable']!=='0';
 return {available:true,mode:runtime.mode==='gadget'?'Gadget · 非 root 执行路径':runtime.mode==='root'?'Root · server 执行路径':'模式未提供',
 environment:debugImage?'可调试 / 未知镜像 · 受限模拟':'user 镜像 · root 状态未独立认证',
 scope:runtime.scope==='self-owned-source-fixture'?'自有源码测试夹具':runtime.scope||'范围未提供',
 profile,checks,failed,startup:runtime.capabilities?.startup_before_attach||'未提供覆盖声明'};
}

// Reverse-proxy scheme describes the upstream, not the observed client transport.
export function clientTransport(flow){
 if(flow?.intercepted_tls===true)return {state:'tls',label:'授权 TLS 捕获',tone:'neutral'};
 if(flow?.intercepted_tls===false)return {state:'plaintext',label:'HTTP 明文',tone:'high'};
 return {state:'unknown',label:'客户端传输未知',tone:'neutral'};
}
