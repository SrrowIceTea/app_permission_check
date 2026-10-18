// Advisory UI gates only; the backend rechecks original APK identity and authorization.
const modes=['nonroot-gadget','root-emulator'];
const fields=new Set(['authorized','mode','serial','scenario','seconds','pcap_sidecar','consent_timeout']);
export function auditState(task,busy=false){
 const workflow=task?.workflow||{},active=busy||['queued','running'].includes(task?.state);
 return {active,canAudit:!active&&workflow.can_audit===true,
  reason:active?'当前任务或操作尚在运行，请等待终止与清理。':workflow.audit_reason||'完整检测尚未配置或当前 APK 未完成静态扫描。',
  modes:Array.isArray(workflow.audit_modes)?workflow.audit_modes.filter(m=>modes.includes(m)):[],
  serial:typeof workflow.audit_serial==='string'?workflow.audit_serial:'',
  scenarios:Array.isArray(workflow.audit_scenarios)?workflow.audit_scenarios.filter(s=>typeof s==='string'):[]};
}
export function defaultScenario(task){
 const wanted=task?.apk?.package==='com.absinthe.libchecker'?'libchecker':task?.apk?.package==='me.ash.reader'?'readyou':'launch';
 const available=auditState(task).scenarios;
 return available.includes(wanted)?wanted:available.includes('launch')?'launch':available[0]||'launch';
}
export function auditDefaults(task){return {authorized:false,mode:auditState(task).modes[0]||'',serial:'',scenario:defaultScenario(task),seconds:20,pcap_sidecar:false,consent_timeout:180};}
export function auditDevices(task,devices){
 const serial=auditState(task).serial;
 return Array.isArray(devices)?devices.filter(d=>d?.serial===serial&&d.state==='device'&&/^emulator-\d{1,5}$/.test(d.serial)):[];
}
export function auditValidation(options,devices,task,busy=false){
 if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>!fields.has(k)))return '完整检测不接受额外字段、主机路径或密钥。';
 const info=auditState(task,busy);
 if(!info.canAudit)return info.reason;
 if(options.authorized!==true)return '请确认 APK 安装、重签插桩授权，以及检测证据向已配置 AI 服务发送。';
 if(!modes.includes(options.mode)||!info.modes.includes(options.mode))return '所选检测模式没有同模式真实正控，请使用服务提供的模式。';
 if(!options.serial)return '请检测并选择已通过正控的模拟器。';
 if(typeof options.serial!=='string'||!/^emulator-\d{1,5}$/.test(options.serial)||options.serial!==info.serial)return '设备必须与本服务真实正控的模拟器一致。';
 if(!auditDevices(task,devices).some(d=>d.serial===options.serial))return '所选正控模拟器未在线，请重新检测连接设备。';
 if(!info.scenarios.includes(options.scenario))return '此检测模式不支持所选场景。';
 if(!Number.isInteger(options.seconds)||options.seconds<5||options.seconds>180)return '观察时长必须为 5 至 180 秒的整数。';
 if(typeof options.pcap_sidecar!=='boolean'||(options.mode!=='nonroot-gadget'&&options.pcap_sidecar))return 'VPN 抓包只可用于非 root 模式，且选项必须为布尔值。';
 if(options.consent_timeout!==180)return '设备授权等待时间应为 180 秒。';
 return null;
}
export function auditStages(task){return [['static','静态与本地政策'],['dynamic','实际动态采集'],['ai','三阶段 AI'],['report','PDF 报告']].map(([key,label])=>({key,label,state:task?.stages?.[key]?.state||'not_requested',reason:task?.stages?.[key]?.reason||''}));}
