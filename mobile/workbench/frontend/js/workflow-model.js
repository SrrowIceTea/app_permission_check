// UI eligibility is advisory; the server validates APK bytes and authorization again.
export function workflowState(task,health,busy=false){
 const active=busy||['queued','running'].includes(task?.state);
 const workflow=task?.workflow||{};
 return {active,canCapture:!active&&health?.capabilities?.device_capture?.available===true&&workflow.can_capture===true,
  canReport:!active&&health?.capabilities?.report_generation?.available===true&&workflow.can_report===true,
  captureReason:workflow.capture_reason||'选择已完成静态扫描的自有夹具任务。',
  reportReason:workflow.report_reason||'先采集或导入本任务的动态证据。'};
}
export function captureValidation(options,devices){
 if(options.authorized!==true)return '请确认已授权安装并运行自有测试夹具。';
 if(!options.serial)return '请选择要使用的设备。';
 if(!Array.isArray(devices)||!devices.some(d=>d.serial===options.serial&&d.state==='device'))return '所选设备未在线，请重新检测连接设备。';
 if(!['allow','deny'].includes(options.permission_response))return '权限响应只能选择允许或拒绝。';
 if(typeof options.generate_report!=='boolean')return '请选择是否在采集成功后生成报告。';
 return null;
}
export function operationLabel(operation){return operation==='audit'?'完整检测（含 AI）':operation==='capture'?'设备采集':operation==='report'?'报告生成':'静态分析';}

// Audit mode remains an audit on failure/cancel; stage badges carry completion state.
export function taskModeLabel(task,context='list'){
 if(task?.mode==='core_audit'||task?.operation?.kind==='audit'||task?.core_run?.state==='done')return '完整审计';
 if(task?.origin==='device_capture')return context==='identity'?'夹具采集':'自有夹具采集';
 if(task?.mode==='static')return context==='identity'?'静态任务':task?.stages?.dynamic?.state==='done'?'静态 + 设备证据':'APK 静态分析';
 return context==='identity'?'证据导入':'证据包导入';
}
