import {h,panel,badge,keyvalues,json} from './ui.js';
import {runtimeSummary} from './evidence-model.js';

export function runtimePanel(runtime){
 const summary=runtimeSummary(runtime);
 if(!summary.available)return h('div',{class:'notice section-gap'},'旧证据包未提供运行环境：不能判断是否 root、是否实机，也不能判断启动阶段覆盖。');
 const profile=summary.profile;
 return h('div',{class:'section-gap'},panel('采集环境与能力边界','证据包声明 · 工作台未独立认证设备或执行采集',
  h('div',{class:'panel-body'},h('div',{class:'evidence-title'},h('strong',{},summary.mode),badge('neutral',summary.environment)),
   keyvalues([['样本范围',summary.scope],['设备串号',profile.serial],['Shell UID',profile.shell_uid],
    ['镜像类型',profile['ro.build.type']],['可调试属性',profile['ro.debuggable']],['启动阶段',summary.startup]]),
   h('div',{class:'notice section-gap'},'自有夹具成功不代表能注入任意第三方 APK；UID 非 0 不证明设备不存在 su。userdebug 只算受限非 root 模拟。'),
   h('p',{class:'section-gap'},summary.checks.length?`声明的采集检查 ${summary.checks.length} 项，必要失败 ${summary.failed.length} 项；不等同整轮管线验收。`:'未提供采集检查，不能推断成功。'),
   summary.failed.length?h('ul',{class:'gaps'},summary.failed.map(name=>h('li',{},name))):null,
   h('details',{},h('summary',{},'运行环境原始记录'),json(runtime)))));
}
