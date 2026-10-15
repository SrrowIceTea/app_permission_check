// Lifecycle is authoritative; missing progress is never displayed as fabricated 0%.
export function jobPresentation(job){
 const active=['queued','running'].includes(job.state);
 const terminal={done:['处理已结束','后台处理已结束；各阶段可用性以任务状态为准。'],failed:['处理失败','后台处理失败，请查看错误与阶段状态。'],cancelled:['处理已取消','本次后台处理已取消，已落盘的日志保留供诊断。']};
 const fallback=terminal[job.state];
 const percent=active&&typeof job.percent==='number'&&Number.isFinite(job.percent)?Math.max(0,Math.min(100,job.percent)):null;
 return {active,percent,stage:active?(job.stage||(job.state==='queued'?'等待处理':'正在处理')):(fallback?.[0]||'状态未知'),
  message:job.error||(active?(job.cancellation_requested?'已请求取消：当前步骤结束后清理并停止。':'后台处理中，数据将自动更新'):fallback?.[1]||'未提供可确认的处理状态。'),
  progressLabel:active?(percent===null?'百分比未报告':`${percent}%`):fallback?.[0]||'状态未知'};
}
