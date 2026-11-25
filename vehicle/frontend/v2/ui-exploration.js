/* Projection of AAOS UI exploration results for the selected audit task. */
(function () {
  'use strict';
  const VS = window.VS;
  const $ = (selector) => document.querySelector(selector);
  const esc = (value) => String(value ?? '').replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const exploreStatus = {
    fixture_read_requested: '已触发夹具读取动作',
    fixture_actions_requested: '夹具读取与订阅操作已发送',
    fixture_controls_unavailable: '未找到剩余的夹具操作控件',
    no_candidates: '没有更多可识别控件', window_ended: '采集窗口已结束', action_limit: '达到动作上限',
    target_not_focused: '目标应用失去前台焦点', emulator_required: '当前设备不是 AAOS 模拟器',
    user_mismatch: '设备当前用户与任务用户不同', target_ui_unavailable: '界面树未包含目标应用',
    timeout: '设备响应超时', invalid_hierarchy: '无法解析界面树',
    device_error: '设备命令失败', unexpected_error: '探索器运行异常',
  };
  const explorationCard = document.createElement('section');
  explorationCard.className = 'card mt16';
  $('#dynBody').closest('.tbl-wrap').before(explorationCard);

  function renderExploration(job) {
    if (VS.state.page !== 'dynamic') return;
    const result = job?.ui_exploration;
    explorationCard.hidden = !result && !job?.options?.auto_explore;
    if (explorationCard.hidden) return;
    const actions = result?.actions || [];
    const reason = result
      ? exploreStatus[result.reason] || '自动探索正在运行'
      : job.state === 'failed' ? '本轮没有自动探索记录' : '等待采集记录';
    const heading = '<h2>自动 UI 探索</h2>';
    explorationCard.innerHTML = heading + '<p class="sub">' + esc(reason) + ' · ' + actions.length + ' 次动作</p>' +
      (actions.length ? '<ol>' + actions.map((action) =>
        '<li>' + esc(action.label) + ' · ' + (action.status === 'sent' ? '已发送' : '结果未确认') + '</li>'
      ).join('') + '</ol>' : '');
  }

  VS.on('page', () => renderExploration(VS.state.job));
  VS.on('job', () => renderExploration(VS.state.job));
}());
