/* Read-only published round, deliberately independent of VehicleUI.current. */
(function () {
  'use strict';
  const U = window.VehicleUI;
  const eligibility = {workflow_only: '仅验证工作流 · 不计分', eligible: '符合配对计分资格', insufficient: '计分证据不足'};
  const workflows = {supported: '业务链有证据支持', insufficient: '证据不足', static_only: '仅静态完成'};
  const reviews = {signed: '已签核', pending: '待签核'};
  function paragraph(host, label, value) {
    host.append(U.node('p', 'review-field', label + '：' + (value ?? '未提供')));
  }
  function list(host, title, rows) {
    const box = U.node('section', 'review-list');
    box.append(U.node('h3', '', title));
    if (!rows.length) box.append(U.node('p', 'hint', '无已发布条目。'));
    else {
      const ul = U.node('ul');
      rows.forEach(row => ul.append(U.node('li', '', row)));
      box.append(ul);
    }
    host.append(box);
  }
  function render(host, data) {
    host.replaceChildren(); host.dataset.round = data.round_id;
    const intro = U.node('div', 'review-intro');
    intro.append(U.node('h3', '', data.round_id), U.node('p', 'notice notice--caveat',
      'subagent 复核 · ' + (data.signoff_status === 'signed' ? '本轮已签核' : '本轮待签核') +
      '。此标签表示 subagent 复核，不代表人工签核。'));
    intro.append(U.node('p', 'hint', '工作流完成、计分资格与审查结论分别记录。不计分不表示审计失败，也不表示应用安全；静态成功不代表动态通过。'));
    host.append(intro);
    const counts = data.counts, threshold = U.node('section', 'review-threshold');
    threshold.append(U.node('h3', '', '本轮样本门槛'));
    paragraph(threshold, '范围', counts.scope === 'this_new_round' ? '本轮新增证据（历史 HA 单列）' : '范围未说明');
    paragraph(threshold, '工作流 App', counts.workflow_apps);
    paragraph(threshold, '符合配对计分的独立 App / 门槛',
      (counts.independent_apps ?? '未提供') + ' / ' + (counts.required_independent_apps ?? '未提供'));
    paragraph(threshold, '计分参考正例对 / 门槛',
      (counts.reference_pairs ?? '未提供') + ' / ' + (counts.required_reference_pairs ?? '未提供'));
    threshold.append(U.node('p', 'hint', 'workflow_only 不计入上述配对计分数量。历史 HA 基线不并入本轮样本数。'));
    host.append(threshold);
    const cases = U.node('div', 'review-cases');
    data.cases.forEach(item => {
      const card = U.node('article', 'review-case'); card.dataset.case = item.id;
      card.append(U.node('h3', '', item.family + ' · ' + item.id));
      paragraph(card, '包名', item.package);
      paragraph(card, '工作流状态', workflows[item.workflow_status] || '状态未说明');
      paragraph(card, '配对计分资格', eligibility[item.eligibility] || item.eligibility);
      paragraph(card, '参考正例对', item.reference_pairs);
      paragraph(card, '复核状态（subagent）', reviews[item.review_status] || '未提供复核结论');
      paragraph(card, '会话 ID', item.session_ids.length ? item.session_ids.join('，') : '未提供动态会话');
      list(card, '资格依据', item.eligibility_reasons);
      list(card, '复核发现', item.findings);
      cases.append(card);
    });
    if (!data.cases.length) cases.append(U.node('p', 'notice notice--empty', '本轮尚未发布案例。'));
    host.append(cases);
    list(host, '结论边界', data.limits);
    const binding = U.node('details', 'evidence-details');
    binding.append(U.node('summary', '', '本轮证据绑定摘要'),
      U.node('pre', 'evidence-json', JSON.stringify(data.bindings, null, 2)));
    host.append(binding);
  }
  let generation = 0;
  U.reviewRound = async function () {
    const request = ++generation, host = document.getElementById('review-round');
    U.empty(host, '正在读取本轮公开复核摘要…');
    try {
      const data = await U.get('/api/review-round');
      if (request === generation) render(host, data);
    } catch (error) {
      if (request === generation) U.empty(host, error.message);
    }
  };
}());
