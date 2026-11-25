/* V·SCANNER v2 · 功能页流程导航。 */
(function () {
  'use strict';
  const VS = window.VS;
  const box = document.querySelector('#flow');
  if (!box) return;

  const STEPS = [
    ['overview', '概览', '选择任务或上传 APK'],
    ['source', '源码', '反编译目录'],
    ['static', '结论', '审计结论与证据'],
    ['dynamic', '动态', '设备观测与采集会话'],
    ['ai', 'AI 复核', 'AI 辅助复核'],
    ['pdf', '报告', '看板、PDF 与证据包'],
    ['review', '证据', '证据复核轮次'],
  ];
  const order = STEPS.map((s) => s[0]);

  box.innerHTML =
    '<div class="flow-inner">' +
      '<ol class="flow-steps" id="flowSteps">' +
        STEPS.map(([page, label, tip]) =>
          `<li><button type="button" class="flow-step" data-page="${page}" title="${tip}">` +
          `<span class="flow-mark" aria-hidden="true"></span><span>${label}</span></button></li>`).join('') +
      '</ol>' +
      '<div class="flow-nav">' +
        '<button type="button" class="flow-btn" id="flowPrev"></button>' +
        '<button type="button" class="flow-btn" id="flowNext"></button>' +
      '</div>' +
    '</div>';

  const steps = Array.from(box.querySelectorAll('.flow-step'));
  const prev = box.querySelector('#flowPrev');
  const next = box.querySelector('#flowNext');

  function paint(page) {
    const idx = order.indexOf(page);
    box.hidden = idx <= 0;                  // 概览（含未知页回落）不显示流程条
    if (box.hidden) return;
    steps.forEach((btn, i) => {
      if (i === idx) btn.setAttribute('aria-current', 'step');
      else btn.removeAttribute('aria-current');
    });
    const previousLabel = STEPS[idx - 1][1];
    const nextLabel = STEPS[idx + 1]?.[1];
    prev.textContent = previousLabel;
    prev.setAttribute('aria-label', '上一页 ' + previousLabel);
    next.textContent = nextLabel || '返回概览';
    next.setAttribute('aria-label', nextLabel ? '下一页 ' + nextLabel : '返回概览');
  }

  box.addEventListener('click', (e) => {
    const step = e.target.closest('.flow-step');
    if (step) { VS.go(step.dataset.page); return; }
    const idx = order.indexOf(VS.state.page);
    if (idx < 0) return;
    if (e.target.closest('#flowPrev')) VS.go(order[Math.max(0, idx - 1)]);
    else if (e.target.closest('#flowNext')) {
      VS.go(idx === order.length - 1 ? 'overview' : order[idx + 1]);
    }
  });

  VS.on('page', paint);
  paint(VS.state.page);
}());
