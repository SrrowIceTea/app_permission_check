/* V·SCANNER v2 · 七步流程引导
   功能页顶部给"第几站 / 上一步 / 下一步"，概览页即起点不显示。
   点击只调用 VS.go()，与顶栏 pill 走同一条导航，不碰任何业务逻辑。 */
(function () {
  'use strict';
  const VS = window.VS;
  const box = document.querySelector('#flow');
  if (!box) return;

  const STEPS = [
    ['overview', '概览', '选任务 · 传 APK'],
    ['source', '源码', '反编译目录'],
    ['static', '静态', '结论行与证据'],
    ['dynamic', '动态', '设备观测'],
    ['ai', '复核', 'AI 辅助复述'],
    ['pdf', '报告', 'PDF 与证据包'],
    ['review', '证据', '复核轮次'],
  ];
  const order = STEPS.map((s) => s[0]);
  const pad = (n) => String(n).padStart(2, '0');

  box.innerHTML =
    '<div class="flow-inner">' +
      '<ol class="flow-steps" id="flowSteps">' +
        STEPS.map(([page, label, tip], i) =>
          `<li><button type="button" class="flow-step" data-page="${page}" title="${tip}">` +
          `<i>${pad(i + 1)}</i><span>${label}</span></button></li>`).join('') +
      '</ol>' +
      '<div class="flow-nav">' +
        '<button type="button" class="flow-btn" id="flowPrev">← 上一步</button>' +
        '<button type="button" class="flow-btn flow-btn-main" id="flowNext">下一步 →</button>' +
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
      btn.classList.toggle('is-on', i === idx);
      btn.classList.toggle('is-past', i < idx);
    });
    prev.disabled = false;
    prev.textContent = '← ' + (idx === 1 ? '概览' : STEPS[idx - 1][1]);
    const last = idx === order.length - 1;
    next.textContent = last ? '完成 · 回概览' : STEPS[idx + 1][1] + ' →';
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
