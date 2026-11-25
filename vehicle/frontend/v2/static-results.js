/* Static candidates are separate from the final audit findings. */
(function () {
  'use strict';
  const VS = window.VS;
  const section = document.createElement('section');
  section.className = 'findings mt16';
  section.innerHTML = '<div class="sec-head"><h2>静态分析候选</h2><span id="staticCandidateCount"></span></div>' +
    '<p class="sub">来自 APK 清单和代码引用，需要人工复核。</p>' +
    '<div class="tbl-wrap"><table><thead><tr><th>规则</th><th>说明</th><th>静态证据</th></tr></thead>' +
    '<tbody id="staticCandidateBody"></tbody></table></div>';
  document.querySelector('#page-static').append(section);
  const body = section.querySelector('tbody');
  const count = section.querySelector('#staticCandidateCount');
  let request = 0;

  function message(text) {
    body.replaceChildren();
    const row = body.insertRow();
    const cell = row.insertCell();
    cell.colSpan = 3;
    cell.className = 'tbl-empty';
    cell.textContent = text;
  }

  async function render() {
    const job = VS.state.job;
    const token = ++request;
    count.textContent = '';
    if (!job) { message('请先选择任务'); return; }
    message('正在读取静态结果…');
    try {
      const data = await VS.api(`/api/pipeline/${encodeURIComponent(job.id)}/static`);
      if (token !== request || VS.state.job !== job) return;
      const rows = Array.isArray(data.findings) ? data.findings : [];
      count.textContent = `${rows.length} 条`;
      if (!rows.length) { message('本轮没有静态候选'); return; }
      body.replaceChildren();
      rows.forEach((item) => {
        const row = body.insertRow();
        row.insertCell().textContent = item.rule_id || '—';
        row.insertCell().textContent = item.rule_title || item.title || '—';
        row.insertCell().textContent = item.note || item.permission || item.evidence_kind || '—';
      });
    } catch (error) {
      if (token !== request || VS.state.job !== job) return;
      message('静态结果暂不可用：' + error.message);
    }
  }
  VS.on('page', (page) => { if (page === 'static') render(); });
  VS.on('job', () => { if (VS.state.page === 'static') render(); });
}());
