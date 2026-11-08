/* Ported mobile workspace interactions, backed exclusively by vehicle/webapp. */
(function () {
  'use strict';
  const U = window.VehicleUI, $ = id => document.getElementById(id);
  const labels = {queued: '排队中', running: '审计中', done: '审计完成', static_only: '仅静态完成', failed: '审计失败'};
  let jobs = [], stages = [], currentPage = 'pipeline';
  const streams = new Map();
  const terminal = state => ['done', 'static_only', 'failed'].includes(state);
  function selected() { return jobs.find(j => j.id === U.current); }
  function error(message) { $('upload-error').textContent = message; }
  function timeline(job) {
    $('pipeline-timeline').replaceChildren();
    stages.forEach(stage => {
      const ev = (job._events || []).filter(e => e.stage === stage.id).pop();
      const row = U.node('li', 'pl-' + (ev?.status || 'pending'));
      row.append(U.node('span', 'pl-dot'), U.node('span', 'pl-label', stage.label),
        U.node('span', 'pl-msg', ev?.message || '等待执行'));
      $('pipeline-timeline').append(row);
    });
  }
  function result(job) {
    const host = $('pipeline-result'); host.replaceChildren();
    host.style.display = terminal(job.state) ? '' : 'none';
    if (!terminal(job.state)) return;
    const card = U.node('div', 'pipeline-card');
    card.append(U.node('h2', '', labels[job.state]),
      U.node('p', 'hint', job.result.message || job.result.error?.message || '本轮未完成。'));
    if (job.result.error) card.append(U.node('p', 'notice bad', job.result.error.next_action || '查看服务日志后重试。'));
    if (job.state === 'done') {
      card.append(U.link('打开审计看板', '/api/pipeline/' + job.id + '/dashboard'),
        U.link('打开 PDF', '/api/pipeline/' + job.id + '/report'));
    }
    card.append(U.node('p', 'hint', '任务编号：' + job.id)); host.append(card);
  }
  function renderJob(job) {
    $('audit-stage').dataset.state = terminal(job.state) ? 'done' : 'running';
    $('pipeline-progress').style.display = '';
    $('pipeline-job').textContent = job.name + ' · ' + labels[job.state];
    timeline(job); result(job); history();
  }
  function history() {
    $('apk-switch').replaceChildren();
    jobs.forEach(job => {
      const opt = U.node('option', '', job.name + ' · ' + labels[job.state] + ' · ' + job.id.slice(-4));
      opt.value = job.id; opt.selected = U.current === job.id; $('apk-switch').append(opt);
    });
    $('apk-switch').style.display = jobs.length ? '' : 'none';
    $('history-picker').hidden = !jobs.length;
    if (!U.current) {
      const placeholder = U.node('option', '', '查看历史任务');
      placeholder.value = ''; placeholder.disabled = true; placeholder.selected = true;
      $('apk-switch').prepend(placeholder);
    }
    $('current-apk-name').textContent = selected()?.name || '尚未选择';
    $('current-apk-name').title = selected()?.name || '尚未选择应用';
    $('new-audit').disabled = jobs.some(j => !terminal(j.state));
  }
  async function view() {
    const job = selected();
    if (currentPage === 'review') return U.reviewRound();
    if (currentPage === 'pdf-report') return U.reports(jobs);
    if (!job) {
      ['static-results', 'dynamic-results', 'ai-report', 'file-tree', 'code-view'].forEach(id =>
        U.empty($(id), '请先在车载审计页选择 APK 或历史任务。'));
      return;
    }
    const views = {source: U.source, static: U.staticView, dynamic: U.dynamicView, 'ai-report': U.aiView};
    const hosts = {source: 'file-tree', static: 'static-results', dynamic: 'dynamic-results', 'ai-report': 'ai-report'};
    if (views[currentPage]) {
      const page = currentPage;
      U.empty($(hosts[page]), '正在读取当前任务…');
      try { await views[page](job); }
      catch (e) { if (U.current === job.id) U.empty($(hosts[page]), e.message); }
    }
  }
  function navigate(page) {
    currentPage = page;
    document.querySelectorAll('.nav-item').forEach(a => a.classList.toggle('active', a.dataset.page === page));
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
    location.hash = page; view();
  }
  function subscribe(job) {
    if (streams.has(job.id)) return;
    job._events = [];
    const connection = new EventSource(U.base + '/api/pipeline/' + job.id + '/events');
    streams.set(job.id, connection);
    connection.onmessage = function (event) {
      job._events.push(JSON.parse(event.data));
      if (U.current === job.id) timeline(job);
      error('');
    };
    connection.addEventListener('end', function (event) {
      Object.assign(job, JSON.parse(event.data)); connection.close(); streams.delete(job.id);
      if (U.current === job.id) { renderJob(job); view(); }
      history();
    });
    connection.onerror = function () {
      if (U.current === job.id) error('进度连接中断，正在重连。后台任务状态未被改写；可刷新恢复历史。');
    };
  }
  function choose(job) {
    U.current = job.id;
    $('code-view').replaceChildren(U.node('p', 'notice', '选择文件查看源码。'));
    renderJob(job); subscribe(job); view();
  }
  async function upload(file) {
    if (!file) return;
    if (jobs.some(j => !terminal(j.state))) return error('当前审计仍在运行，请等待完成。');
    if (!file.name.toLowerCase().endsWith('.apk')) return error('请选择 .apk 文件。');
    if (!$('authorized').checked) return error('请先确认当前 APK 及设备的测试授权。');
    const mode = $('audit-mode').value;
    if (mode === 'replay' && !$('capture-choice').value) return error('请先选择已有采集会话。');
    const query = new URLSearchParams({name: file.name, mode, authorized: 'true',
      capture: $('capture-choice').value, serial: $('device-serial').value,
      user: $('device-user').value, seconds: $('capture-seconds').value});
    $('pipeline-dropzone').setAttribute('aria-disabled', 'true');
    error('正在上传 APK…');
    try {
      const job = await U.get('/api/pipeline?' + query, {method: 'POST', body: file,
        headers: {'Content-Type': 'application/vnd.android.package-archive'}});
      jobs.unshift(job); choose(job); error('');
    } catch (e) { error(e.message); }
    finally { $('pipeline-dropzone').removeAttribute('aria-disabled'); $('pipeline-apk-input').value = ''; }
  }
  document.addEventListener('DOMContentLoaded', async function () {
    document.querySelectorAll('.nav-item').forEach(a => a.addEventListener('click', e => {
      e.preventDefault(); navigate(a.dataset.page);
    }));
    $('audit-options').addEventListener('submit', e => e.preventDefault());
    $('audit-mode').addEventListener('change', function () {
      $('capture-option').hidden = this.value !== 'replay';
      $('device-options').hidden = this.value !== 'live';
    });
    $('pipeline-dropzone').addEventListener('click', () => $('pipeline-apk-input').click());
    $('pipeline-apk-input').addEventListener('change', e => upload(e.target.files[0]));
    $('pipeline-dropzone').addEventListener('dragover', e => e.preventDefault());
    $('pipeline-dropzone').addEventListener('drop', e => { e.preventDefault(); upload(e.dataTransfer.files[0]); });
    $('apk-switch').addEventListener('change', () => choose(jobs.find(j => j.id === $('apk-switch').value)));
    $('source-filter').addEventListener('input', () => { if (selected()) view(); });
    $('new-audit').addEventListener('click', function () {
      streams.forEach(connection => connection.close()); streams.clear(); U.current = null;
      $('audit-stage').dataset.state = 'idle';
      $('pipeline-progress').style.display = 'none'; $('pipeline-result').style.display = 'none';
      $('authorized').checked = false; $('source-filter').value = '';
      $('pdf-viewer-container').replaceChildren(); error(''); history(); navigate('pipeline');
    });
    try {
      const [config, rows] = await Promise.all([U.get('/api/config'), U.get('/api/pipeline')]);
      stages = config.stages; jobs = rows;
      $('service-state').textContent = '车载服务已连接 · AAOS ' + config.api;
      config.captures.forEach(c => {
        const opt = U.node('option', '', c.label + ' · ' + c.packages.join(', '));
        opt.value = c.id; $('capture-choice').append(opt);
      });
      if (jobs.length) choose(jobs[0]);
      const page = location.hash.slice(1);
      if (document.getElementById('page-' + page)) navigate(page);
      history();
    } catch (e) {
      $('service-state').textContent = '车载服务未连接';
      error('无法连接车载审计服务。请运行 vehicle.ps1 web 后刷新。' + e.message);
    }
  });
}());
