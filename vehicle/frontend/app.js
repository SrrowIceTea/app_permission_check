/* Ported mobile workspace interactions, backed exclusively by vehicle/webapp. */
(function () {
  'use strict';
  const U = window.VehicleUI, $ = id => document.getElementById(id);
  const labels = {queued: '排队中', running: '审计中', done: '审计完成', static_only: '仅静态完成', failed: '执行中断'};
  let jobs = [], stages = [], currentPage = 'pipeline', staged = null, checkSeq = 0;
  const streams = new Map();
  const terminal = state => ['done', 'static_only', 'failed'].includes(state);
  function selected() { return jobs.find(j => j.id === U.current); }
  function error(message) { $('upload-error').textContent = message; }
  let serviceLabel = '';
  function online(state, text) {
    const dot = document.querySelector('.status-dot');
    if (dot) dot.dataset.online = state;
    $('service-state').textContent = text;
  }
  /* C 档任务头与耗时：只展示后端返回的字段，缺失即 — + 后端写明的缺口原因 */
  function bytes(size) {
    if (!Number.isFinite(size)) return null;
    if (size < 1024) return size + ' B';
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + ' KiB';
    return (size / 1024 / 1024).toFixed(2) + ' MiB';
  }
  function missing(raw, reason) {
    const ok = !(raw === null || raw === undefined || raw === '');
    const node = U.node('span', ok ? '' : 'field-missing', ok ? String(raw) : '—');
    if (!ok) node.title = reason;
    return node;
  }
  function fmtMs(ms) {
    if (!Number.isFinite(ms)) return null;
    return ms < 1000 ? ms + ' ms' : (ms / 1000).toFixed(1) + ' s';
  }
  function identityCell(label, node) {
    const cell = U.node('div', 'job-identity__cell');
    cell.append(U.node('span', 'job-identity__label', label), node);
    return cell;
  }
  function shaNode(job, gaps) {
    const sha = typeof job.apk_sha256 === 'string' && job.apk_sha256 ? job.apk_sha256 : null;
    if (!sha) return missing(null, gaps.apk_sha256 || '后端未返回 apk_sha256。');
    const box = U.node('details', 'job-sha');
    const brief = U.node('summary', 'job-sha__brief');
    brief.append(U.node('code', 'job-sha__short', sha.slice(0, 12)),
      U.node('span', 'job-sha__cue', '展开全量'));
    const full = U.node('div', 'job-sha__full');
    const copy = U.node('button', 'pl-btn job-sha__copy', '复制');
    copy.type = 'button';
    copy.addEventListener('click', function () {
      const done = ok => { copy.textContent = ok ? '已复制' : '复制失败'; };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(sha).then(() => done(true), () => done(false));
      } else done(false);
    });
    full.append(U.node('code', 'job-sha__code', sha), copy);
    box.append(brief, full);
    return box;
  }
  function jobIdentity(job) {
    const host = $('job-identity');
    host.replaceChildren();
    if (!job) return;
    const gaps = job.field_gaps && typeof job.field_gaps === 'object' ? job.field_gaps : {};
    const grid = U.node('div', 'job-identity__grid');
    grid.append(
      identityCell('被测包名', missing(job.package, gaps.package || '后端未返回 package。')),
      identityCell('APK 大小', missing(bytes(job.apk_size), gaps.apk_size || '后端未返回 apk_size。')),
      identityCell('SHA-256', shaNode(job, gaps)));
    const source = identityCell('哈希来源', missing(job.apk_sha256_source,
      '后端未返回 apk_sha256_source；无法确认该哈希来自产物还是服务端现场计算。'));
    source.classList.add('job-identity__cell--wide');
    grid.append(source);
    host.append(grid);
  }
  function elapsed(job) {
    const node = $('pipeline-elapsed');
    node.hidden = !job;
    const ms = job && Number.isFinite(job.stage_timings_elapsed_ms) ? job.stage_timings_elapsed_ms : null;
    node.textContent = job ? '总耗时 ' + (fmtMs(ms) || '—') : '';
    node.classList.toggle('field-missing', !!job && ms === null);
    if (job) {
      node.title = ms === null
        ? '后端未返回 stage_timings_elapsed_ms：events.jsonl 不足两条数值型时间戳。'
        : '来自后端 stage_timings_elapsed_ms（events.jsonl 首尾时间戳之差）。';
    }
  }
  /* B-03 进度轨始终渲染 5 段：未发生的阶段也生成节点（低对比 + 等待执行） */
  function timeline(job) {
    const list = $('pipeline-timeline');
    list.replaceChildren();
    const timings = job && Array.isArray(job.stage_timings) ? job.stage_timings : [];
    U.progressOf(job).forEach(function (stage, index) {
      const status = stage.status === 'unknown' ? 'pending' : stage.status;
      const row = U.node('li', status === 'pending' ? 'pl-pending pl-idle' : 'pl-' + status);
      row.dataset.stage = stage.id;
      if (status === 'running') row.setAttribute('aria-current', 'step');
      const timing = timings.find(item => item && item.stage === stage.id) || null;
      const dur = U.node('span', 'pl-dur', '耗时 ' + (fmtMs(timing && timing.duration_ms) || '—'));
      if (!Number.isFinite(timing && timing.duration_ms)) {
        dur.classList.add('field-missing');
        dur.title = (timing && timing.unavailable_reason) || '后端 stage_timings 没有该阶段条目。';
      } else dur.title = '来自后端 stage_timings.duration_ms；跨阶段间隙不计入任何阶段。';
      const label = U.node('span', 'pl-label', stage.label);
      label.dataset.step = String(index + 1).padStart(2, '0');
      label.append(dur);
      row.append(U.node('span', 'pl-dot'), label,
        U.node('span', 'pl-msg', stage.message || (status === 'pending' ? '等待执行' : '')));
      list.append(row);
    });
  }
  function result(job) {
    const host = $('pipeline-result'); host.replaceChildren();
    host.style.display = terminal(job.state) ? '' : 'none';
    if (!terminal(job.state)) return;
    if (job.state === 'failed' && U.stateFailed) return U.stateFailed(host, U.failureSpec(job));
    const card = U.node('div', 'pipeline-card');
    card.append(U.node('h2', '', labels[job.state]),
      U.node('p', 'hint', job.result.message || '本轮未完成。'));
    if (job.state === 'done') {
      card.append(U.link('打开审计看板', '/api/pipeline/' + job.id + '/dashboard'),
        U.link('打开 PDF', '/api/pipeline/' + job.id + '/report'));
    }
    if (job.state === 'static_only') {
      card.append(U.node('p', 'hint', '动态采集与关联未执行；静态候选不代表运行时行为。'));
    }
    card.append(U.node('p', 'hint', '任务编号：' + job.id)); host.append(card);
  }
  function renderJob(job) {
    $('audit-stage').dataset.state = terminal(job.state) ? 'done' : 'running';
    $('pipeline-progress').style.display = '';
    const progress = U.progressOf(job), done = progress.filter(p => p.status === 'done').length;
    $('pipeline-job').textContent = job.name + ' · ' + labels[job.state] +
      ' · 已完成 ' + done + ' / ' + progress.length;
    jobIdentity(job); elapsed(job); timeline(job); result(job); history();
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
      online('true', serviceLabel);
      if (U.current === job.id) { renderJob(job); view(); }
      history();
    });
    connection.onerror = function () {
      online('reconnecting', '进度连接中断 · 正在重连');
      if (U.current === job.id) error('进度连接中断，正在重连。后台任务状态未被改写；可刷新恢复历史。');
    };
  }
  function choose(job) {
    U.current = job.id;
    $('code-view').replaceChildren(U.node('p', 'notice notice--empty', '选择文件查看源码。'));
    /* 切换任务时清空 PDF 查看区，避免残留上一任务的报告画面（链接本身仍按 job.id 独立） */
    const viewer = $('pdf-viewer-container');
    if (viewer) viewer.replaceChildren();
    subscribe(job); renderJob(job); view();
  }
  function auditContext(file) {
    return {file: file, mode: $('audit-mode').value, authorized: $('authorized').checked,
      capture: $('capture-choice').value, serial: $('device-serial').value,
      user: $('device-user').value, seconds: $('capture-seconds').value};
  }
  /* B-05 先校验、一次性列出全部不合格项；不逐条弹错，也不在失败时发起上传 */
  async function checkUpload(note) {
    if (!staged) return [];
    const seq = ++checkSeq;
    const rows = await U.validateUpload(auditContext(staged));
    if (seq !== checkSeq) return rows;
    U.renderChecks($('upload-checks'), rows, note);
    $('pipeline-dropzone').dataset.check = U.checksPassed(rows) ? 'pass' : 'fail';
    return rows;
  }
  async function upload(file) {
    if (!file) return;
    if (jobs.some(j => !terminal(j.state))) return error('当前审计仍在运行，请等待完成。');
    error(''); staged = file;
    const plate = $('pipeline-dropzone');
    plate.setAttribute('aria-disabled', 'true'); plate.dataset.check = 'checking';
    const rows = await checkUpload();
    plate.removeAttribute('aria-disabled');
    if (!U.checksPassed(rows)) return;
    const query = new URLSearchParams({name: file.name, mode: $('audit-mode').value,
      authorized: 'true', capture: $('capture-choice').value, serial: $('device-serial').value,
      user: $('device-user').value, seconds: $('capture-seconds').value});
    error('正在上传 APK…');
    try {
      const job = await U.get('/api/pipeline?' + query, {method: 'POST', body: file,
        headers: {'Content-Type': 'application/vnd.android.package-archive'}});
      jobs.unshift(job); choose(job); error('');
      staged = null; $('upload-checks').replaceChildren();
    } catch (e) { error(e.message); }
    finally { plate.removeAttribute('aria-disabled'); $('pipeline-apk-input').value = ''; }
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
    /* 参数改动后，已暂存文件立刻重跑整套校验，仍一次性列出全部不合格项 */
    ['audit-mode', 'authorized', 'capture-choice', 'device-serial', 'device-user', 'capture-seconds']
      .forEach(id => {
        ['input', 'change'].forEach(type => $(id).addEventListener(type, () => {
          if (staged) checkUpload();
        }));
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
      staged = null; ++checkSeq; $('upload-checks').replaceChildren();
      $('pipeline-dropzone').removeAttribute('data-check'); $('pipeline-apk-input').value = '';
      jobIdentity(null); elapsed(null); timeline(null);
    });
    try {
      const [config, rows] = await Promise.all([U.get('/api/config'), U.get('/api/pipeline')]);
      stages = config.stages; U.stages = stages; jobs = rows;
      serviceLabel = '车载服务已连接 · AAOS ' + config.api; online('true', serviceLabel);
      config.captures.forEach(c => {
        const opt = U.node('option', '', c.label + ' · ' + c.packages.join(', '));
        opt.value = c.id; $('capture-choice').append(opt);
      });
      if (jobs.length) choose(jobs[0]); else timeline(null);
      const page = location.hash.slice(1);
      if (document.getElementById('page-' + page)) navigate(page);
      history();
    } catch (e) {
      online('false', '车载服务未连接');
      error('无法连接车载审计服务。请运行 vehicle.ps1 web 后刷新。' + e.message);
    }
  });
}());
