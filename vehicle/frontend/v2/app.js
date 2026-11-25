/* V·SCANNER v2 · 七页工作台（真实数据）
   接口（同源）：GET /api/config · GET /api/pipeline · GET /api/pipeline/{id}
                GET /api/pipeline/{id}/findings · POST /api/pipeline?name&mode&version&authorized
   上传设置和轮询由 upload.js 负责；子页面渲染在 pages.js。
*/
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const state = {
    page: 'overview',
    jobs: [], job: null, rows: [], current: null, note: '',
    cfg: null,
  };
  const STAGE_TEXT = { pending: '等待', running: '进行中', pass: '通过', done: '完成', failed: '失败', skipped: '跳过' };
  const LEVEL = { correlated: ['sev-h', '已关联'], observed: ['sev-m', '已观测'], candidate: ['sev-l', '候选'] };
  const bus = {};
  const escapeHtml = (value) => String(value ?? '').replace(/[&<>"]/g,
    (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[character]));

  async function api(path, init) {
    const res = await fetch(path, Object.assign({ headers: { Accept: 'application/json' } }, init));
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
    if (!res.ok) {
      const problem = data?.error;
      const error = new Error(String(problem?.message || problem?.code || res.status));
      error.nextAction = problem?.next_action;
      throw error;
    }
    return data;
  }
  function on(evt, fn) { (bus[evt] = bus[evt] || []).push(fn); }
  function emit(evt, payload) {
    (bus[evt] || []).forEach((fn) => { try { fn(payload); } catch (e) { console.error(e); } });
  }

  let toastTimer = 0;
  function toast(text) {
    const el = $('#toast');
    if (!el) return;
    el.textContent = text;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2200);
  }
  function online(ok, text) {
    $('#svcDot').style.background = ok ? 'var(--sage)' : 'var(--accent)';
    $('#svcText').textContent = text;
  }

  /* ── 七页导航（hash 可回退） ── */
  function go(page) {
    if (!$('#page-' + page)) page = 'overview';
    state.page = page;
    $$('#nav .pill').forEach((b) => b.classList.toggle('is-active', b.dataset.page === page));
    $$('.view').forEach((v) => { v.hidden = v.id !== 'page-' + page; });
    if ('#' + page !== location.hash) history.replaceState(null, '', '#' + page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
    emit('page', page);
  }

  window.VS = { api, state, on, toast, go, select, refreshJobs };

  /* ── 数字滚动 / 进度环 ── */
  function countUp(el, target, dur) {
    if (el.dataset.done === '1') return;
    el.dataset.done = '1';
    const t0 = performance.now();
    (function step(now) {
      const k = Math.min(1, (now - t0) / (dur || 900));
      el.textContent = Math.round(target * (1 - Math.pow(1 - k, 3)));
      if (k < 1) requestAnimationFrame(step);
    })(t0);
  }
  const C = 2 * Math.PI * 82;
  $('#ringBar').style.strokeDasharray = C;
  function setRing(pct) {
    $('#ringBar').style.strokeDashoffset = C * (1 - Math.max(0, Math.min(1, pct / 100)));
    $('#ringVal').textContent = Math.round(pct);
  }

  /* ── 任务列表 ── */
  function tagOf(job) {
    const s = job.state || 'pending';
    if (s === 'done') return ['t-ok', '已完成'];
    if (s === 'failed') return ['t-idle', '已失败'];
    if (s === 'static_only') return ['t-run', '仅静态完成'];
    const stages = job.stage_timings || [];
    const done = stages.filter((stage) => ['done', 'pass', 'skipped'].includes(stage.status)).length;
    return ['t-run', `${s === 'running' ? '进行中' : '排队'} ${done}/${stages.length || 5}`];
  }
  function renderJobs() {
    const box = $('#jobsList');
    $('#jobCount').textContent = state.jobs.length ? `· ${state.jobs.length}` : '';
    if (!state.jobs.length) {
      box.innerHTML = '<li class="jobs-empty">还没有任务。上传一个 APK 就会出现在这里。</li>';
      return;
    }
    box.innerHTML = state.jobs.slice(0, 6).map((j) => {
      const [cls, text] = tagOf(j);
      const short = String(j.id || '').slice(0, 12);
      const name = j.name || j.package || '未命名 APK';
      return `<li data-id="${escapeHtml(j.id)}" class="${state.current === j.id ? 'is-cur' : ''}">
        <b>${escapeHtml(short)}…</b><em>${escapeHtml(name)}</em>
        <span class="tag ${cls}">${text}</span></li>`;
    }).join('');
    $$('#jobsList li[data-id]').forEach((li) => li.addEventListener('click', () => select(li.dataset.id)));
  }

  /* ── 阶段进度（快照没有 stages 字段，按 stage_timings 渲染） ── */
  function renderStages(job) {
    if (!job) { $('#stagesCard').hidden = true; setRing(0); return; }
    const timings = job.stage_timings || [];
    const stages = timings.length ? timings : ((state.cfg && state.cfg.stages) || []);
    if (!stages.length) { $('#stagesCard').hidden = true; setRing(0); return; }
    $('#stagesCard').hidden = false;
    $('#stagesSub').textContent = `${job.name || job.package || ''} · ${job.state || ''}`;
    const failure = job.state === 'failed' ? job.result?.error : null;
    $('#stageFailure').hidden = !failure;
    $('#stageFailure').textContent = failure ? [failure.message, failure.next_action].filter(Boolean).join(' ') : '';
    $('#stageList').innerHTML = stages.map((s) => {
      const status = s.status || 'pending';
      const cls = ['done', 'pass'].includes(status) ? 'st-ok'
        : status === 'running' ? 'st-run' : status === 'failed' ? 'st-bad' : 'st-wait';
      const dur = Number.isFinite(s.duration_ms) ? ` · ${(s.duration_ms / 1000).toFixed(1)}s` : '';
      return `<li class="${cls}"><i></i><span>${escapeHtml(s.label || s.id)}</span><em>${escapeHtml(STAGE_TEXT[status] || status)}${dur}</em></li>`;
    }).join('');
    const done = stages.filter((s) => ['done', 'pass', 'skipped'].includes(s.status)).length;
    setRing((done / stages.length) * 100);
  }

  /* ── 结论表（概览用） ── */
  function levelOf(row) {
    return LEVEL[String(row.conclusion_level || '').toLowerCase()] || ['sev-l', row.conclusion_level || '待判'];
  }
  function locOf(row) {
    const locs = (row.code_locs || []).filter((l) => l && l.line);
    if (locs.length) return `${locs[0].file}:${locs[0].line}` + (locs.length > 1 ? ` +${locs.length - 1}` : '');
    if (row.permission) return '清单权限 · ' + row.permission;
    if (row.property) return '属性 · ' + row.property;
    return row.code_loc_note || '—';
  }
  function renderFindings(job, rows) {
    const body = $('#findingsBody');
    if (!rows || !rows.length) {
      body.innerHTML = `<tr><td colspan="4" class="tbl-empty">${
        job ? escapeHtml(state.note || '该任务没有可展示的结论行') : '还没有可展示的任务'}</td></tr>`;
      $('#findingsNote').textContent = job ? '没有结论行' : '尚未选择任务';
      return;
    }
    $('#findingsNote').textContent = `${rows.length} 条 · 来自 ${String(job.id).slice(0, 12)}…`;
    body.innerHTML = rows.slice(0, 8).map((row) => {
      const [cls, txt] = levelOf(row);
      const rule = row.rule_id || row.rule || '—';
      const title = row.rule_title || row.title || row.message || row.description || row.note || '—';
      return `<tr><td><span class="sev ${cls}">${escapeHtml(txt)}</span></td>
        <td><b>${escapeHtml(rule)}</b></td><td>${escapeHtml(title)}</td><td>${escapeHtml(locOf(row))}</td></tr>`;
    }).join('');
    if (rows.length > 8) $('#findingsNote').textContent += ' · 概览只显示前 8 条';
  }

  /* ── 选中任务 ── */
  let selection = 0;
  async function select(id) {
    if (!id) return;
    const request = ++selection;
    state.current = id;
    renderJobs();
    if (state.job && state.job.id !== id) {
      state.job = null;
      state.rows = [];
      renderStages(null);
      renderFindings(null, []);
      emit('job');
    }
    try {
      const job = await api('/api/pipeline/' + encodeURIComponent(id));
      if (request !== selection) return;
      let rows = [], note = '';
      if (['done', 'static_only'].includes(job.state)) {
        const action = job.state === 'static_only' ? 'static' : 'findings';
        try {
          const data = await api(`/api/pipeline/${encodeURIComponent(id)}/${action}`);
          rows = Array.isArray(data) ? data : (data && data.findings) || [];
        } catch (error) {
          note = error.message;
        }
      } else {
        note = job.state === 'failed' ? job.result?.error?.message || '审计失败' : '任务仍在执行，结论尚未生成';
      }
      if (request !== selection) return;
      state.job = job;
      state.rows = rows;
      state.note = note;
      const bands = job.findings_by_conclusion_level || {};
      $('#lgOk').textContent = `已关联 ${bands.correlated ?? 0}`;
      $('#lgWarn').textContent = `已观测 ${bands.observed ?? 0}`;
      $('#lgGap').textContent = `候选 ${bands.candidate ?? 0}`;
      $('#ringSub').textContent = `${job.name || job.package || 'APK'} · ${job.findings_total ?? 0} 条结论`;
      renderStages(job);

      renderFindings(job, rows);
      emit('job', { job, rows });
    } catch (e) {
      if (request === selection) toast('读取任务失败：' + e.message);
    }
  }

  async function refreshJobs() {
    const rows = await api('/api/pipeline');
    state.jobs = Array.isArray(rows) ? rows : [];
    renderJobs();
    return state.jobs;
  }

  /* ── 顶栏导航 ── */
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('.pill');
    if (btn) go(btn.dataset.page);
  });
  window.addEventListener('hashchange', () => go(location.hash.slice(1)));

  $('#gotoFindings').addEventListener('click', () => go('static'));

  /* ── 启动 ── */
  document.addEventListener('DOMContentLoaded', async function init() {
    $$('[data-count]').forEach((el) => countUp(el, +el.dataset.count));
    setRing(0);
    go(location.hash.slice(1) || 'overview');
    try {
      const cfg = await api('/api/config');
      state.cfg = cfg;
      emit('config', cfg);
      online(true, `服务已连接 · 目标 AAOS ${cfg.api}`);
      $$('[data-count]').forEach((el, i) => {
        const v = [(cfg.versions || []).length, (cfg.stages || []).length, cfg.api];
        if (v[i]) { el.dataset.done = '0'; countUp(el, v[i]); }
      });
      const jobs = await refreshJobs();
      if (jobs[0] && !state.current) await select(jobs[0].id);
    } catch (e) {
      online(false, '车载服务未连接');
      $('#jobsList').innerHTML = '<li class="jobs-empty">后端未启动：请运行 vehicle.ps1 web</li>';
      renderFindings(null, null);
      toast('后端未连接，页面只显示静态样式');
    }
  });
}());
