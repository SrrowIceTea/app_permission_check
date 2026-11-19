/* V·SCANNER v2 · 七页工作台（真实数据）
   接口（同源）：GET /api/config · GET /api/pipeline · GET /api/pipeline/{id}
                GET /api/pipeline/{id}/findings · POST /api/pipeline?name&mode&version&authorized
   子页面渲染在 pages.js，通过 window.VS 的事件总线协作。
*/
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const state = {
    mode: 'static', version: '15', page: 'overview',
    jobs: [], job: null, rows: [], current: null, note: '',
    timer: null, cfg: null,
  };
  const STAGE_TEXT = { pending: '等待', running: '进行中', pass: '通过', done: '完成', failed: '失败', skipped: '跳过' };
  const LEVEL = { correlated: ['sev-h', '已关联'], observed: ['sev-m', '已观测'], candidate: ['sev-l', '候选'] };
  const bus = {};

  async function api(path, init) {
    const res = await fetch(path, Object.assign({ headers: { Accept: 'application/json' } }, init));
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (e) { data = { raw: text }; }
    if (!res.ok) {
      const msg = (data && data.error && (data.error.message || data.error.code)) || res.status;
      throw new Error(String(msg));
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

  /* 暴露给 pages.js；脚本按 app.js → pages.js 顺序加载，这里同步赋值 */
  window.VS = { api, state, on, toast, go };

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
    const done = (job.stages || []).filter((x) => ['done', 'pass'].includes(x.status)).length;
    return ['t-run', `${s === 'running' ? '进行中' : '排队'} ${done}/${(job.stages || []).length || 5}`];
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
      return `<li data-id="${j.id}" class="${state.current === j.id ? 'is-cur' : ''}">
        <b>${short}…</b><em>${name}</em>
        <span class="tag ${cls}">${text}</span></li>`;
    }).join('');
    $$('#jobsList li[data-id]').forEach((li) => li.addEventListener('click', () => select(li.dataset.id)));
  }

  /* ── 阶段进度（快照没有 stages 字段，按 stage_timings 渲染） ── */
  function renderStages(job) {
    const timings = (job && job.stage_timings) || [];
    const stages = timings.length ? timings : ((state.cfg && state.cfg.stages) || []);
    if (!stages.length) { $('#stagesCard').hidden = true; setRing(0); return; }
    $('#stagesCard').hidden = false;
    $('#stagesSub').textContent = `${job.name || job.package || ''} · ${job.state || ''}`;
    $('#stageList').innerHTML = stages.map((s) => {
      const status = s.status || 'pending';
      const cls = ['done', 'pass'].includes(status) ? 'st-ok'
        : status === 'running' ? 'st-run' : status === 'failed' ? 'st-bad' : 'st-wait';
      const dur = Number.isFinite(s.duration_ms) ? ` · ${(s.duration_ms / 1000).toFixed(1)}s` : '';
      return `<li class="${cls}"><i></i><span>${s.label || s.id}</span><em>${STAGE_TEXT[status] || status}${dur}</em></li>`;
    }).join('');
    const done = stages.filter((s) => ['done', 'pass'].includes(s.status)).length;
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
        job ? (state.note || '该任务没有可展示的结论行') : '还没有审计任务，先上传一个 APK'}</td></tr>`;
      $('#findingsNote').textContent = job ? '没有结论行' : '尚未选择任务';
      return;
    }
    $('#findingsNote').textContent = `${rows.length} 条 · 来自 ${String(job.id).slice(0, 12)}…`;
    body.innerHTML = rows.slice(0, 8).map((row) => {
      const [cls, txt] = levelOf(row);
      const rule = row.rule_id || row.rule || '—';
      const title = row.rule_title || row.title || row.message || row.description || row.note || '—';
      return `<tr><td><span class="sev ${cls}">${txt}</span></td>
        <td><b>${rule}</b></td><td>${title}</td><td>${locOf(row)}</td></tr>`;
    }).join('');
    if (rows.length > 8) $('#findingsNote').textContent += ' · 概览只显示前 8 条';
  }

  /* ── 选中任务 ── */
  async function select(id) {
    if (!id) return;
    state.current = id;
    renderJobs();
    try {
      const job = await api('/api/pipeline/' + encodeURIComponent(id));
      state.job = job;
      state.note = '';
      const bands = job.findings_by_conclusion_level || {};
      $('#lgOk').textContent = `已关联 ${bands.correlated ?? 0}`;
      $('#lgWarn').textContent = `已观测 ${bands.observed ?? 0}`;
      $('#lgGap').textContent = `候选 ${bands.candidate ?? 0}`;
      $('#ringSub').textContent = `${job.name || job.package || 'APK'} · ${job.findings_total ?? 0} 条结论`;
      renderStages(job);

      let rows = [];
      if (['done', 'static_only', 'failed'].includes(job.state)) {
        try {
          const data = await api(`/api/pipeline/${encodeURIComponent(id)}/findings`);
          rows = Array.isArray(data) ? data : (data && data.findings) || [];
        } catch (e) {
          state.note = e.message;
        }
      } else {
        state.note = '任务仍在执行，结论尚未生成';
      }
      state.rows = rows;
      renderFindings(job, rows);
      emit('job', { job, rows });
      toast(`已载入任务 ${String(id).slice(0, 12)}…`);
    } catch (e) {
      online(false, '读取任务失败');
      toast('读取任务失败：' + e.message);
    }
  }

  async function loadJobs(prefer) {
    const rows = await api('/api/pipeline');
    state.jobs = Array.isArray(rows) ? rows : [];
    renderJobs();
    const pick = prefer || (state.jobs[0] && state.jobs[0].id);
    if (pick) await select(pick);
    else { $('#ringSub').textContent = '尚未载入任务'; setRing(0); renderFindings(null, null); emit('job', { job: null, rows: [] }); }
  }

  /* ── 上传 → 轮询 ── */
  async function upload(file) {
    if (!$('#auth').checked) { dzMsg('请先勾选授权声明'); return; }
    const q = new URLSearchParams({ name: file.name, mode: state.mode, version: state.version, authorized: 'true' });
    dzShow(file);
    try {
      const job = await api('/api/pipeline?' + q.toString(), {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file,
      });
      $('#dzPct').textContent = '已提交';
      toast('已提交，正在排队执行');
      poll(job.id);
    } catch (e) {
      dzMsg('提交失败：' + e.message);
      toast('提交失败：' + e.message);
    }
  }
  function poll(id) {
    clearInterval(state.timer);
    state.current = id;
    state.timer = setInterval(async () => {
      try {
        await loadJobs(id);
        const job = state.jobs.find((j) => j.id === id);
        if (job && ['done', 'static_only', 'failed'].includes(job.state)) {
          clearInterval(state.timer);
          $('#dzPct').textContent = job.state === 'done' ? '完成' : '结束';
          toast(job.state === 'done' ? '审计完成' : '任务已结束：' + job.state);
        }
        online(true, '已连接 · 任务 ' + String(id).slice(0, 8));
      } catch (e) { /* 轮询期间的瞬时失败保持上一次状态 */ }
    }, 2000);
  }

  /* ── 上传框交互 ── */
  const dz = $('#dz'), fileInput = $('#file');
  const dzName = $('#dzName'), dzBar = $('#dzBar'), dzPct = $('#dzPct');
  function dzShow(f) {
    dzName.textContent = f.name + ' · ' + (f.size / 1048576).toFixed(1) + ' MB';
    $('#dzFile').classList.add('show');
    dzBar.style.width = '100%';
    dzPct.textContent = '上传中';
  }
  function dzMsg(t) {
    dzName.textContent = t;
    $('#dzFile').classList.add('show');
    dzBar.style.width = '0';
    dzPct.textContent = '—';
  }
  dz.addEventListener('click', () => fileInput.click());
  dz.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
  ['dragenter', 'dragover'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.add('is-drag'); }));
  ['dragleave', 'drop'].forEach((t) => dz.addEventListener(t, (e) => { e.preventDefault(); dz.classList.remove('is-drag'); }));
  dz.addEventListener('drop', (e) => {
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (f) { if (/\.apk$/i.test(f.name)) upload(f); else dzMsg('只接受 .apk 文件'); }
  });
  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (f) { if (/\.apk$/i.test(f.name)) upload(f); else dzMsg('只接受 .apk 文件'); }
  });

  /* ── 配置分段控件 ── */
  $$('.seg').forEach((seg) => seg.addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    $$('button', seg).forEach((b) => b.classList.toggle('is-on', b === btn));
    if (seg.dataset.seg === 'mode') {
      state.mode = btn.dataset.v;
      $('#modeOut').textContent = btn.textContent;
    } else {
      state.version = btn.dataset.v;
      $('#sdkOut').textContent = 'Android ' + btn.dataset.v;
    }
  }));

  /* ── 顶栏导航 ── */
  $('#nav').addEventListener('click', (e) => {
    const btn = e.target.closest('.pill');
    if (btn) go(btn.dataset.page);
  });
  window.addEventListener('hashchange', () => go(location.hash.slice(1)));

  $('#startBtn').addEventListener('click', () => {
    dz.scrollIntoView({ behavior: 'smooth', block: 'center' });
    setTimeout(() => fileInput.click(), 380);
  });
  $('#gotoFindings').addEventListener('click', () => go('static'));

  /* ── 启动 ── */
  document.addEventListener('DOMContentLoaded', async function init() {
    $$('[data-count]').forEach((el) => countUp(el, +el.dataset.count));
    setRing(0);
    go(location.hash.slice(1) || 'overview');
    try {
      const cfg = await api('/api/config');
      state.cfg = cfg;
      online(true, `已连接 · AAOS ${cfg.api}`);
      $$('[data-count]').forEach((el, i) => {
        const v = [(cfg.versions || []).length, (cfg.stages || []).length, cfg.api];
        if (v[i]) { el.dataset.done = '0'; countUp(el, v[i]); }
      });
      const on = $$('.seg[data-seg="sdk"] button').find((b) => b.dataset.v === String(cfg.version));
      if (on) $$('.seg[data-seg="sdk"] button').forEach((b) => b.classList.toggle('is-on', b === on));
      state.version = String(cfg.version || '15');
      $('#sdkOut').textContent = 'Android ' + state.version;
      await loadJobs();
    } catch (e) {
      online(false, '车载服务未连接');
      $('#jobsList').innerHTML = '<li class="jobs-empty">后端未启动：请运行 vehicle.ps1 web</li>';
      renderFindings(null, null);
      toast('后端未连接，页面只显示静态样式');
    }
  });
}());
