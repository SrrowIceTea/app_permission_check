/* V·SCANNER v2 · 子页面渲染（静态 / 动态 / AI / 报告 / 复核）
   全部走真实产物接口；没有数据就明说原因，不伪造空态为"安全"。
   源码页单独在 source.js（文件树 + 悬停小窗）。 */
(function () {
  'use strict';
  const VS = window.VS, S = VS.state;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  const LEVEL = { correlated: ['sev-h', '已关联'], observed: ['sev-m', '已观测'], candidate: ['sev-l', '候选'] };
  const STATE_CLS = { observed: 'state-ok', registration_only: 'state-warn', read_not_obtained: 'state-warn', not_observed: 'state-gap' };
  const STAGE_CN = { pending: '等待', running: '进行中', pass: '通过', done: '完成', failed: '失败', skipped: '跳过' };
  const cache = { view: [], lv: 'all', q: '' };

  function levelOf(row) { return LEVEL[String(row.conclusion_level || '').toLowerCase()] || ['sev-l', row.conclusion_level || '待判']; }
  function locOf(row) {
    const locs = (row.code_locs || []).filter((l) => l && l.line);
    if (locs.length) return `${locs[0].file}:${locs[0].line}` + (locs.length > 1 ? ` +${locs.length - 1}` : '');
    if (row.permission) return '清单权限 · ' + row.permission;
    if (row.property) return '属性 · ' + row.property;
    return row.code_loc_note || '—';
  }
  function badge(el, job, empty) {
    el.textContent = job
      ? `${job.name || job.package || 'APK'} · ${String(job.id).slice(0, 12)}…`
      : empty;
  }
  const GOTO_BTN = '<button type="button" class="tbl-empty-btn" data-goto="overview">去概览选任务</button>';
  function noJob(body, cols, msg, withAction) {
    body.innerHTML = `<tr><td colspan="${cols}" class="tbl-empty">${msg || '请先在概览页选择一个任务'}` +
      `${withAction ? GOTO_BTN : ''}</td></tr>`;
  }

  /* 源码查看（文件树 / 悬停小窗）已拆到 source.js，这里只负责切页时唤起渲染 */

  /* ══════════ 静态审计 ══════════ */
  function renderStatic() {
    badge($('#staticJob'), S.job, '未选择任务');
    const body = $('#staticBody');
    if (!S.job) { noJob(body, 4, '请先在概览页选择一个任务', true); $('#findingCount').textContent = '0 条'; return; }
    const all = Array.isArray(S.rows) ? S.rows : [];
    cache.view = all.filter((r) => (cache.lv === 'all' || r.conclusion_level === cache.lv) &&
      (!cache.q || [r.rule_id, r.rule_title, r.permission, r.property, r.note, locOf(r)]
        .join(' ').toLowerCase().includes(cache.q)));
    $('#findingCount').textContent = `${cache.view.length} / ${all.length} 条`;
    if (!cache.view.length) {
      noJob(body, 4, all.length ? '没有匹配的结论，换个筛选或关键词' : (S.note || '该任务还没有可展示的结论行'));
      return;
    }
    body.innerHTML = cache.view.map((r, i) => {
      const [cls, label] = levelOf(r);
      return `<tr class="f-row" data-i="${i}"><td><span class="sev ${cls}">${label}</span></td>` +
        `<td><b>${esc(r.rule_id || '—')}</b></td>` +
        `<td>${esc(r.rule_title || r.note || '—')}</td>` +
        `<td>${esc(locOf(r))}</td></tr>`;
    }).join('');
  }
  function detailHtml(r) {
    const parts = [];
    if (r.observation_reason_text) parts.push(`<div><div class="lbl">观测说明</div>${esc(r.observation_reason_text)}</div>`);
    const locs = (r.code_locs || []).filter((l) => l && l.line);
    if (locs.length) parts.push(`<div><div class="lbl">代码位置</div>${locs.map((l) =>
      `<div class="loc-item">${esc(l.role === 'egress' ? '外发处' : l.role === 'read' ? '读取处' : l.role || '位置')} · ` +
      `${esc(l.file)}:${esc(l.line)} · ${esc(l.class || '')}${l.method ? '.' + esc(l.method) : ''}</div>`).join('')}</div>`);
    const gaps = r.code_loc_gaps || [];
    if (gaps.length) parts.push(`<div><div class="lbl">定位缺口</div>${gaps.map((g) =>
      `<div class="loc-item">⚠ ${esc(g.reason || g)}</div>`).join('')}</div>`);
    if (!locs.length && r.code_loc_note) parts.push(`<div><div class="lbl">定位说明</div>${esc(r.code_loc_note)}</div>`);
    if (r.note) parts.push(`<div><div class="lbl">规则依据</div>${esc(r.note)}</div>`);
    const ev = (r.event_ids || []).slice(0, 12).map((id) => `<span class="ev-chip">#${esc(id)}</span>`).join('');
    if (ev || r.pair_count) parts.push(`<div><div class="lbl">事件证据</div>` +
      `${r.pair_count ? `<div class="loc-item">读取→外发 ${esc(r.pair_count)} 对</div>` : ''}${ev}</div>`);
    parts.push(`<div><div class="lbl">复核状态</div>${esc(r.review_status || '未复核')}` +
      `${r.review_note ? ' · ' + esc(r.review_note) : ''}</div>`);
    return `<tr class="detail"><td colspan="4"><div class="detail-box">${parts.join('')}</div></td></tr>`;
  }

  /* ══════════ 动态审计 ══════════ */
  function renderDynamic() {
    badge($('#dynJob'), S.job, '未选择任务');
    const job = S.job;
    if (!job) {
      ['#dynStage', '#dynObs', '#dynGaps'].forEach((s) => { $(s).innerHTML = '<span class="muted">请先选择任务</span>'; });
      noJob($('#dynBody'), 3, '请先在概览页选择一个任务', true);
      return;
    }
    const timings = job.stage_timings || [];
    $('#dynStage').innerHTML = timings.map((s) => {
      const dur = Number.isFinite(s.duration_ms) ? `${(s.duration_ms / 1000).toFixed(1)}s` : '—';
      return `<div class="kv-row"><span class="kv-k">${esc(s.label || s.stage)}</span>` +
        `<span><b>${esc(STAGE_CN[s.status] || s.status || '—')}</b> · ${esc(dur)}</span></div>`;
    }).join('') || '<span class="muted">没有阶段记录</span>';

    const obs = job.privacy_observation || {};
    const types = obs.data_types || [];
    if (obs.status !== 'available' || !types.length) {
      $('#dynObs').innerHTML = `<span class="muted">${esc(obs.reason_text || '本轮没有动态观测产物')}</span>`;
      $('#dynGaps').innerHTML = '<span class="muted">—</span>';
      noJob($('#dynBody'), 3, '暂无观测数据（需要设备采集阶段的产物）');
      return;
    }
    const count = (st) => types.filter((t) => t.state === st).length;
    $('#dynObs').innerHTML =
      `<div class="kv-row"><span class="kv-k">已观测</span><span class="state-ok"><b>${count('observed')}</b> 类</span></div>` +
      `<div class="kv-row"><span class="kv-k">仅注册 / 未取值</span><span class="state-warn"><b>${count('registration_only')}</b> 类</span></div>` +
      `<div class="kv-row"><span class="kv-k">未观测</span><span class="state-gap"><b>${count('not_observed')}</b> 类</span></div>`;
    const gaps = obs.observation_gaps || [];
    const fieldGaps = Object.keys(job.field_gaps || {});
    $('#dynGaps').innerHTML =
      `<div class="kv-row"><span class="kv-k">Hook 缺口</span><b>${gaps.length}</b></div>` +
      `<div class="kv-row"><span class="kv-k">字段缺口</span><b>${fieldGaps.length}</b></div>`;
    $('#dynBody').innerHTML = types.map((t) =>
      `<tr><td><b>${esc(t.data_type_name || t.data_type)}</b></td>` +
      `<td>${esc(obs.source || '—')}</td>` +
      `<td><span class="${STATE_CLS[t.state] || 'state-gap'}">${esc(t.state_label || t.state)}</span><br>` +
      `<span class="muted" style="font-size:11.5px">${esc(t.reason_text || '')}</span></td></tr>`).join('');
  }

  /* ══════════ 辅助复核 ══════════ */
  function valueHtml(v) {
    if (v == null) return '<p class="muted">—</p>';
    if (typeof v === 'string') return `<p>${esc(v.slice(0, 4000))}</p>`;
    if (Array.isArray(v)) return `<ul>${v.slice(0, 20).map((x) =>
      `<li>${typeof x === 'string' ? esc(x) : `<code>${esc(JSON.stringify(x).slice(0, 300))}</code>`}</li>`).join('')}</ul>`;
    return `<pre>${esc(JSON.stringify(v, null, 2).slice(0, 4000))}</pre>`;
  }
  async function renderAi() {
    badge($('#aiJob'), S.job, '未选择任务');
    const wrap = $('#aiSections'), banner = $('#aiBanner');
    if (!S.job) {
      banner.classList.add('is-warn');
      banner.innerHTML = '请先在概览页选择一个任务' + GOTO_BTN;
      wrap.innerHTML = '';
      return;
    }
    banner.classList.remove('is-warn');
    banner.textContent = '正在读取 AI 复核状态…';
    wrap.innerHTML = '';
    try {
      const data = await VS.api(`/api/pipeline/${S.job.id}/ai`);
      const st = data.status || {};
      const ok = ['done', 'ok', 'completed', 'success'].includes(String(st.status));
      banner.classList.toggle('is-warn', !ok);
      banner.innerHTML = `<b>状态：${esc(st.status || '未知')}</b>` +
        `${st.reason ? ' · ' + esc(st.reason) : ''}${st.model ? ' · 模型 ' + esc(st.model) : ''}`;
      const res = data.result;
      if (!res) { wrap.innerHTML = '<div class="card muted">本轮没有 AI 复核结果文件。AI 只做辅助复述，不改变规则判定。</div>'; return; }
      const entries = Array.isArray(res) ? res.map((v, i) => ['条目 ' + (i + 1), v])
        : (res && typeof res === 'object') ? Object.entries(res).slice(0, 8) : [['内容', res]];
      wrap.innerHTML = entries.map(([k, v]) =>
        `<article class="card ai-sec"><h2>${esc(k)}</h2>${valueHtml(v)}</article>`).join('');
    } catch (e) {
      banner.classList.add('is-warn');
      banner.textContent = 'AI 复核不可用：' + e.message;
    }
  }

  /* ══════════ PDF 报告 ══════════ */
  function renderPdf() {
    badge($('#pdfJob'), S.job, '未选择任务');
    const done = !!S.job && S.job.state === 'done';
    const base = S.job ? `/api/pipeline/${S.job.id}` : '';
    [['#pdfOpen', '/report'], ['#pdfDown', '/report'], ['#zipDown', '/evidence.zip'], ['#dashOpen', '/dashboard']]
      .forEach(([sel, act]) => {
        const a = $(sel);
        a.href = base ? base + act : '#';
        a.classList.toggle('is-off', !done);
      });
    $('#pdfHint').textContent = done
      ? '任务已完成，产物可直接打开或下载'
      : (S.job ? '任务未完整完成，报告与证据包尚未生成' : '请先在概览页选择一个任务');
  }

  /* ══════════ 证据复核 ══════════ */
  async function renderReview() {
    const box = $('#reviewList');
    box.innerHTML = '<div class="card muted">正在载入复核轮次…</div>';
    try {
      const d = await VS.api('/api/review-round');
      const c = d.counts || {};
      const head = `<div class="card review-head"><b>轮次 ${esc(d.round_id)}</b>` +
        `<span class="muted">签署：${esc(d.signoff_status)}</span>` +
        `<span class="muted">应用 ${esc(c.workflow_apps ?? 0)} · 独测 ${esc(c.independent_apps ?? 0)} · 参照对 ${esc(c.reference_pairs ?? 0)}</span></div>`;
      const cases = (d.cases || []).map((cs) =>
        `<details class="review-case"><summary>${esc(cs.package)} · ${esc(cs.family)}</summary>` +
        `<div class="meta">${esc(cs.id)} · 资格 ${esc(cs.eligibility)} · 工作流 ${esc(cs.workflow_status)} · 复核 ${esc(cs.review_status)}</div>` +
        ((cs.eligibility_reasons || []).length ? `<ul>${cs.eligibility_reasons.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '') +
        ((cs.findings || []).length ? `<ul>${cs.findings.map((x) => `<li>${esc(x)}</li>`).join('')}</ul>` : '') +
        '</details>').join('');
      box.innerHTML = head + (cases || '<div class="card muted">本轮没有公开复核案例</div>') +
        ((d.limits || []).length ? `<div class="card muted mt16">${d.limits.map(esc).join(' · ')}</div>` : '');
    } catch (e) {
      box.innerHTML = `<div class="card muted">${esc(e.message)}</div>`;
    }
  }

  /* ══════════ 事件与启动 ══════════ */
  function render(page) {
    if (page === 'source') VS.source && VS.source.render();
    else if (page === 'static') renderStatic();
    else if (page === 'dynamic') renderDynamic();
    else if (page === 'ai') renderAi();
    else if (page === 'pdf') renderPdf();
    else if (page === 'review') renderReview();
  }

  VS.on('page', render);
  VS.on('job', function () {
    cache.view = [];
    if (VS.source) VS.source.reset();
    render(S.page);
  });

  /* 空态里的「去概览」引导：统一委托，不依赖各页自己绑事件 */
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-goto]');
    if (btn) VS.go(btn.dataset.goto);
  });
  $('#levelFilter').addEventListener('click', (e) => {
    const btn = e.target.closest('button');
    if (!btn) return;
    $$('#levelFilter button').forEach((b) => b.classList.toggle('is-on', b === btn));
    cache.lv = btn.dataset.lv;
    renderStatic();
  });
  $('#findingSearch').addEventListener('input', (e) => {
    cache.q = e.target.value.trim().toLowerCase();
    renderStatic();
  });
  $('#staticBody').addEventListener('click', (e) => {
    const tr = e.target.closest('tr.f-row');
    if (!tr) return;
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('detail')) {
      next.remove(); tr.classList.remove('is-open'); return;
    }
    $$('#staticBody tr.detail').forEach((d) => d.remove());
    $$('#staticBody tr.f-row').forEach((t) => t.classList.remove('is-open'));
    tr.classList.add('is-open');
    const row = cache.view[+tr.dataset.i];
    if (row) tr.insertAdjacentHTML('afterend', detailHtml(row));
  });
  $('#reloadReview').addEventListener('click', renderReview);
}());
