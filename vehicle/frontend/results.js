/* Vehicle evidence views. Only VSC results from the vehicle service are consumed. */
(function () {
  'use strict';
  const U = window.VehicleUI = {};
  U.base = location.protocol === 'file:' || location.pathname.includes('/vehicle/frontend/')
    ? 'http://127.0.0.1:8773' : location.origin;
  U.node = function (tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = String(text);
    return n;
  };
  U.get = async function (path, options) {
    const response = await fetch(U.base + path, options);
    let data;
    try { data = await response.json(); }
    catch (_) { const error = new Error('服务未返回有效 JSON，请检查服务地址和日志。');
      error.status = response.status; throw error; }
    if (!response.ok) {
      const e = data.error || {};
      const error = new Error([e.message || '请求未完成', e.next_action].filter(Boolean).join(' '));
      error.status = response.status; error.code = e.code; throw error;
    }
    return data;
  };
  U.link = function (name, href) {
    const a = U.node('a', 'pl-btn', name);
    a.href = U.base + href; a.target = '_blank'; a.rel = 'noopener';
    return a;
  };
  U.empty = function (host, message) {
    if (U.stateEmpty) return U.stateEmpty(host, {message: message});
    host.replaceChildren(U.node('p', 'notice notice--empty', message));
  };
  function details(title, data) {
    const box = U.node('details', 'evidence-details');
    const pre = U.node('pre', 'evidence-json');
    box.addEventListener('toggle', function () {
      if (!box.open || box.dataset.rendered) return;
      box.dataset.rendered = 'true';
      pre.textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
    });
    box.append(U.node('summary', '', title), pre);
    return box;
  }
  function table(rows, columns) {
    const wrap = U.node('div', 'vehicle-table');
    const t = U.node('table', 'results-table'), head = U.node('tr');
    columns.forEach(c => head.append(U.node('th', '', c[0])));
    const thead = U.node('thead'); thead.append(head); t.append(thead);
    const body = U.node('tbody');
    rows.forEach(row => {
      const tr = U.node('tr');
      columns.forEach(c => {
        const value = c[1](row), td = U.node('td');
        if (value instanceof Node) td.append(value);
        else td.textContent = value == null ? '未提供' : String(value);
        tr.append(td);
      });
      body.append(tr);
    });
    t.append(body); wrap.append(t); return wrap;
  }
  function evidence(row) {
    return U.evidenceCard ? U.evidenceCard(row) : details('规则依据与原始证据', row);
  }
  function levelBadge(level) {
    const LEVELS = {correlated: ['s-critical', '已关联'], observed: ['s-warning', '已观测'],
      candidate: ['s-muted', '候选']};
    const spec = LEVELS[level] || ['s-good', '未判定'];
    const badge = U.node('span', 'result-badge ' + spec[0], spec[1]);
    badge.dataset.level = level ?? ''; badge.title = '原始等级：' + (level ?? '未提供');
    return badge;
  }
  U.levelBadge = levelBadge;
  U.staticView = async function (job) {
    const host = document.getElementById('static-results');
    const data = await U.get('/api/pipeline/' + job.id + '/static');
    if (U.current !== job.id) return;
    host.replaceChildren(U.node('p', 'notice',
      '静态候选仅表示清单或代码引用，不证明运行时读取、外发或违规。'));
    host.append(U.node('p', 'hint', '包名：' + (data.apk?.package || '未提供') +
      '；候选：' + (data.findings || []).length));
    (data.apk_gaps || []).concat(data.dex_gaps || []).forEach(g => host.append(details('静态覆盖缺口', g)));
    host.append(table(data.findings || [], [['规则', r => r.rule_id], ['标题', r => r.title],
      ['类型', r => r.rule_type], ['强度', r => r.static_strength],
      ['结论等级', r => levelBadge(r.conclusion_level)], ['证据链', evidence]]));
    if (!data.findings?.length) host.append(U.node('p', 'hint', '本轮未匹配到静态候选，不代表安全。'));
    try {
      const dec = await U.get('/api/pipeline/' + job.id + '/decompile');
      if (U.current === job.id && (dec.errors || dec.gap || dec.returncode)) host.prepend(details('反编译缺口', dec));
    } catch (_) { /* Decompilation may still be running; its stage reports failures. */ }
  };
  U.dynamicView = async function (job) {
    const host = document.getElementById('dynamic-results');
    if (job.state !== 'done') {
      if (job.state === 'failed' && U.stateFailed) {
        /* 失败任务四档全为 null：汇总条仍显示 — 与后端 field_gaps 原因，不填 0 */
        const spec = U.failureSpec(job);
        if (U.summaryBar) spec.summary = U.summaryBar(job);
        return U.stateFailed(host, spec);
      }
      if (U.statePending) return U.statePending(host, {
        title: '动态审计尚未完整完成',
        message: job.state === 'static_only' ? '仅静态分析：未执行动态采集与关联。'
          : '任务仍在进行；完成后本页会显示汇总条与证据链。',
        progress: U.progressOf(job),
        note: '未执行或已跳过的阶段不会给出结论；「未观测到」不等于安全。'
      });
      return U.empty(host, job.state === 'static_only' ? '仅静态分析：未执行动态采集与关联。'
        : '动态审计尚未完整完成。请查看审计页的进度或失败原因。');
    }
    const prefix = '/api/pipeline/' + job.id;
    const [summary, rows, coverage] = await Promise.all([U.get(prefix + '/summary'), U.get(prefix + '/findings'),
      U.get(prefix + '/coverage').catch(error => ({status: 'unavailable', reason: error.message}))]);
    if (U.current !== job.id) return;
    host.replaceChildren();
    if (U.summaryBar) host.append(U.summaryBar(summary));
    if (U.observationPanel) host.append(U.observationPanel(summary, rows));
    if (U.ledgerPanel) host.append(U.ledgerPanel(summary)); // 诊断账本：缺字段显示「—」，不补 0
    host.append(U.node('p', 'notice', '结论保留原始等级。无观测不代表无风险，代码行号不证明违规语义。'));
    host.append(U.link('打开独立审计看板', prefix + '/dashboard'));
    host.append(details('会话、设备与采集校验', summary.capture_validation));
    host.append(details('逐规则覆盖链与未接线项', coverage));
    host.append(table(rows, [['规则', r => r.rule_id], ['类型', r => r.finding_class || r.rule_type],
      ['结论等级', r => levelBadge(r.conclusion_level)], ['证据链', evidence]]));
    if (!rows.length) host.append(U.node('p', 'hint', '本轮没有生成结论；请结合采集范围和覆盖缺口复核。'));
    host.append(details('覆盖范围与完整审计摘要', summary));
  };
  U.aiView = async function (job) {
    const host = document.getElementById('ai-report');
    if (job.state !== 'done') {
      if (U.statePending) return U.statePending(host, {
        title: '尚未生成辅助复核',
        message: job.state === 'static_only' ? '当前任务只有静态分析，未执行动态审计与辅助复核。'
          : '当前任务没有完整动态审计，未生成辅助复核结果。',
        note: '辅助复核不改变工具结论，也不替代证据校验。'
      });
      return U.empty(host, '当前任务没有完整动态审计，未生成辅助复核结果。');
    }
    const [summary, output] = await Promise.all([U.get('/api/pipeline/' + job.id + '/summary'),
      U.get('/api/pipeline/' + job.id + '/ai')]);
    if (U.current !== job.id) return;
    const ai = summary.ai_review || {status: 'skipped', reason: '未配置 AI。'};
    host.replaceChildren(U.node('p', 'notice', ai.status === 'skipped'
      ? '未执行 AI 复核。只有启动服务时显式配置后才会调用。' : '以下为辅助复核；不替代证据校验或 subagent 签核。'));
    host.append(details('辅助复核状态与输出', ai));
    if (output.result) host.append(details('本轮 AI 详细复核结果', output.result));
    host.append(details('政策与业务用途评估', summary.policy_assessment || {status: 'not_provided'}));
  };
  U.reports = function (jobs) {
    const host = document.getElementById('report-library');
    host.replaceChildren();
    jobs.filter(j => j.state === 'done' && j.result.report).forEach(job => {
      const book = U.node('article', 'vehicle-report');
      book.append(U.node('h3', '', job.name), U.node('p', 'hint', job.result.package),
        U.node('p', 'hint', new Date(job.created * 1000).toLocaleString()));
      const button = U.node('button', 'pl-btn', '查看 PDF');
      button.onclick = function () {
        const viewer = document.getElementById('pdf-viewer-container');
        const frame = U.node('iframe', 'pdf-frame');
        frame.title = job.name + ' 车载审计报告';
        frame.src = U.base + '/api/pipeline/' + job.id + '/report';
        viewer.replaceChildren(U.link('新窗口打开 PDF', '/api/pipeline/' + job.id + '/report'), frame);
      };
      book.append(button, U.link('审计摘要', '/api/pipeline/' + job.id + '/bundle'),
        U.link('下载完整证据包 ZIP', '/api/pipeline/' + job.id + '/evidence.zip'));
      host.append(book);
    });
    if (!host.children.length) U.empty(host, '尚无完整生成的车载报告。仅静态分析不会生成动态审计报告。');
  };
}());
