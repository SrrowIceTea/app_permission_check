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
    const data = await response.json();
    if (!response.ok) {
      const e = data.error || {};
      throw new Error([e.message || '请求未完成', e.next_action].filter(Boolean).join(' '));
    }
    return data;
  };
  U.link = function (name, href) {
    const a = U.node('a', 'pl-btn', name);
    a.href = U.base + href; a.target = '_blank'; a.rel = 'noopener';
    return a;
  };
  U.empty = function (host, message) {
    host.replaceChildren(U.node('p', 'notice', message));
  };
  function details(title, data) {
    const box = U.node('details', 'evidence-details');
    box.append(U.node('summary', '', title), U.node('pre', 'evidence-json',
      typeof data === 'string' ? data : JSON.stringify(data, null, 2)));
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
    return details('规则依据与原始证据', row);
  }
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
      ['结论等级', r => r.conclusion_level], ['依据', evidence]]));
    if (!data.findings?.length) host.append(U.node('p', 'hint', '本轮未匹配到静态候选，不代表安全。'));
    try {
      const dec = await U.get('/api/pipeline/' + job.id + '/decompile');
      if (U.current === job.id && (dec.errors || dec.gap || dec.returncode)) host.prepend(details('反编译缺口', dec));
    } catch (_) { /* Decompilation may still be running; its stage reports failures. */ }
  };
  U.dynamicView = async function (job) {
    const host = document.getElementById('dynamic-results');
    if (job.state !== 'done') return U.empty(host,
      job.state === 'static_only' ? '仅静态分析：未执行动态采集与关联。' :
        '动态审计尚未完整完成。请查看审计页的进度或失败原因。');
    const prefix = '/api/pipeline/' + job.id;
    const [summary, rows] = await Promise.all([U.get(prefix + '/summary'), U.get(prefix + '/findings')]);
    if (U.current !== job.id) return;
    host.replaceChildren(U.node('p', 'notice', '结论保留原始等级。无观测不代表无风险，代码行号不证明违规语义。'));
    host.append(U.link('打开独立审计看板', prefix + '/dashboard'));
    host.append(details('会话、设备与采集校验', summary.capture_validation));
    host.append(table(rows, [['规则', r => r.rule_id], ['类型', r => r.finding_class || r.rule_type],
      ['结论等级', r => r.conclusion_level], ['依据与证据链', evidence]]));
    if (!rows.length) host.append(U.node('p', 'hint', '本轮没有生成结论；请结合采集范围和覆盖缺口复核。'));
    host.append(details('覆盖范围与完整审计摘要', summary));
  };
  U.aiView = async function (job) {
    const host = document.getElementById('ai-report');
    if (job.state !== 'done') return U.empty(host, '当前任务没有完整动态审计，未生成辅助复核结果。');
    const summary = await U.get('/api/pipeline/' + job.id + '/summary');
    if (U.current !== job.id) return;
    const ai = summary.ai_review || {status: 'skipped', reason: '未配置 AI。'};
    host.replaceChildren(U.node('p', 'notice', ai.status === 'skipped'
      ? '未执行 AI 复核。只有启动服务时显式配置后才会调用。' : '以下为辅助复核；不替代证据校验或 subagent 签核。'));
    host.append(details('辅助复核状态与输出', ai));
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
      book.append(button, U.link('审计摘要', '/api/pipeline/' + job.id + '/bundle'));
      host.append(book);
    });
    if (!host.children.length) U.empty(host, '尚无完整生成的车载报告。仅静态分析不会生成动态审计报告。');
  };
}());
