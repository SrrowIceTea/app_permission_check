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
  /* D 档：单条复核。状态词四态中性；没有记录就是 — + 后端写明的原因，不默认「待复核」。 */
  const REVIEW_WORDS = {pending: '待复核', confirmed: '已确认', rejected: '已驳回', needs_more_evidence: '需补充证据'};
  const REVIEW_CHOICES = [['confirmed', '已确认'], ['rejected', '已驳回'], ['needs_more_evidence', '需补充证据']];
  const REVIEW_STATIC = '该行没有 finding_uid（静态候选不是复核对象），后端未返回复核字段。';
  const REVIEW_DISCLAIMER = '复核人是自填文本，服务端没有身份认证，不作为签名证据；'
    + '这里记录的是单条结论的复核意见，与「盲评签核」不是同一件事。复核记录不改变结论等级与上方计数。';
  function reviewWord(status) { return REVIEW_WORDS[status] || String(status); }
  /* 带时区的本地时间；后端只接受带时区的 ISO 8601 */
  function stamp() {
    const now = new Date(), pad = n => String(n).padStart(2, '0');
    const offset = -now.getTimezoneOffset(), abs = Math.abs(offset);
    return now.getFullYear() + '-' + pad(now.getMonth() + 1) + '-' + pad(now.getDate()) + 'T' +
      pad(now.getHours()) + ':' + pad(now.getMinutes()) + ':' + pad(now.getSeconds()) +
      (offset >= 0 ? '+' : '-') + pad(Math.floor(abs / 60)) + ':' + pad(abs % 60);
  }
  function failure(status, code, message, next) {
    const error = new Error(message || '服务未返回原因。');
    error.status = status; error.code = code; error.next = next;
    return error;
  }
  /* 失败原样展示服务端状态码与错误码，不统一改成「提交失败」 */
  function report(error) {
    const head = [error.status ? 'HTTP ' + error.status : '', error.code].filter(Boolean).join(' · ');
    return (head ? head + ' · ' : '') + (error.message || '服务未返回原因。') +
      (error.next ? '（下一步：' + error.next + '）' : '');
  }
  function applyReview(row, stored) {
    row.review_status = stored && stored.status ? stored.status : null;
    row.reviewer = stored && stored.reviewer != null ? stored.reviewer : null;
    row.reviewed_at = stored && stored.reviewed_at != null ? stored.reviewed_at : null;
    row.review_note = stored && stored.note != null ? stored.note : null;
    row.review_status_reason = null;
  }
  /* 一次请求：非 2xx 一律带上服务端状态码与错误码抛出，不用「提交失败」盖掉原因 */
  async function request(url, init) {
    let response, data = null;
    try { response = await fetch(U.base + url, init); }
    catch (network) { throw failure(0, 'network_error', network.message, null); }
    try { data = await response.json(); } catch (_) { data = null; }
    if (response.ok) return data;
    const error = (data && data.error) || {};
    throw failure(response.status, error.code, error.message, error.next_action);
  }
  /* 提交后回读 GET，用服务端文件里的记录更新行；响应体与表单值都不作为结果 */
  async function submitReview(jobId, uid, form) {
    const body = JSON.stringify({finding_uid: uid, status: form.status,
      reviewer_kind: 'human', reviewer: form.reviewer, reviewed_at: stamp(), note: form.note});
    const path = '/api/pipeline/' + jobId + '/finding-reviews';
    await request(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: body});
    const doc = await request(path);
    const stored = doc && doc.findings && typeof doc.findings === 'object' ? doc.findings[uid] : null;
    if (!stored || typeof stored !== 'object') {
      throw failure(0, 'readback_missing', '服务端返回写入成功，但回读没读到 ' + uid + ' 的记录。',
        '检查 review/finding-review.json 是否被其他进程覆盖。');
    }
    return stored;
  }
  function group(label, control) {
    const wrap = U.node('label', '');
    wrap.append(document.createTextNode(label), control);
    return wrap;
  }
  U.reviewBlock = function (row) {
    const box = U.node('section', 'review-block');
    box.append(U.node('h4', 'review-block__title', '结论复核'));
    const body = U.node('div', 'review-block__body');
    box.append(body, U.node('p', 'review-block__disclaimer', REVIEW_DISCLAIMER));
    const jobId = U.current;
    const uid = typeof row.finding_uid === 'string' ? row.finding_uid : '';
    function paint() {
      body.replaceChildren();
      const line = U.node('p', 'review-block__state');
      line.append(U.node('span', 'review-block__label', '复核状态'));
      if (row.review_status) line.append(U.node('span', 'review-block__word', reviewWord(row.review_status)));
      else {
        const dash = U.node('span', 'field-missing', '—');
        dash.title = row.review_status_reason || (uid ? '后端未返回 review_status_reason。' : REVIEW_STATIC);
        line.append(dash);
      }
      body.append(line);
      if (!row.review_status) {
        body.append(U.node('p', 'review-block__reason', row.review_status_reason || REVIEW_STATIC));
        return;
      }
      [['复核人', row.reviewer], ['复核时间', row.reviewed_at], ['复核备注', row.review_note]].forEach(item => {
        const text = item[1] === null || item[1] === undefined || item[1] === '' ? '—' : String(item[1]);
        body.append(U.node('p', 'review-block__meta', item[0] + ' ' + text));
      });
      if (!row.reviewer) body.append(U.node('p', 'review-block__reason', '后端没有返回该条记录的复核人。'));
    }
    paint();
    if (!uid) return box;
    const form = U.node('details', 'review-block__form');
    form.append(U.node('summary', '', '单条复核（提交成功会回读服务端记录，不整页刷新）'));
    const select = U.node('select', '');
    REVIEW_CHOICES.forEach(choice => {
      const option = U.node('option', '', choice[1]);
      option.value = choice[0]; select.append(option);
    });
    const reviewer = U.node('input', '');
    reviewer.type = 'text'; reviewer.maxLength = 100;
    reviewer.placeholder = '复核人姓名或工号（自填，服务端不校验身份）';
    const note = U.node('textarea', '');
    note.rows = 2; note.maxLength = 500; note.placeholder = '复核说明（可选，≤500 字）';
    const actions = U.node('div', 'review-block__actions');
    const button = U.node('button', 'pl-btn', '提交复核');
    button.type = 'button';
    const message = U.node('p', 'review-block__msg');
    actions.append(button);
    const fields = U.node('div', 'review-fieldset');
    fields.append(group('复核结论', select), group('复核人', reviewer), group('复核说明', note));
    form.append(fields, actions);
    button.addEventListener('click', async function () {
      if (button.disabled) return;
      message.dataset.tone = ''; message.textContent = '';
      const name = reviewer.value.trim();
      if (!name) { message.dataset.tone = 'error'; message.textContent = '未提交：复核人不能为空。'; return; }
      button.disabled = true; button.textContent = '提交中…';
      try {
        applyReview(row, await submitReview(jobId, uid,
          {status: select.value, reviewer: name, note: note.value.trim() || null}));
        paint();
        form.open = false;
        message.dataset.tone = 'ok';
        message.textContent = '已回读服务端记录：' + reviewWord(row.review_status) +
          ' · 复核人 ' + row.reviewer + ' · ' + row.reviewed_at;
      } catch (error) {
        message.dataset.tone = 'error';
        message.textContent = report(error);
      } finally {
        button.disabled = false; button.textContent = '提交复核';
      }
    });
    /* 结果消息放在表单外：表单收起后仍能看到回读结果或服务端报错 */
    box.append(form, message);
    return box;
  };
  /* A-03 结论等级只描述证据强度，不做通过/失败判定；原始值保留在 data-level */
  const LEVELS = { correlated: ['s-critical', '已关联'], observed: ['s-warning', '已观测'],
    candidate: ['s-muted', '候选'] };
  function levelBadge(level) {
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
    const [summary, rows] = await Promise.all([U.get(prefix + '/summary'), U.get(prefix + '/findings')]);
    if (U.current !== job.id) return;
    host.replaceChildren();
    if (U.summaryBar) host.append(U.summaryBar(summary));
    if (U.observationPanel) host.append(U.observationPanel(summary, rows));
    /* 诊断账本：漏斗/归因/绑定缺口只作展示，后端缺字段时页面显示「—」，不补 0。 */
    if (U.ledgerPanel) host.append(U.ledgerPanel(summary));
    host.append(U.node('p', 'notice', '结论保留原始等级。无观测不代表无风险，代码行号不证明违规语义。'));
    host.append(U.link('打开独立审计看板', prefix + '/dashboard'));
    host.append(details('会话、设备与采集校验', summary.capture_validation));
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
