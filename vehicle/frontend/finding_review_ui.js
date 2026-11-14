/* Per-finding review UI, backed by the existing checked write/readback contract. */
(function () {
  'use strict';
  const U = window.VehicleUI;
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
}());
