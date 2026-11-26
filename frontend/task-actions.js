(function (global) {
  'use strict';

  const labels = {confirmed:'确认', rejected:'驳回', needs_more_evidence:'待补证'};
  function add(parent, tag, text, cls) {
    const element = document.createElement(tag);
    if (text) element.textContent = text;
    if (cls) element.className = cls;
    parent.appendChild(element);
    return element;
  }
  function url(base, entry, action) {
    return base + '/api/pipeline/' + encodeURIComponent(entry.id) + '/' + action;
  }
  async function request(endpoint, body) {
    const options = body === undefined ? undefined : {
      method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)
    };
    const response = await fetch(endpoint, options);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '操作失败');
    return data;
  }
  function logs(host, entry, base, onRetry) {
    const box = add(host,'details',null,'report-section task-actions');
    add(box,'summary','失败日志与重试');
    const message = add(box,'p',null,'hint');
    message.setAttribute('role','status');
    const failed = add(box,'ul');
    const select = add(box,'select');
    select.setAttribute('aria-label','选择本任务日志');
    select.hidden = true;
    const output = add(box,'pre',null,'evidence-json');
    box.addEventListener('toggle', async () => {
      if (!box.open || box.dataset.loaded) return;
      box.dataset.loaded = 'true';
      message.textContent = '正在读取日志';
      try {
        const data = await request(url(base,entry,'logs'));
        data.failed_stages.forEach(event => add(failed,'li',event.stage + ' · ' + event.message));
        message.textContent = data.error || (data.files.length ? '' : '本任务未留下可读阶段日志');
        add(select,'option','选择日志').value = '';
        data.files.forEach(name => add(select,'option',name).value = name);
        select.hidden = !data.files.length;
      } catch (error) {
        message.textContent = error.message;
        delete box.dataset.loaded;
      }
    });
    select.addEventListener('change', async () => {
      const selection = select.value;
      output.textContent = '';
      if (!selection) return;
      try {
        const log = await request(url(base,entry,'logs?name=' + encodeURIComponent(selection)));
        if (select.value === selection) output.textContent = (log.truncated ? '仅显示末尾 64 KiB\n' : '') + log.text;
      } catch (error) {
        if (select.value === selection) output.textContent = error.message;
      }
    });
    const authorized = add(box,'label');
    const check = add(authorized,'input');
    check.type = 'checkbox';
    add(authorized,'span','我确认仍拥有该 APK 与设备的测试授权');
    const button = add(box,'button','重试原任务','pl-btn');
    button.disabled = true;
    check.addEventListener('change', () => { button.disabled = !check.checked; });
    button.addEventListener('click', async () => {
      if (!check.checked || button.disabled) return;
      button.disabled = check.disabled = true;
      try {
        const job = await request(url(base,entry,'retry'),{authorized:true});
        onRetry(job, entry.name);
      } catch (error) {
        message.textContent = error.message;
        button.disabled = check.disabled = false;
      }
    });
  }
  function render(host, entry, base, onRetry, openOriginal) {
    if (entry.fin.result?.evidence_zip) {
      const link = add(host,'a','下载可重放证据 ZIP','pl-btn');
      link.href = url(base,entry,'evidence.zip');
    } else if (entry.fin.state === 'done' && entry.fin.result?.evidence_zip === false) {
      add(host,'p',entry.fin.result.evidence_zip_error || '本轮缺少可绑定的重放原件。','hint');
    }
    if (entry.retryOf) {
      const original = add(host,'button','查看原失败任务','pl-btn');
      original.addEventListener('click', () => openOriginal(entry.retryOf));
    }
    if (['failed','static_only'].includes(entry.fin.state)) logs(host,entry,base,onRetry);
  }
  function reviewRow(host, data, entry, base) {
    const row = add(host,'details',null,'evidence-row');
    const f = data.finding;
    const title = add(row,'summary',f.rule_id + ' · ' + (f.title || '规则发现'));
    const references = {level:f.conclusion_level, source:f.basis_refs, events:f.event_ids, pairs:f.pairs};
    add(row,'pre',JSON.stringify(references,null,2),'evidence-json');
    const form = add(row,'form',null,'task-review-form');
    const status = add(add(form,'label','复核状态 '),'select');
    for (const [value, text] of Object.entries(labels)) add(status,'option',text).value = value;
    const reviewer = add(add(form,'label','复核人 '),'input');
    reviewer.required = true;
    reviewer.maxLength = 100;
    const note = add(add(form,'label','复核依据 '),'textarea');
    note.required = true;
    note.maxLength = 500;
    const message = add(form,'p',null,'hint');
    message.setAttribute('role','status');
    const button = add(form,'button','保存复核','pl-btn');
    function update(review) {
      if (!review) return;
      status.value = review.status;
      reviewer.value = review.reviewer;
      note.value = review.note;
      title.textContent = f.rule_id + ' · ' + (f.title || '规则发现') + ' · ' + labels[review.status];
      message.textContent = review.reviewer + ' · ' + review.reviewed_at;
    }
    update(data.review);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      button.disabled = true;
      try {
        update(await request(url(base,entry,'reviews'),{finding_uid:data.finding_uid, status:status.value,
          reviewer_kind:'human', reviewer:reviewer.value, note:note.value}));
      } catch (error) {
        message.textContent = error.message;
      } finally {
        button.disabled = false;
      }
    });
  }
  async function reviews(host, entry, base) {
    const message = add(host,'p','正在读取本任务发现','hint');
    try {
      const data = await request(url(base,entry,'reviews'));
      message.textContent = data.findings.length ? '' : '本任务没有可复核的动态规则发现';
      data.findings.forEach(row => reviewRow(host,row,entry,base));
    } catch (error) {
      message.textContent = error.message;
    }
  }
  function resultCard(entry, fin, base, el, switchPage, onRetry, openOriginal) {
    var host = document.getElementById('pipeline-result');
    host.textContent = '';
    host.style.display = '';

    var card = el('div', 'pipeline-card');
    card.appendChild(el('h3', null, '审计结果'));

    var result = (fin && fin.result) || {};
    var badgeCls = fin.state === 'done' ? 'done'
      : (fin.state === 'static_only' ? 'static_only' : 'failed');
    var badgeText = fin.state === 'done' ? '全流程完成'
      : (fin.state === 'static_only' ? '仅静态（动态不可用）' : '失败');
    card.appendChild(el('span', 'pl-status ' + badgeCls, badgeText));

    if (fin.state === 'static_only' && result.device_unavailable) {
      host.appendChild(el('div', 'pl-warn',
        '动态分析跳过：' + result.device_unavailable + '。静态结论仍有效；接入模拟器后重新拖入同一 APK 即可跑完整流程。'));
    }
    if (fin.state === 'failed') {
      host.appendChild(el('div', 'pl-warn', '流水线失败：' + (result.error || '未知错误')));
    }

    // 静态摘要
    var st = result.static || {};
    var dl = el('dl', 'pl-kv');
    plKv(dl, '包名', st.package || '—');
    if (st.app_label) plKv(dl, '应用名', st.app_label);
    plKv(dl, '静态命中', (st.findings_total != null ? st.findings_total : '—') + ' 条'
      + (st.supplement_findings != null ? '（补充扫描 ' + st.supplement_findings + ' 条）' : ''));
    plKv(dl, '求值规则', st.rules_evaluated != null ? st.rules_evaluated + ' 条' : '—');
    if (st.decompile) {
      plKv(dl, '反编译', (st.decompile.classes_written || 0) + ' 个类'
        + (st.decompile.errors ? '（' + st.decompile.errors + ' 个类失败）' : ''));
    }
    card.appendChild(dl);

    // 跳转按钮：静态审计结果 / 源码查看 / 动态审计 / AI 报告
    var navs = el('div', 'pl-links');
    [['查看静态审计结果', 'static'], ['查看源码', 'source'],
     ['查看动态审计', 'dynamic'], ['查看 AI 报告', 'ai-report']].forEach(function (pair) {
      var a = el('a', 'pl-btn', pair[0]);
      a.href = '#';
      a.addEventListener('click', function (e) {
        e.preventDefault();
        switchPage(pair[1]);
      });
      navs.appendChild(a);
    });
    if (result.report) {
      var ra = el('a', 'pl-btn primary', '下载动态审计报告（PDF）');
      ra.href = base + '/api/pipeline/' + entry.id + '/report';
      ra.target = '_blank';
      navs.appendChild(ra);
    }
    if (result.bundle) {
      var ba = el('a', 'pl-btn', '查看证据包（JSON）');
      ba.href = base + '/api/pipeline/' + entry.id + '/bundle';
      ba.target = '_blank';
      navs.appendChild(ba);
    }
    card.appendChild(navs);
    render(card, entry, base, onRetry, openOriginal);
    host.appendChild(card);

    // 验证摘要
    var v = result.verification;
    if (v && v.passed === false) {
      host.appendChild(el('div', 'pl-warn',
        '报告已生成，但动态检测有 ' + (v.failed || []).length + ' 项判据未通过：' +
        (v.failed || []).join('、') + '。详见「动态审计」页与报告中的缺口说明。'));
    }
  }

  function plKv(dl, k, v) {
    add(dl,'dt',k);
    add(dl,'dd',v);
  }

  global.VScanTaskActions = {resultCard,reviews};
})(window);
