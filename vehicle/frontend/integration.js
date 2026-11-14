/* Workbench actions use only job IDs and explicit user selections. */
(function () {
  'use strict';
  const U = window.VehicleUI, $ = id => document.getElementById(id);
  U.settings = function () {
    return {version: $('audit-version').value, scope: $('capture-scope').value, ai_review: String($('ai-enabled').checked),
      tls_bypass: String($('tls-bypass').checked), multi_process: String($('multi-process').checked)};
  };
  U.attach = async function () {
    const files = [...$('evidence-files').files, ...$('evidence-folder').files];
    const policy = $('policy-file').value, scenarios = $('scenarios-file').value;
    if (!policy && !scenarios) return null;
    if (files.length > 64 || files.reduce((sum, f) => sum + f.size, 0) > 4 * 1024 * 1024)
      throw new Error('补充证据最多 64 个文件、合计 4 MiB。');
    const rows = [];
    for (const file of files) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      let text = '';
      for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
      rows.push({path: file.webkitRelativePath || file.name, content_base64: btoa(text)});
    }
    return U.get('/api/attachments', {method: 'POST', headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({files: rows, policy, scenarios})});
  };
  U.failureActions = function (spec) {
    const box = U.node('div', 'state-panel__actions');
    const retry = U.node('button', 'pl-btn', '重试'), logs = U.node('button', 'pl-btn', '打开日志');
    retry.type = logs.type = 'button';
    retry.onclick = () => U.retryJob && U.retryJob(spec.jobId);
    logs.onclick = async function () {
      const viewer = U.node('pre', 'evidence-json', '正在读取本任务日志…');
      box.append(viewer); logs.disabled = true;
      try {
        const data = await U.get('/api/pipeline/' + spec.jobId + '/logs');
        viewer.textContent = data.logs.map(row => '【' + row.name + (row.truncated ? ' · 尾部' : '') + '】\n' + row.text)
          .join('\n\n') || '本任务尚无日志文件。';
      } catch (error) { viewer.textContent = error.message; }
      finally { logs.disabled = false; }
    };
    box.append(retry, logs); return box;
  };
  U.retryDialog = function (job, submit) {
    let dialog = $('retry-dialog');
    if (dialog) dialog.remove();
    dialog = U.node('dialog', 'pipeline-card'); dialog.id = 'retry-dialog';
    dialog.append(U.node('h2', '', '重新执行失败任务'), U.node('p', 'hint',
      '将保留旧任务，新建独立任务重新执行 ' + job.name + '。原采集方式和输入沿用；设备采集会重新操作同一授权设备。'));
    const label = U.node('label', 'authorization'), check = U.node('input'); check.type = 'checkbox';
    label.append(check, document.createTextNode('我有权重新测试该 APK 和原任务所选设备。'));
    const go = U.node('button', 'pl-btn', '新建重试任务'), cancel = U.node('button', 'pl-btn', '取消');
    const message = U.node('p', 'notice'); go.disabled = true;
    check.onchange = () => { go.disabled = !check.checked; };
    go.onclick = async () => { go.disabled = true;
      try { await submit(); dialog.close(); dialog.remove(); }
      catch (error) { message.textContent = error.message; go.disabled = !check.checked; }
    };
    cancel.onclick = () => { dialog.close(); dialog.remove(); };
    dialog.append(label, go, cancel, message); document.body.append(dialog); dialog.showModal();
  };
  U.bindInputs = function () {
    function changed() {
      $(this.id === 'evidence-files' ? 'evidence-folder' : 'evidence-files').value = '';
      const names = Array.from(this.files).map(f => f.webkitRelativePath || f.name).filter(n => /\.json$/i.test(n));
      ['policy-file', 'scenarios-file'].forEach(id => {
        $(id).replaceChildren(U.node('option', '', '未提供'));
        $(id).firstChild.value = '';
        names.forEach(name => { const option = U.node('option', '', name); option.value = name; $(id).append(option); });
      });
    }
    $('evidence-files').onchange = changed; $('evidence-folder').onchange = changed;
  };
}());
