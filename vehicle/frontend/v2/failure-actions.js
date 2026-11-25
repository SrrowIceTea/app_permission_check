/* Task-scoped diagnostics and explicit reauthorization for the AAOS workbench. */
(function () {
  'use strict';
  const VS = window.VS;
  const actionGroups = ['stageFailure', 'dynFailure'].map((id) => {
    const group = document.createElement('div');
    group.className = 'failure-actions';
    group.hidden = true;
    group.innerHTML = '<button type="button" class="btn btn-ghost" data-action="logs">查看失败日志</button>' +
      '<button type="button" class="btn btn-ghost" data-action="retry">重试任务</button>' +
      '<button type="button" class="btn btn-ghost" data-action="original" hidden>查看原失败任务</button>';
    document.getElementById(id).after(group);
    group.addEventListener('click', (event) => {
      const job = VS.state.job;
      if (!job || job.id !== VS.state.current) return;
      const action = event.target.closest('button')?.dataset.action;
      if (action === 'original' && job.retry_of) VS.select(job.retry_of);
      if (job.state !== 'failed') return;
      if (action === 'logs') showLogs(job);
      if (action === 'retry') showRetry(job);
    });
    return group;
  });

  function render() {
    const job = VS.state.job;
    const failed = job?.state === 'failed';
    for (const group of actionGroups) {
      group.hidden = !failed && !job?.retry_of;
      group.querySelector('[data-action="logs"]').hidden = !failed;
      group.querySelector('[data-action="retry"]').hidden = !failed;
      group.querySelector('[data-action="original"]').hidden = !job?.retry_of;
    }
  }

  function openDialog(job, title, content) {
    const dialog = document.createElement('dialog');
    dialog.className = 'failure-dialog';
    dialog.setAttribute('aria-labelledby', 'failure-dialog-title');
    dialog.innerHTML = '<h2 id="failure-dialog-title"></h2><p class="sub" data-task></p>' + content;
    dialog.querySelector('h2').textContent = title;
    dialog.querySelector('[data-task]').textContent = `${job.name || 'APK'} · ${job.id.slice(0, 12)}…`;
    dialog.querySelector('[data-close]').addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => dialog.remove(), { once: true });
    document.body.append(dialog);
    dialog.showModal();
    return dialog;
  }

  const endpoint = (job, action) => `/api/pipeline/${encodeURIComponent(job.id)}/${action}`;
  const errorText = (error) => [error.message, error.nextAction].filter(Boolean).join(' ');

  async function showLogs(job) {
    const dialog = openDialog(job, '失败日志',
      '<p role="status">正在读取本任务日志…</p><pre tabindex="0" aria-label="本任务日志" hidden></pre>' +
      '<button type="button" class="btn btn-ghost" data-close autofocus>关闭</button>');
    const status = dialog.querySelector('[role="status"]');
    try {
      const data = await VS.api(endpoint(job, 'logs'));
      if (!dialog.open) return;
      if (data?.job_id !== job.id || !Array.isArray(data.logs)) throw new Error('日志响应与当前任务不符。');
      status.textContent = data.logs.length ? data.note || '' : '本任务没有可读的日志文件。';
      const viewer = dialog.querySelector('pre');
      viewer.hidden = data.logs.length === 0;
      viewer.textContent = data.logs.map((row) =>
        `【${row.name}${row.truncated ? ' · 尾部' : ''}】\n${row.text}`).join('\n\n');
    } catch (error) {
      if (dialog.open) status.textContent = '无法读取失败日志。' + errorText(error);
    }
  }

  function showRetry(job) {
    const dialog = openDialog(job, '重试失败任务',
      '<p data-context></p><label class="auth-row"><input type="checkbox"> 我确认拥有本次重试所需的测试授权</label>' +
      '<p role="status" hidden></p><div class="actions"><button type="button" class="btn btn-ghost" data-close autofocus>取消</button>' +
      '<button type="button" class="btn btn-primary" data-submit disabled>新建重试任务</button></div>');
    const settings = job.options || {};
    const device = settings.mode === 'live' ? ` 本次会在原设备 ${settings.serial}（用户 ${settings.user}）重新采集。` : '';
    dialog.querySelector('[data-context]').textContent =
      '修复失败原因后，沿用原 APK 和审计设置新建一个任务。原失败任务与日志会保留。' + device;
    const check = dialog.querySelector('input');
    const close = dialog.querySelector('[data-close]');
    const submit = dialog.querySelector('[data-submit]');
    const status = dialog.querySelector('[role="status"]');
    let submitting = false;
    check.addEventListener('change', () => { submit.disabled = !check.checked; });
    dialog.addEventListener('cancel', (event) => { if (submitting) event.preventDefault(); });
    submit.addEventListener('click', async () => {
      if (submitting || !check.checked || VS.state.current !== job.id) return;
      submitting = check.disabled = close.disabled = submit.disabled = true;
      status.hidden = false;
      status.textContent = '正在提交重试…';
      try {
        const result = await VS.api(endpoint(job, 'retry?authorized=true'), {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
        });
        if (!result?.id || result.retry_of !== job.id) throw new Error('服务未返回有效的重试任务编号。');
        dialog.close();
        VS.followJob(result.id);
      } catch (error) {
        submitting = close.disabled = false;
        const rejected = Boolean(error.code) && error.status >= 400 && error.status < 500;
        check.disabled = !rejected;
        submit.disabled = !rejected;
        status.textContent = rejected ? '重试提交失败。' + errorText(error)
          : '提交结果未确认。请关闭窗口并重新加载页面，检查是否已生成重试任务。';
      }
    });
  }

  VS.on('job', render);
}());
