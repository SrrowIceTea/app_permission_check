/* Session-specific SSE with replay de-duplication and HTTP recovery. */
(function () {
  'use strict';
  const U = window.VehicleUI;
  U.streams = new Map();
  U.watch = function (job, hooks) {
    if (U.streams.has(job.id) || (job._loaded && ['done', 'failed', 'static_only'].includes(job.state))) return;
    job._events = job._events || [];
    const seen = new Set(job._events.map(e => JSON.stringify(e)));
    const stream = new EventSource(U.base + '/api/pipeline/' + job.id + '/events');
    let poll = null, checking = false;
    const close = () => { stream.close(); if (poll) clearInterval(poll); U.streams.delete(job.id); };
    U.streams.set(job.id, {close});
    function finish(data) {
      Object.assign(job, data); job._loaded = true; close(); hooks.complete(job);
    }
    stream.onmessage = function (event) {
      try {
        const data = JSON.parse(event.data), key = JSON.stringify(data);
        if (!seen.has(key)) { job._events.push(data); seen.add(key); }
        hooks.progress(job);
      } catch (_) { hooks.error(job, '进度消息无效，正在等待服务恢复。'); }
    };
    stream.addEventListener('end', event => {
      try { finish(JSON.parse(event.data)); }
      catch (_) { hooks.error(job, '任务结束消息无效，请刷新任务状态。'); }
    });
    stream.onerror = function () {
      hooks.error(job, '进度连接中断 · 正在重连；后台任务继续保留。');
      if (!poll) poll = setInterval(async function () {
        if (checking) return; checking = true;
        try {
          const data = await U.get('/api/pipeline/' + job.id);
          if (['done', 'failed', 'static_only'].includes(data.state)) finish(data);
        } catch (error) { if (error.status === 404) { close(); hooks.error(job, '任务已不可用，请刷新历史列表。'); } }
        finally { checking = false; }
      }, 3000);
    };
  };
}());
