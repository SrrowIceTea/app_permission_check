/* V·SCANNER v2 · 源码查看（文件树 + 右侧代码 + 悬停左侧小窗）
   只读产物接口；悬停只在悬浮行左侧弹小窗，绝不改写右侧 #codeView，点击才固定。 */
(function () {
  'use strict';
  const VS = window.VS, S = VS.state;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"]/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const PEEK_LINES = 5;      // 小窗只给节奏感，完整内容留给右侧
  const PEEK_DELAY = 260;    // 滑过文件树时不打爆接口
  const cache = { job: '', tree: null, path: '' };
  const peekCache = new Map();
  let hoverTimer = 0, hoverSeq = 0, peekNode = null, hideTimer = 0;

  const list = () => $('#treeList');

  function badge(el, job, empty) {
    el.textContent = job
      ? `${job.name || job.package || 'APK'} · ${String(job.id).slice(0, 12)}…`
      : empty;
  }

  /* ── 悬停小窗 ── */
  function hidePeek() {
    window.clearTimeout(hideTimer);
    if (peekNode) { peekNode.remove(); peekNode = null; }
  }
  function scheduleHide() {
    window.clearTimeout(hideTimer);
    hideTimer = window.setTimeout(hidePeek, 320);
  }
  function peekText(text) {
    const lines = String(text || '').split('\n');
    const head = lines.slice(0, PEEK_LINES).join('\n');
    return lines.length > PEEK_LINES ? head + '\n…' : head;
  }
  function showPeek(anchor, result) {
    hidePeek();
    const box = document.createElement('div');
    box.className = 'source-peek';
    const head = document.createElement('div');
    head.className = 'source-peek-head';
    head.textContent = result.path || '';
    const body = document.createElement('pre');
    body.className = 'source-peek-code';
    body.textContent = peekText(result.text);
    box.append(head, body);
    // 鼠标移进小窗时保持，滑出即收；小窗本身不抢焦点、不可点击
    box.addEventListener('mouseenter', () => window.clearTimeout(hideTimer));
    box.addEventListener('mouseleave', hidePeek);
    document.body.appendChild(box);

    // 锚定在悬浮行正左方并与该行垂直居中；v2 的文件树贴页面左缘、左侧常常没有空间，
    // 此时改贴在该行下方并与树列左对齐——绝不压到右侧代码区。
    const br = anchor.getBoundingClientRect();
    const pw = box.offsetWidth, ph = box.offsetHeight;
    let left = br.left - pw - 10;
    let top = br.top + (br.height - ph) / 2;
    if (left < 8) {
      left = br.left;
      top = br.bottom + 6;
      if (top + ph > window.innerHeight - 8) top = Math.max(8, br.top - ph - 6);
    }
    left = Math.max(8, Math.min(left, window.innerWidth - pw - 8));
    top = Math.max(8, Math.min(top, window.innerHeight - ph - 8));
    box.style.left = left + 'px';
    box.style.top = top + 'px';
    peekNode = box;
  }

  /* ── 文件树 ── */
  function drawTree() {
    const box = list();
    if (!cache.tree) { box.innerHTML = '<li class="muted">载入中…</li>'; return; }
    const q = $('#treeSearch').value.trim().toLowerCase();
    const rows = cache.tree.filter((r) => !q || String(r.path).toLowerCase().includes(q));
    if (!rows.length) {
      box.innerHTML = `<li class="muted">${cache.tree.length ? '没有匹配的路径' : '该任务还没有反编译源码（需静态阶段完成）'}</li>`;
      return;
    }
    box.innerHTML = rows.slice(0, 600).map((r) =>
      `<li data-p="${esc(r.path)}" class="${cache.path === r.path ? 'is-on' : ''}">` +
      `<span class="p">${esc(r.path)}</span><span class="sz">${(Number(r.size || 0) / 1024).toFixed(1)}K</span></li>`).join('');
    if (rows.length > 600) box.insertAdjacentHTML('beforeend', '<li class="muted">只显示前 600 个文件，用搜索缩小范围</li>');
  }

  async function loadTree() {
    const job = S.job;
    badge($('#srcJob'), job, '未选择任务');
    if (!job) { list().innerHTML = '<li class="muted">请先在概览页选择一个任务</li>'; return; }
    if (cache.job === job.id && cache.tree) { drawTree(); return; }
    list().innerHTML = '<li class="muted">载入文件树…</li>';
    try {
      const rows = await VS.api(`/api/pipeline/${job.id}/tree`);
      cache.tree = Array.isArray(rows) ? rows : [];
      cache.job = job.id;
      drawTree();
    } catch (e) {
      cache.tree = null;
      list().innerHTML = `<li class="muted">文件树不可用：${esc(e.message)}</li>`;
    }
  }

  async function loadSource(path) {
    const job = S.job;
    if (!job) return;
    hidePeek();
    ++hoverSeq;                       // 点击固定后，屏蔽还在路上的悬停结果
    cache.path = path;
    drawTree();
    $('#codePath').textContent = path;
    $('#codeView').textContent = '载入中…';
    try {
      const data = await VS.api(`/api/pipeline/${job.id}/source?path=${encodeURIComponent(path)}`);
      if (S.job !== job) return;
      $('#codeView').textContent = (data.text || '(空文件)') + (data.truncated ? '\n\n/* 文件过大，已截断 */' : '');
      $$('#treeList li[data-p]').forEach((li) => li.classList.toggle('is-on', li.dataset.p === path));
    } catch (e) {
      $('#codeView').textContent = '读取失败：' + e.message;
      VS.toast('源码读取失败');
    }
  }

  async function loadPeek(anchor) {
    const job = S.job, path = anchor.dataset.p;
    if (!job || !path || cache.path === path) return;
    const seq = ++hoverSeq;
    const key = job.id + '|' + path;
    let result = peekCache.get(key);
    if (!result) {
      try {
        const data = await VS.api(`/api/pipeline/${job.id}/source?path=${encodeURIComponent(path)}`);
        result = { path: path, text: data.text || '', truncated: !!data.truncated };
        peekCache.set(key, result);
      } catch (e) {
        console.warn('[v2] 悬停预览失败：' + e.message);
        return;
      }
    }
    if (seq !== hoverSeq || S.job !== job) return;
    showPeek(anchor, result);
  }

  /* ── 事件（树是动态渲染的，统一用委托） ── */
  list().addEventListener('click', (e) => {
    const li = e.target.closest('li[data-p]');
    if (li) loadSource(li.dataset.p);
  });
  list().addEventListener('mouseover', (e) => {
    const li = e.target.closest('li[data-p]');
    if (!li || li.contains(e.relatedTarget)) return;   // 行内子元素间移动不算新悬停
    window.clearTimeout(hideTimer);
    window.clearTimeout(hoverTimer);
    hoverTimer = window.setTimeout(() => loadPeek(li), PEEK_DELAY);
  });
  list().addEventListener('mouseout', (e) => {
    const li = e.target.closest('li[data-p]');
    if (!li || li.contains(e.relatedTarget)) return;
    window.clearTimeout(hoverTimer);
    scheduleHide();
  });
  $('#treeSearch').addEventListener('input', drawTree);
  $('#copyPath').addEventListener('click', async () => {
    const p = $('#codePath').textContent;
    if (!p || p === '未选择文件') { VS.toast('先从左侧选择一个文件'); return; }
    try { await navigator.clipboard.writeText(p); VS.toast('路径已复制'); }
    catch (e) { VS.toast('复制失败，请手动选中'); }
  });
  // 固定定位的小窗在滚动/切页后会脱离锚点，直接收起
  document.addEventListener('scroll', hidePeek, true);
  window.addEventListener('resize', hidePeek);

  VS.source = {
    render: loadTree,
    reset: function () {
      cache.job = ''; cache.tree = null; cache.path = '';
      peekCache.clear();
      window.clearTimeout(hoverTimer);
      ++hoverSeq;
      hidePeek();
      $('#codePath').textContent = '未选择文件';
      $('#codeView').textContent = '从左侧选择一个文件';
    },
  };
}());
