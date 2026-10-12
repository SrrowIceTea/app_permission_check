/* 拖放上传 → 轮询进度 → 渲染静态结论 / 缺口 / 静动对照。
   全部 textContent，零 innerHTML（D603）。 */
(function () {
  'use strict';

  var jobId = null, digest = null, timer = null;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function badge(status, text) { return el('span', 'badge ' + status, text); }
  function clear(id) { var n = document.getElementById(id); if (n) n.textContent = ''; }

  var STRENGTH = {
    strong: ['s-good', '强：有指向该属性的字段引用'],
    medium: ['s-warning', '中：只见到属性 ID 常量'],
    weak: ['s-muted', '弱：同一 dex 里还有别的属性 ID，无法区分'],
    none: ['s-muted', '—']
  };

  // ---------- 拖放 ----------
  function initDrop() {
    var drop = document.getElementById('drop');
    var input = document.getElementById('file');
    ['dragenter', 'dragover'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('hot'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('hot'); });
    });
    drop.addEventListener('drop', function (e) {
      var file = e.dataTransfer.files && e.dataTransfer.files[0];
      if (file) upload(file);
    });
    input.addEventListener('change', function () {
      if (input.files[0]) upload(input.files[0]);
    });
  }

  function upload(file) {
    if (!/\.apk$/i.test(file.name)) {
      alert('只接受 .apk 文件。');
      return;
    }
    showGap('正在上传 ' + file.name + '（' + Math.round(file.size / 1048576) + ' MiB）…', '');
    fetch('/api/apk?name=' + encodeURIComponent(file.name), { method: 'POST', body: file })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showGap('上传失败：' + data.error, 'bad'); return; }
        digest = data.digest;
        jobId = data.job;
        document.getElementById('progress-card').hidden = false;
        if (data.cached) showGap('这个 APK 之前分析过，正在重跑规则匹配（反编译产物可复用）。', 'ok');
        poll();
      })
      .catch(function (err) { showGap('上传失败：' + err, 'bad'); });
  }

  // ---------- 进度 ----------
  function poll() {
    clearTimeout(timer);
    fetch('/api/jobs/' + jobId).then(function (r) { return r.json(); }).then(function (job) {
      var bar = document.getElementById('bar');
      document.getElementById('stage').textContent = job.stage || job.state;
      bar.style.width = (job.percent === null || job.percent === undefined)
        ? (job.state === 'running' ? '15%' : '0%') : job.percent + '%';
      document.getElementById('progress-text').textContent =
        (job.total ? job.done + ' / ' + job.total + ' 个类' : '')
        + (job.error ? '错误：' + job.error : '');
      if (job.state === 'done') { onDone(job.result); return; }
      if (job.state === 'failed') { showGap('分析失败：' + job.error, 'bad'); return; }
      if (job.state === 'cancelled') { showGap('已取消。缓存保留，可重新拖入同一个 APK 继续。', ''); return; }
      timer = setTimeout(poll, 700);
    }).catch(function () { timer = setTimeout(poll, 1500); });
  }

  function cancel() {
    if (jobId) fetch('/api/jobs/' + jobId + '/cancel', { method: 'POST' });
  }

  // ---------- 结果 ----------
  function onDone(result) {
    document.getElementById('progress-card').hidden = true;
    document.getElementById('results').hidden = false;
    renderFindings(result || {});
    renderGaps(result || {});
    window.VSCAN_VIEWER.load(digest);
    loadCrosscheck();
  }

  function renderFindings(result) {
    var tbody = document.querySelector('#findings-table tbody');
    tbody.textContent = '';
    var findings = result.findings || [];
    document.getElementById('static-meta').textContent =
      '（求值 ' + (result.rules_evaluated || 0) + ' 条规则，命中 ' + findings.length + ' 条）';

    var ctx = result.static_context || {};
    var kpi = document.getElementById('kpi');
    kpi.textContent = '';
    [['命中规则', findings.length], ['求值规则', result.rules_evaluated || 0],
     ['CPM 读取 API', ctx.cpm_read_api_referenced ? '有' : '无'],
     ['dex 内已知属性 ID', (ctx.known_property_ids_present_in_dex || 0) + ' / '
        + (ctx.known_property_ids || 0)]].forEach(function (pair) {
      var tile = el('div', 'tile');
      tile.appendChild(el('b', null, String(pair[1])));
      tile.appendChild(el('span', null, pair[0]));
      kpi.appendChild(tile);
    });

    var note = document.getElementById('static-note');
    note.textContent = '';
    if (ctx.discrimination_note) note.appendChild(el('div', 'hint', ctx.discrimination_note));
    if (result.caveat) note.appendChild(el('div', 'hint', result.caveat));

    findings.forEach(function (f) {
      var tr = el('tr');
      tr.appendChild(el('td', 'mono', f.rule_id));
      tr.appendChild(el('td', null, f.rule_type));
      var st = STRENGTH[f.static_strength] || STRENGTH.none;
      var td = el('td'); td.appendChild(badge(st[0], f.static_strength)); tr.appendChild(td);
      var lv = el('td');
      lv.appendChild(badge('s-warning', f.conclusion_level));
      if (f.declared_conclusion_level !== f.conclusion_level) {
        lv.appendChild(el('span', 'hint', ' （规则声明 ' + f.declared_conclusion_level + '，已封顶）'));
      }
      tr.appendChild(lv);
      var sig = Object.keys(f.signals || {}).filter(function (k) { return f.signals[k]; });
      tr.appendChild(el('td', 'mono', sig.join(', ') || '—'));
      tr.appendChild(el('td', 'hint', f.note || ''));
      tbody.appendChild(tr);
    });
  }

  function renderGaps(result) {
    clear('gaps');
    var host = document.getElementById('gaps');
    var dec = result.decompile || {};
    if (dec.gap) {
      host.appendChild(notice('反编译不完整：' + dec.gap.detail + '（成功写出 '
        + (dec.classes_written || 0) + ' 个类）', 'bad'));
    }
    (result.apk_gaps || []).forEach(function (gap) {
      host.appendChild(notice('清单信息缺失：' + gap.kind + ' — ' + gap.detail, 'bad'));
    });
    (result.dex_gaps || []).forEach(function (gap) {
      host.appendChild(notice('有 dex 没解析成功：' + gap.dex + '（返回码 '
        + gap.returncode + '）——"没扫成"不等于"里面没有"', 'bad'));
    });
    if (dec.cancelled) host.appendChild(notice('反编译被取消，源码树可能不完整。', ''));
  }

  function notice(text, kind) {
    return el('div', 'notice ' + kind, text);
  }

  function showGap(text, kind) {
    var host = document.getElementById('gaps');
    host.appendChild(notice(text, kind));
  }

  function loadCrosscheck() {
    clear('crosscheck');
    fetch('/api/apk/' + digest + '/crosscheck').then(function (r) { return r.json(); })
      .then(function (data) {
        var host = document.getElementById('crosscheck');
        if (!data || data.comparable === false) {
          host.appendChild(el('h2', null, '静动交叉核对'));
          host.appendChild(notice('无法对照：' + (data && data.reason ? data.reason : '未知原因'), ''));
          return;
        }
        host.appendChild(el('h2', null, '静动交叉核对'));
        var kpi = el('div', 'kpi');
        Object.keys(data.counts).forEach(function (key) {
          var tile = el('div', 'tile');
          tile.appendChild(el('b', null, String(data.counts[key])));
          tile.appendChild(el('span', null, key));
          kpi.appendChild(tile);
        });
        host.appendChild(kpi);
        host.appendChild(notice(data.attention, data.counts.dynamic_only ? 'bad' : 'ok'));
        host.appendChild(el('div', 'hint', data.caveat));
      })
      .catch(function () { /* 没有会话时本来就没有这一块 */ });
  }

  // ---------- 初始化 ----------
  document.addEventListener('DOMContentLoaded', function () {
    initDrop();
    document.getElementById('cancel').addEventListener('click', cancel);
    fetch('/api/tools').then(function (r) { return r.json(); }).then(function (tools) {
      var missing = Object.keys(tools).filter(function (k) {
        return !k.endsWith('_error') && !tools[k];
      });
      document.getElementById('tools').textContent = missing.length
        ? '⚠ 找不到这些工具，相关功能不可用：' + missing.join('、')
        : '工具就绪：jadx / aapt2 / dexdump 均已找到';
    });
    // 主题切换：显式 data-theme 压过系统偏好（与 phase6 一致）
    document.getElementById('theme-toggle').addEventListener('click', function () {
      var root = document.documentElement;
      var dark = root.dataset.theme ? root.dataset.theme === 'dark'
        : matchMedia('(prefers-color-scheme: dark)').matches;
      root.dataset.theme = dark ? 'light' : 'dark';
    });
  });
})();
