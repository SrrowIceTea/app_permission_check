/* V-Scanner 工作台逻辑。对接 vehicle/workbench 后端 API（127.0.0.1:8770）。
   仅用于授权测试（自有设备与自有 APK）。

   后端端点（见 vehicle/workbench/server.py）：
     POST /api/apk?name=..            -> { digest, job, cached }
     GET  /api/jobs/<id>              -> { state: queued|running|done|failed|cancelled, ... }
     GET  /api/apk/<digest>/tree      -> { files: [{path,size}] }   // 扁平列表
     GET  /api/apk/<digest>/source?path=.. -> { path, size, truncated, text }
     GET  /api/apk/<digest>/static    -> static.json（findings 等）
     GET  /api/apk/<digest>/summary   -> summary.json（apk/findings/decompile 等）
     GET  /api/apk/<digest>/crosscheck -> 四象限对照（或 comparable:false）
     GET  /api/tools                  -> 工具就绪情况
     POST /api/jobs/<id>/cancel       -> 取消任务
*/
(function () {
  'use strict';

  var API_BASE = 'http://127.0.0.1:8770';

  var state = {
    currentPage: 'source',
    apks: [],
    currentApk: null,
    jobId: null,
    treeFilter: ''
  };

  // ---------- 工具 ----------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function emptyState(svg, text) {
    var box = el('div', 'empty-state large');
    if (svg) box.innerHTML = svg;
    box.appendChild(el('p', null, text));
    return box;
  }
  function badge(cls, text) {
    var b = el('span', 'result-badge ' + cls, text);
    return b;
  }
  function clear(node) { if (node) node.textContent = ''; }
  function shortDigest(d) { return d ? d.substring(0, 12) + '…' : ''; }

  var EMPTY_SVGS = {
    source: '<svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" opacity="0.3"><path d="M8 8h32v32H8V8zm4 4v24h24V12H12zm4 4h16v2H16v-2zm0 6h16v2H16v-2zm0 6h10v2H16v-2z"/></svg>',
    file: '<svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" opacity="0.3"><path d="M12 8l-8 16 8 16 4-2-7-14 7-14-4-2zm24 0l-4 2 7 14-7 14 4 2 8-16-8-16z"/></svg>',
    table: '<svg width="64" height="64" viewBox="0 0 64 64" fill="currentColor" opacity="0.3"><path d="M12 8h40v48H12V8zm4 4v40h32V12H16zm6 6h20v4H22v-4zm0 8h20v4H22v-4zm0 8h14v4H22v-4z"/></svg>',
    clock: '<svg width="64" height="64" viewBox="0 0 64 64" fill="currentColor" opacity="0.3"><path d="M32 8a24 24 0 100 48 24 24 0 000-48zm0 4a20 20 0 110 40 20 20 0 010-40zm-2 8v14l12 7 2-3-10-6V20h-4z"/></svg>'
  };

  // ---------- 初始化 ----------
  document.addEventListener('DOMContentLoaded', function () {
    initNavigation();
    initUpload();
    initSourceFilter();
    initPdf();
    renderCurrentApkBar();
  });

  // ---------- 导航 ----------
  function initNavigation() {
    var items = document.querySelectorAll('.nav-item');
    items.forEach(function (item) {
      item.addEventListener('click', function (e) {
        e.preventDefault();
        switchPage(item.dataset.page);
      });
    });
  }

  function switchPage(page) {
    state.currentPage = page;
    document.querySelectorAll('.nav-item').forEach(function (item) {
      item.classList.toggle('active', item.dataset.page === page);
    });
    document.querySelectorAll('.page').forEach(function (p) {
      p.classList.toggle('active', p.id === 'page-' + page);
    });
    updateCurrentPage();
  }

  function updateCurrentPage() {
    switch (state.currentPage) {
      case 'source': renderSourceTree(); break;
      case 'static': renderStaticView(); break;
      case 'dynamic': renderDynamicView(); break;
      case 'ai-report': renderAiReport(); break;
      case 'pdf-report': break; // PDF 由下拉驱动
    }
  }

  // ---------- 上传 ----------
  function initUpload() {
    var zone = document.getElementById('upload-zone');
    var input = document.getElementById('apk-input');
    var cancel = document.getElementById('progress-cancel');

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('dragover'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('dragover');
      var f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) upload(f);
    });
    input.addEventListener('change', function () {
      if (input.files[0]) upload(input.files[0]);
      input.value = '';
    });
    cancel.addEventListener('click', function () {
      if (state.jobId) fetch(API_BASE + '/api/jobs/' + state.jobId + '/cancel', { method: 'POST' });
    });
  }

  function upload(file) {
    if (!/\.apk$/i.test(file.name)) { alert('只接受 .apk 文件。'); return; }
    showProgress('正在上传 ' + file.name + '（' + Math.round(file.size / 1048576) + ' MiB）…', 0, true);

    fetch(API_BASE + '/api/apk?name=' + encodeURIComponent(file.name), {
      method: 'POST',
      body: file
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { showProgress('上传失败：' + data.error, 0, false); return; }
        state.jobId = data.job;
        if (data.cached) showProgress('该 APK 分析过，正在复用缓存重跑规则…', 15, true);
        pollJob(data.digest, file.name);
      })
      .catch(function (err) { showProgress('上传失败：' + err, 0, false); });
  }

  function pollJob(digest, name) {
    fetch(API_BASE + '/api/jobs/' + state.jobId)
      .then(function (r) { return r.json(); })
      .then(function (job) {
        if (job.state === 'done') {
          hideProgress();
          loadApkData(digest, name, job.result);
          return;
        }
        if (job.state === 'failed') {
          showProgress('分析失败：' + (job.error || '未知错误'), 0, false);
          return;
        }
        if (job.state === 'cancelled') {
          showProgress('已取消。缓存保留，可重新拖入同一 APK。', 0, false);
          return;
        }
        var pct = (job.percent === null || job.percent === undefined)
          ? (job.state === 'running' ? 15 : 5) : job.percent;
        var stage = job.stage || job.state;
        var extra = job.total ? job.done + ' / ' + job.total + ' 个类' : '';
        showProgress(stage + (extra ? '（' + extra + '）' : ''), pct, true);
        setTimeout(function () { pollJob(digest, name); }, 700);
      })
      .catch(function () {
        setTimeout(function () { pollJob(digest, name); }, 1500);
      });
  }

  function showProgress(text, pct, active) {
    var bar = document.getElementById('progress-bar');
    var fill = document.getElementById('progress-fill');
    var label = document.getElementById('progress-text');
    bar.style.display = '';
    fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
    fill.classList.toggle('indeterminate', active && pct < 15);
    label.textContent = text;
    document.getElementById('progress-cancel').style.display = active ? '' : 'none';
  }
  function hideProgress() {
    document.getElementById('progress-bar').style.display = 'none';
  }

  // ---------- 载入 APK 数据 ----------
  function loadApkData(digest, name, jobResult) {
    Promise.all([
      fetch(API_BASE + '/api/apk/' + digest + '/tree').then(r => r.json()),
      fetch(API_BASE + '/api/apk/' + digest + '/static').then(r => r.json()).catch(function () { return {}; }),
      fetch(API_BASE + '/api/apk/' + digest + '/summary').then(r => r.json()).catch(function () { return {}; }),
      fetch(API_BASE + '/api/apk/' + digest + '/crosscheck').then(r => r.json()).catch(function () { return null; })
    ]).then(function (results) {
      var tree = results[0].files || [];
      var staticData = results[1];
      var summary = results[2];
      var crosscheck = results[3];

      var entry = {
        digest: digest,
        name: name || (summary.apk && summary.apk.package) || shortDigest(digest),
        tree: tree,
        static: staticData,
        summary: summary,
        crosscheck: crosscheck
      };

      var idx = state.apks.findIndex(function (a) { return a.digest === digest; });
      if (idx >= 0) state.apks[idx] = entry; else state.apks.push(entry);

      state.currentApk = entry;
      renderCurrentApkBar();
      switchPage('static');
    }).catch(function (err) {
      showProgress('载入结果失败：' + err, 0, false);
    });
  }

  function renderCurrentApkBar() {
    var nameEl = document.getElementById('current-apk-name');
    if (!state.currentApk) {
      nameEl.textContent = '尚未上传';
      return;
    }
    nameEl.textContent = state.currentApk.name;
  }

  // ---------- 源码页：文件树 ----------
  function initSourceFilter() {
    var f = document.getElementById('source-filter');
    f.addEventListener('input', function () {
      state.treeFilter = f.value;
      renderSourceTree();
    });
  }

  function renderSourceTree() {
    var treeHost = document.getElementById('file-tree');
    clear(treeHost);
    if (!state.currentApk) {
      treeHost.appendChild(emptyState(EMPTY_SVGS.source, '上传 APK 后查看反编译源码'));
      resetCodeView();
      return;
    }
    var files = state.currentApk.tree || [];
    if (!files.length) {
      treeHost.appendChild(emptyState(EMPTY_SVGS.source, '没有反编译产物（可能反编译失败或未完成）'));
      resetCodeView();
      return;
    }
    var filter = state.treeFilter.trim().toLowerCase();
    if (filter) {
      renderFlatTree(treeHost, files, filter);
    } else {
      renderNestedTree(treeHost, files);
    }
  }

  // 过滤模式：扁平列表，只显示匹配项（前 600 条）
  function renderFlatTree(host, files, filter) {
    var shown = 0;
    files.forEach(function (f) {
      if (f.path.toLowerCase().indexOf(filter) === -1) return;
      if (shown >= 600) return;
      shown++;
      var item = el('div', 'file-tree-item file');
      item.appendChild(el('span', 'ft-icon', '📄'));
      item.appendChild(el('span', 'ft-name', f.path));
      item.addEventListener('click', function () { openSourceFile(f.path); });
      host.appendChild(item);
    });
    if (!shown) host.appendChild(el('div', 'hint', '没有匹配的文件'));
    if (shown >= 600) host.appendChild(el('div', 'hint', '仅显示前 600 条，请用过滤缩小范围'));
  }

  // 无过滤：嵌套目录树，文件夹折叠
  function renderNestedTree(host, files) {
    var root = { dirs: {}, files: [] };
    files.forEach(function (f) {
      var parts = f.path.split('/');
      var node = root;
      for (var i = 0; i < parts.length - 1; i++) {
        if (!node.dirs[parts[i]]) node.dirs[parts[i]] = { name: parts[i], dirs: {}, files: [] };
        node = node.dirs[parts[i]];
      }
      node.files.push({ name: parts[parts.length - 1], path: f.path, size: f.size });
    });
    renderTreeLevel(host, root, 0);
  }

  function renderTreeLevel(host, node, depth) {
    // 文件夹先渲染（按名排序）
    Object.keys(node.dirs).sort().forEach(function (key) {
      var dir = node.dirs[key];
      var row = el('div', 'file-tree-item folder');
      row.style.paddingLeft = (depth * 14 + 8) + 'px';
      row.appendChild(el('span', 'ft-icon', '▸'));
      row.appendChild(el('span', 'ft-name', dir.name));
      var childBox = el('div', 'ft-children');
      childBox.style.display = 'none';
      var expanded = false;
      row.addEventListener('click', function () {
        expanded = !expanded;
        childBox.style.display = expanded ? '' : 'none';
        row.querySelector('.ft-icon').textContent = expanded ? '▾' : '▸';
      });
      host.appendChild(row);
      host.appendChild(childBox);
      renderTreeLevel(childBox, dir, depth + 1);
    });
    // 文件再渲染（按名排序）
    node.files.sort(function (a, b) { return a.name.localeCompare(b.name); }).forEach(function (f) {
      var row = el('div', 'file-tree-item file');
      row.style.paddingLeft = (depth * 14 + 8) + 'px';
      row.appendChild(el('span', 'ft-icon', '📄'));
      row.appendChild(el('span', 'ft-name', f.name));
      row.title = f.path;
      row.addEventListener('click', function () {
        host.querySelectorAll('.file-tree-item').forEach(function (i) { i.classList.remove('active'); });
        row.classList.add('active');
        openSourceFile(f.path);
      });
      host.appendChild(row);
    });
  }

  function resetCodeView() {
    var code = document.getElementById('code-view');
    clear(code);
    code.appendChild(emptyState(EMPTY_SVGS.file, '选择文件查看代码'));
  }

  function openSourceFile(path) {
    var code = document.getElementById('code-view');
    clear(code);
    var meta = el('div', 'code-meta', '载入中 ' + path);
    var pre = el('pre', 'code-content');
    var codeEl = el('code');
    pre.appendChild(codeEl);
    code.appendChild(meta);
    code.appendChild(pre);

    fetch(API_BASE + '/api/apk/' + state.currentApk.digest + '/source?path=' + encodeURIComponent(path))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) {
          meta.textContent = '读取失败：' + data.error;
          return;
        }
        if (window.VSCAN_HL) window.VSCAN_HL.render(codeEl, data.text);
        else codeEl.textContent = data.text;
        meta.textContent = data.path + '  ·  ' + data.size + ' 字节' + (data.truncated ? '（已截断，仅显示前 512 KiB）' : '');
      })
      .catch(function (err) {
        meta.textContent = '读取失败：' + err;
      });
  }

  // ---------- 静态审计页 ----------
  function renderStaticView() {
    var host = document.getElementById('static-results');
    clear(host);
    if (!state.currentApk) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '上传 APK 后查看静态审计结果'));
      return;
    }
    var s = state.currentApk.static || state.currentApk.summary || {};
    var findings = s.findings || [];

    if (!findings.length) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '静态规则未命中任何事实'));
      return;
    }

    var head = el('div', 'static-summary');
    head.appendChild(el('span', null, '求值 ' + (s.rules_evaluated || 0) + ' 条规则，命中 ' + findings.length + ' 条'));
    host.appendChild(head);

    if (s.caveat) host.appendChild(el('div', 'notice', s.caveat));

    var table = el('table', 'results-table');
    var thead = el('thead');
    var hr = el('tr');
    ['规则', '标题', '类型', '强度', '等级', '信号', '依据'].forEach(function (t) {
      hr.appendChild(el('th', null, t));
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el('tbody');
    findings.forEach(function (f) {
      var tr = el('tr');
      tr.appendChild(el('td', 'mono', f.rule_id));
      tr.appendChild(el('td', null, f.title || ''));
      tr.appendChild(el('td', null, f.rule_type || ''));
      tr.appendChild(el('td', null, strengthBadge(f.static_strength)));
      tr.appendChild(el('td', null, levelBadge(f.conclusion_level, f.declared_conclusion_level)));
      var sigs = Object.keys(f.signals || {}).filter(function (k) { return f.signals[k]; });
      tr.appendChild(el('td', 'mono', sigs.join(', ') || '—'));
      tr.appendChild(el('td', 'hint', f.note || ''));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    host.appendChild(table);
  }

  function strengthBadge(strength) {
    var map = { strong: ['s-good', '强：字段引用'], medium: ['s-warning', '中：ID/名字出现'],
      weak: ['s-muted', '弱：无法区分'], none: ['s-muted', '—'] };
    var m = map[strength] || map.none;
    return badge(m[0], m[1]);
  }

  function levelBadge(level, declared) {
    var cls = level === 'candidate' ? 'info' : (level === 'correlated' ? 'critical' : 'warning');
    var text = level;
    if (declared && declared !== level) text += '（声明 ' + declared + '）';
    return badge(cls, text);
  }

  // ---------- 动态审计页（四象限） ----------
  function renderDynamicView() {
    var host = document.getElementById('dynamic-results');
    clear(host);
    if (!state.currentApk) {
      host.appendChild(emptyState(EMPTY_SVGS.clock, '上传 APK 后查看静动交叉核对结果'));
      return;
    }
    var cc = state.currentApk.crosscheck;
    if (!cc || cc.comparable === false) {
      var reason = (cc && cc.reason) ? cc.reason : '未返回交叉核对结果';
      host.appendChild(notice('无法静动对照：' + reason));
      return;
    }

    // 四象限 KPI
    var kpi = el('div', 'kpi-grid');
    var labels = { both: '静动命中', static_only: '仅静态', dynamic_only: '仅动态', none: '均无' };
    ['both', 'static_only', 'dynamic_only', 'none'].forEach(function (q) {
      var tile = el('div', 'kpi-tile kpi-' + q);
      tile.appendChild(el('b', null, String((cc.counts && cc.counts[q]) || 0)));
      tile.appendChild(el('span', null, labels[q]));
      kpi.appendChild(tile);
    });
    host.appendChild(kpi);

    if (cc.identity) {
      var idNote = el('div', 'notice' + (cc.identity.same_apk === false ? ' bad' : ' ok'),
        cc.identity.reason || '');
      host.appendChild(idNote);
    }
    if (cc.attention) host.appendChild(el('div', 'notice' + (cc.counts && cc.counts.dynamic_only ? ' bad' : ''), cc.attention));
    if (cc.caveat) host.appendChild(el('div', 'hint', cc.caveat));

    // 逐条对照表
    var rows = cc.rows || [];
    if (rows.length) {
      var h = el('h3', 'section-subtitle', '逐条规则对照（共 ' + (cc.rules_compared || rows.length) + ' 条）');
      host.appendChild(h);
      var table = el('table', 'results-table');
      var thead = el('thead');
      var hr = el('tr');
      ['规则', '象限', '静态强度', '静态等级', '动态等级'].forEach(function (t) { hr.appendChild(el('th', null, t)); });
      thead.appendChild(hr);
      table.appendChild(thead);
      var tbody = el('tbody');
      rows.forEach(function (r) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', r.rule_id));
        tr.appendChild(el('td', null, quadrantBadge(r.quadrant)));
        tr.appendChild(el('td', null, strengthBadge(r.static_strength)));
        tr.appendChild(el('td', null, r.static_conclusion_level ? levelBadge(r.static_conclusion_level) : el('span', 'hint', '—')));
        tr.appendChild(el('td', null, r.dynamic_level ? levelBadge(r.dynamic_level) : el('span', 'hint', '—')));
        tbody.appendChild(tr);
      });
      table.appendChild(tbody);
      host.appendChild(table);
    }
  }

  function quadrantBadge(q) {
    var map = { both: ['s-good', 'both'], static_only: ['s-warning', 'static_only'],
      dynamic_only: ['s-critical', 'dynamic_only'], none: ['s-muted', 'none'] };
    var m = map[q] || map.none;
    return badge(m[0], m[1]);
  }

  function notice(text) {
    return el('div', 'notice', text);
  }

  // ---------- AI 报告页 ----------
  function renderAiReport() {
    var host = document.getElementById('ai-report');
    clear(host);
    if (!state.currentApk) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '上传 APK 后查看综合审计报告'));
      return;
    }
    var summary = state.currentApk.summary || {};
    var apk = summary.apk || {};
    var findings = summary.findings || [];
    var dec = summary.decompile || {};
    var ctx = summary.static_context || {};

    // 概览
    addSection(host, '审计概览', [
      ['包名', apk.package || 'N/A'],
      ['版本', (apk.version_name || '') + '（' + (apk.version_code || '') + '）'],
      ['SDK', 'min ' + (apk.min_sdk || '?') + ' / target ' + (apk.target_sdk || '?')],
      ['命中规则', String(findings.length) + ' / ' + (summary.rules_evaluated || 0) + ' 条求值'],
      ['反编译', (dec.classes_written || 0) + ' 个类' + (dec.errors ? '（' + dec.errors + ' 个类失败）' : '')]
    ]);

    // 权限清单
    if (apk.permissions && apk.permissions.length) {
      var permBox = el('div', 'perm-list');
      apk.permissions.forEach(function (p) {
        permBox.appendChild(el('div', 'perm-chip mono', p));
      });
      var sec = el('div', 'report-section');
      sec.appendChild(el('div', 'report-section-title', '声明权限（' + apk.permissions.length + '）'));
      sec.appendChild(permBox);
      host.appendChild(sec);
    }

    // 风险分布
    var byType = {};
    findings.forEach(function (f) {
      byType[f.rule_type] = (byType[f.rule_type] || 0) + 1;
    });
    var dist = Object.keys(byType).map(function (k) {
      return '<p><b>' + esc(k) + '</b> : ' + byType[k] + ' 条</p>';
    }).join('');
    if (dist) addSectionRaw(host, '风险分布（按规则类型）', dist);

    // 静态上下文
    if (ctx.cpm_read_api_referenced !== undefined || ctx.discrimination_note) {
      var ctxHtml = '';
      if (ctx.cpm_read_api_referenced !== undefined) {
        ctxHtml += '<p><b>CPM 读取 API 引用</b> : ' + (ctx.cpm_read_api_referenced ? '有' : '无') + '</p>';
      }
      if (ctx.known_property_ids !== undefined) {
        ctxHtml += '<p><b>已知属性 ID</b> : ' + ctx.known_property_ids_present_in_dex + ' / ' + ctx.known_property_ids + ' 个出现在 dex</p>';
      }
      if (ctx.discrimination_note) ctxHtml += '<p class="hint">' + esc(ctx.discrimination_note) + '</p>';
      addSectionRaw(host, '静态上下文', ctxHtml);
    }

    // 高优先级发现（数据外发）
    var egress = findings.filter(function (f) { return f.rule_type === 'data_egress'; });
    if (egress.length) {
      addSectionRaw(host, '数据外发相关（' + egress.length + ' 条）',
        '<ul>' + egress.map(function (f) {
          return '<li><b>' + esc(f.rule_id) + '</b> — ' + esc(f.title || '') +
            '（' + esc(f.static_strength || '') + '）<br><span class="hint">' + esc(f.note || '') + '</span></li>';
        }).join('') + '</ul>');
    }

    // 缺口
    var gaps = [];
    if (dec.gap) gaps.push(dec.gap.detail + '（成功写出 ' + (dec.classes_written || 0) + ' 个类）');
    (summary.apk_gaps || []).forEach(function (g) { gaps.push(g.kind + ' — ' + g.detail); });
    (summary.dex_gaps || []).forEach(function (g) { gaps.push('有 dex 未解析成功：' + g.dex); });
    if (gaps.length) {
      addSectionRaw(host, '已知缺口', gaps.map(function (g) {
        return '<div class="notice bad">' + esc(g) + '</div>';
      }).join(''));
    }

    // 建议
    addSectionRaw(host, '审计建议', '<ul>' +
      '<li>静态结论等级封顶 candidate——代码里出现引用<strong>不证明</strong>运行时行为，违规仍需人工判定。</li>' +
      '<li>优先核对 data_egress 规则：确认外发数据是否经过 TLS、是否为业务最小必要。</li>' +
      '<li>逐条确认 manifest 权限必要性；CPM 读取属性 ID 的出现无法区隔"用了哪个"，需结合运行时观测。</li>' +
      '<li>关注"仅动态"象限——运行时观测到而代码里找不到，可能意味着规则库覆盖不全或反射/动态加载。</li>' +
      '</ul>');

    if (summary.caveat) host.appendChild(el('div', 'notice', summary.caveat));
  }

  function addSection(host, title, kvPairs) {
    var sec = el('div', 'report-section');
    sec.appendChild(el('div', 'report-section-title', title));
    var content = el('div', 'report-content');
    kvPairs.forEach(function (pair) {
      var p = el('p');
      p.appendChild(el('strong', null, pair[0] + ': '));
      p.appendChild(document.createTextNode(pair[1]));
      content.appendChild(p);
    });
    sec.appendChild(content);
    host.appendChild(sec);
  }

  function addSectionRaw(host, title, html) {
    var sec = el('div', 'report-section');
    sec.appendChild(el('div', 'report-section-title', title));
    var content = el('div', 'report-content');
    content.innerHTML = html;
    sec.appendChild(content);
    host.appendChild(sec);
  }

  // ---------- PDF 页 ----------
  function initPdf() {
    var sel = document.getElementById('pdf-select');
    sel.addEventListener('change', function () {
      if (sel.value) loadPdf(sel.value);
    });
  }

  function loadPdf(url) {
    var container = document.getElementById('pdf-viewer-container');
    var ext = document.getElementById('pdf-open-external');
    clear(container);
    container.className = 'pdf-viewer-container has-frame';

    if (window.location.protocol === 'file:') {
      container.className = 'pdf-viewer-container';
      container.appendChild(emptyState(EMPTY_SVGS.table,
        'PDF 内嵌查看需要通过 HTTP 服务器访问（file:// 下浏览器可能阻止）'));
      ext.style.display = '';
      ext.querySelector('a').href = url;
      return;
    }

    var frame = el('iframe', 'pdf-frame');
    frame.src = url;
    frame.title = url;
    container.appendChild(frame);
    ext.style.display = '';
    ext.querySelector('a').href = url;
  }

})();
