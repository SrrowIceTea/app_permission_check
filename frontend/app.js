/* V-Scanner 移动端工作台逻辑。对接 mobile/pipeline 一键审计后端（127.0.0.1:8771）。
   仅用于授权测试（自有设备与自有 APK）。

   APK 只允许在「一键审计」页拖入；其余页面展示该流水线任务的结果。

   后端端点（见 mobile/pipeline/server.py）：
     POST /api/pipeline?name=..       -> { id, name }
     GET  /api/stages                 -> [{id,label}]
     GET  /api/pipeline/<id>/events   -> SSE（阶段事件 + end）
     GET  /api/pipeline/<id>/static   -> static.json（MOB-* findings 明细）
     GET  /api/pipeline/<id>/tree     -> phase7-tree.json（扁平 [{path,size}]）
     GET  /api/pipeline/<id>/source?path=.. -> { path,size,truncated,text }
     GET  /api/pipeline/<id>/report   -> 动态审计 PDF
     GET  /api/pipeline/<id>/bundle   -> 证据包 JSON
*/
(function () {
  'use strict';

  var PIPELINE_API_BASE = 'http://127.0.0.1:8771';   // 一键审计流水线（mobile/pipeline）

  var state = {
    currentPage: 'pipeline',
    current: null,        // {id, name, staticData, tree, fin, stageStatus}
    history: [],          // 历史流水线任务（供切换回看）
    treeFilter: ''
  };

  var pipelineState = {
    stages: [],
    status: {},           // stageId -> {status, message}
    jobId: null,
    es: null
  };

  function loadCheckedAI(entry) {
    if(entry && entry.fin && entry.fin.state === 'done' && !entry.bundleOutput) {
      fetch(PIPELINE_API_BASE+'/api/pipeline/'+entry.id+'/bundle').then(function(r){if(!r.ok)throw new Error('证据未就绪');return r.json();})
        .then(function(b){entry.bundleOutput=b;if(state.current===entry)updateCurrentPage();}).catch(function(){});
    }
    if (!entry || entry.aiOutput || !entry.fin || entry.fin.state !== 'done') return;
    fetch(PIPELINE_API_BASE + '/api/pipeline/' + entry.id + '/ai').then(function(r) {
      if (!r.ok) throw new Error('AI 尚不可用'); return r.json();
    }).then(function(data) { entry.aiOutput = data; if(state.current === entry) updateCurrentPage(); }).catch(function(){});
  }
  function restoreHistory() {
    fetch(PIPELINE_API_BASE + '/api/pipeline').then(function(r) { if(!r.ok) throw new Error('任务列表不可用');return r.json(); })
      .then(function(rows) {
        if (!Array.isArray(rows)) return;
        rows.forEach(function(row) {
          if (!state.history.some(function(e){return e.id === row.id;})) state.history.push({id:row.id,name:row.name,
            staticData:null,tree:null,fin:{state:row.state,error:row.error,result:row.result}});
        });
        if (!state.current && state.history.length) {
          state.current=state.history[0];loadPipelineArtifacts(state.current.id);loadCheckedAI(state.current);
          if (state.current.fin.state === 'queued' || state.current.fin.state === 'running') {
            pipelineState.jobId=state.current.id;subscribePipeline(state.current.id);
          } else showPipelineResult(state.current,state.current.fin);
        }
        renderCurrentApkBar();updateCurrentPage();
      }).catch(function(){});
  }

  // ---------- 工具 ----------
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) {
      if (typeof text === 'object' && text.nodeType) n.appendChild(text);
      else n.textContent = text;
    }
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
  function badge(cls, text) { return el('span', 'result-badge ' + cls, text); }
  function clear(node) { if (node) node.textContent = ''; }
  function notice(text, cls) { return el('div', 'notice' + (cls ? ' ' + cls : ''), text); }

  var EMPTY_SVGS = {
    source: '<svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" opacity="0.3"><path d="M8 8h32v32H8V8zm4 4v24h24V12H12zm4 4h16v2H16v-2zm0 6h16v2H16v-2zm0 6h10v2H16v-2z"/></svg>',
    file: '<svg width="48" height="48" viewBox="0 0 48 48" fill="currentColor" opacity="0.3"><path d="M12 8l-8 16 8 16 4-2-7-14 7-14-4-2zm24 0l-4 2 7 14-7 14 4 2 8-16-8-16z"/></svg>',
    table: '<svg width="64" height="64" viewBox="0 0 64 64" fill="currentColor" opacity="0.3"><path d="M12 8h40v48H12V8zm4 4v40h32V12H16zm6 6h20v4H22v-4zm0 8h20v4H22v-4zm0 8h14v4H22v-4z"/></svg>',
    clock: '<svg width="64" height="64" viewBox="0 0 64 64" fill="currentColor" opacity="0.3"><path d="M32 8a24 24 0 100 48 24 24 0 000-48zm0 4a20 20 0 110 40 20 20 0 010-40zm-2 8v14l12 7 2-3-10-6V20h-4z"/></svg>'
  };

  // ---------- 初始化 ----------
  document.addEventListener('DOMContentLoaded', function () {
    initNavigation();
    initSourceFilter();
    initPdf();
    initApkSwitch();
    initPipeline();
    document.getElementById('new-audit').addEventListener('click', function() {
      if(state.history.some(function(e){return !e.fin || ['queued','running'].includes(e.fin.state);})) {
        alert('当前检测仍在运行，请等待完成。');return;
      }
      state.current=null;resetPipelineResult();setPipelineJob('');
      pipelineState.stages.forEach(function(s){pipelineState.status[s.id]={status:'pending',message:''};});
      renderPipelineTimeline();renderCurrentApkBar();switchPage('pipeline');
    });
    renderCurrentApkBar();
    restoreHistory();
    if (location.hash) {
      var target = location.hash.replace('#', '');
      if (target && document.getElementById('page-' + target)) switchPage(target);
    }
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
    document.querySelector('.page-container').scrollTop = 0;
    document.querySelectorAll('.nav-item').forEach(function (item) {
      item.classList.toggle('active', item.dataset.page === page);
    });
    document.querySelectorAll('.page').forEach(function (p) {
      p.classList.toggle('active', p.id === 'page-' + page);
    });
    // 切到结果页时若产物还没到位，顺手补拉一次（static done 事件漏掉时也能恢复）
    if (state.current && state.current.id === pipelineState.jobId &&
        (!state.current.staticData || !state.current.tree) && !state.current._artLoading) {
      loadPipelineArtifacts(state.current.id);
    }
    updateCurrentPage();
    if (page === "pdf-report" && window.VScanResults) window.VScanResults.renderLibrary(document.getElementById("page-pdf-report"),state.history,PIPELINE_API_BASE);
  }

  function updateCurrentPage() {
    switch (state.currentPage) {
      case 'source': renderSourceTree(); break;
      case 'static': renderStaticView(); break;
      case 'dynamic': renderDynamicView(); break;
      case 'ai-report': renderAiReport(); break;
      case 'pdf-report': break; // PDF 由下拉驱动
      case 'pipeline': break;   // 一键审计由 SSE 驱动
    }
  }

  // ---------- 当前样本栏（含历史切换） ----------
  function renderCurrentApkBar() {
    var nameEl = document.getElementById('current-apk-name');
    var sel = document.getElementById('apk-switch');
    if (!state.current) {
      nameEl.textContent = '尚未拖入';
      if(state.history.length){fillApkSwitch(sel);sel.style.display='';sel.selectedIndex=-1;} else sel.style.display='none';
      return;
    }
    nameEl.textContent = state.current.name;
    if (state.history.length > 1) {
      fillApkSwitch(sel);
      sel.style.display = '';
    } else {
      sel.style.display = 'none';
    }
  }

  function fillApkSwitch(sel) {
    var current = state.current ? state.current.id : null;
    sel.textContent = '';
    state.history.forEach(function (a) {
      var opt = el('option');
      opt.value = a.id;
      opt.textContent = a.name + " · " + ((a.fin && a.fin.result && a.fin.result.mode) || "检测中") + " · " + a.id.slice(-4);
      if (a.id === current) opt.selected = true;
      sel.appendChild(opt);
    });
  }

  function initApkSwitch() {
    var sel = document.getElementById('apk-switch');
    sel.addEventListener('change', function () {
      var entry = state.history.find(function (a) { return a.id === sel.value; });
      if (!entry) return;
      state.current = entry;
      if (!entry.staticData) loadPipelineArtifacts(entry.id);
      loadCheckedAI(entry);
      if (entry.fin && ["done","failed","static_only"].includes(entry.fin.state)) showPipelineResult(entry,entry.fin);
      renderCurrentApkBar();
      updateCurrentPage();
    });
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
    if (!state.current || !state.current.tree) {
      treeHost.appendChild(emptyState(EMPTY_SVGS.source, '在一键审计页拖入 APK 后查看反编译源码'));
      resetCodeView();
      return;
    }
    var files = state.current.tree || [];
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
    node.files.sort(function (a, b) { return a.name.localeCompare(b.name); }).forEach(function (f) {
      var row = el('div', 'file-tree-item file');
      row.style.paddingLeft = (depth * 14 + 8) + 'px';
      row.appendChild(el('span', 'ft-icon', '📄'));
      row.appendChild(el('span', 'ft-name', f.name));
      row.title = f.path;
      row.addEventListener('click', function () {
        document.querySelectorAll('#file-tree .file-tree-item.active').forEach(function (i) { i.classList.remove('active'); });
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

    fetch(PIPELINE_API_BASE + '/api/pipeline/' + state.current.id + '/source?path=' + encodeURIComponent(path))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { meta.textContent = '读取失败：' + data.error; return; }
        if (window.VSCAN_HL) window.VSCAN_HL.render(codeEl, data.text);
        else codeEl.textContent = data.text;
        meta.textContent = data.path + '  ·  ' + data.size + ' 字节' + (data.truncated ? '（已截断，仅显示前 512 KiB）' : '');
      })
      .catch(function (err) { meta.textContent = '读取失败：' + err; });
  }

  // ---------- 静态审计页（移动规则库 MOB-* findings） ----------
  function renderStaticView() {
    var host = document.getElementById('static-results');
    clear(host);
    if (!state.current || !state.current.staticData) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '在一键审计页拖入 APK，静态剖析完成后此处显示结果'));
      return;
    }
    var s = state.current.staticData || {};
    var findings = s.findings || [];

    var head = el('div', 'static-summary');
    head.appendChild(el('span', null, '求值 ' + (s.rules_evaluated || 0) + ' 条规则，命中 ' + findings.length + ' 条'));
    host.appendChild(head);

    if (s.caveat) host.appendChild(notice(s.caveat));
    if (!findings.length) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '静态规则未命中任何事实'));
      return;
    }

    var table = el('table', 'results-table');
    var thead = el('thead');
    var hr = el('tr');
    ['规则', '标题', '类型', '严重度', '强度', '等级', '信号', '依据'].forEach(function (t) {
      hr.appendChild(el('th', null, t));
    });
    thead.appendChild(hr);
    table.appendChild(thead);

    var tbody = el('tbody');
    findings.forEach(function (f) {
      var tr = el('tr');
      tr.appendChild(el('td', 'mono', f.rule_id));
      var titleText = f.title || '';
      var titleTd = el('td');
      var titleSpan = el('span', 'cell-clamp', titleText);
      titleSpan.title = titleText;
      titleTd.appendChild(titleSpan);
      tr.appendChild(titleTd);
      tr.appendChild(el('td', null, f.rule_type || ''));
      tr.appendChild(el('td', null, f.severity || ''));
      tr.appendChild(el('td', null, strengthBadge(f.static_strength)));
      tr.appendChild(el('td', null, levelBadge(f.conclusion_level, f.declared_conclusion_level)));
      var sigs = Object.keys(f.signals || {}).filter(function (k) { return f.signals[k]; });
      tr.appendChild(el('td', 'mono', sigs.join(', ') || '—'));
      var note = f.note || '';
      var noteTd = el('td', 'hint');
      var noteSpan = el('span', 'cell-clamp', note.length > 120 ? note.slice(0, 120) + '…' : note);
      noteSpan.title = note;
      noteTd.appendChild(noteSpan);
      tr.appendChild(noteTd);
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

  // ---------- 动态审计页（流水线动态阶段 + 判据 + 报告） ----------
  function renderDynamicView() {
    var host = document.getElementById('dynamic-results');
    if(state.current && state.current.bundleOutput && window.VScanResults) {window.VScanResults.renderDynamic(host,state.current);return;}
    clear(host);
    if (!state.current) {
      host.appendChild(emptyState(EMPTY_SVGS.clock, '在一键审计页拖入 APK 后查看动态审计结果'));
      return;
    }
    var entry = state.current;
    var isRunning = entry.id === pipelineState.jobId && !entry.fin;

    if (!entry.fin) {
      if (isRunning) {
        host.appendChild(notice('动态采集进行中，结束后此处显示判据与报告。当前阶段状态：'));
        appendStageStatus(host, liveDynamicStages());
      } else {
        host.appendChild(emptyState(EMPTY_SVGS.clock, '该任务没有动态审计结果（可能仅完成静态或已失败）'));
      }
      return;
    }

    var fin = entry.fin || {};
    var result = fin.result || {};
    var stateText = fin.state === 'done' ? '全流程完成'
      : (fin.state === 'static_only' ? '仅静态（动态不可用）' : fin.state);
    var head = el('div', 'static-summary');
    head.appendChild(el('span', null, '流水线状态：' + stateText));
    host.appendChild(head);

    if (fin.state === 'static_only' && result.device_unavailable) {
      host.appendChild(notice('动态分析跳过：' + result.device_unavailable, 'bad'));
    }
    if (entry.stageStatus) appendStageStatus(host, dynamicStageRows(entry.stageStatus));

    var v = result.verification;
    if (v) {
      var sec = el('div', 'report-section');
      sec.appendChild(el('div', 'report-section-title', '动态检测判据（' + (v.passed ? '通过' : '未通过') + '）'));
      var tbl = el('table', 'results-table');
      var thead = el('thead'), hr = el('tr');
      ['判据', '结果', '说明'].forEach(function (t) { hr.appendChild(el('th', null, t)); });
      thead.appendChild(hr); tbl.appendChild(thead);
      var tbody = el('tbody');
      (v.checks || []).forEach(function (c) {
        var tr = el('tr');
        tr.appendChild(el('td', 'mono', c.name));
        tr.appendChild(el('td', null, badge(c.exit_code === 0 ? 's-good' : 's-critical', c.exit_code === 0 ? '通过' : '失败')));
        tr.appendChild(el('td', 'hint', c.note || ''));
        tbody.appendChild(tr);
      });
      tbl.appendChild(tbody);
      sec.appendChild(tbl);
      host.appendChild(sec);
    } else if (fin.state !== 'done') {
      host.appendChild(notice('流水线失败：' + (result.error || fin.error || entry.name), 'bad'));
    }

    var links = el('div', 'pl-links');
    if (result.report !== undefined) {
      // end 事件里 report 可能是 null（未产出）；仍给端点链接，404 时浏览器会提示
      if (result.report) {
        var ra = el('a', 'pl-btn primary', '下载动态审计报告（PDF）');
        ra.href = PIPELINE_API_BASE + '/api/pipeline/' + entry.id + '/report';
        ra.target = '_blank';
        links.appendChild(ra);
      }
      if (result.bundle) {
        var ba = el('a', 'pl-btn', '查看证据包（JSON）');
        ba.href = PIPELINE_API_BASE + '/api/pipeline/' + entry.id + '/bundle';
        ba.target = '_blank';
        links.appendChild(ba);
      }
    }
    if (links.childNodes.length) host.appendChild(links);
  }

  function liveDynamicStages() {
    var rows = {};
    pipelineState.stages.forEach(function (s) {
      if (['install', 'launch', 'conn_probe', 'mitm', 'hooks', 'explore',
           'death_probe', 'correlate', 'ai_review', 'report'].indexOf(s.id) >= 0) {
        rows[s.id] = pipelineState.status[s.id] || { status: 'pending' };
      }
    });
    return rows;
  }

  function dynamicStageRows(stageStatus) {
    var rows = {};
    ['install', 'launch', 'conn_probe', 'mitm', 'hooks', 'explore',
     'death_probe', 'correlate', 'ai_review', 'report'].forEach(function (sid) {
      if (stageStatus[sid]) rows[sid] = stageStatus[sid];
    });
    return rows;
  }

  function appendStageStatus(host, rows) {
    var keys = Object.keys(rows);
    if (!keys.length) return;
    var tbl = el('table', 'results-table');
    var thead = el('thead'), hr = el('tr');
    ['阶段', '状态', '信息'].forEach(function (t) { hr.appendChild(el('th', null, t)); });
    thead.appendChild(hr); tbl.appendChild(thead);
    var tbody = el('tbody');
    keys.forEach(function (sid) {
      var st = rows[sid];
      var tr = el('tr');
      tr.appendChild(el('td', null, stageLabel(sid)));
      var cls = st.status === 'done' ? 's-good' : (st.status === 'failed' ? 's-critical'
        : (st.status === 'skipped' ? 's-muted' : 's-warning'));
      tr.appendChild(el('td', null, badge(cls, st.status)));
      tr.appendChild(el('td', 'hint', st.message || ''));
      tbody.appendChild(tr);
    });
    tbl.appendChild(tbody);
    host.appendChild(tbl);
  }

  function stageLabel(sid) {
    var s = pipelineState.stages.find(function (x) { return x.id === sid; });
    return s ? s.label : sid;
  }

  // ---------- AI 报告页（静态综合 + 动态判据摘要） ----------
  function renderAiReport() {
    var host = document.getElementById('ai-report');
    if (window.VScanResults && state.current) { window.VScanResults.renderAI(host, state.current); return; }
    clear(host);
    if (!state.current || !state.current.staticData) {
      host.appendChild(emptyState(EMPTY_SVGS.table, '在一键审计页拖入 APK 后查看综合审计报告'));
      return;
    }
    var s = state.current.staticData || {};
    var apk = s.apk || {};
    var findings = s.findings || [];
    var fin = state.current.fin || {};
    var result = fin.result || {};
    var st = result.static || {};

    var decompile = st.decompile;
    var decompileLabel = decompile
      ? (decompile.classes_written || 0) + ' 个类' + (decompile.errors ? '（' + decompile.errors + ' 个类失败）' : '')
      : ((state.current.tree || []).length
          ? (state.current.tree || []).length + ' 个类（复用缓存产物）'
          : '未反编译');

    addSection(host, '审计概览', [
      ['包名', apk.package || st.package || 'N/A'],
      ['版本', (apk.version_name || '') + '（' + (apk.version_code || '') + '）'],
      ['命中规则', String(findings.length) + ' / ' + (s.rules_evaluated || 0) + ' 条求值'],
      ['反编译', decompileLabel]
    ]);

    if (apk.permissions && apk.permissions.length) {
      var permBox = el('div', 'perm-list');
      apk.permissions.forEach(function (p) { permBox.appendChild(el('div', 'perm-chip mono', p)); });
      var sec = el('div', 'report-section');
      sec.appendChild(el('div', 'report-section-title', '声明权限（' + apk.permissions.length + '）'));
      sec.appendChild(permBox);
      host.appendChild(sec);
    }

    var byType = {};
    findings.forEach(function (f) { byType[f.rule_type] = (byType[f.rule_type] || 0) + 1; });
    var dist = Object.keys(byType).map(function (k) {
      return '<p><b>' + esc(k) + '</b> : ' + byType[k] + ' 条</p>';
    }).join('');
    if (dist) addSectionRaw(host, '风险分布（按规则类型）', dist);

    var v = result.verification;
    if (v) {
      addSectionRaw(host, '动态检测判据',
        '<p><b>结论</b> : ' + (v.passed ? '通过' : '未通过（' + (v.failed || []).join(', ') + '）') + '</p>');
    }
    if (fin.state === 'static_only' && result.device_unavailable) {
      addSectionRaw(host, '已知缺口',
        '<div class="notice bad">设备不可用，动态分析整段跳过：' + esc(result.device_unavailable) + '</div>');
    }

    addSectionRaw(host, '审计建议', '<ul>' +
      '<li>静态结论等级封顶 candidate——代码里出现引用<strong>不证明</strong>运行时行为，违规仍需人工判定。</li>' +
      '<li>逐条确认 manifest 权限必要性；优先核对数据外发与敏感采集相关规则。</li>' +
      '<li>关注动态判据中的失败项——采集缺口会在报告里如实记录。</li>' +
      '</ul>');

    if (s.caveat) host.appendChild(notice(s.caveat));
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

  // ---------- 一键审计流水线 ----------
  function initPipeline() {
    var zone = document.getElementById('pipeline-dropzone');
    var input = document.getElementById('pipeline-apk-input');
    if (!zone || !input) return;

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', function () { zone.classList.remove('dragover'); });
    zone.addEventListener('drop', function (e) {
      e.preventDefault();
      zone.classList.remove('dragover');
      var f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) uploadPipeline(f);
    });
    input.addEventListener('change', function () {
      if (input.files[0]) uploadPipeline(input.files[0]);
      input.value = '';
    });

    loadPipelineStages();
  }

  function loadPipelineStages() {
    fetch(PIPELINE_API_BASE + '/api/stages')
      .then(function (r) { return r.json(); })
      .then(function (list) {
        if(!Array.isArray(list)) throw new Error("不是流水线服务");
        var addr=document.querySelector(".service-addr");if(addr)addr.textContent="已连接 · 127.0.0.1:8771";
        document.querySelector(".status-dot").dataset.online="true";
        pipelineState.stages = list;
        pipelineState.stages.forEach(function (s) {
          pipelineState.status[s.id] = { status: 'pending', message: '' };
        });
        renderPipelineTimeline();
      })
      .catch(function () { var addr=document.querySelector('.service-addr');if(addr)addr.textContent='检测服务未连接';document.querySelector('.status-dot').dataset.online='false'; });
  }

  function uploadPipeline(file) {
    if (!/\.apk$/i.test(file.name)) { alert('只接受 .apk 文件。'); return; }
    resetPipelineResult();
    setPipelineJob('正在上传 ' + file.name + ' …');

    fetch(PIPELINE_API_BASE + '/api/pipeline?name=' + encodeURIComponent(file.name), {
      method: 'POST',
      body: file
    })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { setPipelineJob('上传失败：' + data.error); return; }
        pipelineState.jobId = data.id;
        var entry = { id: data.id, name: data.name || file.name,
                      staticData: null, tree: null, fin: null, stageStatus: null };
        state.current = entry;
        state.history.push(entry);
        renderCurrentApkBar();
        setPipelineJob('任务 ' + data.id + ' · ' + entry.name + '（流水线启动中…）');
        subscribePipeline(data.id);
      })
      .catch(function (err) {
        setPipelineJob('上传失败：' + err + '（一键审计后端 127.0.0.1:8771 是否已启动？）');
      });
  }

  function subscribePipeline(id) {
    if (pipelineState.es) pipelineState.es.close();
    pipelineState.es = new EventSource(PIPELINE_API_BASE + '/api/pipeline/' + id + '/events');

    pipelineState.es.onmessage = function (e) {
      var ev;
      try { ev = JSON.parse(e.data); } catch (err) { return; }
      updatePipelineStage(ev.stage, ev.status, ev.message);
      // 静态剖析一完成就把静态结果 + 源码树拉给各结果页（不等全流程结束）
      if (ev.stage === 'static' && ev.status === 'done' && state.current
          && state.current.id === id) {
        loadPipelineArtifacts(id);
      }
    };

    pipelineState.es.addEventListener('end', function (e) {
      var fin;
      try { fin = JSON.parse(e.data); } catch (err) { return; }
      if (pipelineState.es) pipelineState.es.close();
      onPipelineEnd(id, fin);
    });
  }

  function loadPipelineArtifacts(id) {
    var entry = state.history.find(function (a) { return a.id === id; });
    if (!entry || entry._artLoading) return;
    entry._artLoading = true;
    // 两份产物互不拖累：tree 还没生成时，static 结果也要能显示
    Promise.allSettled([
      fetch(PIPELINE_API_BASE + '/api/pipeline/' + id + '/static').then(function (r) { return r.json(); }),
      fetch(PIPELINE_API_BASE + '/api/pipeline/' + id + '/tree').then(function (r) { return r.json(); })
    ]).then(function (results) {
      var s = results[0].status === 'fulfilled' ? results[0].value : null;
      var tree = results[1].status === 'fulfilled' ? results[1].value : null;
      if (s && !s.error) entry.staticData = s;
      if (Array.isArray(tree)) entry.tree = tree;
      else if (tree && Array.isArray(tree.files)) entry.tree = tree.files;
      entry._artLoading = false;
      if (state.current && state.current.id === id) updateCurrentPage();
    }).catch(function () { entry._artLoading = false; });
  }

  function onPipelineEnd(id, fin) {
    var entry = state.history.find(function (a) { return a.id === id; });
    if (!entry) return;
    entry.fin = fin;
    entry.stageStatus = JSON.parse(JSON.stringify(pipelineState.status));
    loadCheckedAI(entry);
    // 兜底：万一 static done 事件先于订阅到达，这里再拉一次
    if (!entry.staticData) loadPipelineArtifacts(id);
    showPipelineResult(entry, fin);
    renderCurrentApkBar();
    if (state.current && state.current.id === id) updateCurrentPage();
  }

  function updatePipelineStage(stageId, status, message) {
    if (!pipelineState.status[stageId]) return;
    pipelineState.status[stageId] = { status: status, message: message || '' };
    renderPipelineTimeline();
  }

  function renderPipelineTimeline() {
    var host = document.getElementById('pipeline-timeline');
    var area = document.getElementById('pipeline-progress');
    if (!host) return;
    host.textContent = '';
    pipelineState.stages.forEach(function (s) {
      var st = pipelineState.status[s.id] || { status: 'pending', message: '' };
      var li = el('li', 'pl-' + st.status);
      li.appendChild(el('span', 'pl-dot'));
      var body = el('div');
      body.appendChild(el('div', 'pl-label', s.label));
      if (st.message) body.appendChild(el('div', 'pl-msg', st.message));
      li.appendChild(body);
      host.appendChild(li);
    });
    area.style.display = pipelineState.stages.length ? '' : 'none';
  }

  function setPipelineJob(text) {
    document.getElementById('pipeline-job').textContent = text;
    document.getElementById('pipeline-progress').style.display = '';
  }

  function resetPipelineResult() {
    var r = document.getElementById('pipeline-result');
    r.textContent = '';
    r.style.display = 'none';
  }

  function showPipelineResult(entry, fin) {
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
      ra.href = PIPELINE_API_BASE + '/api/pipeline/' + entry.id + '/report';
      ra.target = '_blank';
      navs.appendChild(ra);
    }
    if (result.bundle) {
      var ba = el('a', 'pl-btn', '查看证据包（JSON）');
      ba.href = PIPELINE_API_BASE + '/api/pipeline/' + entry.id + '/bundle';
      ba.target = '_blank';
      navs.appendChild(ba);
    }
    card.appendChild(navs);
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
    dl.appendChild(el('dt', null, k));
    dl.appendChild(el('dd', null, v));
  }

})();

(function () { /* v3 前端补丁：舞台三态 / 进度轨 / 书架；只读现有 DOM，不改既有函数。 */
  var stage = document.getElementById('audit-stage'), prog = document.getElementById('pipeline-progress'),
      res = document.getElementById('pipeline-result'), rail = document.querySelector('[data-rail]'),
      list = document.getElementById('pipeline-timeline'), jobEl = document.getElementById('pipeline-job'), errEl = document.getElementById('upload-error');
  function sync() {
    if (stage && prog && res) {
      var running = prog.style.display !== 'none' && jobEl && jobEl.textContent.trim() !== '', done = res.style.display !== 'none' && res.children.length > 0;
      var failed = !!res.querySelector('.pl-status.failed');
      stage.dataset.state = jobEl && /^上传失败/.test(jobEl.textContent) ? 'idle' : (done ? 'done' : (running ? 'running' : 'idle'));
      var label = stage.querySelector('.done-only'); if(label) label.textContent = failed ? 'AUDIT FAILED' : 'AUDIT COMPLETE';
      if (errEl) errEl.textContent = jobEl && /^上传失败/.test(jobEl.textContent) ? jobEl.textContent : '';
    }
    if (rail && list) {
      var n = list.querySelectorAll('.pl-done, .pl-failed, .pl-skipped, .pl-unavailable').length;
      rail.style.setProperty('--p', n);
      if (rail.parentNode) rail.parentNode.style.setProperty('--p', n);
    }
    if (list) list.scrollTop = list.scrollHeight;
  }
  if (prog && res && window.MutationObserver) {
    var mo = new MutationObserver(sync);
    mo.observe(prog, { attributes: true, attributeFilter: ['style'], childList: true, subtree: true });
    mo.observe(res, { attributes: true, attributeFilter: ['style'], childList: true });
  }
  sync();

})();
