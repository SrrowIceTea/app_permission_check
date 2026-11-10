// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 6 — 预警看板各区块的渲染。
//
// 数据全部经 textContent 写入 DOM（结论里的包名、权限名、文件路径都是**不可信数据**），
// 本文件里没有任何 innerHTML 赋值。看板是静态页，不发起网络请求。
// 常量表与 DOM 小工具在 ui.js（window.VSCAN_UI）。
// ============================================================================
'use strict';
(function () {
  var DATA = window.VSCAN_DATA;
  var U = window.VSCAN_UI;
  if (!DATA || !U) return;
  var LEVELS = U.LEVELS, LEVEL_ORDER = U.LEVEL_ORDER, TYPE_LABEL = U.TYPE_LABEL,
      SEV_LABEL = U.SEV_LABEL, SEV_ORDER = U.SEV_ORDER, LOC_ROLE = U.LOC_ROLE, DEX = U.DEX,
      state = U.state, el = U.el, badge = U.badge, tipRow = U.tipRow, bindTip = U.bindTip;

  function sortedFindings() {
    return DATA.findings.slice().sort(function (a, b) {
      var dl = LEVEL_ORDER.indexOf(a.conclusion_level) - LEVEL_ORDER.indexOf(b.conclusion_level);
      if (dl !== 0) return dl;
      var ds = SEV_ORDER[a.severity || 'unrated'] - SEV_ORDER[b.severity || 'unrated'];
      if (ds !== 0) return ds;
      return String(a.rule_id).localeCompare(String(b.rule_id));
    });
  }
  function slice() {
    return sortedFindings().filter(function (f) { return U.matchesFinding(f); });
  }

  function renderMeta() {
    var row = document.getElementById('meta-row');
    row.textContent = '';
    var chips = [
      ['系统版本', DATA.meta.android_version],
      ['规则库版本', (DATA.meta.rule_versions || []).join(', ')],
      ['规则库 SHA-256', DATA.meta.rules_sha256 ? DATA.meta.rules_sha256.slice(0, 16) + '…' : '未提供'],
      ['规则总数 / 已启用', DATA.meta.rules_total + ' / ' + DATA.meta.rules_enabled],
      ['输入规模', '读取 ' + DATA.meta.inputs.reads + ' · 出站 ' + DATA.meta.inputs.egress_connections +
                   ' · 流 ' + DATA.meta.inputs.proxy_flows +
                   ' · 清单权限 ' + DATA.meta.inputs.requested_permissions],
    ];
    chips.push(['隐私观测', '不在本页 · 见同轮 PDF 第七节或工作台动态审计页']);
    chips.forEach(function (pair) {
      var c = el('span', 'meta-chip');
      c.appendChild(el('b', null, pair[0] + ' '));
      c.appendChild(document.createTextNode(pair[1]));
      row.appendChild(c);
    });
  }

  function renderFilters() {
    var row = document.getElementById('filter-row');
    row.textContent = '';
    row.appendChild(el('span', 'filter-label', '结论等级'));
    var counts = {};
    DATA.findings.forEach(function (f) { counts[f.conclusion_level] = (counts[f.conclusion_level] || 0) + 1; });
    LEVEL_ORDER.forEach(function (lv) {
      var b = el('button', 'chip', LEVELS[lv].icon + ' ' + LEVELS[lv].label + ' ' + (counts[lv] || 0));
      b.type = 'button';
      b.setAttribute('aria-pressed', String(state.levels.has(lv)));
      b.dataset.level = lv;
      b.classList.add(state.levels.has(lv) ? 'on' : 'off');
      b.addEventListener('click', function () {
        if (state.levels.has(lv)) { state.levels.delete(lv); } else { state.levels.add(lv); }
        renderAll();
        row.querySelector('[data-level=' + lv + ']').focus();
      });
      row.appendChild(b);
    });
  }

  function renderKpi() {
    var row = document.getElementById('kpi-row');
    row.textContent = '';
    var counts = {};
    DATA.findings.forEach(function (f) { counts[f.conclusion_level] = (counts[f.conclusion_level] || 0) + 1; });
    var tiles = [['结论总数', DATA.findings.length, DATA.meta.package + ' · ' + DATA.meta.rule_versions.join(', '), null]];
    LEVEL_ORDER.forEach(function (lv) { tiles.push([LEVELS[lv].label, counts[lv] || 0, LEVELS[lv].sub, lv]); });
    tiles.forEach(function (t) {
      var tile = el('div', 'tile' + (t[3] && !state.levels.has(t[3]) ? ' ghosted' : ''));
      tile.appendChild(el('div', 'label', t[0]));
      tile.appendChild(el('div', 'value', t[1]));
      tile.appendChild(el('div', 'sub', t[2]));
      row.appendChild(tile);
    });
  }

  function renderDist() {
    var chart = document.getElementById('dist-chart');
    var legend = document.getElementById('dist-legend');
    chart.textContent = '';
    legend.textContent = '';
    var counts = {};
    var total = 0;
    DATA.findings.forEach(function (f) { counts[f.conclusion_level] = (counts[f.conclusion_level] || 0) + 1; total++; });
    if (!total) { chart.appendChild(el('div', 'empty-note', '本轮无结论')); return; }
    LEVEL_ORDER.forEach(function (lv) {
      var n = counts[lv] || 0;
      if (!n) return;
      var seg = el('div', 'dist-seg ' + LEVELS[lv].status + (!state.levels.has(lv) ? ' ghost' : ''));
      seg.style.width = (n / total * 100) + '%';
      seg.style.backgroundColor = 'var(--status-' + LEVELS[lv].status.slice(2) + ')';
      if (n / total * 100 >= 14) {
        // 段内标签按填充亮度取白或黑（palette.md 的唯一例外条款）：
        // critical 红上必须用白，serious/warning 浅色上用黑
        var lb = el('span', 'in-label', n);
        lb.style.color = (lv === 'correlated') ? '#ffffff' : '#0b0b0b';
        seg.appendChild(lb);
      }
      seg.setAttribute('aria-label', LEVELS[lv].label + ' ' + n + ' 条');
      bindTip(seg, function () { return [tipRow(LEVELS[lv].label + '（共 ' + total + ' 条）', String(n) + ' 条')]; });
      chart.appendChild(seg);
      var item = el('div', 'legend-item' + (!state.levels.has(lv) ? ' ghost' : ''));
      item.appendChild(el('span', 'swatch', null));
      item.querySelector('.swatch').style.background = 'var(--status-' + LEVELS[lv].status.slice(2) + ')';
      item.appendChild(el('span', null, LEVELS[lv].icon + ' ' + LEVELS[lv].label + ' ' + n + ' 条'));
      legend.appendChild(item);
    });
  }

  function renderChains() {
    var card = document.getElementById('chain-card');
    var list = document.getElementById('chain-list');
    list.textContent = '';
    var chains = slice().filter(function (f) { return f.rule_type === 'data_egress'; });
    card.hidden = false;
    if (!chains.length) list.appendChild(el('p', 'empty-note', '当前筛选下没有读取与外发配对。可重置筛选，或检查本轮采集证据。'));
    chains.forEach(function (f) {
      var item = el('div', 'chain-item');
      var head = el('div', 'chain-head');
      head.appendChild(el('b', null, f.rule_id));
      head.appendChild(el('span', 'muted small', ' · ' + TYPE_LABEL[f.rule_type] +
        ' · ' + (f.property || f.permission || '') +
        ' · 严重度 ' + (SEV_LABEL[f.severity] || f.severity)));
      if (!f.rule_enabled) head.appendChild(badge('s-muted', '⚪', '规则未启用（草案）', 'small'));
      head.appendChild(document.createTextNode(' '));
      head.appendChild(badge(LEVELS[f.conclusion_level].status, LEVELS[f.conclusion_level].icon,
                             LEVELS[f.conclusion_level].label, 'small'));
      item.appendChild(head);
      (f.pairs || []).forEach(function (p) {
        var row = el('div', 'pair-row');
        var win = f.window_ms || 1;
        var label = el('div', 'pair-label');
        label.appendChild(el('span', null, '读取 #' + p.read_event_id + ' → 流 #' + p.flow_event_id));
        label.appendChild(el('span', 'ok', (p.content_match ? '✓' : '✗') + ' 内容匹配 ' + (p.content_match ? '是' : '否')));
        label.appendChild(el('span', null, 'TLS 拦截 ' + (p.client_tls ? '是' : '否')));
        row.appendChild(label);
        var meter = el('div', 'meter');
        meter.setAttribute('role', 'img');
        meter.setAttribute('aria-label', '外发间隔 ' + p.delta_ms + ' 毫秒，时间窗 ' + win + ' 毫秒');
        var fill = el('div', 'fill');
        fill.style.width = Math.min(p.delta_ms / win * 100, 100) + '%';
        meter.appendChild(fill);
        if (p.delta_ms / win * 100 >= 12) {
          var tipEl = el('span', 'tip', p.delta_ms + ' ms');
          tipEl.style.left = Math.min(p.delta_ms / win * 100, 100) + '%';
          meter.appendChild(tipEl);
        }
        bindTip(meter, function () {
          return [tipRow(p.delta_ms + ' ms', '读取 #' + p.read_event_id + ' → 流 #' + p.flow_event_id),
                  tipRow(p.content_match ? '是' : '否', '内容匹配'),
                  tipRow(p.client_tls ? '是' : '否', 'TLS 拦截'),
                  tipRow(p.flow_method + ' ' + p.flow_host + p.flow_path, '目标')];
        });
        row.appendChild(meter);
        var meta = el('div', 'pair-meta');
        meta.textContent = '时间窗 ' + win + ' ms' +
          (f.window_overridden ? '（规则声明 ' + f.window_declared_ms + ' ms，分析时用实测校准值覆盖）' : '');
        row.appendChild(meta);
        item.appendChild(row);
      });
      list.appendChild(item);
    });
  }

  function renderBoundary() {
    var list = document.getElementById('boundary-list');
    list.textContent = '';
    var bullets = [];
    if (DATA.summary.caveat) bullets.push(DATA.summary.caveat);
    if (DATA.verify && DATA.verify.caveat) bullets.push('代码位置核对：' + DATA.verify.caveat);
    bullets = bullets.concat([
      '本看板不含通用隐私来源的观测结果（位置/麦克风/联系人/Android ID/广告标识的已观测、' +
        '仅注册未取值、有读取但未取到值、未观测）。这一节只在同轮 PDF 报告《七、车载场景与证据覆盖》' +
        '与工作台「动态审计」页给出；未观测不等于未采集，也不代表安全。',
      '时间相邻本身不构成外泄证据；只有 content_match 为真，才说明外发报文中确实出现了被读取的属性。',
      '包名归因依赖时间配对（容差2000ms、亚军距离500ms、等待3000ms）；歧义流不参与关联，仍有统计误差。',
      '覆盖限于已挂钩Java路径；native TLS、Cronet、MQTT、QUIC与未解析gRPC消息不在明文验证范围。',
      '代码位置 ≠ 违规判定：dex 核对只证明该行号属于该方法，不证明该行就是违规语义所在。',
      '本看板不产出 policy_violation。是否构成违规是政策判定，需人工完成。',
    ]);
    bullets.forEach(function (b) { list.appendChild(el('div', null, '· ' + b)); });
  }

  function renderAll() {
    renderFilters();
    renderKpi();
    renderDist();
    renderChains();
    U.renderFindings(slice());
  }

  U.renderAll = renderAll;
  renderMeta();
  renderAll();
  renderBoundary();

  var toggle = document.getElementById('theme-toggle');
  function effDark() {
    var root = document.documentElement;
    return root.dataset.theme === 'dark' ||
      (!root.dataset.theme && window.matchMedia &&
       window.matchMedia('(prefers-color-scheme: dark)').matches);
  }
  // 按钮显示的是**当前**深浅，点击切到另一套（显式 data-theme 压过系统偏好）
  toggle.textContent = effDark() ? '浅色' : '深色';
  toggle.addEventListener('click', function () {
    var root = document.documentElement;
    if (effDark()) { root.dataset.theme = 'light'; toggle.textContent = '深色'; }
    else { root.dataset.theme = 'dark'; toggle.textContent = '浅色'; }
  });
})();
