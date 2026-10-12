// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 6 — 看板的常量表与 DOM 小工具。
//
// 从 render.js 拆出来是因为它贴着 300 行的单文件上限。这半边是**静态配置**
// （等级/类型/严重度的中文标签、状态色映射）和**与数据无关的 DOM 工具**
// （建元素、徽章、悬浮提示）；render.js 那半边是"每个区块画什么"。
// 两块改动的理由不同：换文案不动渲染，改渲染不动文案。
//
// 通过 window.VSCAN_UI 共享：内嵌脚本用经典 IIFE，不用 ES module——
// Chrome 禁止从 file:// 加载 module 文件，看板必须双击即开。
// ============================================================================
'use strict';
(function () {
  var LEVELS = {
    correlated: { label: '已关联', icon: '●', status: 's-critical',
                  sub: '读取与外发在时间窗内，且内容匹配' },
    observed: { label: '已观测', icon: '▲', status: 's-serious',
                sub: '读取事实成立' },
    candidate: { label: '候选', icon: '⚠', status: 's-warning',
                 sub: '需人工复核' },
  };
  var LEVEL_ORDER = ['correlated', 'observed', 'candidate'];
  var TYPE_LABEL = { over_permission: '过度索权', sensitive_read: '敏感读取', data_egress: '数据外发' };
  var SEV_LABEL = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息', unrated: '未评级' };
  var SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unrated: 5 };
  var LOC_ROLE = { read: '读取处', egress: '外发处' };
  var DEX = {
    VERIFIED: { label: 'dex 已核对', status: 's-good' },
    LINE_NOT_IN_METHOD: { label: '行号不在该方法', status: 's-warning' },
    METHOD_NOT_FOUND: { label: '方法不存在', status: 's-warning' },
    CLASS_NOT_FOUND: { label: '类不存在', status: 's-warning' },
    DEX_UNAVAILABLE: { label: '未核对', status: 's-muted' },
    INCOMPLETE: { label: '无源码行号', status: 's-warning' },
  };

  var state = { levels: new Set(LEVEL_ORDER), query: '', type: '' };
  function matchesFinding(f) {
    var haystack = [f.rule_id, f.permission, f.property, f.note, JSON.stringify(f.code_locs || [])].join(' ').toLowerCase();
    return state.levels.has(f.conclusion_level) && (!state.type || state.type === f.rule_type) &&
      (!state.query || haystack.includes(state.query));
  }

  var tip = document.createElement('div');
  tip.className = 'tooltip';
  document.body.appendChild(tip);

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = String(text);
    return n;
  }
  function badge(status, icon, label, extraCls) {
    var b = el('span', 'badge ' + status + (extraCls ? ' ' + extraCls : ''));
    if (icon) b.appendChild(el('span', null, icon));
    b.appendChild(el('span', null, label));
    return b;
  }
  function tipRow(name, value) {
    var d = el('div');
    d.appendChild(el('div', 'tt-val', value));
    d.appendChild(el('div', 'tt-name', name));
    return d;
  }
  function showTip(htmlNodes, x, y) {
    tip.textContent = '';
    htmlNodes.forEach(function (n) { tip.appendChild(n); });
    tip.style.display = 'block';
    var w = tip.offsetWidth, h = tip.offsetHeight;
    tip.style.left = Math.min(x + 14, window.innerWidth - w - 8) + 'px';
    tip.style.top = Math.min(y + 14, window.innerHeight - h - 8) + 'px';
  }
  function hideTip() { tip.style.display = 'none'; }
  function bindTip(node, nodesBuilder) {
    node.addEventListener('pointermove', function (e) { showTip(nodesBuilder(), e.clientX, e.clientY); });
    node.addEventListener('pointerleave', hideTip);
    node.tabIndex = 0;
    node.addEventListener('focus', function () {
      var r = node.getBoundingClientRect();
      showTip(nodesBuilder(), r.left, r.bottom);
    });
    node.addEventListener('blur', hideTip);
  }

  window.VSCAN_UI = {
    LEVELS: LEVELS, LEVEL_ORDER: LEVEL_ORDER, TYPE_LABEL: TYPE_LABEL,
    SEV_LABEL: SEV_LABEL, SEV_ORDER: SEV_ORDER, LOC_ROLE: LOC_ROLE, DEX: DEX,
    state: state, matchesFinding: matchesFinding,
    el: el, badge: badge, tipRow: tipRow, showTip: showTip, hideTip: hideTip,
    bindTip: bindTip,
  };
})();
