// 仅用于授权测试。筛选与导航只影响视图，不修改内嵌证据。
(function () {
  'use strict';
  var U = window.VSCAN_UI, data = window.VSCAN_DATA;
  var search = document.getElementById('finding-search');
  var type = document.getElementById('finding-type');
  document.getElementById('session-package').textContent = data.meta.package;
  document.getElementById('session-id').textContent = '会话 ' + (data.summary.session_id || '未声明，需复核输入批次');
  document.getElementById('nav-count').textContent = data.findings.length;
  document.getElementById('generated-at').textContent = '生成于 ' + data.meta.generated_at;
  search.addEventListener('input', function () {
    U.state.query = search.value.trim().toLowerCase(); U.renderAll();
  });
  type.addEventListener('change', function () { U.state.type = type.value; U.renderAll(); });
  document.getElementById('reset-filters').addEventListener('click', function () {
    search.value = ''; type.value = ''; U.state.query = ''; U.state.type = '';
    U.state.levels = new Set(U.LEVEL_ORDER); U.renderAll(); search.focus();
  });
  var navigation = document.querySelectorAll('nav a');
  function markActive() {
    var current = location.hash || '#overview';
    navigation.forEach(function (link) {
      if (link.getAttribute('href') === current) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
  }
  window.addEventListener('hashchange', markActive); markActive();
  document.getElementById('print-report').addEventListener('click', function () { window.print(); });
  var folded = [], theme;
  window.addEventListener('beforeprint', function () {
    folded = Array.from(document.querySelectorAll('details:not([open])'));
    folded.forEach(function (d) { d.open = true; });
    theme = document.documentElement.dataset.theme;
    document.documentElement.dataset.theme = 'light';
  });
  window.addEventListener('afterprint', function () {
    folded.forEach(function (d) { d.open = false; });
    document.documentElement.dataset.theme = theme;
  });
})();
