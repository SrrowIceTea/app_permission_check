(function () {
  'use strict';
  var screen = document.getElementById('afterScreen');
  var copyHint = document.createElement('p');
  copyHint.setAttribute('role', 'status');
  copyHint.setAttribute('aria-live', 'polite');
  copyHint.style.cssText = 'position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)';
  document.body.appendChild(copyHint);

  // 主题与状态只作用于“改后”一栏，改前保持现状。
  function setTheme(value) {
    screen.setAttribute('data-theme', value);
    document.querySelectorAll('[data-theme-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.themeSet === value));
    });
  }
  function setState(value) {
    screen.setAttribute('data-state', value);
    document.querySelectorAll('[data-state-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.dataset.stateSet === value));
    });
  }
  document.querySelectorAll('[data-theme-set]').forEach(function (btn) {
    btn.addEventListener('click', function () { setTheme(btn.dataset.themeSet); });
  });
  document.querySelectorAll('[data-state-set]').forEach(function (btn) {
    btn.addEventListener('click', function () { setState(btn.dataset.stateSet); });
  });
  // 便于截图与评审直达：compare.html?theme=light&state=fail
  var params = new URLSearchParams(location.search);
  if (params.get('theme')) setTheme(params.get('theme'));
  if (params.get('state')) setState(params.get('state'));

  // 复制：127.0.0.1 下用 Clipboard API；file:// 或旧环境下回退到临时 textarea。
  function fallback(text) {
    var area = document.createElement('textarea');
    area.value = text;
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.appendChild(area);
    area.select();
    try { document.execCommand('copy'); } catch (e) { /* 无剪贴板权限时静默 */ }
    document.body.removeChild(area);
  }
  document.querySelectorAll('[data-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var text = btn.getAttribute('data-copy');
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).catch(function () { fallback(text); });
      } else {
        fallback(text);
      }
      btn.setAttribute('data-copied', '1');
      copyHint.textContent = '已复制：' + text;
      setTimeout(function () { btn.removeAttribute('data-copied'); }, 1200);
    });
  });

  // 结论筛选：chips + 搜索只影响“完成”态的卡片列表，纯前端演示。
  var cards = Array.prototype.slice.call(document.querySelectorAll('.a-list .finding'));
  var chips = Array.prototype.slice.call(document.querySelectorAll('.chip'));
  var search = document.querySelector('.a-search');
  var level = 'all';
  function applyFilter() {
    var q = (search && search.value || '').trim().toLowerCase();
    cards.forEach(function (card) {
      var okLevel = level === 'all' || card.dataset.level === level;
      var okText = !q || card.innerText.toLowerCase().indexOf(q) !== -1;
      card.style.display = okLevel && okText ? '' : 'none';
    });
  }
  chips.forEach(function (chip) {
    chip.addEventListener('click', function () {
      level = chip.dataset.filter || 'all';
      chips.forEach(function (c) { c.classList.toggle('chip--on', c === chip); });
      applyFilter();
    });
  });
  if (search) search.addEventListener('input', applyFilter);
})();
