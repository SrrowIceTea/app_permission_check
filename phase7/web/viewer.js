/* 文件树 + 源码查看。按需拉单个文件——大 APK 有上万文件、几百 MB，
   一次全灌进浏览器会把页面和服务端一起拖死。

   全部用 textContent，零 innerHTML（D603）。路径来自服务端返回的相对路径，
   在这里只当**文本**用，绝不拼进选择器或 HTML。 */
(function () {
  'use strict';

  var state = { digest: null, files: [], current: null };

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function renderTree(filter) {
    var host = document.getElementById('tree');
    if (!host) return;
    host.textContent = '';
    var needle = (filter || '').toLowerCase();
    var shown = 0;
    state.files.forEach(function (file) {
      if (needle && file.path.toLowerCase().indexOf(needle) === -1) return;
      if (shown >= 600) return;                 // 只渲染前 600 条，其余靠过滤
      shown++;
      var button = el('button', null, file.path);
      button.type = 'button';
      button.setAttribute('aria-current', String(file.path === state.current));
      button.addEventListener('click', function () { open(file.path); });
      host.appendChild(button);
    });
    if (!shown) host.appendChild(el('div', 'hint', '没有匹配的文件'));
    if (shown >= 600) host.appendChild(el('div', 'hint', '仅显示前 600 条，请用过滤缩小范围'));
  }

  function open(path) {
    state.current = path;
    renderTree(document.getElementById('filter').value);
    var codeEl = document.querySelector('#code code');
    var meta = document.getElementById('source-meta');
    meta.textContent = '载入中 ' + path;
    fetch('/api/apk/' + state.digest + '/source?path=' + encodeURIComponent(path))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        if (data.error) { meta.textContent = '读取失败：' + data.error; return; }
        window.VSCAN_HL.render(codeEl, data.text);
        meta.textContent = data.path + '  ·  ' + data.size + ' 字节'
          + (data.truncated ? '（已截断）' : '');
      })
      .catch(function (err) { meta.textContent = '读取失败：' + err; });
  }

  function load(digest) {
    state.digest = digest;
    state.current = null;
    document.querySelector('#code code').textContent = '';
    fetch('/api/apk/' + digest + '/tree')
      .then(function (r) { return r.json(); })
      .then(function (data) {
        state.files = data.files || [];
        document.getElementById('source-meta').textContent =
          state.files.length + ' 个 .java' + (state.files.length ? '' : '（可能还在反编译，或全部失败）');
        renderTree('');
      });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var filter = document.getElementById('filter');
    if (filter) filter.addEventListener('input', function () { renderTree(filter.value); });
  });

  window.VSCAN_VIEWER = { load: load, open: open };
})();
