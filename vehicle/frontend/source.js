/* Source viewer uses the same audited core/static source path boundary. */
(function () {
  'use strict';
  const U = window.VehicleUI;
  let sourceRequest = 0, treeRequest = 0;
  U.source = async function (job) {
    const request = ++treeRequest;
    ++sourceRequest;
    const tree = document.getElementById('file-tree');
    const data = await U.get('/api/pipeline/' + job.id + '/tree');
    if (U.current !== job.id || request !== treeRequest) return;
    const filter = document.getElementById('source-filter').value.toLowerCase();
    const files = data.filter(row => row.path.toLowerCase().includes(filter));
    tree.replaceChildren();
    for (const file of files.slice(0, 2000)) {
      const button = U.node('button', 'file-tree-item', file.path);
      button.onclick = async function () {
        const selectedRequest = ++sourceRequest;
        const host = document.getElementById('code-view');
        tree.querySelectorAll('button').forEach(n => n.classList.toggle('active', n === button));
        try {
          const result = await U.get('/api/pipeline/' + job.id + '/source?path=' + encodeURIComponent(file.path));
          if (U.current !== job.id || selectedRequest !== sourceRequest) return;
          host.replaceChildren(U.node('p', 'code-meta', result.path + (result.truncated ? '（内容已截断）' : '')));
          const code = U.node('pre', 'code-content');
          // The highlighter returns safe DOM nodes and never writes APK text as HTML.
          if (window.VSCAN_HL) window.VSCAN_HL.render(code, result.text);
          else code.textContent = result.text;
          host.append(code);
        } catch (error) {
          if (U.current === job.id && selectedRequest === sourceRequest) U.empty(host, error.message);
        }
      };
      tree.append(button);
    }
    if (!files.length) U.empty(tree, data.length ? '没有符合筛选的文件。' : '源码尚未就绪；请查看反编译阶段及覆盖缺口。');
    if (files.length > 2000) tree.prepend(U.node('p', 'hint', '当前显示前 2000 项，请输入路径缩小范围。'));
  };
}());
