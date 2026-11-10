/* B 档上传前校验清单：逐项对照 vehicle/webapp 的实际接受条件。
   前端不重复做 APK 容器 / AndroidManifest 校验，也不添加比后端更严或更松的门槛。 */
(function () {
  'use strict';
  const U = window.VehicleUI;
  const LIMIT = 512 * 1024 * 1024;
  const MODE = {static: '仅静态分析', replay: '重放已有采集', live: '新建 AAOS 采集'};
  const MARK = {pass: '✓', fail: '✕', skip: '–', info: 'i'};
  function row(label, state, detail) { return {label: label, state: state, detail: detail}; }
  function asInt(raw) {
    const text = String(raw === undefined || raw === null ? '' : raw).trim();
    return /^[+-]?\d+$/.test(text) ? Number(text) : null;
  }
  function paramRows(ctx) {
    const rows = [row('审计方式', 'info', MODE[ctx.mode] || String(ctx.mode || '未选择'))];
    rows.push(row('授权声明', ctx.authorized ? 'pass' : 'fail',
      ctx.authorized ? '已勾选' : '未勾选；服务端 options() 会以 authorization_required 拒绝上传。'));
    if (ctx.mode === 'replay') {
      rows.push(row('采集会话', ctx.capture ? 'pass' : 'fail',
        ctx.capture ? '已选择会话：' + ctx.capture : '未选择；服务端会以 unknown_capture 拒绝。'));
    }
    if (ctx.mode === 'live') {
      const serialOk = /^[A-Za-z0-9_.:-]{1,100}$/.test(String(ctx.serial || ''));
      rows.push(row('设备序列号', serialOk ? 'pass' : 'fail',
        serialOk ? String(ctx.serial) : '须为 1–100 位字母、数字或 _ . : -；与后端正则一致。'));
      const user = asInt(ctx.user);
      rows.push(row('用户编号', user !== null && user >= 0 ? 'pass' : 'fail',
        user !== null && user >= 0 ? 'user ' + user : '须为非负整数；后端按 int() 解析后要求 ≥ 0。'));
      const seconds = asInt(ctx.seconds);
      const secondsOk = seconds !== null && seconds >= 5 && seconds <= 300;
      rows.push(row('采集秒数', secondsOk ? 'pass' : 'fail',
        secondsOk ? seconds + ' 秒' : '须为 5–300 的整数秒；与后端范围一致。'));
    }
    return rows;
  }
  function extRow(file) {
    const ok = /\.apk$/i.test(file.name);
    return row('文件类型', ok ? 'pass' : 'fail',
      ok ? file.name : '扩展名不是 .apk；服务端只接受 .apk 文件名。');
  }
  function humanSize(size) {
    if (size < 1024) return size + ' B';
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + ' KiB';
    return (size / 1024 / 1024).toFixed(2) + ' MiB';
  }
  function sizeRow(file) {
    const size = Number(file.size);
    const ok = size > 0 && size <= LIMIT;
    return row('文件大小', ok ? 'pass' : 'fail',
      ok ? humanSize(size) + '（上限 512 MiB）' : (size === 0 ? '文件为空；服务端要求 Content-Length > 0。' :
        humanSize(size) + '，超过服务端 512 MiB 上限。'));
  }
  async function readableRow(file) {
    try {
      const head = await file.slice(0, 4).arrayBuffer();
      return head.byteLength > 0 ? row('文件可读性', 'pass', '可读取文件头 4 字节')
        : row('文件可读性', 'fail', '读取到 0 字节；文件可能已被移动或没有读取权限。');
    } catch (error) {
      return row('文件可读性', 'fail', '读取失败：' + (error && error.message ? error.message : '未知原因'));
    }
  }
  U.validateUpload = async function (ctx) {
    const rows = paramRows(ctx);
    if (!ctx.file) return rows.concat([row('APK 文件', 'fail', '尚未选择文件。')]);
    rows.push(extRow(ctx.file), sizeRow(ctx.file), await readableRow(ctx.file),
      row('APK 容器', 'info',
        'ZIP 结构与 AndroidManifest.xml 由服务端 upload() 校验；前端不重复判断，避免比后端更严或更松。'));
    return rows;
  };
  U.checksPassed = function (rows) { return rows.every(item => item.state !== 'fail'); };
  U.renderChecks = function (host, rows, note) {
    host.replaceChildren();
    if (!rows || !rows.length) return;
    const box = U.node('section', 'upload-checks');
    box.append(U.node('p', 'upload-checks__title', '上传前校验 · 与后端接受条件一致'));
    rows.forEach(item => {
      const line = U.node('div', 'check-row');
      line.dataset.state = item.state;
      line.append(U.node('span', 'check-mark', MARK[item.state] || '·'),
        U.node('span', 'check-label', item.label),
        U.node('span', 'check-detail', item.detail));
      box.append(line);
    });
    const failed = rows.filter(item => item.state === 'fail').length;
    box.append(U.node('p', 'upload-checks__foot', note || (failed
      ? '共 ' + failed + ' 项不合格；修正后重新选择文件，不会发起上传。'
      : '前置校验通过。')));
    host.append(box);
  };
}());
