/* Upload settings and task progress for the authorized AAOS workbench. */
(function () {
  'use strict';
  const VS = window.VS;
  const $ = (selector) => document.querySelector(selector);
  const dropzone = $('#dz');
  const fileInput = $('#file');
  const capture = $('#replayCapture');
  const deviceSelect = $('#deviceSerial');
  const deviceStatus = $('#deviceStatus');
  const deviceRefresh = $('#refreshDevices');
  const devices = new Map();
  let mode = 'static', version = '15', busy = false;

  function message(text) {
    $('#dzName').textContent = text;
    $('#dzFile').classList.add('show');
    $('#dzBar').style.width = '0';
    $('#dzPct').textContent = '—';
  }

  function settings(file) {
    const query = new URLSearchParams({ name: file.name, mode, version, authorized: 'true' });
    if (mode === 'replay') {
      if (capture.disabled || !capture.value) throw new Error('请先选择已登记的采集会话');
      query.set('capture', capture.value);
    } else if (mode === 'live') {
      const selected = devices.get(deviceSelect.value);
      if (!selected || deviceSelect.disabled) {
        deviceSelect.focus();
        throw new Error('请先刷新并选择在线 AAOS 设备');
      }
      const user = $('#deviceUser'), seconds = $('#deviceSeconds');
      if (!user.reportValidity() || !seconds.reportValidity()) {
        throw new Error('请检查用户编号和采集时长');
      }
      query.set('serial', selected.serial);
      query.set('version', selected.version);
      query.set('user', user.value);
      query.set('seconds', seconds.value);
      query.set('auto_explore', String($('#autoExplore').checked));
      query.set('scope', selected.version === '15' ? 'all' : 'general');
      query.set('tls_bypass', 'false');
    }
    return query;
  }

  function locked(value) {
    busy = value;
    VS.attachments.lock(value);
    dropzone.setAttribute('aria-disabled', String(value));
    fileInput.disabled = value;
    $('#startBtn').disabled = value;
  }

  async function upload(file) {
    if (!file || busy) return;
    if (!/\.apk$/i.test(file.name)) { message('只接受 .apk 文件'); return; }
    if (!$('#auth').checked) { message('请先勾选授权声明'); return; }
    let query;
    try { query = settings(file); }
    catch (error) { message(error.message); return; }
    locked(true);
    $('#dzName').textContent = file.name + ' · ' + (file.size / 1048576).toFixed(1) + ' MB';
    $('#dzFile').classList.add('show');
    $('#dzBar').style.width = '100%';
    $('#dzPct').textContent = '上传中';
    try {
      if (query.get('mode') !== 'static') {
        const material = await VS.attachments.submit();
        if (material) query.set('attachment_id', material.id);
      }
      const job = await VS.api('/api/pipeline?' + query, {
        method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: file,
      });
      if (query.get('mode') !== 'static') VS.attachments.reset();
      $('#dzPct').textContent = '已提交';
      VS.followJob(job.id, {
        onTerminal: (finished) => {
          locked(false);
          if (mode === 'replay' && finished.state === 'done' && finished.options?.mode === 'live') refreshCaptures();
          const error = finished.result?.error;
          if (error) message(['审计失败：' + error.message, error.next_action].filter(Boolean).join(' '));
          $('#dzPct').textContent = finished.state === 'failed' ? '失败' : '完成';
        },
        onReconnect: () => { $('#dzPct').textContent = '等待重连'; },
      });
    } catch (error) {
      locked(false);
      message(['提交失败：' + error.message, error.nextAction].filter(Boolean).join(' '));
    }
  }

  function paintVersion() {
    const live = mode === 'live';
    const selected = live ? devices.get(deviceSelect.value)?.version : version;
    $('#sdkOut').textContent = selected ? 'Android ' + selected : '选择在线设备后确定';
    document.querySelectorAll('[data-seg="sdk"] button').forEach((item) => {
      item.classList.toggle('is-on', item.dataset.v === selected);
      item.disabled = live;
    });
  }

  async function refreshCaptures() {
    if (capture.disabled) return;
    const previous = capture.value;
    capture.disabled = true;
    capture.replaceChildren(new Option('正在读取采集会话…', ''));
    try {
      const { captures = [] } = await VS.api('/api/config');
      capture.options[0].textContent = captures.length ? '请选择采集会话' : '暂无已完成的健康采集';
      captures.forEach((row) => capture.add(new Option(`${row.label} · ${row.session}`, row.id)));
      if (captures.some((row) => row.id === previous)) capture.value = previous;
    } catch (error) {
      capture.options[0].textContent = '读取失败，点击「采集回放」重试';
    } finally {
      capture.disabled = false;
    }
  }

  async function refreshDevices() {
    const previous = deviceSelect.value;
    deviceSelect.disabled = deviceRefresh.disabled = true;
    deviceStatus.textContent = '正在读取在线设备…';
    deviceSelect.replaceChildren(new Option('请选择 AAOS 设备', ''));
    devices.clear();
    try {
      const inventory = await VS.api('/api/live-devices');
      for (const device of inventory.devices) {
        devices.set(device.serial, device);
        deviceSelect.add(new Option(`${device.serial} · Android ${device.version} / API ${device.api}`, device.serial));
      }
      if (devices.has(previous)) deviceSelect.value = previous;
      deviceStatus.textContent = devices.size
        ? '选择设备后同步 Android 版本和当前用户。请上传与装机版本完全相同的 APK。'
        : '未找到可用的在线 AAOS 设备。启动或连接授权设备后刷新。';
    } catch (error) {
      deviceStatus.textContent = [error.message, error.nextAction].filter(Boolean).join(' ');
    } finally {
      deviceSelect.disabled = deviceRefresh.disabled = false;
      paintVersion();
    }
  }

  deviceRefresh.addEventListener('click', refreshDevices);
  deviceSelect.addEventListener('change', () => {
    const device = devices.get(deviceSelect.value);
    if (device) $('#deviceUser').value = device.user;
    paintVersion();
  });

  VS.on('config', (config) => {
    const button = Array.from(document.querySelectorAll('[data-seg="sdk"] button'))
      .find((item) => item.dataset.v === String(config.version));
    if (button) version = button.dataset.v;
    paintVersion();
  });

  $('[data-seg="sdk"]').addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (button && mode !== 'live') {
      version = button.dataset.v;
      paintVersion();
    }
  });
  $('[data-seg="mode"]').addEventListener('click', (event) => {
    const button = event.target.closest('button');
    if (!button) return;
    mode = button.dataset.v;
    document.querySelectorAll('[data-seg="mode"] button').forEach((item) => {
      item.classList.toggle('is-on', item === button);
    });
    $('#modeOut').textContent = button.textContent;
    $('#replayOptions').hidden = mode !== 'replay';
    $('#liveOptions').hidden = mode !== 'live';
    VS.attachments.setMode(mode);
    paintVersion();
    if (mode === 'live' && !deviceRefresh.disabled) refreshDevices();
    if (mode === 'replay') refreshCaptures();
  });

  dropzone.addEventListener('click', () => fileInput.click());
  dropzone.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); fileInput.click(); }
  });
  ['dragenter', 'dragover'].forEach((type) => dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    if (!busy) dropzone.classList.add('is-drag');
  }));
  ['dragleave', 'drop'].forEach((type) => dropzone.addEventListener(type, (event) => {
    event.preventDefault();
    dropzone.classList.remove('is-drag');
  }));
  dropzone.addEventListener('drop', (event) => upload(event.dataTransfer.files[0]));
  fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    fileInput.value = '';
    upload(file);
  });
  $('#startBtn').addEventListener('click', () => {
    dropzone.scrollIntoView({ behavior: 'smooth', block: 'center' });
    fileInput.click();
  });
}());
