// 只读静态展示，所有外部内容用 textContent；不发起网络请求。
(function () {
  'use strict';
  const data = window.VSCAN_DATA;
  const summary = data.summary || {};
  const section = document.createElement('section');
  section.className = 'card coverage-card';
  section.id = 'coverage-card';
  const title = document.createElement('h2');
  title.textContent = '规则覆盖与时间基准';
  section.appendChild(title);
  const coverage = summary.coverage || {};
  const lines = [
    '已启用读取规则覆盖属性数：' + (coverage.enabled_read_properties || []).length,
    '观测到但没有启用规则的属性：' + ((coverage.observed_properties_without_rule || []).join('、') || '无记录'),
    '缺少主机接收时间的读取事件：' + (coverage.reads_without_host_clock || 0),
    '会话：' + (summary.session_id || '历史记录未声明会话，需复核输入批次'),
    '时间基准：' + (summary.clock_basis || '旧版记录，请复核校准信息'),
  ];
  for (const text of lines) {
    const line = document.createElement('p');
    line.textContent = text;
    section.appendChild(line);
  }
  document.getElementById('boundary-card').before(section);
})();
