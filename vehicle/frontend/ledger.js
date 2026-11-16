/* 本轮采集诊断面板：只消费 /summary 的 observation_ledger 与 capture_validation。
   仅用于授权测试（自有 AAOS 设备与授权 APK）。
   红线（与 vehicle/analyze/observation_ledger.py 的 LIMITS 对齐）：
   - 漏斗各层是独立计数，绝不相加、绝不折算成「总检测率」；
   - 后端没有给的字段显示「—」，绝不补 0，也不由页面推断结论；
   - diagnostic_only / emits_findings=false / device_acceptance=pending 不得渲染成「通过」；
   - gaps / limits 只做原样文本展示，不注入 HTML、不引入外链。 */
(function () {
  'use strict';
  const U = window.VehicleUI;
  const MISSING = '—';
  const FUNNEL = [
    ['healthy_session', '健康会话'],
    ['business_touch', '业务触达（经绑定核验）'],
    ['real_obtained', '真实取得'],
    ['identity_verified', '身份可核验'],
    ['complete_body', '完整正文'],
    ['verified_body', '已核验正文（排除弱归因）'],
    ['content_correlated_pairs', '内容关联配对'],
    ['source_ambiguous_flows', '来源歧义流'],
    ['rule_hits', '规则命中'],
    ['traceable_rule_hits', '可追溯规则命中'],
    ['business_evidence_receipts', '业务证据回执（与业务触达同源）']
  ];
  const QUALITY = [
    ['flows', '范围内出站流'],
    ['unresolved_or_ambiguous', '归因未解 / 歧义'],
    ['single_package_fallback', '单包兜底归因'],
    ['unknown_uid', 'UID 未知'],
    ['loose_attribution', '弱归因'],
    ['short_or_failed_connections', '短连接 / 失败连接'],
    ['strict_uid_user_bound', '严格 UID + user 绑定']
  ];
  const GENERAL = [
    ['scenarios_declared', '声明场景数'],
    ['wired_egress_data_types', '已接线通用外发类型'],
    ['observed_data_types', '本轮观测到的类型'],
    ['observed_not_wired', '观测到但未接线'],
    ['location_supported_forms', '已支持定位格式'],
    ['location_unsupported_forms', '未支持定位格式'],
    ['default_wiring_changed', '默认接线是否变更']
  ];
  const BINDING = {
    binding_consistent: '绑定一致（仍待设备验收）',
    not_declared: '未声明会话绑定',
    incomplete: '会话绑定不完整',
    failed: '会话绑定核验失败'
  };

  function node(tag, cls, text) { return U.node(tag, cls, text); }
  function obj(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
  function text(value) {
    if (value === undefined || value === null || value === '') return MISSING;
    if (typeof value === 'boolean') return value ? '是' : '否';
    if (Array.isArray(value)) return value.length ? value.map(text).join('、') : '无';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }
  function chip(label, value, tone) {
    const el = node('span', 'ledger-chip', label + '：' + value);
    el.dataset.tone = tone || 'neutral';
    return el;
  }
  function sub(host, title, note) {
    const box = node('section', 'ledger-sub');
    box.append(node('h3', 'ledger-sub__title', title));
    if (note) box.append(node('p', 'ledger-sub__note', note));
    host.append(box);
    return box;
  }
  function stats(host, pairs, data) {
    const grid = node('div', 'ledger-grid');
    pairs.forEach(pair => {
      const key = pair[0], cell = node('div', 'ledger-stat');
      cell.dataset.key = key;
      cell.append(node('span', 'ledger-stat__label', pair[1]),
        node('span', 'ledger-stat__value', text(data[key])));
      grid.append(cell);
    });
    host.append(grid);
  }
  function bullets(host, cls, title, items, emptyText) {
    const box = node('details', cls);
    const rows = Array.isArray(items) ? items : [];
    box.append(node('summary', '', title + ' ' + rows.length + ' 条'));
    if (!rows.length) box.append(node('p', 'ledger-list__empty', emptyText));
    else {
      const ul = node('ul', 'ledger-list');
      rows.forEach(row => ul.append(node('li', '', text(row))));
      box.append(ul);
    }
    host.append(box);
  }

  /* 采集校验 / 会话绑定：门禁通过只是门禁，绝不是设备验收完成。 */
  function bindingBlock(host, summary, ledger) {
    const validation = obj(summary.capture_validation);
    const binding = obj(validation.session_binding);
    const tls = obj(validation.tls_readiness);
    const box = sub(host, '会话绑定与采集校验',
      '状态来自后端 preflight / session_binding；页面不推断，门禁通过不代表设备验收完成。');
    const chips = node('div', 'ledger-chips');
    chips.append(chip('采集校验门禁', validation.status === 'passed'
      ? 'passed（仅门禁，不等于设备验收）' : text(validation.status),
      validation.status === 'passed' ? 'neutral' : 'warn'));
    const status = binding.status === undefined ? ledger.binding_status : binding.status;
    chips.append(chip('会话绑定', BINDING[status] || (status === undefined
      ? '未提供绑定状态' : '状态未识别：' + text(status)),
      status === 'binding_consistent' ? 'neutral' : 'warn'));
    const acceptance = validation.device_acceptance === undefined
      ? ledger.device_acceptance : validation.device_acceptance;
    chips.append(chip('设备验收', acceptance === 'pending'
      ? '待设备验收（pending）' : text(acceptance), 'warn'));
    box.append(chips);
    const facts = node('div', 'ledger-grid');
    [['会话 ID', validation.session_id === undefined ? ledger.session_id : validation.session_id],
      ['绑定 bundle 摘要', binding.bundle_sha256
        ? String(binding.bundle_sha256).slice(0, 12) + '…' : MISSING],
      ['声明动作', binding.actions], ['已核验回执', binding.observed_receipts],
      ['TLS 开关声明', tls.tls_switch_state], ['TLS 绕过预期', tls.tls_bypass_expected],
      ['采集校验缺口', Array.isArray(validation.gaps) ? validation.gaps.length + ' 条' : MISSING]
    ].forEach(pair => {
      const cell = node('div', 'ledger-stat');
      cell.dataset.key = pair[0];
      cell.append(node('span', 'ledger-stat__label', pair[0]),
        node('span', 'ledger-stat__value', text(pair[1])));
      facts.append(cell);
    });
    box.append(facts);
    bullets(box, 'ledger-validate-gaps', '采集校验缺口', validation.gaps,
      '后端未返回采集校验缺口；不等于没有缺口。');
    return box;
  }

  U.ledgerPanel = function (summary) {
    const data = obj(summary), raw = data.observation_ledger;
    const panel = node('section', 'ledger-panel');
    panel.setAttribute('aria-label', '本轮采集诊断');
    const head = node('div', 'ledger-panel__head');
    const ledger = obj(raw);
    const diagnostic = ledger.status === 'diagnostic_only' && ledger.emits_findings === false;
    head.append(node('span', 'ledger-panel__title',
      !raw ? '本轮采集诊断 · 后端未提供账本'
        : (diagnostic ? '本轮采集诊断 · 仅诊断，不构成结论' : '本轮采集诊断 · 后端状态异常，需复核')),
      node('span', 'ledger-panel__meta',
        '会话 ' + text(ledger.session_id) + ' · 包名 ' + text(ledger.package) +
        ' · schema ' + text(ledger.schema_version)));
    panel.append(head, node('p', 'ledger-panel__note',
      '漏斗各层为独立计数，不相加为检测率；缺失字段显示为「—」，不等于 0，也不代表安全阴性。'));
    const chips = node('div', 'ledger-chips');
    chips.append(chip('账本状态', ledger.status === undefined ? '未提供'
      : (diagnostic ? 'diagnostic_only（仅诊断）' : '非仅诊断：' + text(ledger.status)),
      diagnostic ? 'neutral' : 'warn'));
    chips.append(chip('是否产出结论', ledger.emits_findings === false ? '否（仅诊断）'
      : (ledger.emits_findings === undefined ? '未提供' : '是（需复核）'),
      ledger.emits_findings === false ? 'neutral' : 'warn'));
    const acceptance = data.capture_validation && data.capture_validation.device_acceptance !== undefined
      ? data.capture_validation.device_acceptance : ledger.device_acceptance;
    chips.append(chip('设备验收', acceptance === 'pending'
      ? '待设备验收（pending）' : text(acceptance), 'warn'));
    panel.append(chips);
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      panel.append(node('p', 'ledger-panel__gap',
        '后端未返回 observation_ledger；本轮没有诊断账本，不能据此认为采集完整或无风险。'));
      bindingBlock(panel, data, ledger);
      return panel;
    }
    const funnel = sub(panel, '证据漏斗（逐层独立计数）',
      '规则命中、实验候选与业务证据分列；各层不同分母，不相加为总检测率。');
    stats(funnel, FUNNEL, obj(ledger.funnel));
    const quality = sub(panel, '归因质量',
      'unknown / fallback / 弱归因单列，不能当作已核验正文或安全阴性。');
    stats(quality, QUALITY, obj(ledger.attribution_quality));
    const general = sub(panel, '通用关联覆盖',
      '只列出后端声明的已接线类型与格式；未命中不等于未外发。');
    const merged = Object.assign({}, obj(ledger.general_correlation));
    if (ledger.scenarios_declared !== undefined) merged.scenarios_declared = ledger.scenarios_declared;
    stats(general, GENERAL, merged);
    bullets(panel, 'ledger-gaps', '本轮诊断缺口', ledger.gaps,
      '后端未返回诊断缺口；不等于没有缺口。');
    bullets(panel, 'ledger-limits', '结论边界', ledger.limits,
      '后端未返回结论边界说明；请核对完整摘要。');
    bindingBlock(panel, data, ledger);
    return panel;
  };
}());
