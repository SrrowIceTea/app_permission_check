/* 隐私观测三态：已观测 / 仅注册未取值 / 未观测。
   只消费后端 privacy_observation 与结论行的 read_evidence；三态在颜色、图标、文案上都必须可区分，
   且「未观测」不得渲染成通过、无风险或安全。 */
(function () {
  'use strict';
  const U = window.VehicleUI;
  const EMPTY = '—';
  const STATE_TITLES = {
    observed: '已观测：拿到值，可逐条复核',
    registration_only: '仅注册 / 未取值：按判据不升级',
    read_not_obtained: '有读取但未取到值',
    not_observed: '未观测：本轮没有相关事件'
  };
  function node(tag, cls, text) { return U.node(tag, cls, text); }

  /* 三态徽标：颜色分别为亮/中/虚线灰，图标为 ◐ / ◑ / ?，没有一个像「通过」 */
  function badge(state, label) {
    const el = node('span', 'obs-badge');
    el.dataset.state = state;
    el.append(node('span', 'obs-badge__mark', {observed: '◐', registration_only: '◑',
      read_not_obtained: '◔', not_observed: '?'}[state] || '?'),
      node('span', 'obs-badge__word', label || STATE_TITLES[state] || state));
    el.title = STATE_TITLES[state] || state;
    return el;
  }

  /* 逐条读取证据：evt_id / collection_state / value_hash 前 12 位 / 时间 */
  function evidenceTable(events) {
    const wrap = node('div', 'obs-evidence');
    const table = node('table', 'obs-evidence__table');
    const head = node('tr');
    ['事件 evt_id', 'collection_state', 'value_hash（前 12 位）', '时间'].forEach(label => {
      head.append(node('th', '', label));
    });
    const thead = node('thead'); thead.append(head); table.append(thead);
    const body = node('tbody');
    events.forEach(event => {
      const tr = node('tr');
      const id = node('td', 'obs-evidence__id', event.evt_id === undefined ? EMPTY : event.evt_id);
      if (event.api) id.title = event.api;
      const state = node('td', '', event.collection_state === undefined ? EMPTY : event.collection_state);
      const hash = node('td', 'obs-evidence__hash',
        typeof event.value_hash === 'string' && event.value_hash ? event.value_hash.slice(0, 12) : EMPTY);
      if (typeof event.value_hash === 'string') hash.title = '完整值哈希：' + event.value_hash;
      const when = node('td', 'obs-evidence__time',
        typeof event.host_received_ts === 'number'
          ? new Date(event.host_received_ts).toLocaleString() : EMPTY);
      tr.append(id, state, hash, when);
      body.append(tr);
    });
    table.append(body); wrap.append(table);
    return wrap;
  }

  function basisFacts(basis) {
    const grid = node('div', 'obs-basis');
    [['判据', basis.criterion], ['collection_state', basis.collection_state],
      ['本轮出现过的状态', Array.isArray(basis.states_seen) ? basis.states_seen.join(' / ') : null],
      ['带值哈希的读取', basis.value_hash_present], ['带长度的读取', basis.value_len_present]
    ].forEach(item => {
      const cell = node('div', 'obs-basis__cell');
      cell.append(node('span', 'obs-basis__label', item[0]),
        node('span', 'obs-basis__value', item[1] === null || item[1] === undefined ? EMPTY : item[1]));
      grid.append(cell);
    });
    return grid;
  }

  function evidenceOf(rows, item) {
    const ids = new Set(item.evidence_event_ids || []);
    const out = [];
    (rows || []).forEach(row => {
      if (row.data_type !== item.data_type || !Array.isArray(row.read_evidence)) return;
      row.read_evidence.forEach(event => {
        if (!ids.size || ids.has(event.evt_id)) out.push(event);
      });
    });
    return out;
  }

  function row(rows, item) {
    const observed = item.state === 'observed' || item.state === 'correlated';
    const box = observed ? node('details', 'obs-row') : node('div', 'obs-row');
    box.dataset.state = item.state;
    const head = observed ? node('summary', 'obs-row__head') : node('div', 'obs-row__head');
    head.append(badge(item.state, item.state_label), node('span', 'obs-row__name', item.data_type_name),
      node('span', 'obs-row__meta', '读取 ' + item.read_events + ' 条 · 注册 ' +
        item.call_only_events + ' 条 · 值哈希 ' + item.value_hash_present + ' 条'));
    if (observed) head.append(node('span', 'obs-row__cue', '展开逐条证据'));
    box.append(head,
      node('p', 'obs-row__text', item.reason_text || '后端未返回该状态的说明。'),
      node('p', 'obs-row__code', '原因码 ' + item.reason_code));
    if (!observed) return box;
    const body = node('div', 'obs-row__body');
    const events = evidenceOf(rows, item);
    (rows || []).forEach(findingRow => {
      if (findingRow.data_type !== item.data_type || !findingRow.observed_basis) return;
      body.append(basisFacts(findingRow.observed_basis));
    });
    if (events.length) body.append(evidenceTable(events));
    else body.append(node('p', 'obs-row__text', '后端没有返回该数据类型的 read_evidence，无法逐条复核。'));
    box.append(body);
    return box;
  }

  U.observationPanel = function (summary, rows) {
    const data = summary && summary.privacy_observation;
    const section = node('section', 'obs-panel');
    section.setAttribute('aria-label', '隐私数据观测');
    const head = node('div', 'obs-panel__head');
    head.append(node('span', 'obs-panel__title', '隐私数据观测'));
    if (!data || data.status === 'not_available') {
      section.append(head, node('p', 'obs-panel__gap', data && data.reason_text
        ? data.reason_text : '后端未返回 privacy_observation；不能据此认为未采集或安全。'));
      return section;
    }
    const items = Array.isArray(data.data_types) ? data.data_types : [];
    const count = state => items.filter(i => i.state === state).length;
    head.append(node('span', 'obs-panel__meta',
      '已观测 ' + count('observed') + ' · 仅注册未取值 ' + count('registration_only') +
      ' · 有读取未取到值 ' + count('read_not_obtained') + ' · 未观测 ' + count('not_observed')));
    section.append(head, node('p', 'obs-panel__note', data.note || ''));
    const list = node('div', 'obs-list');
    items.forEach(item => list.append(row(rows, item)));
    section.append(list);
    if (Array.isArray(data.observation_gaps) && data.observation_gaps.length) {
      const gap = node('details', 'obs-gaps');
      gap.append(node('summary', '', '本轮 Hook 缺口 ' + data.observation_gaps.length +
        ' 条（无事件不等于未采集）'));
      data.observation_gaps.forEach(g => gap.append(node('p', 'obs-gaps__item',
        (g.where || 'unknown') + ' · ' + (g.message || '后端未返回说明'))));
      section.append(gap);
    }
    return section;
  };

  /* 结论卡里的扩展区：判据 + 逐条读取证据（只在有该字段时出现） */
  U.observationWord = state => ({observed: '已观测（可按事件逐条复核）',
    correlated: '已关联（跨源配对）', unverified: '未验证（没有运行时读取证据）'}[state]);

  U.readEvidenceSection = function (row) {
    const box = node('div', 'obs-evidence-block');
    if (row.observed_basis && typeof row.observed_basis === 'object') {
      box.append(node('h4', 'obs-evidence-block__title', '升级判据（observed_basis）'),
        basisFacts(row.observed_basis));
    }
    if (Array.isArray(row.read_evidence) && row.read_evidence.length) {
      box.append(node('h4', 'obs-evidence-block__title',
        '逐条读取证据 ' + row.read_evidence.length + ' 条（read_evidence）'),
        evidenceTable(row.read_evidence));
    }
    return box.children.length ? box : null;
  };
}());
