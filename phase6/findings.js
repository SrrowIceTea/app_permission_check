// 仅用于授权测试。结论、事件级定位与依据的只读展示。
(function () {
  'use strict';
  var DATA = window.VSCAN_DATA, U = window.VSCAN_UI;
  var el = U.el, badge = U.badge, DEX = U.DEX, LEVELS = U.LEVELS;
  var TYPE_LABEL = U.TYPE_LABEL, SEV_LABEL = U.SEV_LABEL, LOC_ROLE = U.LOC_ROLE;
  function dexBadgeFor(ruleId, role, eventId) {
    if (!DATA.verify || !DATA.verify.details) return null;
    var d = DATA.verify.details.find(function (x) {
      return x.rule_id === ruleId && x.role === role && x.event_id === eventId;
    });
    if (!d) return null;
    var spec = DEX[d.status] || { label: d.status, status: 's-muted' };
    return badge(spec.status, d.status === 'VERIFIED' ? '✓' : '⚠', spec.label, 'small');
  }

  function renderFindings(list) {
    var table = document.getElementById('findings-table');
    table.textContent = '';
    document.getElementById('result-count').textContent = '显示 ' + list.length + ' / ' + DATA.findings.length + ' 条';
    if (!list.length) { table.appendChild(el('div', 'empty-note', DATA.findings.length ? '没有匹配的结论。请更换关键词、类型或重置筛选。' : '本轮没有结论。请核对采集输入与规则覆盖；这不表示没有风险。')); return; }
    var t = el('table', 'findings');
    var thead = el('tr');
    ['规则', '结论', '类型', '严重度', '权限 / 属性', '代码位置', '证据'].forEach(function (h) {
      var th = el('th', null, h); th.scope = 'col'; thead.appendChild(th);
    });
    t.appendChild(thead);
    list.forEach(function (f) {
      var tr = el('tr');
      var ruleCell = el('td', 'rule-cell');
      ruleCell.appendChild(el('span', 'rule-id', f.rule_id));
      ruleCell.appendChild(el('span', 'rev', ' v' + f.rule_revision));
      if (!f.rule_enabled) ruleCell.appendChild(el('div', 'small muted', '规则未启用'));
      tr.appendChild(ruleCell);
      var lv = LEVELS[f.conclusion_level] || { label: f.conclusion_level, icon: '', status: 's-muted' };
      tr.appendChild(el('td', null)).appendChild(badge(lv.status, lv.icon, lv.label));
      tr.appendChild(el('td', null, TYPE_LABEL[f.rule_type] || f.rule_type));
      tr.appendChild(el('td', null, SEV_LABEL[f.severity] || f.severity));
      tr.appendChild(el('td', null, f.permission || f.property || '—'));
      var locCell = el('td');
      var locs = (f.code_locs || []).filter(function (l) { return l.line; });
      locs.forEach(function (loc) {
        var line = el('div', 'loc-line');
        line.appendChild(el('span', null, (LOC_ROLE[loc.role] || loc.role) + ' '));
        line.appendChild(el('span', 'file', loc.file + ':' + loc.line));
        line.appendChild(el('span', ' muted', ' ' + loc.class.split('.').pop() + '.' + loc.method));
        var d = dexBadgeFor(f.rule_id, loc.role, loc.event_id);
        if (d) { line.appendChild(document.createTextNode(' ')); line.appendChild(d); }
        locCell.appendChild(line);
      });
      (f.code_loc_gaps || []).forEach(function (g) {
        locCell.appendChild(el('div', 'gap-line', '⚠ 定位缺口：' + g.reason));
      });
      if (!locs.length && f.code_loc_note && f.evidence_kind !== 'manifest_permission') {
        locCell.appendChild(el('div', 'muted small', f.code_loc_note));
      }
      if (!locCell.childNodes.length) locCell.appendChild(el('span', 'muted', '—'));
      if (locs.length) {
        var fold = el('details', 'location-details');
        fold.appendChild(el('summary', null, locs.length + ' 个代码位置' + ((f.code_loc_gaps || []).length ? ' · 含缺口' : '')));
        while (locCell.firstChild) fold.appendChild(locCell.firstChild);
        locCell.appendChild(fold);
      }
      tr.appendChild(locCell);
      var evCell = el('td');
      if (f.rule_type === 'data_egress') {
        evCell.appendChild(el('div', null, '读取→外发 ' + (f.pair_count || 0) + ' 对'));
      } else if ((f.event_ids || []).length) {
        evCell.appendChild(el('div', null, '事件 #' + f.event_ids.join(', #')));
      } else {
        evCell.appendChild(el('span', 'muted', '清单权限'));
      }
      var proof = el('details', 'evidence-details');
      proof.appendChild(el('summary', null, '规则依据'));
      if (f.note) proof.appendChild(el('p', null, f.note));
      [['判定依据', f.basis_refs], ['来源记录', f.source_refs]].forEach(function (entry) {
        proof.appendChild(el('strong', null, entry[0]));
        proof.appendChild(el('pre', null, entry[1] && entry[1].length ? JSON.stringify(entry[1], null, 2) : '未提供，需复核来源'));
      });
      evCell.appendChild(proof);
      tr.appendChild(evCell);
      t.appendChild(tr);
    });
    table.appendChild(t);
  }

  U.renderFindings = renderFindings;
})();
