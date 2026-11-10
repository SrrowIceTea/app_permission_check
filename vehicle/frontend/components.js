/* B 档组件层：结论汇总条 / 证据链卡片 / 空态·未完成·失败三态。
   零构建；只消费后端真实字段，缺字段显示 "—" 并写明缺失原因，前端不自行计数或推断。 */
(function () {
  'use strict';
  const U = window.VehicleUI;
  const EMPTY = '—';
  const BANDS = [
    {level: 'correlated', name: '已关联'},
    {level: 'observed', name: '已观测'},
    {level: 'candidate', name: '候选'},
    {level: 'unjudged', name: '未判定'}
  ];
  U.DEFAULT_STAGES = [
    {id: 'static', label: '车载规则静态分析'},
    {id: 'decompile', label: '反编译源码'},
    {id: 'capture', label: 'AAOS 设备采集'},
    {id: 'audit', label: '证据校验与关联审计'},
    {id: 'dashboard', label: '审计看板与报告'}
  ];
  const STATUS_TEXT = {done: '已完成', running: '执行中', failed: '执行中断',
    skipped: '已跳过', pending: '等待执行', unknown: '阶段记录尚未载入'};
  const STATUS_MARK = {done: '●', running: '◐', failed: '!', skipped: '–', pending: '○', unknown: '·'};
  function has(value) {
    if (value === null || value === undefined || value === '') return false;
    if (Array.isArray(value)) return value.length > 0;
    if (typeof value === 'object') return Object.keys(value).length > 0;
    return true;
  }
  function dash(reason) {
    const node = U.node('span', 'field-missing', EMPTY);
    node.title = reason;
    return node;
  }
  function value(raw, reason) { return has(raw) ? String(raw) : dash(reason); }

  /* 1. 结果页顶部汇总条：四档直接取后端计数，缺失时 — + 后端写明的缺口原因 */
  function gapMap(source) {
    const out = {};
    if (!source || typeof source !== 'object') return out;
    [source.field_gaps, source.findings_by_conclusion_level_gaps].forEach(gaps => {
      if (!gaps || typeof gaps !== 'object' || Array.isArray(gaps)) return;
      Object.keys(gaps).forEach(key => { if (!has(out[key])) out[key] = String(gaps[key]); });
    });
    return out;
  }
  function bandName(level) {
    const band = BANDS.find(b => b.level === level);
    return band ? band.name : level;
  }
  U.summaryBar = function (source) {
    const bar = U.node('section', 'summary-bar');
    bar.setAttribute('aria-label', '结论等级分布');
    const counts = source && source.findings_by_conclusion_level;
    const map = counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : null;
    const gaps = gapMap(source);
    const total = source && Number.isFinite(source.findings_total) ? source.findings_total : null;
    const head = U.node('div', 'summary-bar__head');
    head.append(U.node('span', 'summary-bar__title', '结论等级分布'));
    const totalNode = U.node('span', 'summary-bar__total', '结论合计 ' + (total === null ? EMPTY : total));
    if (total === null) {
      totalNode.title = gaps.findings_total || gaps.findings_by_conclusion_level
        || '后端 findings_total 缺失或不是数字。';
    }
    head.append(totalNode);
    bar.append(head);
    const grid = U.node('div', 'summary-bar__grid');
    BANDS.forEach(band => {
      const item = U.node('div', 'summary-item');
      item.dataset.band = band.level;
      item.append(U.levelBadge(band.level === 'unjudged' ? undefined : band.level));
      const count = Number.isFinite(map && map[band.level]) ? map[band.level] : null;
      const strong = U.node('strong', 'summary-item__count', count === null ? EMPTY : String(count));
      if (count === null) {
        strong.classList.add('field-missing');
        strong.title = gaps['findings_by_conclusion_level.' + band.level]
          || gaps.findings_by_conclusion_level || '后端未返回该档计数。';
      } else if (band.level === 'unjudged') {
        strong.title = '来自后端 findings_by_conclusion_level.unjudged'
          + '（结论合计减去已关联/已观测/候选，并加回原始未判定）；只描述证据强度。';
      } else {
        strong.title = '来自后端 findings_by_conclusion_level.' + band.level;
      }
      item.append(strong, U.node('span', 'summary-item__unit', '条'));
      grid.append(item);
    });
    bar.append(grid);
    const notes = ['数据来源：后端 findings_by_conclusion_level'];
    const nulls = map ? BANDS.filter(b => !Number.isFinite(map[b.level])).map(b => b.name) : [];
    if (!map) notes.push('该字段缺失，四档均显示 —');
    else if (nulls.length) notes.push(nulls.join('、') + ' 本轮为 null，显示 —，不做前端推算');
    const extra = map ? Object.keys(map).filter(k => !BANDS.some(b => b.level === k)) : [];
    if (extra.length) notes.push('后端另返回未归入四档的键：' + extra.map(k => k + '=' + map[k]).join('、'));
    notes.push('计数只描述证据强度，不代表安全或合规结论');
    bar.append(U.node('p', 'summary-bar__note', notes.join('；')));
    Object.keys(gaps).filter(key => key === 'findings_total' || key.startsWith('findings_by_conclusion_level'))
      .forEach(key => {
        const label = key === 'findings_total' ? '结论合计'
          : key.startsWith('findings_by_conclusion_level.') ? bandName(key.split('.').pop()) : '分档计数';
        bar.append(U.node('p', 'summary-bar__gap', '缺口 · ' + label + '：' + gaps[key]));
      });
    return bar;
  };

  /* 2. 证据链卡片：一级给结论与关键字段，二级按需生成原始 JSON */
  function pairing(row) {
    const ids = Array.isArray(row.event_ids) ? row.event_ids : [];
    const pred = Array.isArray(row.predicate) ? row.predicate : (has(row.predicate) ? [row.predicate] : []);
    if (ids.length) return '事件 ' + ids.length + ' 条' + (pred.length ? ' · ' + pred.join(' / ') : '');
    if (Array.isArray(row.basis_refs) && row.basis_refs.length) {
      return '依据 ' + row.basis_refs.length + ' 项（未提供事件配对）';
    }
    return null;
  }
  function metaLine(row) {
    const parts = [];
    if (has(row.package)) parts.push(row.package);
    const time = row.ts ?? row.time ?? row.timestamp;
    if (has(time)) parts.push(typeof time === 'number' ? new Date(time * 1000).toLocaleString() : String(time));
    if (Array.isArray(row.code_locs) && row.code_locs.length) parts.push('代码位置 ' + row.code_locs.length + ' 处');
    return parts.length ? parts.join(' · ') : '关键字段未提供，展开查看缺失原因';
  }
  /* 规则标题取值顺序按后端契约：rule_title（后端已优先中文）→ 静态行的 title → rule_id 回退 */
  function ruleTitle(row) {
    if (has(row.rule_title)) return row.rule_title;
    if (has(row.title)) return row.title;
    return has(row.rule_id) ? row.rule_id : null;
  }
  function titleReason(row) {
    if (has(row.rule_title) || has(row.title)) return '';
    return has(row.rule_id)
      ? '该结论未在规则库登记标题（rule_title 为 null）；此处显示 rule_id。'
      : '后端未返回 rule_id 与 rule_title。';
  }
  function titleNote(row) {
    if (has(row.rule_title) || has(row.title)) return null;
    return has(row.rule_id) ? '该结论未在规则库登记标题；显示 rule_id 代替。' : null;
  }
  function facts(row) {
    const grid = U.node('div', 'evidence-facts');
    [
      ['规则', has(row.rule_id) ? row.rule_id : null, '后端未返回 rule_id。'],
      ['规则标题', ruleTitle(row), titleReason(row), titleNote(row)],
      ['标题来源', row.rule_title_source, '后端未返回 rule_title_source，无法确认标题取自规则库还是人工映射。'],
      ['类型', row.finding_class || row.rule_type, '后端未返回 finding_class / rule_type。'],
      ['包名', row.package, '后端结论行未提供 package。'],
      ['时间', row.ts ?? row.time ?? row.timestamp,
        '后端结论行未提供时间戳；summary 只有任务创建时间，不能当作结论时间。'],
      ['读取 / 外发配对', pairing(row),
        '后端结论行未返回 event_ids / predicate，无法确认读取与外发的配对关系。'],
      ['证据类型', row.evidence_kind, '后端未返回 evidence_kind。']
    ].forEach(item => {
      const cell = U.node('div', 'evidence-fact');
      const text = U.node('span', 'evidence-fact__value');
      text.append(value(item[1], item[2]));
      if (item[3]) text.append(U.node('span', 'evidence-fact__note', item[3]));
      cell.append(U.node('span', 'evidence-fact__label', item[0]), text);
      grid.append(cell);
    });
    if (has(row.note)) {
      const note = U.node('div', 'evidence-fact evidence-fact--wide');
      note.append(U.node('span', 'evidence-fact__label', '说明'),
        U.node('span', 'evidence-fact__value', row.note));
      grid.append(note);
    }
    if (U.reviewBlock) grid.append(U.reviewBlock(row));
    return grid;
  }
  function rawDrawer(row) {
    const box = U.node('details', 'evidence-raw');
    box.append(U.node('summary', '', '原始 JSON（展开后才生成，默认不渲染）'));
    const pre = U.node('pre', 'evidence-json');
    box.addEventListener('toggle', function () {
      if (!box.open || box.dataset.rendered) return;
      box.dataset.rendered = 'true';
      pre.textContent = JSON.stringify(row, null, 2);
    });
    box.append(pre);
    return box;
  }
  U.evidenceCard = function (row) {
    const card = U.node('details', 'evidence-card');
    const head = U.node('summary', 'evidence-card__summary');
    const rule = U.node('span', 'evidence-card__rule', ruleTitle(row) || EMPTY);
    if (row.rule_title_source) rule.title = '标题来源：' + row.rule_title_source;
    else if (!ruleTitle(row)) rule.title = titleReason(row);
    head.append(U.levelBadge(row.conclusion_level), rule,
      U.node('span', 'evidence-card__meta', metaLine(row)),
      U.node('span', 'evidence-card__cue', '展开证据链'));
    const body = U.node('div', 'evidence-card__body');
    body.append(facts(row), rawDrawer(row));
    card.append(head, body);
    return card;
  };

  /* 3. 三态组件 */
  function panel(kind, spec) {
    const box = U.node('section', 'state-panel state-panel--' + kind);
    box.setAttribute('role', kind === 'failed' ? 'alert' : 'status');
    box.append(U.node('span', 'state-panel__mark', kind === 'failed' ? '!' : kind === 'pending' ? '◐' : '○'));
    const heading = U.node('div', 'state-panel__heading');
    if (spec.title) heading.append(U.node('h3', 'state-panel__title', spec.title));
    if (spec.message) heading.append(U.node('p', 'state-panel__message', spec.message));
    box.append(heading);
    return box;
  }
  function progressList(progress) {
    const list = U.node('ul', 'state-progress');
    progress.forEach(step => {
      const item = U.node('li', 'state-progress__item');
      item.dataset.status = step.status;
      item.append(U.node('span', 'state-progress__mark', STATUS_MARK[step.status] || '○'),
        U.node('span', 'state-progress__label', step.label),
        U.node('span', 'state-progress__msg', step.message || STATUS_TEXT[step.status] || ''));
      list.append(item);
    });
    return list;
  }
  U.progressOf = function (job) {
    const defs = U.stages && U.stages.length ? U.stages : U.DEFAULT_STAGES;
    const events = job && Array.isArray(job._events) ? job._events : null;
    return defs.map(stage => {
      if (!job) return {id: stage.id, label: stage.label, status: 'pending', message: '等待执行'};
      if (!events) return {id: stage.id, label: stage.label, status: 'unknown', message: STATUS_TEXT.unknown};
      const event = events.filter(e => e.stage === stage.id).pop();
      return {id: stage.id, label: stage.label, status: event ? event.status : 'pending',
        message: event ? event.message : '等待执行'};
    });
  };
  U.stateEmpty = function (host, spec) {
    const box = panel('empty', spec || {});
    if (!spec || !spec.title) box.classList.add('state-panel--compact');
    host.replaceChildren(box);
  };
  U.statePending = function (host, spec) {
    const box = panel('pending', spec || {});
    if (spec && spec.progress) box.append(progressList(spec.progress));
    if (spec && spec.note) box.append(U.node('p', 'state-panel__note', spec.note));
    host.replaceChildren(box);
  };
  function section(title, items, fallback) {
    const box = U.node('div', 'state-panel__section');
    box.append(U.node('h4', '', title));
    if (!items || !items.length) {
      box.append(U.node('p', 'state-panel__message', fallback));
      return box;
    }
    const list = U.node('ul', '');
    items.forEach(text => list.append(U.node('li', '', text)));
    box.append(list);
    return box;
  }
  function action(name, why) {
    const box = U.node('div', 'state-action');
    const button = U.node('button', 'pl-btn', name);
    button.type = 'button';
    button.disabled = true;
    button.title = why;
    box.append(button, U.node('span', '', why));
    return box;
  }
  U.failureSpec = function (job) {
    const progress = U.progressOf(job);
    const suffix = {pending: '（等待执行）', skipped: '（已跳过）', unknown: '（阶段记录尚未载入）'};
    return {
      reason: job.result.error?.message || job.result.message || '服务未返回原因。',
      code: job.result.error?.code,
      next_action: job.result.error?.next_action,
      done: progress.filter(p => p.status === 'done').map(p => p.label),
      failed: progress.filter(p => p.status === 'failed')
        .map(p => p.label + '（' + (p.message || '执行中断') + '）'),
      pending: progress.filter(p => p.status !== 'done' && p.status !== 'failed')
        .map(p => p.label + (suffix[p.status] || '')),
      jobId: job.id
    };
  };
  U.stateFailed = function (host, spec) {
    const box = panel('failed', {title: spec.title || '本轮审计未完成', message: spec.reason});
    if (spec.code) box.append(U.node('p', 'state-panel__code', '错误码：' + spec.code));
    if (spec.failed && spec.failed.length) {
      box.append(U.node('p', 'state-panel__code', '中断阶段：' + spec.failed.join('；')));
    }
    box.append(section('已完成', spec.done, '本轮没有已完成的阶段记录。'),
      section('未执行', spec.pending, '没有未执行的阶段。'));
    if (spec.next_action) box.append(U.node('p', 'state-panel__next', '建议：' + spec.next_action));
    const actions = U.node('div', 'state-panel__actions');
    actions.append(
      action('重试', '后端未提供按任务重新执行的接口：POST /api/pipeline 只接受新上传，不能复用原任务编号。'),
      action('打开日志', '后端未提供日志读取接口；失败堆栈只保留在服务端 output/vehicle-web/' +
        (spec.jobId || '<任务编号>') + '/failure.log。'));
    box.append(actions, U.node('p', 'state-panel__gap',
      '缺口：以上两个动作依赖后端接口。本轮按约束不改后端，因此按钮置灰并写明原因。'));
    if (spec.summary instanceof Node) host.replaceChildren(spec.summary, box);
    else host.replaceChildren(box);
  };
}());
