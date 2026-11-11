// 仅用于授权测试（自有设备与自有 APK）。
// 本轮采集诊断面板的离线回归：node test_ledger_panel.mjs
// 不需要设备、不需要服务、不需要浏览器；用 vm + 极小 DOM 桩跑真实 ledger.js。
// 钉住的不是「页面好看」，而是几条会静默骗人的口径：
//   1. 后端缺字段不能补 0；2. 漏斗各层不能相加成检测率；
//   3. pending / diagnostic_only 不能渲染成通过；4. 后端文本不能变成 HTML。
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const source = fs.readFileSync(new URL('./ledger.js', import.meta.url), 'utf8');
const checks = [];
function check(name, fn) {
  try { fn(); checks.push({name, ok: true}); }
  catch (error) { checks.push({name, ok: false, msg: String(error && error.message || error)}); }
}

function render(summary) {
  const created = [];
  const U = {
    node(tag, cls, text) {
      const el = {
        tag, className: cls || '', textContent: text === undefined ? '' : String(text),
        dataset: {}, attrs: {}, children: [],
        append(...kids) { this.children.push(...kids); },
        setAttribute(key, value) { this.attrs[key] = value; }
      };
      created.push(el);
      return el;
    }
  };
  const scope = {
    window: {VehicleUI: U},
    // 面板只能经 U.node 造节点；直接摸 document 会让这条桩抛错。
    document: {createElement() { throw new Error('ledger.js must use U.node'); }}
  };
  vm.runInNewContext(source, scope, {filename: 'ledger.js'});
  const panel = U.ledgerPanel(summary), all = [];
  (function walk(n) { all.push(n); (n.children || []).forEach(walk); })(panel);
  return {
    panel, all, created,
    text: all.map(n => n.textContent).filter(Boolean).join(' | '),
    stat(key) {
      const cell = all.find(n => n.dataset && n.dataset.key === key);
      return cell ? cell.children.map(c => c.textContent).join(':') : null;
    },
    chips: all.filter(n => n.className === 'ledger-chip'),
    tags: all.map(n => n.tag)
  };
}
function fixture() {
  return {
    observation_ledger: {
      schema_version: 1, status: 'diagnostic_only', emits_findings: false,
      session_id: 's-001', package: 'com.example.own',
      funnel: {healthy_session: 1, business_touch: 1, real_obtained: 3,
        identity_verified: 2, complete_body: 2, verified_body: 1,
        content_correlated_pairs: 1, source_ambiguous_flows: 1, rule_hits: 2,
        traceable_rule_hits: 2, business_evidence_receipts: 1},
      attribution_quality: {flows: 4, unresolved_or_ambiguous: 1,
        single_package_fallback: 1, unknown_uid: 1, loose_attribution: 1,
        short_or_failed_connections: 1, strict_uid_user_bound: 2},
      general_correlation: {
        wired_egress_data_types: ['android_id', 'contacts'],
        observed_data_types: ['android_id', 'location'],
        observed_not_wired: ['location'],
        location_supported_forms: ['whole_pair_d6'],
        location_unsupported_forms: ['geojson_or_nested_object', 'protobuf_or_binary_payload'],
        default_wiring_changed: false},
      scenarios_declared: 3, binding_status: 'binding_consistent',
      device_acceptance: 'pending',
      gaps: ['规则命中、实验候选、业务证据分列；不得相加成总检测率。', '<img src=x onerror=alert(1)>'],
      limits: ['funnel stages are independent counts, never summed into one detection rate']
    },
    capture_validation: {
      status: 'passed', session_id: 's-001', device_acceptance: 'pending',
      session_binding: {status: 'binding_consistent', session_id: 's-001',
        bundle_sha256: 'a'.repeat(64), actions: 10, observed_receipts: 1,
        device_acceptance: 'pending'},
      tls_readiness: {tls_bypass_expected: false, tls_switch_state: 'declared'},
      gaps: ['仅覆盖 attach 后行为']
    }
  };
}

check('无账本时明确报缺口，不伪造任何漏斗计数', () => {
  const r = render({});
  assert.match(r.text, /后端未返回 observation_ledger/);
  assert.match(r.text, /不能据此认为采集完整或无风险/);
  assert.equal(r.created.filter(n => n.className === 'ledger-stat').length, 7,
    '只允许展示采集校验事实，不能出现伪造的漏斗统计格');
  assert.doesNotMatch(r.text, /设备验收通过/);
});

check('11 个漏斗层各自独立成格，数值逐字来自后端', () => {
  const r = render(fixture());
  const expected = {healthy_session: 1, business_touch: 1, real_obtained: 3,
    identity_verified: 2, complete_body: 2, verified_body: 1,
    content_correlated_pairs: 1, source_ambiguous_flows: 1, rule_hits: 2,
    traceable_rule_hits: 2, business_evidence_receipts: 1};
  Object.entries(expected).forEach(([key, value]) => {
    assert.ok(r.stat(key), `缺漏斗层 ${key}`);
    assert.ok(r.stat(key).endsWith(':' + value), `${key} 应显示 ${value}，实际 ${r.stat(key)}`);
  });
  assert.equal(Object.keys(expected).length, 11);
});

check('漏斗不相加：没有总数格，也不出现「总检测率 N」', () => {
  const r = render(fixture());
  assert.match(r.text, /不相加为检测率/);
  assert.ok(!r.all.some(n => /total|detection_rate/i.test(n.dataset.key || '')));
  assert.doesNotMatch(r.text, /总检测率\s*[:：]?\s*\d/);
  assert.doesNotMatch(r.text, /检出率\s*[:：]?\s*\d/);
});

check('归因质量 7 项与通用关联覆盖原样展示', () => {
  const r = render(fixture());
  ['flows', 'unresolved_or_ambiguous', 'single_package_fallback', 'unknown_uid',
    'loose_attribution', 'short_or_failed_connections', 'strict_uid_user_bound',
    'scenarios_declared', 'wired_egress_data_types', 'observed_not_wired',
    'location_unsupported_forms'].forEach(key => assert.ok(r.stat(key), `缺 ${key}`));
  assert.match(r.stat('location_unsupported_forms'), /geojson_or_nested_object、protobuf_or_binary_payload/);
  assert.equal(r.stat('scenarios_declared'), '声明场景数:3');
});

check('缺字段显示「—」，绝不补 0', () => {
  const data = fixture();
  delete data.observation_ledger.funnel.real_obtained;
  delete data.observation_ledger.funnel.rule_hits;
  const r = render(data);
  assert.equal(r.stat('real_obtained'), '真实取得:—');
  assert.equal(r.stat('rule_hits'), '规则命中:—');
  delete data.observation_ledger.funnel;
  const empty = render(data);
  assert.equal(empty.stat('healthy_session'), '健康会话:—');
  assert.doesNotMatch(empty.text, /健康会话:0/);
});

check('diagnostic_only / emits_findings=false 不显示为通过', () => {
  const r = render(fixture());
  assert.match(r.text, /diagnostic_only（仅诊断）/);
  assert.match(r.text, /是否产出结论：否（仅诊断）/);
  assert.equal(r.chips.every(c => c.dataset.tone !== 'success' && c.dataset.tone !== 'ok'), true);
});

check('后端状态异常时改为「需复核」警示，不冒充仅诊断', () => {
  const data = fixture();
  data.observation_ledger.status = 'review';
  data.observation_ledger.emits_findings = true;
  const r = render(data);
  assert.match(r.text, /后端状态异常，需复核/);
  assert.match(r.text, /是（需复核）/);
  assert.ok(r.chips.filter(c => c.dataset.tone === 'warn').length >= 3);
});

check('device_acceptance=pending 只说「待设备验收」', () => {
  const r = render(fixture());
  assert.ok(r.chips.some(c => /待设备验收（pending）/.test(c.textContent)));
  assert.ok(!r.chips.some(c => /已验收|验收通过/.test(c.textContent)));
  // 「不代表设备验收完成」是否定式说明，不算把 pending 写成完成。
  assert.match(r.text, /不代表设备验收完成/);
});

check('采集门禁 passed 明确「仅门禁，不等于设备验收」', () => {
  const r = render(fixture());
  assert.match(r.text, /passed（仅门禁，不等于设备验收）/);
  assert.doesNotMatch(r.text, /设备验收通过/);
  assert.match(r.stat('TLS 开关声明'), /declared/);
  assert.match(r.text, /仅覆盖 attach 后行为/);
});

check('绑定状态四种口径都不写成验收完成', () => {
  const labels = {binding_consistent: '绑定一致（仍待设备验收）',
    not_declared: '未声明会话绑定', incomplete: '会话绑定不完整', failed: '会话绑定核验失败'};
  Object.entries(labels).forEach(([status, label]) => {
    const data = fixture();
    data.capture_validation.session_binding.status = status;
    const r = render(data);
    assert.match(r.text, new RegExp(label.replace(/[（）]/g, '.')));
    assert.match(r.text, /待设备验收（pending）/);
  });
});

check('无 capture_validation 时降级不崩，不编造绑定与验收', () => {
  const data = fixture();
  delete data.capture_validation;
  const r = render(data);
  assert.match(r.text, /绑定一致（仍待设备验收）/);
  assert.match(r.text, /待设备验收（pending）/);
  assert.equal(r.stat('会话 ID'), '会话 ID:s-001');
});

check('gaps / limits 原样文本展示，XSS 串不生成标签', () => {
  const r = render(fixture());
  assert.ok(r.text.includes('<img src=x onerror=alert(1)>'));
  assert.ok(r.text.includes('funnel stages are independent counts'));
  assert.ok(!r.tags.includes('img') && !r.tags.includes('script') && !r.tags.includes('iframe'));
  assert.ok(!r.created.some(n => 'innerHTML' in n));
});

check('源码零外链、零 innerHTML、零直接 DOM/fetch', () => {
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML/);
  assert.doesNotMatch(source, /document\.createElement|fetch\(|https?:\/\//);
  assert.match(source, /U\.ledgerPanel/);
});

const failed = checks.filter(c => !c.ok);
checks.forEach(c => console.log((c.ok ? 'PASS ' : 'FAIL ') + c.name + (c.msg ? ' :: ' + c.msg : '')));
console.log(`ledger panel: ${checks.length - failed.length}/${checks.length} passed`);
if (failed.length) process.exitCode = 1;
