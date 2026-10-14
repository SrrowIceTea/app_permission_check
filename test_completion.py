"""新增功能离线验收，含跨包/时钟/禁用规则反例与真实双应用流回放。"""
import base64
import hashlib
import json
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.request import Request, urlopen
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
for sub in ('vehicle/analyze', 'vehicle/traffic', 'vehicle/hooks', 'vehicle/rules/python'):
    sys.path.insert(0, str(ROOT / sub))
from core.event_store import EventStore
from evaluation import evaluate_data_egress, evaluate_sensitive_read, coverage
from ownership import lookup, normalize, parse_rdap
from core.collector.payloads import capture
from core.collector.collector_server import Collector
from correlate import body_scan_totals, load_rules, load_jsonl
from egress_calibration import calibrate
from report_extras import payload_images
from gadget_prepare import prepare


def rule(kind='data_egress', enabled=1):
    return dict(rule_id='TEST-E1', rule_revision=1, rule_type=kind, severity='medium',
                conclusion_level='correlated', condition_json='{"property_id":289408000}',
                enabled=enabled, window_ms=30000, basis_refs_json='[]', source_refs_json='[]')


def read(pkg='app.a', ts=1000):
    return dict(pkg=pkg, ts=999999, host_received_ts=ts, evt_id=1, ev='VHAL_READ',
                outcome='ok', prop_id=289408000, prop_name='GEAR_SELECTION')


def flow(pkg='app.a', ts=12000):
    return dict(package=pkg, ts=ts, evt_id=1, request_tokens=['GEAR_SELECTION'])


class EvaluationTests(unittest.TestCase):
    def test_cross_session_never_correlated(self):
        r = dict(read(), session_id='one')
        f = dict(flow(), session_id='two')
        self.assertEqual([], evaluate_data_egress([rule()], [r], [f]))

    def test_native_callback_keeps_chain_and_reports_location_gap(self):
        from core.evidence import codeloc
        r = dict(read(), stack='app.a.Callback.onChangeEvent(Native Method)')
        finding = dict(package='app.a', rule_id='TEST', evidence_kind='read_event', event_ids=[1])
        result = codeloc.attach([finding], [r], [], [], 'app.a')[0]
        self.assertIsNone(result['code_locs'][0]['line'])
        self.assertEqual(1, result['code_loc_gaps'][0]['event_id'])

    def test_disabled(self):
        self.assertEqual([], evaluate_data_egress([rule(enabled=0)], [read()], [flow()]))

    def test_host_clock_overrides_stale_device_offset(self):
        result = evaluate_data_egress([rule()], [read()], [flow()], 530)
        self.assertEqual(11000, result[0]['pairs'][0]['delta_ms'])

    def test_missing_clock_not_guessed(self):
        r = read(); r.pop('host_received_ts')
        self.assertEqual([], evaluate_data_egress([rule()], [r], [flow()]))

    def test_explicit_legacy_clock(self):
        r = read(); r.pop('host_received_ts'); r['ts'] = 1530
        self.assertEqual(1, len(evaluate_data_egress([rule()], [r], [flow()], 530)))

    def test_response_only_not_egress(self):
        f = flow(); f['response_tokens'] = f.pop('request_tokens')
        self.assertEqual([], evaluate_data_egress([rule()], [read()], [f]))

    def test_ambiguous_not_correlated(self):
        self.assertEqual([], evaluate_data_egress([rule()], [read()],
                                                 [dict(flow(), attribution_ambiguous=True)]))

    def test_boundary_and_negative_delta(self):
        self.assertEqual(1, len(evaluate_data_egress([rule()], [read()], [flow(ts=31000)])))
        self.assertEqual([], evaluate_data_egress([rule()], [read()], [flow(ts=31001), flow(ts=999)]))

    def test_packages_not_merged(self):
        results = evaluate_data_egress([rule()], [read('app.a'), read('app.ab')],
                                       [flow('app.a'), flow('app.ab')])
        self.assertEqual({'app.a', 'app.ab'}, {f['package'] for f in results})
        self.assertTrue(all(f['pair_count'] == 1 for f in results))
        results = evaluate_sensitive_read([rule('sensitive_read')], [read('app.a'), read('app.ab')])
        self.assertEqual(2, len(results))

    def test_loose_attribution_caps_to_candidate(self):
        """归因距离 ≥ ATTRIB_LOOSE_MS 时，correlated 封顶 candidate（D414）。"""
        f = dict(flow()); f['attribution_delta_ms'] = 1800
        result = evaluate_data_egress([rule()], [read()], [f])
        self.assertEqual(1, len(result))
        self.assertEqual('candidate', result[0]['conclusion_level'])
        self.assertEqual('correlated', result[0]['declared_conclusion_level'])
        self.assertEqual('attribution_loose', result[0]['conclusion_capped_by'])
        self.assertTrue(result[0]['pairs'][0]['attribution_loose'])

    def test_tight_attribution_keeps_correlated(self):
        """归因距离很小（< LOOSE）时不得无端封顶。"""
        f = dict(flow()); f['attribution_delta_ms'] = 5
        result = evaluate_data_egress([rule()], [read()], [f])
        self.assertEqual('correlated', result[0]['conclusion_level'])

    def test_subscription_registration_not_read(self):
        r = dict(read(), ev='SUBSCRIPTION_REGISTER')
        self.assertEqual([], evaluate_sensitive_read([rule('sensitive_read')], [r]))

    def test_coverage_gap(self):
        self.assertEqual([289408000], coverage([], [read()])['observed_properties_without_rule'])

    def test_real_multi_app_flows_with_synthetic_reads(self):
        # 原始流为实测；读取时间为合成，不能声称本用例是设备端到端实测。
        flows = load_jsonl(ROOT / 'vehicle/traffic/evidence/flows-multi-app.jsonl')
        chosen = [f for f in flows if f.get('package') and 'GEAR_SELECTION' in f.get('request_tokens', [])]
        self.assertEqual(2, len({f['package'] for f in chosen}))
        reads = [read(f['package'], f['ts'] - 1000) for f in chosen]
        results = evaluate_data_egress([rule()], reads, chosen)
        self.assertEqual(2, len(results))
        self.assertEqual({f['package'] for f in chosen}, {f['package'] for f in results})


class StorageTests(unittest.TestCase):
    def test_concurrent_collectors_initialise_and_write(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as tmp:
            barrier = threading.Barrier(4)
            def collect(index):
                barrier.wait()
                store = EventStore(Path(tmp) / 'events.db')
                try:
                    store.append('one', str(index), read())
                finally:
                    store.close()
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(collect, range(4)))
            store = EventStore(Path(tmp) / 'events.db')
            self.assertEqual(4, len(store.query('one', 0, 2000)))
            store.close()

    def test_session_isolation_replay_and_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / 'events.db')
            for session in ('one', 'two'):
                for _ in range(2):
                    store.append(session, 'reads', read())
            self.assertEqual(1, len(store.query('one', 1000, 1001, 'app.a')))
            self.assertEqual([], store.query('one', 0, 1000))
            self.assertEqual(1, store.buckets('one')[0]['count'])
            store.close()

    def test_unknown_clock_not_bucketed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / 'events.db')
            store.append('one', 'reads', dict(ts=1000, pkg='app.a'))
            self.assertEqual([], store.buckets('one'))
            store.close()


class OwnershipTests(unittest.TestCase):
    def test_private_never_networks(self):
        self.assertEqual('non_public', lookup('10.0.2.2', '.', True)['status'])

    def test_offline_and_host_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual('offline_miss', lookup('example.com', tmp)['status'])
        with self.assertRaises(ValueError):
            normalize('example.com/path')

    def test_country_not_geolocation(self):
        data = parse_rdap({'country': 'US', 'entities': [
            {'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', 'Registrar']]]}]})
        self.assertIsNone(data['server_location'])
        self.assertIsNone(data['registered_organization'])


class CaptureTests(unittest.TestCase):
    def test_bytes_and_truncation(self):
        class Message:
            raw_content = b'x' * (1024 * 1024 + 10)
            content = raw_content
        result = capture(Message())
        self.assertTrue(result['raw_truncated'])
        self.assertEqual(hashlib.sha256(Message.raw_content).hexdigest(), result['raw_sha256'])
        self.assertEqual(1024 * 1024, len(base64.b64decode(result['raw_base64'])))

    def test_legacy_screenshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            images = payload_images(dict(evt_id=1, request_preview='<script>证据</script>'),
                                    'request', Path(tmp))
            self.assertTrue(images[0].exists())

    def test_collect_response(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            request = Request(f'http://127.0.0.1:{server.server_port}/collect', data=b'{"x":1}')
            with urlopen(request) as response:
                self.assertEqual(200, response.status)
                self.assertEqual(7, json.load(response)['received_bytes'])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_collect_accepts_proxy_absolute_form(self):
        """urlopen 发的是 origin-form，覆盖不到 absolute-form——这正是 2026-09-28 漏掉的那条路径。

        设备上残留全局 http_proxy 时，应用会改发 `POST http://host:port/collect`；
        它和 origin-form 是同一个端点，接收端必须都收。这里用裸 socket 手动构造，
        否则 urlopen 永远只发 origin-form，测试会一直绿着而线上 404。"""
        server = ThreadingHTTPServer(('127.0.0.1', 0), Collector)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            for label, target in (('origin-form', '/collect'),
                                  ('absolute-form', f'http://127.0.0.1:{server.server_port}/collect')):
                body = b'{"x":1}'
                request = (f'POST {target} HTTP/1.1\r\nHost: 10.0.2.2:8888\r\n'
                           f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode() + body
                with socket.create_connection(('127.0.0.1', server.server_port), timeout=5) as conn:
                    conn.sendall(request)
                    chunks = []
                    while chunk := conn.recv(4096):   # Connection: close，读到 EOF 才是完整响应
                        chunks.append(chunk)
                response = b''.join(chunks).decode('utf-8', 'replace')
                self.assertTrue(response.startswith('HTTP/1.0 200'),
                                f'{label} 未被接收端接受：{response[:200]}')
                self.assertIn('"received_bytes": 7', response)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_gadget_rejects_wrong_arch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); library = root / 'g.so'
            library.write_bytes(b'\x7fELF' + b'\0' * 14 + (183).to_bytes(2, 'little'))
            with self.assertRaises(ValueError):
                prepare(root, 'app.test', 'x86_64', library)


class BodyScanTotalsTest(unittest.TestCase):
    """summary 必须能说出"有多少条报文没被完整扫过"。

    标签为空有两种含义：报文里确实没有敏感字段，和我们没看全。后者被读成前者，
    报告就会把"未命中"当成"不含敏感数据"。
    """

    def test_counts_truncated_and_undecodable(self) -> None:
        flows = [
            {"request_scan": {"truncated": True, "decode_error": False},
             "response_scan": {"truncated": False, "decode_error": True}},
            {"request_scan": {"truncated": False, "decode_error": False}},
        ]
        self.assertEqual(body_scan_totals(flows),
                         {"bodies_truncated": 1, "bodies_undecodable": 1})

    def test_legacy_flows_without_scan_fields_count_zero(self) -> None:
        """旧证据没有 scan 字段——不能因此报错，也不能被算成"扫过且完整"。"""
        self.assertEqual(body_scan_totals([{}, {"request_tags": []}, {"request_scan": None}]),
                         {"bodies_truncated": 0, "bodies_undecodable": 0})


class CorrelateCliTest(unittest.TestCase):
    """目标包无观测必须与「分析完成、无命中」区分开。

    这条只能在 CLI 层面验：`build_delivery.py` 正是靠 `accepted=(0,)` 拦下载的，
    单元函数返回什么都不影响它。原缺陷是判空写在包名过滤**之前**，于是
    "只喂 App B 的数据、却要求分析 App A" 会 exit 0 并把结论数报成 0——
    使用者会把它读成"该 App 没有风险"。
    """

    def _run(self, tmp: str, package: str, reads: list[dict]):
        root = Path(tmp)
        write = lambda name, rows: (root / name).write_text(          # noqa: E731
            ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in rows), encoding='utf-8')
        write('reads.jsonl', reads)
        write('flows.jsonl', [])
        write('egress.jsonl', [])
        write('permissions.txt', [])
        return subprocess.run(
            [sys.executable, str(ROOT / 'vehicle/analyze/correlate.py'),
             '--rules', str(ROOT / 'vehicle/rules/rules_library/rules.db'),
             '--reads', str(root / 'reads.jsonl'), '--flows', str(root / 'flows.jsonl'),
             '--egress', str(root / 'egress.jsonl'),
             '--permissions', str(root / 'permissions.txt'),
             '--package', package, '--session', 's1',
             '--out', str(root / 'findings.jsonl'), '--summary', str(root / 'summary.json')],
            capture_output=True, encoding='utf-8', errors='replace', timeout=60, cwd=ROOT)

    @staticmethod
    def _read(pkg: str, ts: int = 1000) -> dict:
        return dict(ev='VHAL_READ', outcome='ok', pkg=pkg, prop_id=289408000,
                    prop_name='GEAR_SELECTION', evt_id=1, host_received_ts=ts, session_id='s1')

    def test_absent_target_package_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(tmp, 'app.a', [self._read('app.b')])
            self.assertEqual(2, result.returncode, result.stderr)
            self.assertIn('no_target_observations', result.stderr)
            # 必须说清这批输入里实际有哪个包，否则使用者不知道是不是输入喂错了
            self.assertIn('app.b', result.stderr)
            # 不产出伪造的产物：空的 findings.jsonl 本身就是一份"没有风险"的假结论
            self.assertFalse((Path(tmp) / 'findings.jsonl').exists())
            self.assertFalse((Path(tmp) / 'summary.json').exists())

    def test_target_with_reads_but_no_egress_still_succeeds(self):
        """reads 非空、flows 为空是合法运行（确实没观测到外发），不能变成新的假阴性闸门。"""
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run(tmp, 'app.a', [self._read('app.a')])
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((Path(tmp) / 'summary.json').exists())


if __name__ == '__main__':
    unittest.main()
