"""Real mitmproxy request/mode controls for attribution. 仅用于授权测试。"""
import unittest
from mitmproxy import http
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.test import tflow
from core.collector import flow_entry
from core.collector.attribution import TimeAttribution


class TargetModeTests(unittest.TestCase):
    def make_flow(self, mode, url, host):
        flow = tflow.tflow(resp=True)
        flow.client_conn.proxy_mode = ProxyMode.parse(mode)
        flow.request = http.Request.make('GET', url)
        flow.request.headers['Host'] = host
        flow.server_conn.peername = ('192.0.2.12', 80)
        return flow

    def test_regular_custom_host_cannot_match_another_apps_destination(self):
        flow = self.make_flow('regular', 'http://actual.example/data', 'decoy.example')
        target = flow_entry.target(flow)
        self.assertEqual({'host': 'actual.example', 'ip': '192.0.2.12'}, target)
        attribution = TimeAttribution(target_check=True, conservative=True, events=[
            (1000, 'other.app', 'egress_hook', {'host': 'decoy.example', 'uid': 1012345})])
        self.assertFalse(attribution.resolve(1100, target).resolved)

    def test_reverse_uses_original_host_but_never_the_upstream_peer_ip(self):
        for host in ('10.0.2.2:8888', '127.0.0.1'):
            flow = self.make_flow('reverse:http://127.0.0.1:2345', 'http://127.0.0.1:2345/data', host)
            target = flow_entry.target(flow)
            self.assertEqual(flow.request.pretty_host, target['host'])
            self.assertIsNone(target['ip'])

    def test_pending_record_keeps_its_original_anchor(self):
        for mode in ('regular', 'reverse:http://127.0.0.1:2345'):
            flow = self.make_flow(mode, 'http://actual.example/data', 'decoy.example')
            target = flow_entry.target(flow)
            record = flow_entry.unanswered(flow,
                TimeAttribution().resolve(1000), 1000, 's1', 'timeout')
            self.assertEqual(target, flow_entry.recorded_target(record))


if __name__ == '__main__':
    unittest.main()
