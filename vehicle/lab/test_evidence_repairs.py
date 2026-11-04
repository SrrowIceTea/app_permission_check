"""Regression controls for scoped lab capture and verification."""
import hashlib
import io
import struct
import tempfile
import unittest
from pathlib import Path
from threading import Event

from vehicle.lab.abs_capture import read_pcap
from vehicle.lab.abs_send_evidence import SOURCE, attribute_writes
from vehicle.privacy.abs_contract import CALLER
from vehicle.privacy import abs_contract as abs_scope
from vehicle.privacy.abs_runtime import audit_requests, seal_requests
from vehicle.pipeline.contracts import read_json
from vehicle.lab.browser_run import PKG, matching_post, matching_webview_request, proxy_post_line
from vehicle.lab.abs_socket_identity import attribute_requests
from vehicle.lab.yaabsa_run import evaluate
from vehicle.privacy.ha_contract import PACKAGE
from vehicle.privacy.ha_socket_diagnostics import add_capture_gaps


def pcap_record(data, seq):
    frame = bytearray(54)
    frame[12:14] = b'\x08\x00'
    frame[14] = 0x45
    struct.pack_into('!H', frame, 16, 40 + len(data))
    frame[23] = 6
    frame[26:34] = b'\x7f\x00\x00\x01' * 2
    struct.pack_into('!HHI', frame, 34, 45000, 18125, seq)
    frame[46] = 0x50
    return struct.pack('<IIII', 1, 0, 54 + len(data), 54 + len(data)) + frame + data


class EvidenceRepairTests(unittest.TestCase):
    def test_split_http_body_persists_only_allowlisted_fields(self):
        body = b'{"duration":45,"currentTime":6,"timeListened":2,"token":"discard"}'
        session = 'a71cc095-ef24-431c-abc1-4b0f13a01ecc'
        head = (f'POST /api/session/{session}/sync HTTP/1.1\r\n'
                f'Authorization: Bearer discard\r\nContent-Length: {len(body)}\r\n\r\n').encode()
        global_header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        evidence = read_pcap(io.BytesIO(global_header + pcap_record(head, 1)
                                      + pcap_record(body, 1 + len(head))), Event())
        self.assertEqual([{'session_id': session, 'device_ts_ms': 1000,
                           'connection_port': 45000,
                           'body': {'duration': 45, 'currentTime': 6, 'timeListened': 2}}], evidence)
        lost = read_pcap(io.BytesIO(global_header + pcap_record(head, 1)
                                   + pcap_record(body, 2 + len(head))), Event())
        self.assertEqual([], lost)

    def test_abs_wrong_session_same_numbers_is_rejected(self):
        before = {'sessions': []}
        after = {'progress': {'currentTime': 8}, 'sessions': [
            {'id': 'server', 'timeListening': 3, 'updatedAt': 1}]}
        request = {'session_id': 'server', 'body': {'currentTime': 8, 'timeListened': 3}}
        self.assertEqual('playback_progress_aligned', evaluate([request], before, after, 5, 5)['status'])
        request['session_id'] = 'other'
        self.assertEqual('playback_progress_gap', evaluate([request], before, after, 5, 5)['status'])

    def test_browser_requires_complete_matching_request(self):
        body = 'marker=fixture'
        receipt = {'ts_ms': 2000, 'status': 200, 'path': '/submit',
                   'body_sha256': hashlib.sha256(body.encode()).hexdigest()}
        flow = {'session_id': 's', 'method': 'POST', 'host': 'loop', 'target_port': 18124, 'path': '/submit',
                'package': PKG, 'user_id': 10, 'uid': 1010000, 'attribution': 'connect', 'ts': 1950,
                'request_payload': {'text': body}, 'status_code': 200}
        self.assertTrue(matching_post(flow, 'loop', 'fixture', receipt, 's', 1900))
        for change in ({'host': 'other'}, {'uid': 10000}, {'request_payload': {}},
                       {'request_payload': {'text': body, 'raw_truncated': True}},
                       {'request_payload': {'text': 'marker=other'}},
                       {'request_payload': {'text': body + '&extra=1'}}, {'ts': 1800}):
            self.assertFalse(matching_post(flow | change, 'loop', 'fixture', receipt, 's', 1900), change)

    def test_browser_bridge_requires_same_marker_uid_and_session(self):
        receipt = {'ts_ms': 2000, 'path': '/submit?vscan_id=fixture',
                   'status': 200, 'complete_marker_body': True}
        event = {'src': 'mg4_webview', 'ev': 'WEBVIEW_POST_REQUEST', 'session_id': 's',
                 'pkg': PKG, 'uid': 1010000, 'user_id': 10, 'host': 'loop',
                 'port': 18124, 'path': '/submit', 'marker': 'fixture', 'host_received_ts': 1950}
        self.assertTrue(matching_webview_request(event, 'loop', 'fixture', receipt, 's', 1900, 1010000))
        for changed in ({'marker': 'other'}, {'uid': 1010001}, {'session_id': 'other'},
                        {'host_received_ts': 1800}, {'host': 'other'}):
            self.assertFalse(matching_webview_request(event | changed, 'loop', 'fixture', receipt,
                                                      's', 1900, 1010000))
        self.assertFalse(matching_webview_request(event, 'loop', 'fixture',
            receipt | {'complete_marker_body': False}, 's', 1900, 1010000))

    def test_ha_no_response_and_socket_gaps_survive(self):
        common = dict(pkg=PACKAGE, session_id='s', user_id=10, uid=1010000, pid=2,
                      evt_id=3, ts=1000, device_serial='owned')
        events = [dict(common, src='ha_transport', ev='HA_BODY_GAP', reason='request_failed'),
                  dict(common, src='ha_socket', ev='HA_WS_GAP', reason='unsupported_text')]
        summary = add_capture_gaps({}, events, 's', 10)
        self.assertEqual({'ha_transport.request_failed': 1, 'ha_socket.unsupported_text': 1},
                         summary['capture_gap_counts'])

    def test_proxy_post_summary_accepts_only_the_matching_truncated_prefix(self):
        path = '/submit?vscan_id=0123456789abcdef'
        base = '127.0.0.1:58003: POST http://198.18.0.1:18124/submit?vscan_id='
        self.assertTrue(proxy_post_line(base + '0123456789abcde… HTTP/1.1', '198.18.0.1', path))
        self.assertFalse(proxy_post_line(base + '0123456789abcd0… HTTP/1.1', '198.18.0.1', path))
        self.assertFalse(proxy_post_line(base + '0… HTTP/1.1', '198.18.0.1', path))

    def test_socket_attribution_requires_bracketing_and_same_inode(self):
        request = {'session_id': 's', 'connection_port': 40000, 'device_ts_ms': 1000}
        samples = [dict(port=40000, ts=t, pids=[4], inode=6) for t in (900, 1100)]
        self.assertEqual('uid_verified', attribute_requests([request], samples, 4, 1010000)[0]['status'])
        self.assertEqual('ownership_unresolved', attribute_requests([request], samples[:1], 4, 1010000)[0]['status'])
        samples[1]['inode'] = 7
        self.assertEqual('ownership_unresolved', attribute_requests([request], samples, 4, 1010000)[0]['status'])

    def test_native_write_binding_requires_successful_exact_same_session_evidence(self):
        request = {'session_id': 'abs-session', 'connection_port': 40000, 'device_ts_ms': 1100,
                   'body_sha256': 'a' * 64, 'body_bytes': 51}
        identity = dict(session='capture', serial='device', package='test.app', pid=4, uid=1010000)
        event = {'src': SOURCE, 'session_id': 'capture', 'device_serial': 'device', 'pkg': 'test.app',
                 'ev': 'ABS_SYNC_WRITE', 'evt_id': 8, 'pid': 4, 'uid': 1010000, 'user_id': 10,
                 'api': 'sendto', 'caller': CALLER,
                 'peer_host': '127.0.0.1', 'peer_port': 18125, 'local_port': 40000,
                 'body_sha256': 'a' * 64, 'body_bytes': 51, 'write_size': 51, 'returned_bytes': 51,
                 'device_start_ms': 1099, 'device_end_ms': 1101}
        self.assertEqual('uid_verified', attribute_writes([request], [event], **identity)[0]['status'])
        for delta in ({'returned_bytes': -1}, {'returned_bytes': 50}, {'pid': 5}, {'uid': 1010001},
                      {'local_port': 40001}, {'body_sha256': 'b' * 64}, {'session_id': 'other'},
                      {'abs_session_id': 'other'}, {'device_end_ms': 1200, 'device_start_ms': 1200}):
            self.assertEqual('ownership_unresolved',
                attribute_writes([request], [event | delta], **identity)[0]['status'], delta)
        self.assertEqual('ambiguous_write_candidates', attribute_writes(
            [request], [event, event | {'evt_id': 9}], **identity)[0]['reason'])
        self.assertTrue(all(r['status'] == 'ownership_unresolved'
                            for r in attribute_writes([request, request], [event], **identity)))
        ready = event | {'ev': 'ARMED', 'pkg': abs_scope.PACKAGE, 'evt_id': 1}
        reads = [ready, event | {'pkg': abs_scope.PACKAGE}]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            seal_requests(root, [request, request | {'connection_port': 40001}], reads,
                          'capture', 'device', 4, 10)
            sealed = read_json(root / abs_scope.INPUT)
            self.assertEqual([request], sealed['requests'])
            self.assertEqual(1, sealed['unresolved_requests_discarded'])
            self.assertEqual(1, audit_requests(root, reads, 'capture', 10)['verified_requests'])
