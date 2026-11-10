"""Validate both sides of 56 flows and keep protocol guesses out of matching."""
import hashlib
import json
import unittest
from types import SimpleNamespace

from mitmproxy import http
from mitmproxy.test import tflow

from core.collector.attribution import Attribution
from core.collector.body import MAX_BODY_SCAN
from core.collector.flow_entry import answered, unanswered
from core.collector.inspection import inspect_body
from core.collector.parse import STATUSES, parse_body, parse_summary
from core.collector.parse_stats import body_parse_totals
from core.collector.payloads import LIMIT, capture
from vehicle.analyze.value_match import match_content
from vehicle.traffic.tagging import tag_fields, tag_sensitive

PROPERTY = 'PERF_VEHICLE_SPEED'
MULTIPART = (b'--fixture\r\nContent-Disposition: form-data; name="GEAR_SELECTION"\r\n\r\n'
             b'4\r\n--fixture\r\nContent-Disposition: form-data; name="blob"; filename="file-secret"\r\n'
             b'Content-Type: application/octet-stream\r\n\r\nfile-body-secret\r\n--fixture--\r\n')
PROTOBUF = b'\x0a\x04gear\x12\x05speed'
FORM = b'GEAR%5FSELECTION=4&access%5Ftoken=ABCDEF12345678901'


def inspect(message):
    return inspect_body(message, tag_sensitive, tag_fields)


class ParseTests(unittest.TestCase):
    def test_two_sides_and_json_tag_compatibility(self):
        cases = [('application/json', json.dumps({PROPERTY: i}).encode(), 'parsed_json')
                 for i in range(20)]
        for media, body, status in [
                ('application/x-www-form-urlencoded', FORM, 'parsed_form'),
                ('multipart/form-data; boundary=fixture', MULTIPART, 'parsed_multipart'),
                ('application/x-protobuf', PROTOBUF, 'parsed_protobuf_heuristic'),
                ('application/x-protobuf', PROTOBUF + b'\x18\x80', 'unparsed_binary'),
                ('application/octet-stream', b'\x00\xff', 'unparsed_binary'),
                ('application/json', b'{"truncated":', 'unparsed_binary'),
                ('application/json', b'\xff', 'unparsed_decode_error'),
                # 真正的体积上限与 payloads/value_match 的 1MB 对齐，
                # 打标用的 256KB 窗口不再被当成解析上限。
                ('application/json', b'x' * (LIMIT + 1), 'unparsed_truncated'),
                ('application/octet-stream', b'', 'unparsed_empty'),
                ('text/html', b'<p>hello</p>', 'unparsed_unknown_content_type'),
                ('application/x-www-form-urlencoded', b'x=%1', 'unparsed_binary'),
                ('multipart/form-data; boundary=fixture', MULTIPART[:-13], 'unparsed_binary')]:
            cases.extend([(media, body, status)] * 3)
        entries = []
        for media, body, status in cases:
            with self.subTest(media=media, expected=status):
                flow = tflow.tflow(resp=True)
                headers = {'Content-Type': media}
                flow.request = http.Request.make('POST', 'http://fixture/upload', body, headers)
                flow.response = http.Response.make(200, body, headers)
                tags, scans, parses = {}, {}, {}
                for side in ('request', 'response'):
                    scan, summary, labels, tokens = inspect(getattr(flow, side))
                    self.assertIn(summary['parse_status'], STATUSES)
                    self.assertEqual(status, summary['parse_status'])
                    self.assertEqual(hashlib.sha256(body).hexdigest(), summary['payload_sha256'])
                    self.assertNotIn('fields', summary)
                    if status.startswith('unparsed_'):
                        self.assertTrue(summary['unparsed_reason'])
                    if status == 'parsed_json':
                        self.assertEqual(tag_sensitive(body.decode()), (labels, tokens))
                    tags.update({side + '_tags': labels, side + '_tokens': tokens})
                    scans[side + '_scan'] = scan
                    parses[side + '_parse'] = summary
                row = answered(flow, Attribution(package='test.app'), 1, 'fixture', tags, scans, parses)
                entries.append(row)
                self.assertNotIn('file-body-secret', json.dumps(row))
                self.assertNotIn('file-secret', json.dumps(row))
                self.assertNotIn('ABCDEF12345678901', json.dumps(row))
        self.assertEqual(56, len(entries))
        stats = body_parse_totals(entries + [{}])
        self.assertEqual(stats['request'], stats['response'])
        self.assertEqual(1, stats['request']['by_status']['legacy_unrecorded'])
        self.assertEqual(3, stats['response']['coverage_gaps']['multipart_file_bodies_uninspected'])
        req = stats['request']
        self.assertEqual(56, req['parsed'] + req['unparsed'])
        # 分母是全部 57 条（56 条有状态 + 1 条 legacy），不是只数有状态的。
        self.assertEqual(57, req['total'])
        self.assertEqual(1, req['legacy'])
        self.assertEqual(0, req['invalid'])
        self.assertAlmostEqual(round(req['parsed'] / 57, 4), req['parsed_coverage'], places=4)

    def test_unpersisted_bodies_still_get_tags(self):
        """text/html 与 octet-stream 的正文不落盘，但标签不能为空。"""
        for media, body in [('text/html', b'<p>PERF_VEHICLE_SPEED=88</p>'),
                            ('application/octet-stream', b'\x00\x01PERF_VEHICLE_SPEED')]:
            with self.subTest(media=media):
                message = http.Request.make('POST', 'http://fixture/x', body,
                                            {'Content-Type': media})
                self.assertEqual('omitted_content_type', capture(message)['retention'])
                _, summary, labels, tokens = inspect(message)
                self.assertTrue(labels)
                self.assertTrue(tokens)
                # 正文没有落盘，绝不能声称标签来自可复核的 safe_text。
                self.assertEqual('unavailable', summary['scan_basis'])

    def test_gzip_json_is_parsed_not_decode_error(self):
        # `make` 会把 content 按 Content-Encoding 编码成 raw_content：
        # 线上报文就是 gzip 压缩态，`.content`/`get_text` 才是解压后的 JSON。
        message = http.Request.make('POST', 'http://fixture/x',
                                    b'{"PERF_VEHICLE_SPEED": 30}', {
                                        'Content-Type': 'application/json',
                                        'Content-Encoding': 'gzip'})
        self.assertTrue(message.raw_content.startswith(b'\x1f\x8b'))
        summary = parse_summary(parse_body(message))
        self.assertEqual('parsed_json', summary['parse_status'])
        self.assertFalse(summary['decode_error'])
        self.assertTrue(summary['field_count'] > 0)
        self.assertTrue(summary['field_paths_sha256'])

    def test_parse_uses_full_body_beyond_scan_window(self):
        body = b'{"PERF_VEHICLE_SPEED":"' + b'x' * (MAX_BODY_SCAN + 1) + b'"}'
        message = http.Request.make('POST', 'http://fixture/x', body,
                                    {'Content-Type': 'application/json'})
        summary = parse_summary(parse_body(message))
        self.assertEqual('parsed_json', summary['parse_status'])
        self.assertTrue(summary['scan_truncated'])
        self.assertFalse(summary['truncated'])

    def test_json_media_variants_and_plain_sniffing(self):
        for media, body, status in [
                ('application/vnd.api+json', b'{"a": 1}', 'parsed_json'),
                ('text/plain', b'{"a": 1}', 'parsed_json'),
                ('text/plain', b'plain text', 'unparsed_unknown_content_type')]:
            with self.subTest(media=media, body=body):
                message = http.Request.make('POST', 'http://fixture/x', body,
                                            {'Content-Type': media})
                self.assertEqual(status, parse_summary(parse_body(message))['parse_status'])

    def test_parsed_fields_are_counted_and_hashed(self):
        message = http.Request.make('POST', 'http://fixture/x', b'{"a": {"b": 1}, "c": [2]}',
                                    {'Content-Type': 'application/json'})
        summary = parse_summary(parse_body(message))
        self.assertGreater(summary['field_count'], 0)
        self.assertTrue(summary['field_paths_sha256'])

    def test_no_response_and_empty_response_are_distinct(self):
        flow = tflow.tflow()
        attempt = unanswered(flow, Attribution(package='test.app'), 1, 'fixture', 'timeout')
        self.assertEqual('no_response_body', attempt['response_parse']['unparsed_reason'])
        self.assertIsNone(attempt['response_parse']['payload_sha256'])
        empty = parse_body(http.Response.make(204, b''))
        self.assertEqual('empty_body', empty['unparsed_reason'])
        self.assertEqual(hashlib.sha256(b'').hexdigest(), empty['payload_sha256'])

    def test_websocket_parser_requires_trusted_frame_source(self):
        for content in (b'{"speed":2}', b'notice', b'\xf0\x9f\x9a\x97'):
            message = http.Request.make('POST', 'http://fixture/frames', content, {
                'Content-Type': 'application/websocket', 'X-Vscan-Frame': 'text'})
            self.assertEqual('unparsed_unknown_content_type', parse_body(message)['parse_status'])
            parsed = parse_body(message, frame_type='text')
            self.assertNotIn('fields', parse_summary(parsed))
            self.assertEqual('websocket_binary_frame',
                             parse_body(message, frame_type='binary')['unparsed_reason'])
            if content == b'{"speed":2}':
                self.assertEqual('parsed_websocket_text', parsed['parse_status'])
            else:
                self.assertEqual('unparsed_websocket_text', parsed['parse_status'])
                self.assertEqual('websocket_text_no_structure', parsed['unparsed_reason'])

    def test_heuristics_and_unrelated_vin_never_create_value_match(self):
        for index in range(10):
            self.assertEqual(([], []), tag_fields([{'path': 'unrelated', 'value': f'ABCDE1234567890{index:02}'}]))
        msg = SimpleNamespace(raw_content=PROTOBUF, content=PROTOBUF,
                              headers={'content-type': 'application/protobuf'})
        summary = parse_summary(parse_body(msg))
        self.assertTrue(summary['heuristic'])
        self.assertIsNone(match_content({'prop_name': PROPERTY, 'value_raw': '4'}, {
            'request_parse': summary, 'request_payload': {'text': '{"PERF_VEHICLE_SPEED":4}'},
            'request_tokens': [PROPERTY]}))


class PayloadContractTests(unittest.TestCase):
    """封存 payload 必须带报文格式声明；缺失时只走嗅探、且不得报错。"""

    def test_new_capture_records_declared_media(self):
        message = http.Request.make('POST', 'http://fixture/auth/token', FORM, {
            'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Content-Encoding': 'identity'})
        payload = capture(message)
        self.assertEqual('application/x-www-form-urlencoded; charset=utf-8',
                         payload['content_type'])
        self.assertEqual('identity', payload['content_encoding'])
        self.assertEqual('parsed_form', parse_summary(parse_body(message))['parse_status'])

    def test_legacy_payload_without_declaration_still_sniffs(self):
        replay = SimpleNamespace(raw_content=FORM, content=FORM, headers={})
        summary = parse_summary(parse_body(replay))
        self.assertEqual('unparsed_unknown_content_type', summary['parse_status'])
        self.assertEqual('missing_content_type', summary['unparsed_reason'])
        self.assertNotIn('content_encoding', summary)

    def test_replay_uses_persisted_declaration(self):
        replay = SimpleNamespace(raw_content=FORM, content=FORM, headers={})
        summary = parse_summary(parse_body(
            replay, content_type='application/x-www-form-urlencoded'))
        self.assertEqual('parsed_form', summary['parse_status'])
        self.assertEqual('application/x-www-form-urlencoded', summary['content_type'])
        self.assertEqual(hashlib.sha256(FORM).hexdigest(), summary['payload_sha256'])


if __name__ == '__main__':
    unittest.main()
