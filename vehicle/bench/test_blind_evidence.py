"""Offline tests for the blind evidence projections. 仅用于授权测试。

The key regression here is conceptual, not structural: on 2026-11-10 all three
reviewers named the browser item their least certain one because the card
shipped `post_marker_matched` with no statement of what was compared. A boolean
whose scope is unstated invites the reader to invent one.
"""
import unittest

from vehicle.bench.blind_evidence import MARKER_MATCH_SCOPE, browser


class StubSource:
    """Minimal stand-in: only what ``browser()`` actually touches."""

    def __init__(self, business, reads=(), flows=()):
        self.business = business
        self._events = {'reads.jsonl': list(reads), 'flows.jsonl': list(flows)}

    def events(self, name):
        return self._events[name]


def business(**overrides):
    base = {'marker': 'deadbeefdeadbeef',
            'server_receipts': [{'method': 'POST', 'status': 200, 'ts_ms': 1000,
                                 'path': '/submit?vscan_id=deadbeef', 'marker': 'deadbeefdeadbeef',
                                 'body_sha256': 'a' * 64}],
            'proxy_observed_post': True, 'post_marker_matched': True,
            'post_flow_attributed': 0,
            'gaps': ['代理观察到 /submit POST，但缺少可验证的 App 身份与完整同值正文。']}
    base.update(overrides)
    return base


class MarkerScopeTests(unittest.TestCase):
    def test_card_states_what_the_boolean_compares(self):
        card = browser(StubSource(business()))
        self.assertEqual(MARKER_MATCH_SCOPE, card['post_marker_matched_scope'])
        self.assertIn('不表示该请求已绑定到目标应用进程', card['post_marker_matched_scope'])

    def test_card_carries_the_receipt_gaps_verbatim(self):
        card = browser(StubSource(business()))
        self.assertEqual(business()['gaps'], card['recorded_gaps'])
        self.assertIn('缺少可验证的 App 身份', card['recorded_gaps'][0])

    def test_attribution_basis_appears_only_when_the_receipt_declares_one(self):
        self.assertNotIn('attribution_basis', browser(StubSource(business())))
        card = browser(StubSource(business(
            attribution_basis='webview_callback_and_server_body_substitution')))
        self.assertEqual('webview_callback_and_server_body_substitution',
                         card['attribution_basis'])

    def test_raw_marker_never_reaches_the_card(self):
        card = browser(StubSource(business()))
        self.assertNotIn('deadbeefdeadbeef', repr(card))
        self.assertEqual('marker-1', card['server_post_receipts'][0]['marker_ref'])

    def test_app_side_event_is_what_distinguishes_the_two_mg4_runs(self):
        read = {'src': 'mg4_webview', 'ev': 'WEBVIEW_POST_REQUEST',
                'evt_id': 2, 'ts_ms': 900, 'path': '/submit?x=1', 'marker': 'deadbeefdeadbeef'}
        without = browser(StubSource(business()))
        with_event = browser(StubSource(business(), reads=[read]))
        self.assertEqual([], without['app_request_events'])
        self.assertEqual(1, len(with_event['app_request_events']))
        # Same boolean, different evidence -- the card must make that visible.
        self.assertEqual(without['post_marker_matched'], with_event['post_marker_matched'])


if __name__ == '__main__':
    unittest.main()
