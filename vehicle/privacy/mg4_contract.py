"""Opt-in request observer for the pinned MG4 lab sample. 仅用于授权测试。

归因替代关系（审查要求写死在契约里）：
- 代理逐流归因要求：flows.jsonl 里同一 session、同一 host、POST `/submit`、
  完整同值正文且可核验 App 身份。
- 替代条件：代理逐流不可得时，允许用「App 内 WebView 请求事件（抓取自 App 进程，
  `src=mg4_webview`）+ 服务端收到的同值正文」替代。
- 约束：替代只在其一命中时成立（一个 WebView POST 事件 + 一个服务端同值正文），
  必须在 business.json 显式标注 `attribution_substitution`，不得表述成"代理已逐流归因"；
  仍保留 `post_body_attribution_gap`/`proxy_observed_post=false` 等原始缺口字段。
"""
from pathlib import Path

from vehicle.pipeline.contracts import digest

PACKAGE = 'com.tommasov.mg4browser'
APK_SHA256 = '376b931673869c0ac6a23fb719a4b642252eae6cab0fd1fc436d182ded4cf396'
BUNDLE = 'hook_vehicle_mg4.bundle.js'
MANIFEST_KEY = 'mg4_webview_contract_sha256'
REQUIRED = {('mg4_webview', 'ARMED')}
SUBSTITUTION = {
    'relation': 'app_webview_callback_plus_server_same_value_body_substitutes_for_proxy_per_flow',
    'required': ['one_webview_post_event_from_app_process', 'one_server_receipt_with_same_marker_and_body',
                 'same_capture_session'],
    'limits': '仅限本授权夹具；不能用于代理可见流的身份归因，也不能改写代理缺口字段。',
}


def contract_hash():
    return digest(Path(__file__))


def supports(package, identity):
    return (package == PACKAGE and identity.get('installed_apk_sha256') == APK_SHA256
            and identity.get('device_sdk') == 35 and identity.get('data_scope') == 'general'
            and identity.get('user_id') == 10)
