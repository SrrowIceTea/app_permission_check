"""`GET /api/stages` 的离线契约：服务端必须原样吐出 `stages.STAGES`。

仅用于授权测试（自有设备与已授权的公开第三方样本）。

为什么需要它：前端契约测试（`frontend/test_pipeline_contract.mjs`）只能证明
"前端把 /api/stages 当成唯一来源"，它的 payload 是测试自己用 `stages.py` 造的。
如果 `mobile/pipeline/server.py:128-130` 哪天改成返回 `STAGE_LABEL`（字典顺序）
或漏掉一个阶段，前端测试仍然全绿，只有真的打开浏览器才会发现时间线少一行。
这条用例把服务端那一半也钉住：起一个真 HTTP 服务（回环 + 随机端口），走一次
`urllib`，断言 id/label 的顺序与条数逐项等于契约。全程离线、不碰设备。
"""
from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from unittest import TestCase, main

from mobile.pipeline import stages
from mobile.pipeline.server import Handler


class StagesApiTests(TestCase):
    def setUp(self):
        # 只绑回环 + 端口 0（内核分配）：不占 8771，不与真实服务或其它用例抢端口。
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)

    def _get(self, path: str) -> tuple[int, bytes]:
        url = f"http://127.0.0.1:{self.server.server_address[1]}{path}"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:      # 4xx 也要能读到 body
            return exc.code, exc.read()

    def test_stages_endpoint_matches_contract(self):
        status, body = self._get("/api/stages")
        self.assertEqual(status, 200)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual([row["id"] for row in payload], [sid for sid, _ in stages.STAGES])
        self.assertEqual([row["label"] for row in payload], [label for _, label in stages.STAGES])
        self.assertEqual(len(payload), 17, "阶段数变了就同步前端与文档")

    def test_unknown_endpoint_still_404(self):
        """顺带确认 Handler 的路由没被写坏（否则上一条的 200 可能来自别处）。"""
        status, body = self._get("/api/not-a-real-endpoint")
        self.assertEqual(status, 404)
        self.assertIn("error", json.loads(body.decode("utf-8")))


if __name__ == "__main__":
    main()
