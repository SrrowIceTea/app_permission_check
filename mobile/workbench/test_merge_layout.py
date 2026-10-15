"""Mobile UI is additive: default site and source assets must not replace vehicle frontend."""
from __future__ import annotations

import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from mobile.workbench.runtime import Runtime
from mobile.workbench.server import create_server
from mobile.workbench.store import ROOT


class MergeLayoutTest(unittest.TestCase):
    def test_default_site_serves_isolated_mobile_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = Runtime(Path(tmp), ROOT / "mobile/rules/rules_mobile.db", "36")
            server = create_server(runtime, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.assertEqual(server.frontend, ROOT / "mobile/workbench/frontend")
                for path, marker in (("/", b"Permission Lab"),
                                     ("/app.js", b"./js/app.js"),
                                     ("/js/workflow.js", b"capture-device"),
                                     ("/css/workflow.css", b"workflow")):
                    with self.subTest(path=path):
                        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
                        connection.request("GET", path)
                        response = connection.getresponse()
                        self.assertEqual(response.status, 200)
                        self.assertIn(marker, response.read())
                        connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
                runtime.close()


if __name__ == "__main__":
    unittest.main()
