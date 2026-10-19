"""Policy snapshots must have byte-identical stored text and digest on Windows."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from mobile.policy import policy_fetch


class PolicyBytesTests(unittest.TestCase):
    def test_text_newlines_do_not_invalidate_snapshot_digest(self):
        text = '隐私政策\n一、信息收集\n二、信息使用\n'
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory)
            record = policy_fetch.save(store, raw=b'<html>policy</html>',
                extract={'text': text, 'chars': len(text), 'status': 'ok', 'cjk_ratio': 1},
                meta={'source': 'local-unit-test'}, tag='test')
            persisted = (store / record['text_file']).read_bytes()
            self.assertEqual(persisted, text.encode('utf-8'))
            self.assertEqual(hashlib.sha256(persisted).hexdigest(), record['text_sha256'])


if __name__ == '__main__':
    unittest.main()
