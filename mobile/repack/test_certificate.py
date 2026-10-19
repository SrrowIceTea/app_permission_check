"""Actual apksigner textual formats incl. v3.1 rotation, no signature forgery."""
from pathlib import Path
import unittest
from unittest.mock import patch
from mobile.repack.toolchain import certificate


class CertificateTests(unittest.TestCase):
    def test_v3_rotated_sdk_ranged_signers_are_preserved(self):
        text = ('Verifies\nSigner (minSdkVersion=33, maxSdkVersion=2147483647) certificate SHA-256 digest: '
                + 'a' * 64 + '\nSigner (minSdkVersion=24, maxSdkVersion=32) certificate SHA-256 digest: '
                + 'b' * 64 + '\n')
        with patch('mobile.repack.toolchain.run', return_value=text):
            self.assertEqual(certificate(Path('original.apk'), Path('signature.log'))['certificate_sha256'],
                             ['a' * 64, 'b' * 64])

    def test_numbered_signer_and_missing_digest(self):
        with patch('mobile.repack.toolchain.run', return_value='Signer #1 certificate SHA-256 digest: ' + 'A' * 64):
            self.assertEqual(certificate(Path('original.apk'), Path('signature.log'))['certificate_sha256'], ['a' * 64])
        with patch('mobile.repack.toolchain.run', return_value='Number of signers: 0'):
            with self.assertRaisesRegex(ValueError, 'no signer'):
                certificate(Path('original.apk'), Path('signature.log'))


if __name__ == '__main__':
    unittest.main()
