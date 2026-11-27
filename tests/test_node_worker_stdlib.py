"""Tests verifying pure-Python cryptography with no Node.js subprocess boundary."""
import unittest
from pathlib import Path
from unittest.mock import patch


class PurePythonCryptoTests(unittest.TestCase):
    def test_node_bridge_files_removed(self):
        crypto_dir = Path(__file__).resolve().parent.parent / "src" / "crypto"
        self.assertFalse((crypto_dir / "node_bridge.py").exists())
        self.assertFalse((crypto_dir / "node_aead.cjs").exists())

    def test_aead_and_kdf_spawn_no_subprocess(self):
        from src.crypto import aead, classical, primitives

        with patch("subprocess.Popen", side_effect=AssertionError("unexpected subprocess")), \
             patch("subprocess.run", side_effect=AssertionError("unexpected subprocess")):
            key = b"a" * 32
            nonce = b"b" * 12
            ct, tag = aead.encrypt(key, nonce, b"aad", b"secret")
            self.assertEqual(aead.decrypt(key, nonce, b"aad", ct, tag), b"secret")

            bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
            with self.assertRaisesRegex(primitives.CryptoError, "AEAD authentication failed"):
                aead.decrypt(key, nonce, b"aad", ct, bad_tag)

            derived = primitives.hkdf(b"ikm", b"salt", b"info", 32)
            self.assertEqual(len(derived), 32)

            pub_a, priv_a = classical.keypair()
            pub_b, ss_b = classical.ephemeral_shared(pub_a)
            ss_a = classical.shared(priv_a, pub_b)
            self.assertEqual(ss_a, ss_b)
