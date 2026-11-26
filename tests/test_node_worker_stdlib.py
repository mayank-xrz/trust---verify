"""Worker protocol tests runnable without the optional crypto package on the host."""
import unittest
from unittest.mock import patch
from src.crypto import node_bridge


class WorkerTests(unittest.TestCase):
    class Error(ValueError):
        pass

    def tearDown(self):
        node_bridge._stop_worker()

    def test_reuses_worker(self):
        request = {"op": "hkdf", "ikm": "YQ==", "salt": "Yg==", "info": "Yw==", "length": 32}
        first = node_bridge.call_node(request, self.Error)
        pid = node_bridge._worker.pid
        self.assertEqual(first, node_bridge.call_node(request, self.Error))
        self.assertEqual(pid, node_bridge._worker.pid)

    def test_restarts_after_crash(self):
        request = {"op": "hkdf", "ikm": "YQ==", "salt": "Yg==", "info": "Yw==", "length": 32}
        node_bridge.call_node(request, self.Error)
        old_pid = node_bridge._worker.pid
        node_bridge._worker.kill()
        node_bridge._worker.wait()
        node_bridge.call_node(request, self.Error)
        self.assertNotEqual(node_bridge._worker.pid, old_pid)

    def test_missing_node_error(self):
        node_bridge._stop_worker()
        previous = node_bridge._NODE_BIN
        node_bridge._NODE_BIN = None
        try:
            with patch.object(node_bridge.shutil, "which", return_value=None):
                with self.assertRaisesRegex(self.Error, "not found in PATH"):
                    node_bridge.call_node({}, self.Error)
        finally:
            node_bridge._NODE_BIN = previous

    def test_authentication_error_is_distinct(self):
        import base64
        request = {"op": "decrypt", "key": base64.b64encode(b"a" * 32).decode(),
                   "nonce": base64.b64encode(b"b" * 12).decode(), "aad": "", "data": "",
                   "tag": base64.b64encode(b"c" * 16).decode()}
        with self.assertRaisesRegex(self.Error, "AEAD authentication failed"):
            node_bridge.call_node(request, self.Error)
