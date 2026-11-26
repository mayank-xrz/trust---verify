"""Bounded encrypted chunk delivery with loss and corruption reporting."""
import hashlib
import math
import secrets
import time

from .envelope import ReplayRejected
from .primitives import CryptoError

MAX_CHUNKS = 256
MAX_BYTES = 8 * 1024 * 1024


def make_chunks(codec, data, chunk_size=65536):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES or type(chunk_size) is not int or not 1 <= chunk_size <= 1024 * 1024:
        raise CryptoError("invalid delivery input")
    count = max(1, math.ceil(len(data) / chunk_size))
    if count > MAX_CHUNKS:
        raise CryptoError("too many chunks")
    message_id = secrets.token_hex(16)
    whole_hash = hashlib.sha256(data).hexdigest()
    return [codec.seal(data[i * chunk_size:(i + 1) * chunk_size], message_id=message_id,
                       chunk_index=i, chunk_count=count, whole_hash=whole_hash) for i in range(count)]


class DeliveryReceiver:
    def __init__(self, codec, timeout=300):
        self.codec = codec
        self.timeout = timeout
        self.pending = {}
        self.failed = set()

    def _failure(self, header, reason):
        message_id = str(header.get("message_id", ""))
        self.pending.pop(message_id, None)
        self.failed.add(message_id)
        self.codec.events.emit("delivery_failed_invalid", "deny", actor=self.codec.identity,
                               source_service=self.codec.peer, target_service=self.codec.identity,
                               session_id=self.codec.session.session_id, message_id=message_id,
                               reason=reason)

    def ingest(self, packet):
        header = packet.get("header", {}) if isinstance(packet, dict) else {}
        message_id = header.get("message_id")
        if message_id in self.failed:
            return {"status": "discarded", "message_id": message_id}
        try:
            chunk = self.codec.open(packet)
        except ReplayRejected:
            return {"status": "duplicate", "message_id": message_id}
        except CryptoError as exc:
            self._failure(header, str(exc))
            return {"status": "invalid", "message_id": message_id}
        index, count = header["chunk_index"], header["chunk_count"]
        whole_hash = header["whole_hash"]
        item = self.pending.setdefault(message_id, {"created": time.monotonic(),
                         "count": count, "whole_hash": whole_hash, "chunks": {}})
        if item["count"] != count or item["whole_hash"] != whole_hash or index in item["chunks"]:
            self._failure(header, "conflicting_chunk")
            return {"status": "invalid", "message_id": message_id}
        item["chunks"][index] = chunk
        if sum(map(len, item["chunks"].values())) > MAX_BYTES:
            self._failure(header, "message_too_large")
            return {"status": "invalid", "message_id": message_id}
        if len(item["chunks"]) == count:
            data = b"".join(item["chunks"][i] for i in range(count))
            if hashlib.sha256(data).hexdigest() != whole_hash:
                self._failure(header, "whole_hash_mismatch")
                return {"status": "invalid", "message_id": message_id}
            del self.pending[message_id]
            return {"status": "delivered", "message_id": message_id,
                    "data": data, "whole_hash": whole_hash}
        return {"status": "incomplete", "message_id": message_id,
                "missing": sorted(set(range(count)) - set(item["chunks"]))}

    def expire(self, now=None):
        now = time.monotonic() if now is None else now
        failures = []
        for message_id, item in list(self.pending.items()):
            if now - item["created"] < self.timeout:
                continue
            missing = sorted(set(range(item["count"])) - set(item["chunks"]))
            self.codec.events.emit("delivery_failed_incomplete", "deny", actor=self.codec.identity,
                                   source_service=self.codec.peer, target_service=self.codec.identity,
                                   session_id=self.codec.session.session_id, message_id=message_id,
                                   reason="missing_chunks:" + ",".join(map(str, missing)))
            failures.append({"message_id": message_id, "missing": missing})
            del self.pending[message_id]
            self.failed.add(message_id)
        return failures
