"""Authenticated bounded transfer framing and reassembly."""
import hashlib
import json
import math
import secrets
import time

from .primitives import CryptoError, b64, canonical, unb64

MAX_TRANSFER = 20 * 1024 * 1024
MAX_CHUNKS = 512


def make_transfer(session, data, chunk_size=65536, max_transfer=MAX_TRANSFER):
    if not isinstance(data, bytes) or len(data) > min(max_transfer, MAX_TRANSFER):
        raise CryptoError("transfer too large")
    if type(chunk_size) is not int or not 1 <= chunk_size <= 1024 * 1024:
        raise CryptoError("invalid chunk size")
    count = max(1, math.ceil(len(data) / chunk_size))
    if count > MAX_CHUNKS:
        raise CryptoError("too many chunks")
    transfer_id = secrets.token_hex(16)
    manifest = {"kind": "manifest", "transfer_id": transfer_id, "size": len(data),
                "count": count, "chunk_size": chunk_size, "sha256": hashlib.sha256(data).hexdigest()}
    packets = [session.encrypt(canonical(manifest))]
    for index in range(count):
        chunk = data[index * chunk_size:(index + 1) * chunk_size]
        packets.append(session.encrypt(canonical({"kind": "chunk", "transfer_id": transfer_id,
                                                 "index": index, "data": b64(chunk)})))
    return packets


class Reassembler:
    def __init__(self, session, ledger, max_transfer=MAX_TRANSFER, timeout=300):
        self.session = session
        self.ledger = ledger
        self.max_transfer = min(max_transfer, MAX_TRANSFER)
        self.timeout = timeout
        self.transfers = {}
        self.seen_packets = set()

    def cleanup(self):
        now = time.monotonic()
        expired = [key for key, value in self.transfers.items() if now - value["created"] > self.timeout]
        for key in expired:
            del self.transfers[key]
        return expired

    def missing(self, transfer_id):
        transfer = self.transfers.get(transfer_id)
        if not transfer or not transfer["manifest"]:
            return None
        return sorted(set(range(transfer["manifest"]["count"])) - set(transfer["chunks"]))

    def ingest(self, packet):
        self.cleanup()
        fingerprint = hashlib.sha256(canonical(packet)).digest()
        if fingerprint in self.seen_packets:
            return {"status": "duplicate"}
        plaintext = self.session.decrypt(packet, self.ledger)
        try:
            item = json.loads(plaintext)
        except (ValueError, UnicodeError) as exc:
            raise CryptoError("invalid transfer frame") from exc
        if not isinstance(item, dict) or item.get("kind") not in ("manifest", "chunk"):
            raise CryptoError("invalid transfer frame")
        transfer_id = item.get("transfer_id")
        if not isinstance(transfer_id, str) or len(transfer_id) != 32:
            raise CryptoError("invalid transfer ID")
        scope = (self.session.transcript["session_id"],
                 self.session.peer + "/" + self.session.peer_device,
                 self.session.identity + "/" + self.session.device)
        if self.ledger.transfer_completed(*scope, transfer_id):
            raise CryptoError("completed transfer replay rejected")
        if transfer_id not in self.transfers:
            if len(self.transfers) >= 8:
                raise CryptoError("too many active transfers")
            self.transfers[transfer_id] = {"created": time.monotonic(), "manifest": None, "chunks": {}}
        transfer = self.transfers[transfer_id]
        if item["kind"] == "manifest":
            if transfer["manifest"] is not None:
                raise CryptoError("conflicting manifest")
            count, size, chunk_size = item.get("count"), item.get("size"), item.get("chunk_size")
            if (type(count) is not int or not 1 <= count <= MAX_CHUNKS or
                type(size) is not int or not 0 <= size <= self.max_transfer or
                type(chunk_size) is not int or not 1 <= chunk_size <= 1024 * 1024 or
                count != max(1, math.ceil(size / chunk_size)) or
                not isinstance(item.get("sha256"), str) or len(item["sha256"]) != 64):
                raise CryptoError("invalid transfer manifest")
            for index, chunk in transfer["chunks"].items():
                expected = max(0, min(chunk_size, size - index * chunk_size))
                if index >= count or len(chunk) != expected:
                    raise CryptoError("buffered chunk conflicts with manifest")
            transfer["manifest"] = item
        else:
            index = item.get("index")
            if type(index) is not int or not 0 <= index < MAX_CHUNKS:
                raise CryptoError("invalid chunk index")
            chunk = unb64(item.get("data"))
            if transfer["manifest"]:
                manifest = transfer["manifest"]
                expected = max(0, min(manifest["chunk_size"], manifest["size"] - index * manifest["chunk_size"]))
                if index >= manifest["count"] or len(chunk) != expected:
                    raise CryptoError("chunk conflicts with manifest")
            if index in transfer["chunks"]:
                if transfer["chunks"][index] != chunk:
                    raise CryptoError("conflicting chunk")
            else:
                if len(chunk) > 1024 * 1024 or sum(map(len, transfer["chunks"].values())) + len(chunk) > self.max_transfer:
                    raise CryptoError("transfer exceeds memory limit")
                transfer["chunks"][index] = chunk
        self.seen_packets.add(fingerprint)
        manifest = transfer["manifest"]
        if manifest and len(transfer["chunks"]) == manifest["count"]:
            chunks = transfer["chunks"]
            data = b"".join(chunks[index] for index in range(manifest["count"]))
            if len(data) != manifest["size"] or hashlib.sha256(data).hexdigest() != manifest["sha256"]:
                del self.transfers[transfer_id]
                raise CryptoError("transfer integrity failure")
            self.ledger.mark_transfer(*scope, transfer_id)
            del self.transfers[transfer_id]
            return {"status": "delivered", "transfer_id": transfer_id, "data": data}
        return {"status": "incomplete", "transfer_id": transfer_id,
                "missing": self.missing(transfer_id)}
