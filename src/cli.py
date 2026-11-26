"""Reproducible Demo & Verification CLI (`python -m src.cli <subcommand>`)."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import List

from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier
from src.crypto.delivery import ChunkReceiver, chunk_and_seal
from src.crypto.envelope import (
    AEADFailedError,
    RecipientMismatchError,
    open_envelope,
    seal_envelope,
)
from src.crypto.handshake import EphemeralHandshakeSession
from src.crypto.replay_cache import PersistentReplayCache, ReplayRejectedError
from src.crypto.resumption import PersistentResumptionStore, ResumptionPeerMismatchError


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def cmd_demo_replay() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        logger = AuditLogger("node-bob", str(tmp_path / "audit.log"))
        cache = PersistentReplayCache(tmp_path / "replay.db")
        alice_pk, alice_sk = ml_dsa_65.keygen()
        key = b"K" * 32

        env = seal_envelope(
            sender_identity="alice",
            sender_device="dev-1",
            recipient_identity="bob",
            recipient_device="dev-2",
            session_id="sess-demo-1",
            session_key=key,
            signing_secret_key=alice_sk,
            plaintext=b"hello-bob",
            counter=1,
        )
        # 1. Valid accept
        pt = open_envelope(
            env,
            local_identity="bob",
            local_device="dev-2",
            session_key=key,
            sender_public_key=alice_pk,
            replay_cache=cache,
            audit_logger=logger,
        )
        assert pt == b"hello-bob"

        # 2. Replay rejected
        replay_rejected = False
        try:
            open_envelope(
                env,
                local_identity="bob",
                local_device="dev-2",
                session_key=key,
                sender_public_key=alice_pk,
                replay_cache=cache,
                audit_logger=logger,
            )
        except ReplayRejectedError:
            replay_rejected = True

        # 3. Wrong recipient rejected before decryption
        wrong_recipient_rejected = False
        try:
            open_envelope(
                env,
                local_identity="charlie",
                local_device="dev-9",
                session_key=key,
                sender_public_key=alice_pk,
                replay_cache=cache,
                audit_logger=logger,
            )
        except RecipientMismatchError:
            wrong_recipient_rejected = True

        print(json.dumps({
            "demo": "demo-replay",
            "valid_accepted": True,
            "replay_rejected": replay_rejected,
            "recipient_mismatch_rejected": wrong_recipient_rejected,
            "log_valid": AuditLogVerifier().verify_file(str(tmp_path / "audit.log")).is_valid,
        }, indent=2))
        return 0 if (replay_rejected and wrong_recipient_rejected) else 1


def cmd_demo_forward_secrecy() -> int:
    alice_pk, alice_sk = ml_dsa_65.keygen()
    bob_pk, bob_sk = ml_dsa_65.keygen()

    bob_hs = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    alice_hs = EphemeralHandshakeSession("alice", "dev-a", alice_sk)

    hello = bob_hs.create_responder_hello()
    init_msg, alice_keys = alice_hs.initiate(hello, bob_pk)
    bob_keys = bob_hs.complete_responder(init_msg, alice_pk)

    assert alice_keys.tx_key == bob_keys.rx_key
    assert not bob_hs.has_ephemeral_secrets()
    assert not alice_hs.has_ephemeral_secrets()

    # Even if long-term ML-DSA-65 identity keys are exposed, they cannot decrypt past AEAD ciphertext
    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id=alice_keys.session_id,
        session_key=alice_keys.tx_key,
        signing_secret_key=alice_sk,
        plaintext=b"secret-session-data",
        counter=0,
    )
    identity_key_decrypt_failed = False
    try:
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b",
            session_key=bob_sk[:32],
            sender_public_key=alice_pk,
        )
    except AEADFailedError:
        identity_key_decrypt_failed = True

    print(json.dumps({
        "demo": "demo-forward-secrecy",
        "session_keys_match": alice_keys.tx_key == bob_keys.rx_key,
        "ephemerals_wiped": (not bob_hs.has_ephemeral_secrets() and not alice_hs.has_ephemeral_secrets()),
        "long_term_identity_key_cannot_decrypt": identity_key_decrypt_failed,
    }, indent=2))
    return 0 if identity_key_decrypt_failed else 1


def cmd_demo_chunked_loss() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        logger = AuditLogger("node-bob", str(tmp_path / "audit.log"))
        cache = PersistentReplayCache(tmp_path / "replay.db")
        alice_pk, alice_sk = ml_dsa_65.keygen()
        key = b"M" * 32

        now = [100.0]
        rx = ChunkReceiver(
            local_identity="bob",
            local_device="dev-b",
            replay_cache=cache,
            audit_logger=logger,
            timeout_seconds=10.0,
            clock=lambda: now[0],
        )

        # Reordered delivery succeeds
        envs = chunk_and_seal(
            sender_identity="alice",
            sender_device="dev-a",
            recipient_identity="bob",
            recipient_device="dev-b",
            session_id="sess-chunk-1",
            session_key=key,
            signing_secret_key=alice_sk,
            plaintext=b"A" * 2500,
            chunk_size=1000,
        )
        for env in reversed(envs):
            res = rx.ingest_chunk(env, session_key=key, sender_public_key=alice_pk)
        reordered_ok = (res == b"A" * 2500)

        # Missing chunk triggers delivery_failed_incomplete on timeout
        envs2 = chunk_and_seal(
            sender_identity="alice",
            sender_device="dev-a",
            recipient_identity="bob",
            recipient_device="dev-b",
            session_id="sess-chunk-2",
            session_key=key,
            signing_secret_key=alice_sk,
            plaintext=b"B" * 2500,
            chunk_size=1000,
        )
        rx.ingest_chunk(envs2[0], session_key=key, sender_public_key=alice_pk)
        rx.ingest_chunk(envs2[2], session_key=key, sender_public_key=alice_pk)
        now[0] += 15.0
        timeouts = rx.check_timeouts()

        print(json.dumps({
            "demo": "demo-chunked-loss",
            "reordered_delivered": reordered_ok,
            "incomplete_reported": timeouts,
            "log_valid": AuditLogVerifier().verify_file(str(tmp_path / "audit.log")).is_valid,
        }, indent=2))
        return 0 if (reordered_ok and len(timeouts) == 1 and timeouts[0]["missing_chunks"] == [1]) else 1


def cmd_demo_resumption_binding() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        logger = AuditLogger("node-bob", str(tmp_path / "audit.log"))
        store = PersistentResumptionStore(tmp_path / "resumption.db", audit_logger=logger)
        res_secret = b"R" * 32
        ticket = store.issue_ticket(
            session_id="sess-orig-1",
            peer_identity="alice",
            peer_device="dev-a",
            original_transcript_hash="th-orig",
            resumption_secret=res_secret,
        )

        # Hijack attempt by mallory using alice's session_id
        hijack_rejected = False
        try:
            store.resume(
                ticket,
                presented_identity="mallory",
                presented_device="dev-m",
                fresh_nonce=b"N" * 16,
                proof_of_possession="00",
                new_transcript_hash="th-new",
            )
        except ResumptionPeerMismatchError:
            hijack_rejected = True

        # Legitimate peer resumes
        nonce = b"N" * 16
        pop = store.create_proof_of_possession(res_secret, nonce, "th-new-alice")
        new_keys, _ = store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-new-alice",
        )

        print(json.dumps({
            "demo": "demo-resumption-binding",
            "peer_mismatch_rejected": hijack_rejected,
            "legitimate_peer_resumed": new_keys.peer_identity == "alice",
            "log_valid": AuditLogVerifier().verify_file(str(tmp_path / "audit.log")).is_valid,
        }, indent=2))
        return 0 if (hijack_rejected and new_keys.peer_identity == "alice") else 1


def cmd_verify_logs(path: str | None) -> int:
    if path is None:
        # Verify a freshly generated in-temp log if no path provided
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "verify.log"
            logger = AuditLogger("cli-verify", str(log_path))
            logger.log_event("crypto", "verify_check", "cli", "audit_log", status="SUCCESS")
            res = AuditLogVerifier().verify_file(str(log_path))
            print(json.dumps(res.to_dict(), indent=2))
            return 0 if res.is_valid else 1
    res = AuditLogVerifier().verify_file(path)
    print(json.dumps(res.to_dict(), indent=2))
    return 0 if res.is_valid else 1


def cmd_doc_check() -> int:
    root = _repo_root()
    required_docs = [
        "docs/01-course-provenance.md",
        "docs/02-protocol-risk.md",
        "docs/03-syllabus.md",
        "docs/04-nist-standards.md",
        "docs/05-migration-engineering.md",
        "docs/06-math-foundations.md",
        "docs/07-corrections-and-scope.md",
    ]
    missing: List[str] = []
    broken_links: List[str] = []

    for rel in required_docs:
        p = root / rel
        if not p.exists():
            missing.append(rel)

    checklist_path = root / "docs/07-corrections-and-scope.md"
    unchecked: List[str] = []
    if checklist_path.exists():
        text = checklist_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if line.strip().startswith("- [ ]"):
                unchecked.append(line.strip())
        # Verify markdown links in docs/01-07 and README.md resolve to existing files
        for rel in required_docs + ["README.md"]:
            fp = root / rel
            if not fp.exists():
                continue
            content = fp.read_text(encoding="utf-8")
            for match in re.finditer(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)", content):
                target = match.group(1)
                if target.startswith(("http://", "https://", "mailto:", "file://")):
                    continue
                resolved = (fp.parent / target).resolve()
                if not resolved.exists():
                    broken_links.append(f"{rel} -> {target}")

    ok = not missing and not unchecked and not broken_links
    print(json.dumps({
        "doc_check": "PASS" if ok else "FAIL",
        "missing_docs": missing,
        "unchecked_items": unchecked,
        "broken_links": broken_links,
    }, indent=2))
    return 0 if ok else 1


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m src.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo-replay")
    sub.add_parser("demo-forward-secrecy")
    sub.add_parser("demo-chunked-loss")
    sub.add_parser("demo-resumption-binding")
    vp = sub.add_parser("verify-logs")
    vp.add_argument("--path", default=None)
    sub.add_parser("doc-check")

    args = parser.parse_args(argv)
    if args.command == "demo-replay":
        return cmd_demo_replay()
    if args.command == "demo-forward-secrecy":
        return cmd_demo_forward_secrecy()
    if args.command == "demo-chunked-loss":
        return cmd_demo_chunked_loss()
    if args.command == "demo-resumption-binding":
        return cmd_demo_resumption_binding()
    if args.command == "verify-logs":
        return cmd_verify_logs(args.path)
    if args.command == "doc-check":
        return cmd_doc_check()
    return 1


if __name__ == "__main__":
    sys.exit(main())
