"""Exercise device authorization and missed key revocation on live localhost services."""

import json
import os
import secrets
import sqlite3
import tempfile
from contextlib import ExitStack, closing
from pathlib import Path

from alembic import command
from alembic.config import Config

from scripts.measure_live_revocation import start_node, wait_for_sync
from scripts.measure_revocation import REPO_ROOT, _enroll_and_authenticate
from scripts.seed_sandbox import seed_database
from src.identity_keys.crypto import b64e, generate_ed25519_keypair
from src.identity_keys.db import create_db_engine, create_session_factory


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def expect_denial(response, status, detail):
    if response.status_code != status or response.json().get("detail") != detail:
        raise RuntimeError(f"Expected {status} {detail}; received {response.status_code}")


def run():
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="tbv-device-send-")))
        db = f"sqlite+pysqlite:///{directory / 'identity.db'}"
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db)
        command.upgrade(cfg, "head")
        engine = create_db_engine(db)
        stack.callback(engine.dispose)
        users = seed_database(create_session_factory(engine))
        _, seed = generate_ed25519_keypair()
        admin, operator, enroll, sync, recipient = (secrets.token_urlsafe(32) for _ in range(5))
        authority = start_node(stack, directory, "device-authority", {
            **os.environ, "DATABASE_URL": db,
            "ADMIN_ENROLL_TOKEN": admin, "TOKEN_SIGNING_SEED_B64": b64e(seed),
            "CLUSTER_SYNC_SECRET": secrets.token_urlsafe(32), "HEARTBEAT_INTERVAL_MS": "250",
        })
        wait_for_sync("device-authority", authority)
        admin_headers = {"X-Admin-Enroll-Token": admin}
        device_id, device_token = _enroll_and_authenticate(
            authority, users["alice"], "device-to-revoke", admin_headers,
        )
        _, unaffected = _enroll_and_authenticate(authority, users["alice"], "unaffected", admin_headers)
        _, revoker = _enroll_and_authenticate(authority, users["carol"], "administrator", admin_headers)
        common = {
            **os.environ, "DEMO_OPERATOR_TOKEN": operator, "DEMO_PEER_ENROLL_TOKEN": enroll,
            "DEMO_RECIPIENT_TOKEN": recipient, "DEMO_REVOCATION_SYNC_TOKEN": sync,
            "PEER_NODES": "", "DEMO_DEVICE_AUTHORITY_URL": "", "DEMO_DEVICE_RESOURCES": "{}",
            "DEMO_PEER_AUTHORITIES": "{}",
        }

        def start_transport(scope, node, **configuration):
            return start_node(
                scope, directory, node, {**common, "DATA_DIR": str(directory / node), **configuration},
                app="demo.node.server:app", health="/health",
            )

        receiver = start_transport(stack, "node-b")
        old_bundle = receiver.get("/keys/public").raise_for_status().json()

        def start_sender(scope):
            return start_transport(
                scope, "node-a", DEMO_DEVICE_AUTHORITY_URL=str(authority.base_url),
                DEMO_DEVICE_RESOURCES=json.dumps({"node-b": "brief-alpha"}),
                DEMO_PEER_AUTHORITIES=json.dumps({"node-b": str(receiver.base_url)}),
            )

        def bind(sender, bundle):
            sender.post("/peers", json=bundle, headers=bearer(enroll)).raise_for_status()

        def send(sender, token, message):
            return sender.post(
                "/send", json={"recipient_id": "node-b", "payload": {"message": message}},
                headers={**bearer(operator), "X-Device-Authorization": f"Bearer {token}"},
            )

        def deliver(sender, token, message):
            envelope = send(sender, token, message).raise_for_status().json()["envelope"]
            receipt = receiver.post("/receive", json=envelope).raise_for_status().json()
            delivered = receiver.get(f"/inbox/{receipt['receipt_id']}", headers=bearer(recipient))
            if delivered.raise_for_status().json()["payload"] != {"message": message}:
                raise RuntimeError("Delivered payload did not match")

        with ExitStack() as online:
            sender = start_sender(online)
            bind(sender, old_bundle)
            bind(receiver, sender.get("/keys/public").raise_for_status().json())
            deliver(sender, device_token, "before device revocation")
            authority.post(
                "/revocations/device", headers=bearer(revoker),
                json={"device_id": device_id, "reason_code": "DEVICE_LOST"},
            ).raise_for_status()
            expect_denial(send(sender, device_token, "fresh message"), 403, "DEVICE_REVOKED")
            deliver(sender, unaffected, "unaffected device")
            print("[PASS] Device authorization: delivery, DEVICE_REVOKED denial, unaffected delivery")

        receiver.post("/keys/revoke", headers=bearer(operator), json={
            "key_id": old_bundle["kem_key_id"],
        }).raise_for_status()
        sender = start_sender(stack)
        bind(sender, old_bundle)
        expect_denial(send(sender, unaffected, "stale peer bundle"), 409, "Peer recipient key is revoked")

        # The pull must persist what it learned, not just deny on this request.
        with closing(sqlite3.connect(directory / "node-a/node-a_inbox.sqlite3")) as state:
            if state.execute("SELECT 1 FROM revoked_peer_keys WHERE peer_id=? AND key_id=?",
                             ("node-b", old_bundle["kem_key_id"])).fetchone() is None:
                raise RuntimeError("Missed revocation was not recorded locally")

        receiver.post("/keys/rotate", headers=bearer(operator)).raise_for_status()
        new_bundle = receiver.get("/keys/public").raise_for_status().json()
        bind(sender, new_bundle)
        dispatched = send(sender, unaffected, "replacement key").raise_for_status().json()
        if dispatched["envelope"]["key_id"] != new_bundle["kem_key_id"]:
            raise RuntimeError("Sender did not use the replacement key")
        print("[PASS] Reconnected sender persisted the missed revocation and sealed with the replacement key")


if __name__ == "__main__":
    run()
