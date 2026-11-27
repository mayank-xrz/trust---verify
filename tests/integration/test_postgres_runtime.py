"""PostgreSQL-only migration and runtime smoke test for the CI service container."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import select, text

from scripts.seed_sandbox import seed_database
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.db import create_db_engine, create_session_factory
from src.identity_keys.models import Device, RateLimit
from src.identity_keys.services import IdentityService
from src.identity_keys.tokens import TokenAuthority

POSTGRES_URL = os.environ.get("POSTGRES_TEST_DATABASE_URL", "")

pytestmark = pytest.mark.skipif(
    not POSTGRES_URL.startswith("postgresql+psycopg://"),
    reason="POSTGRES_TEST_DATABASE_URL is required for the PostgreSQL gate",
)


def test_postgres_migrations_and_auth_rate_limit_runtime() -> None:
    engine = create_db_engine(POSTGRES_URL)
    assert engine.dialect.name == "postgresql"
    session_factory = create_session_factory(engine)
    users = seed_database(session_factory, seed=9001)

    with session_factory() as session:
        device_id = session.execute(
            select(Device.device_id).where(Device.user_id == users["alice"])
        ).scalar_one()

    clock = FakeClock()
    service = IdentityService(
        session_factory,
        clock,
        AuditEmitter(node_id="postgres-ci", clock=clock),
        TokenAuthority(clock),
    )
    challenge = service.issue_challenge(device_id, requester_key="198.51.100.8")
    assert challenge["challenge_id"]

    with session_factory() as session:
        rows = session.execute(select(RateLimit)).scalars().all()
        assert len(rows) == 1
        assert rows[0].attempts == 1

    with engine.connect() as connection:
        payload_type = connection.execute(
            text(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_schema=current_schema() "
                "AND table_name='audit_outbox' AND column_name='payload'"
            )
        ).scalar_one()
    assert payload_type == "jsonb"
