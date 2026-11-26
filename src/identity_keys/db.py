"""SQLAlchemy 2.x database engine and transactional session helpers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """Declarative base for all identity_keys models."""


def get_database_url() -> str:
    """Resolve DATABASE_URL from env (defaults to local SQLite file if unset)."""
    return os.environ.get("DATABASE_URL", "sqlite+pysqlite:///./tbv_identity.db")


def create_db_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine with FK enforcement enabled for SQLite."""
    url = database_url or get_database_url()
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, future=True, pool_pre_ping=True, connect_args=connect_args)

    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _connection_record) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create a bound sessionmaker."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)


@contextmanager
def tx_session(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    """Execute work inside a single atomic DB transaction."""
    session = session_factory()
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()
