from __future__ import annotations

import hashlib
import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from llm_intruder.core.audit_log import sha256, write_audit_entry
from llm_intruder.db.schema import AuditLogEntry, Base


@pytest.fixture()
def db_session():
    """In-memory SQLite session, torn down after each test."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()


# ── sha256 helper ─────────────────────────────────────────────────────────────

def test_sha256_known_value() -> None:
    result = sha256("hello")
    expected = hashlib.sha256(b"hello").hexdigest()
    assert result == expected


def test_sha256_empty_string() -> None:
    result = sha256("")
    assert result == hashlib.sha256(b"").hexdigest()


def test_sha256_returns_64_char_hex() -> None:
    result = sha256("llm-intruder")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)


# ── write_audit_entry ─────────────────────────────────────────────────────────

def test_write_audit_entry_creates_row(db_session) -> None:
    entry = write_audit_entry(
        db_session,
        engagement_id="ENG-001",
        event_type="session_start",
        operator="test",
        payload="test-payload",
        response="",
        details={"dry_run": True},
    )
    assert entry.id is not None
    assert entry.engagement_id == "ENG-001"
    assert entry.event_type == "session_start"
    assert entry.operator == "test"


def test_write_audit_entry_hashes_payload(db_session) -> None:
    payload = "sensitive-data"
    entry = write_audit_entry(
        db_session,
        engagement_id="ENG-001",
        event_type="probe",
        payload=payload,
    )
    assert entry.payload_hash == sha256(payload)
    assert payload not in entry.payload_hash  # raw value must not appear


def test_write_audit_entry_hashes_response(db_session) -> None:
    response = "model-output"
    entry = write_audit_entry(
        db_session,
        engagement_id="ENG-001",
        event_type="probe",
        response=response,
    )
    assert entry.response_hash == sha256(response)


def test_write_audit_entry_details_serialised_as_json(db_session) -> None:
    details = {"scope_count": 3, "dry_run": False}
    entry = write_audit_entry(
        db_session,
        engagement_id="ENG-001",
        event_type="session_start",
        details=details,
    )
    parsed = json.loads(entry.details)
    assert parsed == details


def test_write_audit_entry_persisted_to_db(db_session) -> None:
    write_audit_entry(
        db_session,
        engagement_id="ENG-002",
        event_type="session_start",
    )
    rows = db_session.query(AuditLogEntry).filter_by(engagement_id="ENG-002").all()
    assert len(rows) == 1
    assert rows[0].event_type == "session_start"


def test_write_multiple_entries(db_session) -> None:
    for i in range(5):
        write_audit_entry(
            db_session,
            engagement_id="ENG-003",
            event_type=f"event_{i}",
        )
    rows = db_session.query(AuditLogEntry).filter_by(engagement_id="ENG-003").all()
    assert len(rows) == 5
