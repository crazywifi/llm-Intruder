from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from llm_intruder.db.schema import AuditLogEntry


def sha256(data: str) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def write_audit_entry(
    session: Session,
    engagement_id: str,
    event_type: str,
    operator: str = "system",
    payload: str = "",
    response: str = "",
    details: dict[str, Any] | None = None,
) -> AuditLogEntry:
    """Write a SHA-256-hashed audit log entry and commit to the database."""
    entry = AuditLogEntry(
        engagement_id=engagement_id,
        timestamp=datetime.now(UTC),
        event_type=event_type,
        payload_hash=sha256(payload),
        response_hash=sha256(response),
        operator=operator,
        details=json.dumps(details or {}),
    )
    session.add(entry)
    session.commit()
    return entry
