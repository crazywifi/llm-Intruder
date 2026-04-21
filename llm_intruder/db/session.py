from __future__ import annotations

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from llm_intruder.db.schema import Base


def _migrate(engine: Engine) -> None:
    """Apply lightweight schema migrations for columns added after initial release."""
    with engine.connect() as conn:
        # Add request_payload column to trials if missing (added in v3+)
        result = conn.execute(text("PRAGMA table_info(trials)"))
        existing_cols = {row[1] for row in result}
        if "request_payload" not in existing_cols:
            conn.execute(text("ALTER TABLE trials ADD COLUMN request_payload TEXT"))
            conn.commit()
        if "target_url" not in existing_cols:
            conn.execute(text("ALTER TABLE trials ADD COLUMN target_url TEXT"))
            conn.commit()


def get_engine(db_path: str = "llm_intruder.db") -> Engine:
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    _migrate(engine)
    return engine


def get_session_factory(db_path: str = "llm_intruder.db") -> sessionmaker[Session]:
    engine = get_engine(db_path)
    return sessionmaker(bind=engine, autoflush=True)
