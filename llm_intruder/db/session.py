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


# Track every Engine we hand out so we can dispose them all at delete time.
# Keyed by absolute path → Engine.  Without this, a project's .db file stays
# locked on Windows after a campaign and ``shutil.rmtree`` raises
# ``PermissionError: [WinError 32] The process cannot access the file …``.
_ENGINE_CACHE: dict[str, Engine] = {}


def get_engine(db_path: str = "llm_intruder.db") -> Engine:
    import os
    key = os.path.abspath(str(db_path))
    cached = _ENGINE_CACHE.get(key)
    if cached is not None:
        return cached
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    _migrate(engine)
    _ENGINE_CACHE[key] = engine
    return engine


def get_session_factory(db_path: str = "llm_intruder.db") -> sessionmaker[Session]:
    engine = get_engine(db_path)
    return sessionmaker(bind=engine, autoflush=True)


def dispose_all_engines() -> None:
    """Close every cached SQLAlchemy engine and clear the cache.

    Must be called before the dashboard tries to delete a project workspace
    on Windows, otherwise the ``.db`` files inside the workspace stay locked
    by the engine's pool and ``shutil.rmtree`` fails with WinError 32.
    """
    for engine in list(_ENGINE_CACHE.values()):
        try:
            engine.dispose()
        except Exception:
            pass
    _ENGINE_CACHE.clear()
