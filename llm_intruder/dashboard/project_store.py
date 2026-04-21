"""Project workspace management — creates/lists/reads project folders."""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from llm_intruder.dashboard.models import ProjectCreate, ProjectSummary

# Default root: ~/llm_intruder_projects/
_DEFAULT_ROOT = Path.home() / "llm_intruder_projects"


def _root() -> Path:
    root = _DEFAULT_ROOT
    root.mkdir(parents=True, exist_ok=True)
    return root


def _slug(name: str) -> str:
    """Convert project name to a safe folder name."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", name.strip())[:64]


def _meta_path(project_dir: Path) -> Path:
    return project_dir / ".sentinel_meta.json"


def _load_meta(project_dir: Path) -> dict:
    p = _meta_path(project_dir)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_meta(project_dir: Path, meta: dict) -> None:
    _meta_path(project_dir).write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )


def create_project(req: ProjectCreate) -> ProjectSummary:
    slug = _slug(req.name)
    project_dir = _root() / slug
    if project_dir.exists():
        # Load existing instead of overwriting
        return get_project(slug)
    project_dir.mkdir(parents=True)
    (project_dir / "runs").mkdir()
    meta = {
        "id": slug,
        "name": req.name,
        "description": req.description,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _save_meta(project_dir, meta)
    return _summary(project_dir, meta)


def list_projects() -> list[ProjectSummary]:
    root = _root()
    summaries = []
    for d in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if d.is_dir() and not d.name.startswith("."):
            meta = _load_meta(d)
            if meta:
                summaries.append(_summary(d, meta))
    return summaries


def get_project(project_id: str) -> ProjectSummary:
    project_dir = _root() / project_id
    if not project_dir.exists():
        raise KeyError(f"Project '{project_id}' not found")
    meta = _load_meta(project_dir)
    return _summary(project_dir, meta)


def get_project_dir(project_id: str) -> Path:
    d = _root() / project_id
    if not d.exists():
        raise KeyError(f"Project '{project_id}' not found")
    return d


def _summary(project_dir: Path, meta: dict) -> ProjectSummary:
    runs_dir = project_dir / "runs"
    run_dirs = sorted(runs_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True) if runs_dir.exists() else []
    run_count = len([r for r in run_dirs if r.is_dir()])
    last_run_at = None
    last_run_mode = None
    last_run_status = None
    if run_dirs:
        run_meta_path = run_dirs[0] / "run_meta.json"
        if run_meta_path.exists():
            try:
                rm = json.loads(run_meta_path.read_text())
                last_run_at = rm.get("started_at")
                last_run_mode = rm.get("run_mode")
                last_run_status = rm.get("status")
            except Exception:
                pass
    return ProjectSummary(
        id=meta.get("id", project_dir.name),
        name=meta.get("name", project_dir.name),
        description=meta.get("description", ""),
        created_at=meta.get("created_at", ""),
        run_count=run_count,
        last_run_at=last_run_at,
        last_run_mode=last_run_mode,
        last_run_status=last_run_status,
        workspace_path=str(project_dir),
    )


def create_run_dir(project_id: str, run_id: str) -> Path:
    project_dir = get_project_dir(project_id)
    run_dir = project_dir / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def list_run_dirs(project_id: str) -> list[Path]:
    project_dir = get_project_dir(project_id)
    runs_dir = project_dir / "runs"
    if not runs_dir.exists():
        return []
    return sorted(
        [d for d in runs_dir.iterdir() if d.is_dir()],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )


def get_run_meta(project_id: str, run_id: str) -> dict:
    run_dir = get_project_dir(project_id) / "runs" / run_id
    path = run_dir / "run_meta.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def delete_project(project_id: str) -> None:
    """Permanently remove the project directory and all its run data.

    On Windows, SQLite files inside run directories may be held open by a
    background process (e.g. a previous campaign run that has not fully
    shut down).  We close any sqlite3 connections we can reach, then attempt
    the removal.  If a file is still locked we force-remove what we can and
    rename the remainder so the directory no longer appears in the project list.
    """
    import shutil
    import sqlite3
    import time

    project_dir = _root() / project_id
    if not project_dir.exists():
        raise KeyError(f"Project '{project_id}' not found")

    # Step 1: Flush any lingering sqlite3 connections to DB files inside the project
    for db_file in project_dir.rglob("*.db"):
        try:
            con = sqlite3.connect(str(db_file))
            con.close()
        except Exception:
            pass

    # Step 2: Attempt a normal rmtree with a retry-on-error handler
    errors: list = []

    def _on_error(func, path, exc_info):
        """Retry after a short pause (Windows file-lock race); record failures."""
        import stat as _stat
        try:
            Path(path).chmod(_stat.S_IWRITE)
            func(path)
        except Exception:
            time.sleep(0.05)
            try:
                func(path)
            except Exception as e:
                errors.append((path, e))

    shutil.rmtree(str(project_dir), onerror=_on_error)

    # Step 3: If the directory still exists (locked files remain), rename it
    # so it no longer appears as a valid project in list_projects().
    if project_dir.exists():
        import uuid as _uuid
        tombstone = project_dir.parent / f".deleted_{project_id}_{_uuid.uuid4().hex[:8]}"
        try:
            project_dir.rename(tombstone)
        except Exception:
            pass
        # Remove the meta file so list_projects() skips this directory
        for candidate in (project_dir, tombstone):
            try:
                _meta_path(candidate).unlink(missing_ok=True)
            except Exception:
                pass


def save_run_meta(project_id: str, run_id: str, meta: dict) -> None:
    run_dir = create_run_dir(project_id, run_id)
    (run_dir / "run_meta.json").write_text(
        json.dumps(meta, indent=2), encoding="utf-8"
    )
