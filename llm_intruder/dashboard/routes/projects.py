"""Project CRUD routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from llm_intruder.dashboard.models import ProjectCreate, ProjectSummary
from llm_intruder.dashboard.project_store import create_project, delete_project, get_project, list_projects

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("", response_model=list[ProjectSummary])
def list_all_projects() -> list[ProjectSummary]:
    return list_projects()


@router.post("", response_model=ProjectSummary, status_code=201)
def new_project(req: ProjectCreate) -> ProjectSummary:
    return create_project(req)


@router.get("/{project_id}", response_model=ProjectSummary)
def get_one_project(project_id: str) -> ProjectSummary:
    try:
        return get_project(project_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/{project_id}", status_code=204)
def remove_project(project_id: str) -> None:
    """Permanently delete a project and all its run data from disk."""
    try:
        delete_project(project_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
