"""Curriculum and campaign-library API.

Serves the SC-200 aligned lesson content and the shipped campaign library, plus
lightweight lesson-completion tracking so the Learn page can show progress.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from deps import hunts, registry
from curriculum import MODULES, LESSON_BY_ID, total_lessons
from scenarios import library

router = APIRouter(prefix="/api", tags=["curriculum"])


@router.get("/library")
async def library_list() -> dict:
    """The shipped campaign library, with which ones are already built."""
    built = {c.slug for c in registry.list()}
    entries = library.list_entries()
    for e in entries:
        e["built"] = e["slug"] in built
    return {"campaigns": entries}


@router.get("/library/{slug}/spec")
async def library_spec(slug: str) -> dict:
    entry = library.get(slug)
    if not entry:
        raise HTTPException(404, f"no library campaign {slug!r}")
    return {"spec": entry.to_spec().as_dict(), "meta": entry.meta()}


@router.get("/curriculum")
async def curriculum() -> dict:
    completed = set(hunts.completed_lessons())
    modules = []
    for m in MODULES:
        md = m.as_dict()
        for lesson in md["lessons"]:
            lesson["completed"] = lesson["id"] in completed
        modules.append(md)
    return {
        "modules": modules,
        "total_lessons": total_lessons(),
        "completed": len(completed),
    }


class LessonProgress(BaseModel):
    completed: bool


@router.post("/curriculum/lessons/{lesson_id}/progress")
async def set_progress(lesson_id: str, body: LessonProgress) -> dict:
    if lesson_id not in LESSON_BY_ID:
        raise HTTPException(404, f"no lesson {lesson_id!r}")
    if body.completed:
        hunts.complete_lesson(lesson_id)
    else:
        hunts.uncomplete_lesson(lesson_id)
    return {"lesson_id": lesson_id, "completed": body.completed}
