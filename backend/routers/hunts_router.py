"""PEAK hunt workspace API.

Everything the hunt UI drives: creating a hunt, editing the ABLE hypothesis,
running searches (which are auto-logged), pinning evidence, promoting findings,
saving detections, exporting Sigma, and validating a detection against the clean
twin.

The one place this differs from the plain /api/range/query endpoint: searches
run *inside a hunt* are logged, so the Act-phase write-up and the phase-6 scorer
have a record of what the analyst actually did — how many queries before the
first true positive, which pivots they took.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from deps import hunts, kusto, registry
from hunts.scoring import score_hunt, scoreboard
from hunts.reveal import attack_events as reveal_attack_events
from detections import to_sigma
from detections.validate import validate as validate_detection
from kusto import KustoError, KustoUnavailable
from scenarios import attack as catalogue

logger = logging.getLogger("range.hunts")
router = APIRouter(prefix="/api/hunts", tags=["hunts"])


# ── Hunts ────────────────────────────────────────────────────────────────

class NewHunt(BaseModel):
    campaign_slug: str
    title: str
    hunt_type: str = "hypothesis"


class HuntPatch(BaseModel):
    title: str | None = None
    phase: str | None = None
    actor: str | None = None
    behavior: str | None = None
    location: str | None = None
    evidence_expected: str | None = None
    scope: str | None = None
    data_sources: list[str] | None = None
    success_criteria: str | None = None
    techniques: list[str] | None = None
    writeup: str | None = None
    outcome: str | None = None


@router.get("")
async def list_hunts(campaign: str | None = None) -> dict:
    return {"hunts": hunts.list_hunts(campaign)}


def _draft_hypothesis(campaign_slug: str) -> dict:
    """A first-draft ABLE hypothesis seeded from the campaign's primary technique.

    Uses only the public catalogue reference — the technique summary, its tables,
    and its variant tells — the same material on the Techniques page. It never
    reads ground truth, so it hints at *what to look for*, not what was planted.
    Returns {} when the campaign has no stored spec or no known technique.
    """
    import json

    from generators import attack as emitters

    stored = registry.get_spec(campaign_slug)
    if not stored:
        return {}
    try:
        spec = json.loads(stored[0])
    except (ValueError, TypeError):
        return {}
    tids = [s.get("technique_id") for s in spec.get("steps", []) if s.get("technique_id")]
    primary = next((t for t in tids if t in catalogue.BY_ID), None)
    if not primary:
        return {}

    t = catalogue.BY_ID[primary]
    tables = ", ".join(t.tables) if t.tables else "the relevant tables"
    tells = []
    if emitters.has(primary):
        tells = [v.tells for v in emitters.get(primary).variants if v.tells][:2]
    return {
        "techniques": [primary],
        "data_sources": list(t.tables),
        "actor": "An adversary operating with valid access, assumed post-compromise.",
        "behavior": t.summary,
        "location": f"Expected in {tables}.",
        "evidence_expected": "; ".join(tells) if tells else f"Telemetry consistent with {t.name}.",
    }


@router.post("", status_code=201)
async def create_hunt(body: NewHunt) -> dict:
    if not registry.get(body.campaign_slug):
        raise HTTPException(404, f"no campaign {body.campaign_slug!r}")
    seed = _draft_hypothesis(body.campaign_slug)
    return hunts.create_hunt(body.campaign_slug, body.title,
                             hunt_type=body.hunt_type, seed=seed)


@router.get("/{hunt_id}")
async def get_hunt(hunt_id: str) -> dict:
    h = hunts.get_hunt(hunt_id)
    if not h:
        raise HTTPException(404, "no such hunt")
    return {
        "hunt": h,
        "searches": hunts.list_searches(hunt_id),
        "evidence": hunts.list_evidence(hunt_id),
        "findings": hunts.list_findings(hunt_id),
    }


@router.patch("/{hunt_id}")
async def patch_hunt(hunt_id: str, body: HuntPatch) -> dict:
    if not hunts.get_hunt(hunt_id):
        raise HTTPException(404, "no such hunt")
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    return hunts.update_hunt(hunt_id, fields)  # type: ignore[return-value]


@router.delete("/{hunt_id}")
async def delete_hunt(hunt_id: str) -> dict:
    hunts.delete_hunt(hunt_id)
    return {"deleted": hunt_id}


@router.get("/scoreboard/summary")
async def scoreboard_summary() -> dict:
    """Aggregate scores + ATT&CK coverage across every hunt."""
    return scoreboard(hunts, registry)


@router.get("/{hunt_id}/score")
async def score(hunt_id: str) -> dict:
    """Grade the hunt against ground truth and return the answer key.

    This is the debrief: the metrics plus what was actually planted, so the
    analyst can see how they did and what they missed or were fooled by.
    """
    result = score_hunt(hunts, registry, hunt_id)
    if result is None:
        raise HTTPException(404, "no such hunt")
    return result.as_dict()


@router.get("/{hunt_id}/attack-events")
async def attack_events(hunt_id: str) -> dict:
    """The specific planted attack log rows, each flagged found or missed.

    Turns "you surfaced 0 of 10" into the actual events — the exact logs the
    attacker generated — so the analyst can see precisely what they missed.
    Queries the campaign database, so it's a separate call from the score (kept
    lazy: only fetched when the debrief is expanded).
    """
    hunt = hunts.get_hunt(hunt_id)
    if not hunt:
        raise HTTPException(404, "no such hunt")
    slug = hunt["campaign_slug"]
    campaign = registry.get(slug)
    if not campaign:
        raise HTTPException(404, "campaign not found")

    attack_ids = registry.attack_item_ids(slug)
    found = set(hunts.evidence_item_ids(hunt_id)) & attack_ids
    techniques = registry.planted_techniques(slug)
    try:
        events = await reveal_attack_events(
            kusto, campaign.db_name, attack_item_ids=attack_ids,
            found_item_ids=found, techniques=techniques)
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc

    return {
        "events": events,
        "total": len(attack_ids),
        "found": len(found),
        "missed": len(attack_ids) - len(found),
    }


# ── Searches (auto-logged query execution) ───────────────────────────────

class SearchRequest(BaseModel):
    csl: str
    db: str


@router.post("/{hunt_id}/search")
async def run_search(hunt_id: str, body: SearchRequest) -> dict:
    """Run a query in the context of a hunt and log it.

    Returns the same shape as /api/range/query, plus the logged search id so the
    UI can attach pinned evidence to it.
    """
    if not hunts.get_hunt(hunt_id):
        raise HTTPException(404, "no such hunt")
    try:
        result = await kusto.query(body.db, body.csl)
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KustoError as exc:
        search = hunts.log_search(hunt_id, body.csl, body.db, row_count=0,
                                  elapsed_ms=0, ok=False, error=exc.message)
        return {"ok": False, "error": {"message": exc.message, "code": exc.code},
                "columns": [], "rows": [], "search_id": search["id"]}

    search = hunts.log_search(hunt_id, body.csl, body.db, row_count=len(result.rows),
                              elapsed_ms=result.elapsed_ms, ok=True)
    return {
        "ok": True,
        "columns": result.columns,
        "column_types": result.column_types,
        "rows": result.rows,
        "row_count": len(result.rows),
        "elapsed_ms": round(result.elapsed_ms, 2),
        "search_id": search["id"],
    }


# ── Evidence ─────────────────────────────────────────────────────────────

class PinRequest(BaseModel):
    row: dict
    search_id: str = ""
    note: str = ""


@router.post("/{hunt_id}/evidence")
async def pin_evidence(hunt_id: str, body: PinRequest) -> dict:
    if not hunts.get_hunt(hunt_id):
        raise HTTPException(404, "no such hunt")
    return hunts.pin_evidence(hunt_id, body.row, search_id=body.search_id, note=body.note)


@router.delete("/evidence/{evidence_id}")
async def unpin_evidence(evidence_id: str) -> dict:
    hunts.unpin_evidence(evidence_id)
    return {"deleted": evidence_id}


# ── Findings ─────────────────────────────────────────────────────────────

class NewFinding(BaseModel):
    title: str
    technique: str = ""
    confidence: str = "medium"
    description: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


@router.post("/{hunt_id}/findings")
async def create_finding(hunt_id: str, body: NewFinding) -> dict:
    if not hunts.get_hunt(hunt_id):
        raise HTTPException(404, "no such hunt")
    if body.technique and body.technique not in catalogue.BY_ID:
        raise HTTPException(422, f"unknown technique {body.technique!r}")
    return hunts.create_finding(
        hunt_id, body.title, technique=body.technique, confidence=body.confidence,
        description=body.description, evidence_ids=body.evidence_ids)


@router.delete("/findings/{finding_id}")
async def delete_finding(finding_id: str) -> dict:
    hunts.delete_finding(finding_id)
    return {"deleted": finding_id}
