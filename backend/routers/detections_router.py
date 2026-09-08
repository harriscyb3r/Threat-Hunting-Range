"""Detections API: save a successful query, export Sigma, validate against the
clean twin.

A detection is the durable output of a hunt — a query that found something,
saved with its ATT&CK tags and false-positive notes. Validation is what tells
you whether it's any good: run it against the campaign for true positives and
against the twin for false positives, and durability by re-running against a
re-rolled campaign (phase 6 wires the re-roll; the twin check is here).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from deps import hunts, kusto, registry
from detections import to_sigma
from detections.validate import validate as run_validation
from kusto import KustoError, KustoUnavailable
from scenarios import attack as catalogue

logger = logging.getLogger("range.detections")
router = APIRouter(prefix="/api/detections", tags=["detections"])


class NewDetection(BaseModel):
    title: str
    csl: str
    campaign_slug: str = ""
    hunt_id: str = ""
    techniques: list[str] = Field(default_factory=list)
    description: str = ""
    fp_notes: str = ""
    severity: str = "medium"


@router.get("")
async def list_detections(campaign: str | None = None) -> dict:
    return {"detections": hunts.list_detections(campaign)}


@router.post("", status_code=201)
async def save_detection(body: NewDetection) -> dict:
    unknown = [t for t in body.techniques if t not in catalogue.BY_ID]
    if unknown:
        raise HTTPException(422, f"unknown technique ids: {unknown}")
    return hunts.save_detection(
        body.title, body.csl, hunt_id=body.hunt_id, campaign_slug=body.campaign_slug,
        techniques=body.techniques, description=body.description,
        fp_notes=body.fp_notes, severity=body.severity)


@router.get("/{detection_id}")
async def get_detection(detection_id: str) -> dict:
    d = hunts.get_detection(detection_id)
    if not d:
        raise HTTPException(404, "no such detection")
    return d


@router.delete("/{detection_id}")
async def delete_detection(detection_id: str) -> dict:
    hunts.delete_detection(detection_id)
    return {"deleted": detection_id}


@router.get("/{detection_id}/sigma")
async def export_sigma(detection_id: str) -> dict:
    d = hunts.get_detection(detection_id)
    if not d:
        raise HTTPException(404, "no such detection")
    result = to_sigma(
        d["title"], d["csl"], techniques=d.get("techniques", []),
        description=d.get("description", ""), level=d.get("severity", "medium"),
        fp_notes=d.get("fp_notes", ""))
    return {
        "yaml": result.yaml,
        "complete": result.complete,
        "warnings": result.warnings,
        "table": result.table,
    }


class SigmaPreview(BaseModel):
    title: str
    csl: str
    techniques: list[str] = Field(default_factory=list)
    description: str = ""
    severity: str = "medium"
    fp_notes: str = ""


@router.post("/sigma-preview")
async def sigma_preview(body: SigmaPreview) -> dict:
    """Preview the Sigma for a query before saving it, so the Act phase can show
    the conversion (and its warnings) inline."""
    result = to_sigma(
        body.title or "Untitled detection", body.csl, techniques=body.techniques,
        description=body.description, level=body.severity, fp_notes=body.fp_notes)
    return {"yaml": result.yaml, "complete": result.complete,
            "warnings": result.warnings, "table": result.table}


@router.post("/{detection_id}/validate")
async def validate(detection_id: str) -> dict:
    """Run TP (campaign) and FP (clean twin) validation for a saved detection.

    The detection must belong to a campaign that has a twin, or FP can't be
    measured — which is the whole point of the exercise.
    """
    d = hunts.get_detection(detection_id)
    if not d:
        raise HTTPException(404, "no such detection")
    slug = d.get("campaign_slug")
    campaign = registry.get(slug) if slug else None
    if not campaign:
        raise HTTPException(422, "detection has no campaign to validate against")

    twin = next((c for c in registry.list() if c.twin_of == slug), None)
    if not twin:
        raise HTTPException(
            422, f"campaign {slug!r} has no clean twin — rebuild it with the twin to "
            "measure false positives")

    attack_ids = registry.attack_item_ids(slug)
    try:
        result = await run_validation(
            kusto, d["csl"], campaign_db=campaign.db_name, twin_db=twin.db_name,
            attack_item_ids=attack_ids)
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc

    if not result.error and result.can_grade_tp:
        hunts.update_detection_validation(
            detection_id, fp_count=result.fp_count, tp_count=result.tp_count)

    # Contextualise: total planted attack events, so recall is meaningful.
    total_attack = len(attack_ids)
    out = result.as_dict()
    out["total_attack_events"] = total_attack
    out["recall"] = (result.tp_count / total_attack) if total_attack and result.can_grade_tp else None
    return out
