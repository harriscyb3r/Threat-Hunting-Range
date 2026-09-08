"""Scenario resolution and campaign building — the behaviour-first API.

This is what the phase-3 UI drives. The flow:

    POST /api/scenarios/resolve   "WMI abuse"  -> ranked candidates + ambiguity
    POST /api/scenarios/spec      chosen ids   -> an editable ScenarioSpec
    POST /api/scenarios/build     a spec       -> a populated campaign (background)

Building runs in a background task because a 300k-event campaign takes ~70s;
the endpoint returns immediately and status is polled via /api/range/status.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from config import settings
from deps import kusto, registry
from kusto import KustoError, KustoUnavailable, admin
from org import build_org
from scenarios import attack as catalogue
from scenarios import resolver
from scenarios.models import ScenarioSpec, spec_from_techniques
from scenarios.drafter import draft_from_cti

logger = logging.getLogger("range.scenarios")
router = APIRouter(prefix="/api/scenarios", tags=["scenarios"])

_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


def db_name_for(slug: str) -> str:
    return "HR_" + slug.replace("-", "_")


class ResolveRequest(BaseModel):
    text: str


class SpecRequest(BaseModel):
    technique_ids: list[str]
    name: str = ""
    context_depth: str = "contextual"
    loudness: int = 3
    window_days: int = 14


class BuildRequest(BaseModel):
    slug: str
    spec: dict
    seed: int = 1337
    preset: str = "midsize"
    target_events: int = 200_000
    with_twin: bool = True
    reset: bool = False


@router.get("/techniques")
async def techniques() -> dict:
    """The full catalogue, for the technique browser."""
    from generators.attack import all_emitters
    emitters = all_emitters()
    out = []
    for t in sorted(catalogue.CATALOGUE, key=lambda x: (catalogue.tactic_sort_key(x), x.id)):
        e = emitters.get(t.id)
        out.append({
            "id": t.id, "name": t.name, "tactic": t.tactic,
            "summary": t.summary, "tables": list(t.tables), "url": t.attack_url,
            "has_emitter": e is not None,
            "variants": [
                {"key": v.key, "label": v.label, "tells": v.tells, "defeats": v.defeats}
                for v in (e.variants if e else [])
            ],
        })
    return {"techniques": out, "count": len(out),
            "implemented": sum(1 for t in out if t["has_emitter"])}


class DraftRequest(BaseModel):
    text: str
    name: str = ""
    loudness: int = 3
    window_days: int = 14


@router.post("/draft")
async def draft(body: DraftRequest) -> dict:
    """Actor-first: parse a pasted CTI report into a draft campaign spec.

    Runs locally (no API cost) — extracts the ATT&CK techniques the report
    names, the actor, and IOC counts, and drafts a kill-chain spec the analyst
    reviews before building. Techniques the report names but the range can't yet
    plant are returned separately so nothing is silently dropped.
    """
    if not body.text.strip():
        raise HTTPException(422, "no text to parse")
    d = draft_from_cti(body.text, name=body.name, loudness=body.loudness,
                       window_days=body.window_days)
    return d.as_dict()


@router.post("/resolve")
async def resolve(body: ResolveRequest) -> dict:
    candidates = resolver.resolve(body.text)
    return {
        "text": body.text,
        "ambiguous": resolver.ambiguous(candidates),
        "candidates": [c.as_dict() for c in candidates],
    }


@router.post("/spec")
async def make_spec(body: SpecRequest) -> dict:
    unknown = [t for t in body.technique_ids if t not in catalogue.BY_ID]
    if unknown:
        raise HTTPException(422, f"unknown technique ids: {unknown}")
    spec = spec_from_techniques(
        body.technique_ids, name=body.name or "", context_depth=body.context_depth,
        loudness=body.loudness, window_days=body.window_days)
    return {"spec": spec.as_dict(), "unresolved": spec.unresolved()}


async def _run_build(slug: str, spec: ScenarioSpec, body: BuildRequest) -> None:
    """Background campaign build. Errors are recorded on the campaign status."""
    from generators.campaign import build_campaign_from_spec
    org = build_org(body.preset, body.seed, window_days=spec.window_days)
    targets = [(slug, db_name_for(slug), True)]
    if body.with_twin:
        targets.append((f"{slug}-clean", db_name_for(f"{slug}-clean"), False))
    try:
        for s, db, with_attack in targets:
            registry.set_status(s, "building")
            report = await build_campaign_from_spec(
                kusto, db, spec, preset=body.preset, seed=body.seed,
                target_events=body.target_events, attack=with_attack, org=org)
            if with_attack:
                registry.store_ground_truth(s, report.labels)
                registry.store_spec(s, json.dumps(spec.as_dict()),
                                    json.dumps(report.steps))
            registry.set_status(s, "ready")
        logger.info("campaign %s built", slug)
    except (KustoError, KustoUnavailable) as exc:
        logger.error("build of %s failed: %s", slug, exc)
        registry.set_status(slug, "failed")


@router.post("/build", status_code=202)
async def build(body: BuildRequest) -> dict:
    if not _SLUG_RE.match(body.slug):
        raise HTTPException(422, "invalid slug")
    try:
        spec = ScenarioSpec.from_dict(body.spec)
    except (KeyError, TypeError) as exc:
        raise HTTPException(422, f"invalid spec: {exc}") from exc

    existing = registry.get(body.slug)
    if existing and not body.reset:
        raise HTTPException(409, f"campaign {body.slug!r} exists; pass reset=true to rebuild")

    # Provision databases synchronously so a failure here is a clean 4xx/5xx,
    # then hand the slow generation off to the background.
    try:
        targets = [(body.slug, db_name_for(body.slug), True)]
        if body.with_twin:
            targets.append((f"{body.slug}-clean", db_name_for(f"{body.slug}-clean"), False))
        for slug, db, with_attack in targets:
            ex = registry.get(slug)
            if ex and body.reset:
                paths = await admin.reset_database(
                    kusto, db, settings.kusto_data_dir, ex.generation)
                registry.set_paths(slug, paths.generation, paths.md, paths.data)
            elif not ex:
                _a, paths = await admin.ensure_database(kusto, db, settings.kusto_data_dir)
                registry.add(slug, body.spec.get("name", slug) if with_attack
                             else f"{body.spec.get('name', slug)} (clean twin)",
                             db, seed=body.seed,
                             kind="campaign" if with_attack else "clean_twin",
                             twin_of=None if with_attack else body.slug,
                             generation=paths.generation, md_path=paths.md,
                             data_path=paths.data, status="building")
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KustoError as exc:
        raise HTTPException(502, str(exc)) from exc

    asyncio.create_task(_run_build(body.slug, spec, body))
    return {"slug": body.slug, "status": "building",
            "poll": "/api/range/status",
            "note": "generation runs in the background; watch status for 'ready'"}


@router.get("/campaigns/{slug}/answer-key")
async def answer_key(slug: str) -> dict:
    """Study-mode reveal: the planted steps and ground-truth counts.

    Deliberately a separate endpoint from the campaign status, so the UI can
    keep a hunt blind by default and only fetch this when Study mode is on.
    """
    campaign = registry.get(slug)
    if not campaign:
        raise HTTPException(404, f"no campaign {slug!r}")
    stored = registry.get_spec(slug)
    if not stored:
        raise HTTPException(404, "no spec recorded for this campaign")
    spec_json, steps_json = stored
    return {
        "slug": slug,
        "spec": json.loads(spec_json),
        "steps": json.loads(steps_json),
        "ground_truth": registry.ground_truth_counts(slug),
    }
