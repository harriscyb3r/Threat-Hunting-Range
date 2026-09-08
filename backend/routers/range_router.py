"""Range administration — engine status, campaign databases, raw KQL.

The /query endpoint here is the seed of the Query Lab. It stays deliberately
thin: hand the analyst's KQL to the engine untouched and hand back either rows
or the engine's own error text. Anything that rewrites a query behind an
analyst's back would teach them the wrong thing about what their KQL does.
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from config import settings
from deps import kusto, registry
from kusto import KustoError, KustoUnavailable
from kusto import admin, schemas
from kusto.asim import UNIFYING_PARSERS

logger = logging.getLogger("range.api")
router = APIRouter(prefix="/api/range", tags=["range"])

_SLUG_RE = re.compile(r"^[a-z][a-z0-9-]{0,40}$")


def db_name_for(slug: str) -> str:
    """Campaign slug -> Kusto database name. `apt29-drill` -> `HR_apt29_drill`."""
    return "HR_" + slug.replace("-", "_")


class CreateCampaign(BaseModel):
    slug: str = Field(..., description="lowercase, digits and hyphens")
    display_name: str | None = None
    seed: int = 0
    with_twin: bool = Field(
        True,
        description="Also create the benign-only twin database used for "
                    "false-positive measurement.",
    )


class QueryRequest(BaseModel):
    db: str
    csl: str
    timeout_s: float | None = None


@router.get("/schema")
async def schema() -> dict:
    """Table and column metadata for the Query Lab editor and schema browser.

    Static — derived from the schema registry, not from a live database — so the
    editor has completion data before any campaign exists.
    """
    tables = []
    for sc in schemas.all_schemas():
        tables.append({
            "name": sc.name,
            "family": sc.family,
            "description": sc.description,
            "docs": sc.docs,
            "columns": [{"name": n, "type": t} for n, t in sc.columns],
        })
    asim = [{"name": name, "schema": schema_name, "kind": "asim"}
            for name, schema_name in UNIFYING_PARSERS.items()]
    return {"tables": tables, "asim": asim}


@router.get("/status")
async def status() -> dict:
    up = await kusto.is_up()
    engine_dbs: list[str] = []
    if up:
        try:
            engine_dbs = sorted(await admin.show_databases(kusto))
        except KustoError as exc:
            logger.warning("could not list databases: %s", exc)

    campaigns = registry.list()
    return {
        "engine": {
            "url": settings.kusto_url,
            "up": up,
            "databases": engine_dbs,
        },
        "campaigns": [
            {
                "slug": c.slug,
                "display_name": c.display_name,
                "db_name": c.db_name,
                "kind": c.kind,
                "twin_of": c.twin_of,
                "status": c.status,
                "attached": c.db_name in engine_dbs,
                "created_at": c.created_at,
            }
            for c in campaigns
        ],
        "drafter": settings.drafter,
    }


@router.get("/campaigns/counts")
async def campaign_counts() -> dict:
    """Total telemetry events per ready campaign database.

    `union *` counts rows across every ingested table (ASIM parsers are stored
    functions, not tables, so they're excluded — this is the raw event volume).
    `count` is served from extent metadata, so it stays cheap even on large
    campaigns. Detached or non-ready databases are skipped; a db that errors
    comes back as null rather than failing the whole call, so one bad campaign
    can't blank the dropdown.
    """
    counts: dict[str, int | None] = {}
    if not await kusto.is_up():
        return {"counts": counts}
    try:
        engine_dbs = set(await admin.show_databases(kusto))
    except KustoError:
        return {"counts": counts}

    for c in registry.list():
        if c.status != "ready" or c.db_name not in engine_dbs:
            continue
        try:
            result = await kusto.query(
                c.db_name, "union isfuzzy=true * | count", timeout=30)
            counts[c.db_name] = int(result.rows[0][0]) if result.rows else 0
        except KustoError as exc:
            logger.warning("count failed for %s: %s", c.db_name, exc)
            counts[c.db_name] = None
    return {"counts": counts}


@router.post("/reconcile")
async def reconcile() -> dict:
    """Re-attach every registered database the engine is not showing."""
    report = await admin.reconcile(kusto, registry.attach_entries())
    if report.attached:
        registry.statuses_by_db(report.attached, "ready")
    if report.missing:
        registry.statuses_by_db(report.missing, "missing")
    return {
        "attached": report.attached,
        "already_present": report.already_present,
        "missing": report.missing,
        "failed": report.failed,
        "summary": report.summary(),
    }


@router.post("/campaigns", status_code=201)
async def create_campaign(body: CreateCampaign) -> dict:
    if not _SLUG_RE.match(body.slug):
        raise HTTPException(
            422,
            "slug must start with a lowercase letter and contain only "
            "lowercase letters, digits and hyphens",
        )
    if registry.get(body.slug):
        raise HTTPException(409, f"campaign {body.slug!r} already exists")

    created: list[str] = []
    try:
        main_db = db_name_for(body.slug)
        action, paths = await admin.ensure_database(kusto, main_db, settings.kusto_data_dir)
        created.append(main_db)
        registry.add(
            body.slug,
            body.display_name or body.slug,
            main_db,
            seed=body.seed,
            status="empty",
            generation=paths.generation,
            md_path=paths.md,
            data_path=paths.data,
        )

        if body.with_twin:
            twin_slug = f"{body.slug}-clean"
            twin_db = db_name_for(twin_slug)
            _, twin_paths = await admin.ensure_database(
                kusto, twin_db, settings.kusto_data_dir)
            created.append(twin_db)
            registry.add(
                twin_slug,
                f"{body.display_name or body.slug} (clean twin)",
                twin_db,
                kind="clean_twin",
                twin_of=body.slug,
                seed=body.seed,
                status="empty",
                generation=twin_paths.generation,
                md_path=twin_paths.md,
                data_path=twin_paths.data,
            )
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KustoError as exc:
        raise HTTPException(502, f"engine rejected database creation: {exc}") from exc

    return {"slug": body.slug, "databases": created, "action": action}


@router.delete("/campaigns/{slug}")
async def delete_campaign(slug: str) -> dict:
    campaign = registry.get(slug)
    if not campaign:
        raise HTTPException(404, f"no campaign {slug!r}")

    # Drop the twin alongside its parent; a twin without its campaign is only
    # a source of confusion.
    targets = [campaign]
    targets += [c for c in registry.list() if c.twin_of == slug]

    detached: list[str] = []
    purged: list[str] = []
    for target in targets:
        try:
            await admin.detach_database(kusto, target.db_name)
            detached.append(target.db_name)
        except KustoUnavailable as exc:
            raise HTTPException(503, str(exc)) from exc
        except KustoError as exc:
            raise HTTPException(502, f"could not detach {target.db_name}: {exc}") from exc
        if target.md_path and admin.purge_paths(
                admin.PersistPaths(target.generation, target.md_path, target.data_path),
                mount=settings.kusto_volume_mount):
            purged.append(target.db_name)
        registry.remove(target.slug)

    # `.drop database` only detaches — the files stay on the volume unless this
    # process can see it. Say which happened rather than reporting "deleted".
    return {
        "detached": detached,
        "files_purged": purged,
        "note": ("files remain on the Docker volume; they are unreferenced and "
                 "will never be reattached" if len(purged) < len(detached) else ""),
    }


@router.post("/campaigns/{slug}/reset")
async def reset_campaign(slug: str) -> dict:
    """Empty a campaign's database, ready for a rebuild.

    Moves it to a new persist generation, because the engine cannot create a
    database over a path that already holds files and dropping does not remove
    them.
    """
    campaign = registry.get(slug)
    if not campaign:
        raise HTTPException(404, f"no campaign {slug!r}")
    try:
        paths = await admin.reset_database(
            kusto, campaign.db_name, settings.kusto_data_dir, campaign.generation)
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KustoError as exc:
        raise HTTPException(502, f"could not reset {campaign.db_name}: {exc}") from exc
    registry.set_paths(slug, paths.generation, paths.md, paths.data)
    registry.set_status(slug, "empty")
    return {"slug": slug, "generation": paths.generation, "md_path": paths.md}


@router.post("/query")
async def run_query(body: QueryRequest) -> dict:
    """Execute KQL and return columns/rows, or the engine's own error."""
    try:
        result = await kusto.query(body.db, body.csl, timeout=body.timeout_s)
    except KustoUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except KustoError as exc:
        # 200 with an error payload, not a 4xx: a rejected query is a normal
        # outcome in a query editor, and the UI renders the message inline
        # rather than treating it as a transport failure.
        return {
            "ok": False,
            "error": {"message": exc.message, "code": exc.code},
            "columns": [], "rows": [], "elapsed_ms": 0.0,
        }
    return {
        "ok": True,
        "columns": result.columns,
        "column_types": result.column_types,
        "rows": result.rows,
        "row_count": len(result.rows),
        "elapsed_ms": round(result.elapsed_ms, 2),
    }
