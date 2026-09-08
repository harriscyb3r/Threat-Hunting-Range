"""Kusto Threat Hunting Range — backend entry point.

Run:  .venv/Scripts/python -m uvicorn main:app --port 8780 --reload

Binds to loopback. This is a single-user practice tool with no authentication,
which is only defensible while it stays unreachable off the machine.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from config import settings
from deps import kusto, registry
from kusto import KustoUnavailable
from kusto import admin
from routers import (curriculum_router, detections_router, hunts_router,
                     range_router, scenarios_router)
from store import SCHEMA_VERSION

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
# httpx logs every request at INFO. Ingest fires one request per 10k-row batch,
# so this would bury the useful output under hundreds of identical lines.
logging.getLogger("httpx").setLevel(logging.WARNING)

logger = logging.getLogger("range")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("registry ready: schema v%s at %s", SCHEMA_VERSION, settings.db_path)

    # Wait for the engine, then reattach persisted databases.
    #
    # This is the whole reason the reconciler exists. Persisted databases are
    # NOT auto-attached: recreate the container and `.show databases` returns
    # only NetDefaultDB while every campaign still sits on the volume, intact
    # and invisible. Without this step each `docker compose down` would look
    # exactly like total data loss.
    try:
        waited = await kusto.wait_ready(timeout=settings.kusto_ready_timeout_s)
        logger.info("kusto ready at %s (%.1fs)", settings.kusto_url, waited)
    except KustoUnavailable as exc:
        # Start anyway. The UI can then show "engine down" and offer a retry,
        # which beats a backend that refuses to boot because Docker is slow.
        logger.error("kusto not reachable: %s", exc)
        logger.error("backend is up but the range is unusable until the engine starts")
    else:
        expected = registry.attach_entries()
        if expected:
            report = await admin.reconcile(kusto, expected)
            if report.attached:
                registry.statuses_by_db(report.attached, "ready")
            if report.missing:
                registry.statuses_by_db(report.missing, "missing")
                logger.warning(
                    "registered but no data on the volume: %s", ", ".join(report.missing)
                )
            for name, err in report.failed.items():
                logger.error("could not attach %s: %s", name, err)
            logger.info("database reconcile: %s", report.summary())
        else:
            logger.info("no campaigns registered yet")

    yield

    await kusto.aclose()
    registry.close()


app = FastAPI(title="Hunting Range API", version="0.1.0", lifespan=lifespan)

_ALLOWED_ORIGINS = [
    "http://localhost:5175", "http://127.0.0.1:5175",   # Vite dev server (phase 3)
    f"http://localhost:{settings.port}", f"http://127.0.0.1:{settings.port}",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type"],
)
# Result sets are large, repetitive JSON — they compress extremely well.
app.add_middleware(GZipMiddleware, minimum_size=1024)

app.include_router(range_router.router)
app.include_router(scenarios_router.router)
app.include_router(hunts_router.router)
app.include_router(detections_router.router)
app.include_router(curriculum_router.router)


@app.get("/api/health")
async def health() -> dict:
    return {
        "ok": True,
        "service": "hunting-range",
        "schema_version": SCHEMA_VERSION,
        "engine_up": await kusto.is_up(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
