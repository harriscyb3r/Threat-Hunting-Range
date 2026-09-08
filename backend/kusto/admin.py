"""Database lifecycle for the range.

Three engine behaviours drive this module, all established by probing the
emulator directly rather than assumed (PLAN.md §3.1):

1. A persistent database must be created with explicit md/data paths under the
   mounted volume. Without `persist (...)` it is memory-only and dies with the
   container.

2. **Persisted databases are not auto-attached.** Recreate the container and
   `.show databases` lists only NetDefaultDB while every campaign still sits on
   the volume, intact and invisible. `reconcile()` fixes that at startup.

3. **`.drop database` does not delete anything.** It detaches. Every file stays
   on the volume, `.attach` brings the rows straight back, and creating a new
   database over the same path fails with an internal service error. `.detach
   database` behaves identically.

Point 3 is why persist paths are **generation-scoped**:

    /kustodata/dbs/<name>/gen3/md
    /kustodata/dbs/<name>/gen3/data

Resetting a campaign drops it and recreates at the next generation, which is a
guaranteed-empty path. The registry records the live path, so reconciliation
attaches the right generation and never resurrects a superseded one. Old
generations leak on the volume; `purge_paths()` removes them when the volume is
reachable, and `docker compose down -v` clears everything.
"""
from __future__ import annotations

import logging
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .client import KustoClient, KustoError

logger = logging.getLogger("range.kusto.admin")

MASTER_DB = "NetDefaultDB"

# Database names are interpolated into control-command text, so they are
# validated rather than escaped. A conservative subset costs nothing and closes
# the injection path outright.
_DB_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,62}$")


class InvalidDatabaseName(ValueError):
    pass


def validate_db_name(name: str) -> str:
    if not _DB_NAME_RE.match(name or ""):
        raise InvalidDatabaseName(
            f"invalid database name {name!r}: must start with a letter and contain "
            "only letters, digits and underscores (max 63 chars)"
        )
    return name


@dataclass(frozen=True, slots=True)
class PersistPaths:
    generation: int
    md: str
    data: str

    @property
    def root(self) -> str:
        return self.md.rsplit("/", 1)[0]


def persist_paths(name: str, root: str, generation: int = 1) -> PersistPaths:
    validate_db_name(name)
    if generation < 1:
        raise ValueError("generation starts at 1")
    base = f"{root.rstrip('/')}/{name}/gen{generation}"
    return PersistPaths(generation, f"{base}/md", f"{base}/data")


@dataclass(slots=True)
class ReconcileReport:
    attached: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.failed and not self.missing

    def summary(self) -> str:
        bits = []
        if self.attached:
            bits.append(f"{len(self.attached)} attached")
        if self.already_present:
            bits.append(f"{len(self.already_present)} already up")
        if self.missing:
            bits.append(f"{len(self.missing)} missing")
        if self.failed:
            bits.append(f"{len(self.failed)} failed")
        return ", ".join(bits) or "nothing to do"


async def show_databases(client: KustoClient) -> set[str]:
    result = await client.mgmt(MASTER_DB, ".show databases | project DatabaseName")
    return {row[0] for row in result.rows}


async def create_database(client: KustoClient, name: str, paths: PersistPaths) -> None:
    """Create a persistent database at `paths`. The path must be empty — see the
    module docstring on why that means a new generation after every drop."""
    validate_db_name(name)
    await client.mgmt(
        MASTER_DB,
        f'.create database {name} persist ( @"{paths.md}", @"{paths.data}" )',
    )
    logger.info("created database %s at %s", name, paths.md)


async def attach_database(client: KustoClient, name: str, md_path: str) -> None:
    validate_db_name(name)
    await client.mgmt(MASTER_DB, f'.attach database {name} from @"{md_path}"')
    logger.info("attached database %s from %s", name, md_path)


async def detach_database(client: KustoClient, name: str) -> None:
    """Remove the database from the engine's view.

    Named `detach` rather than `drop` on purpose: `.drop database` in this engine
    does not delete data, and calling it "drop" led to an API that reported
    campaigns as deleted while their telemetry sat on the volume, reattachable.
    """
    validate_db_name(name)
    await client.mgmt(MASTER_DB, f".drop database {name} ifexists")
    logger.info("detached database %s (files remain on the volume)", name)


def purge_paths(paths: PersistPaths, *, mount: str | None = None) -> bool:
    """Best-effort delete of a generation's files.

    Only possible when this process can see the volume — true for the
    containerised backend, false when running on the host against a named
    volume. Returns whether anything was removed; the caller treats False as
    "leaked, harmless" rather than an error, because nothing references a
    superseded generation.
    """
    target = Path(mount) / paths.root.lstrip("/") if mount else Path(paths.root)
    try:
        if target.is_dir():
            shutil.rmtree(target)
            logger.info("purged %s", target)
            return True
    except OSError as exc:
        logger.warning("could not purge %s: %s", target, exc)
    return False


async def next_generation(client: KustoClient, name: str, root: str,
                          current: int, *, max_probe: int = 50) -> PersistPaths:
    """Find the next usable generation for a database.

    Normally `current + 1`, but if a previous run died between creating the
    directory and recording it, that path is occupied and the engine rejects it.
    Rather than track that separately, try successive generations until one is
    accepted — the engine is the only authority on whether a path is empty.
    """
    validate_db_name(name)
    for gen in range(current + 1, current + 1 + max_probe):
        paths = persist_paths(name, root, gen)
        try:
            await create_database(client, name, paths)
            return paths
        except KustoError as exc:
            if "must be empty" in str(exc) or "internal service error" in str(exc).lower():
                continue
            raise
    raise KustoError(
        f"no empty persist path for {name} after {max_probe} generations from {current + 1}")


async def ensure_database(client: KustoClient, name: str, root: str,
                          *, md_path: str | None = None,
                          generation: int = 1) -> tuple[str, PersistPaths]:
    """Make `name` queryable. Returns (action, paths).

    Attach is tried before create: a database whose files survive on the volume
    must be reattached, not recreated, or the new one starts empty alongside
    orphaned data that still holds the real telemetry.
    """
    validate_db_name(name)
    paths = persist_paths(name, root, generation)
    if md_path:
        paths = PersistPaths(generation, md_path, md_path.rsplit("/", 1)[0] + "/data")

    if name in await show_databases(client):
        return "present", paths
    try:
        await attach_database(client, name, paths.md)
        return "attached", paths
    except KustoError as exc:
        logger.debug("attach of %s failed (%s); creating", name, exc)
    try:
        await create_database(client, name, paths)
        return "created", paths
    except KustoError as exc:
        if "must be empty" not in str(exc) and "internal service error" not in str(exc).lower():
            raise
        # The path is occupied by files the engine will not attach. Move on to a
        # clean generation rather than failing the whole campaign.
        paths = await next_generation(client, name, root, generation)
        return "created", paths


async def reset_database(client: KustoClient, name: str, root: str,
                         current_generation: int) -> PersistPaths:
    """Empty a campaign: detach, then recreate at the next generation."""
    await detach_database(client, name)
    return await next_generation(client, name, root, current_generation)


async def reconcile(client: KustoClient, entries: list[tuple[str, str]]) -> ReconcileReport:
    """Re-attach registered databases the engine is not currently showing.

    `entries` is [(db_name, md_path)] from the registry — not a disk scan, since
    the backend may be running on the host with no access to the volume. It also
    means a deleted campaign stays deleted: leftover files are never resurrected
    because nothing references them any more.
    """
    report = ReconcileReport()
    if not entries:
        return report

    present = await show_databases(client)
    for name, md_path in entries:
        try:
            validate_db_name(name)
        except InvalidDatabaseName as exc:
            report.failed[name] = str(exc)
            continue
        if name in present:
            report.already_present.append(name)
            continue
        try:
            await attach_database(client, name, md_path)
            report.attached.append(name)
        except KustoError as exc:
            text = str(exc).lower()
            if any(s in text for s in ("not found", "does not exist", "no such")):
                report.missing.append(name)
            else:
                report.failed[name] = str(exc)
    return report
