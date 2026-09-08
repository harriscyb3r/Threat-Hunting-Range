"""Batched ingest into Kusto.

Rows are serialised into `.set-or-append <table> <| datatable(...) [...]`
literals. Verified against the engine (see PLAN.md §3.1 and the notes below):

* The engine rejects command text over roughly 2 MB, so batches are sized **by
  serialised bytes**, not by row count. A `DnsEvents` row is ~120 bytes and a
  `DeviceProcessEvents` row with a long command line can be 1.5 KB — a fixed
  row count would either waste round trips or blow the limit depending on the
  table. Byte-based batching sizes itself.

* `datatable` takes *literals only*. `todynamic("...")` and `parse_json("...")`
  are both rejected inside it; `dynamic({...})` with embedded JSON is the only
  form that works for dynamic columns.

* String escaping round-trips backslashes, embedded quotes, tabs, newlines and
  non-ASCII intact — confirmed against the engine rather than assumed, because
  Windows command lines are full of the first two.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from .client import KustoClient
from .schemas import TableSchema

logger = logging.getLogger("range.ingest")

# Command text ceiling is ~2 MB. Flush at 1.5 MB so a single oversized final row
# cannot push a batch over the edge.
MAX_BATCH_BYTES = 1_500_000
MAX_BATCH_ROWS = 20_000


def kql_string(value: str) -> str:
    """A KQL string literal. Order matters: backslash first, or it doubles the
    escapes introduced for the other characters."""
    out = (
        value.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t")
    )
    return f'"{out}"'


def kql_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    # Kusto keeps 100ns ticks; isoformat gives microseconds, which is plenty and
    # round-trips exactly.
    return f"datetime({value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')}Z)"


def kql_value(value: Any, ktype: str) -> str:
    """Serialise one Python value as a KQL literal of the given column type."""
    if value is None:
        return '""' if ktype == "string" else f"{ktype}(null)"

    if ktype == "string":
        return kql_string(value if isinstance(value, str) else str(value))
    if ktype == "datetime":
        if isinstance(value, datetime):
            return kql_datetime(value)
        return f"datetime({value})"
    if ktype in ("int", "long"):
        return str(int(value))
    if ktype == "real":
        return repr(float(value))
    if ktype == "bool":
        return "true" if value else "false"
    if ktype == "guid":
        return f"guid({value})"
    if ktype == "timespan":
        return f"timespan({value})"
    if ktype == "dynamic":
        if isinstance(value, str):
            # Already-serialised JSON. Round-trip it so malformed input fails
            # here rather than as an opaque engine error 10k rows later.
            value = json.loads(value)
        return f"dynamic({json.dumps(value, separators=(',', ':'), ensure_ascii=False)})"
    raise ValueError(f"unsupported Kusto type {ktype!r}")


@dataclass(slots=True)
class IngestStats:
    table: str = ""
    rows: int = 0
    batches: int = 0
    bytes_sent: int = 0
    elapsed_s: float = 0.0
    errors: list[str] = field(default_factory=list)

    @property
    def rows_per_second(self) -> float:
        return self.rows / self.elapsed_s if self.elapsed_s > 0 else 0.0

    def __str__(self) -> str:
        return (f"{self.table}: {self.rows:,} rows in {self.batches} batches, "
                f"{self.elapsed_s:.1f}s ({self.rows_per_second:,.0f}/s)")


async def create_tables(client: KustoClient, db: str, schemas: Sequence[TableSchema]) -> None:
    """Create tables if absent. `.create table` is idempotent for an identical
    schema, so this is safe to re-run."""
    for schema in schemas:
        await client.mgmt(db, schema.create_command())
    logger.info("created %d tables in %s", len(schemas), db)


async def ingest_rows(
    client: KustoClient,
    db: str,
    schema: TableSchema,
    rows: Iterable[dict[str, Any]],
    *,
    columns: Sequence[str] | None = None,
    max_bytes: int = MAX_BATCH_BYTES,
    max_rows: int = MAX_BATCH_ROWS,
) -> IngestStats:
    """Write rows to a table, batching by serialised size.

    Only `columns` are written (defaults to every column in the schema). Any
    column absent from a row becomes a typed null — which is realistic: a real
    `SigninLogs` row leaves most columns empty too.
    """
    cols = tuple(columns) if columns else schema.column_names
    types = [schema.type_of(c) for c in cols]
    header = ", ".join(f"{c}:{t}" for c, t in zip(cols, types))
    prefix = f".set-or-append {schema.name} <| datatable({header}) ["
    stats = IngestStats(table=schema.name)
    started = time.perf_counter()

    buf: list[str] = []
    size = len(prefix)

    async def flush() -> None:
        nonlocal buf, size
        if not buf:
            return
        command = prefix + ",".join(buf) + "]"
        await client.mgmt(db, command)
        stats.batches += 1
        stats.bytes_sent += len(command)
        buf = []
        size = len(prefix)

    for row in rows:
        literal = ",".join(kql_value(row.get(c), t) for c, t in zip(cols, types))
        if buf and (size + len(literal) + 1 > max_bytes or len(buf) >= max_rows):
            await flush()
        buf.append(literal)
        size += len(literal) + 1
        stats.rows += 1

    await flush()
    stats.elapsed_s = time.perf_counter() - started
    return stats
