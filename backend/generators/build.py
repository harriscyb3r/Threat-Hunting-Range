"""Campaign builder — org in, populated Kusto database out.

One knob drives volume: `target_events`. Tables are filled in the proportions a
real Sentinel workspace shows, so the *shape* of the haystack is right at any
size. Chasing per-table row counts by hand would drift out of proportion the
first time one generator changed.

Two generators fan out across more than one table (a process execution is both
a `DeviceProcessEvents` row and a 4688), so rows are routed on a `__table` key
rather than assumed to match the generator's name.
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from kusto import KustoClient, asim, ingest, schemas
from org import OrgProfile, build_org

from . import noise
from .benign import endpoint, identity, network
from .common import GenContext

logger = logging.getLogger("range.build")

# Share of total events per table, approximating a real workspace. DNS and
# non-interactive sign-ins dominate; the tables an analyst reaches for first
# (SigninLogs, AuditLogs) are a sliver of the volume, which is the point.
#
# `process` and `logon` are logical generators writing to two tables each; their
# share covers every row they emit.
MIX: dict[str, float] = {
    "dns":        0.300,
    "devnet":     0.180,
    "noninter":   0.130,
    "process":    0.120,   # -> DeviceProcessEvents + SecurityEvent 4688
    "firewall":   0.100,
    "kerberos":   0.055,   # -> SecurityEvent 4768/4769
    "logon":      0.045,   # -> DeviceLogonEvents + SecurityEvent 4624/4625
    "signin":     0.030,
    "devfile":    0.020,
    "office":     0.012,
    "devreg":     0.005,
    "audit":      0.003,
}

# Concurrent .set-or-append streams. Four is where the measured gain flattens.
INGEST_CONCURRENCY = 4

# generator key -> (callable, default destination table)
GENERATORS: dict[str, tuple[Callable[[GenContext, int], Iterator[dict]], str]] = {
    "dns":      (network.dns_events, "DnsEvents"),
    "firewall": (network.firewall_events, "CommonSecurityLog"),
    "signin":   (identity.signin_logs, "SigninLogs"),
    "noninter": (identity.non_interactive_signin_logs, "AADNonInteractiveUserSignInLogs"),
    "audit":    (identity.audit_logs, "AuditLogs"),
    "office":   (identity.office_activity, "OfficeActivity"),
    "process":  (endpoint.process_events, "DeviceProcessEvents"),
    "logon":    (endpoint.logon_events, "DeviceLogonEvents"),
    "kerberos": (endpoint.kerberos_events, "SecurityEvent"),
    "devnet":   (endpoint.device_network_events, "DeviceNetworkEvents"),
    "devfile":  (endpoint.device_file_events, "DeviceFileEvents"),
    "devreg":   (endpoint.device_registry_events, "DeviceRegistryEvents"),
}


@dataclass(slots=True)
class BuildReport:
    database: str = ""
    org_summary: str = ""
    rows_by_table: dict[str, int] = field(default_factory=dict)
    parsers: list[str] = field(default_factory=list)
    labels: dict[str, dict[str, Any]] = field(default_factory=dict)
    generate_s: float = 0.0
    ingest_s: float = 0.0
    bytes_sent: int = 0

    @property
    def total_rows(self) -> int:
        return sum(self.rows_by_table.values())

    @property
    def mb_per_second(self) -> float:
        """The honest throughput metric. Rows/s depends entirely on table width —
        an 18-column DnsEvents row and a 60-column SigninLogs row are not
        comparable units, and the engine is bound by bytes of command text."""
        return (self.bytes_sent / 1e6) / self.ingest_s if self.ingest_s else 0.0

    def summary(self) -> str:
        rate = self.total_rows / self.ingest_s if self.ingest_s else 0
        return (f"{self.total_rows:,} rows across {len(self.rows_by_table)} tables — "
                f"generate {self.generate_s:.1f}s, ingest {self.ingest_s:.1f}s "
                f"({rate:,.0f} rows/s, {self.mb_per_second:.1f} MB/s, "
                f"{self.bytes_sent/1e6:.0f} MB)")

    def table_breakdown(self) -> str:
        width = max((len(t) for t in self.rows_by_table), default=10)
        lines = []
        for table, n in sorted(self.rows_by_table.items(), key=lambda kv: -kv[1]):
            pct = 100 * n / self.total_rows if self.total_rows else 0
            lines.append(f"  {table:<{width}}  {n:>8,}  {pct:5.1f}%")
        return "\n".join(lines)


def generate_benign(org: OrgProfile, target_events: int,
                    *, with_noise: bool = True) -> tuple[dict[str, list[dict]], dict]:
    """Generate all benign telemetry in memory, grouped by destination table.

    Held in memory on purpose: 500k rows is roughly 400 MB of dicts, which is
    fine on a laptop, and it lets the builder report exact counts before writing
    anything to the engine.
    """
    ctx = GenContext.create(org)
    by_table: dict[str, list[dict]] = defaultdict(list)

    for i, (key, share) in enumerate(MIX.items()):
        fn, default_table = GENERATORS[key]
        count = int(target_events * share)
        if count <= 0:
            continue
        # Each generator gets its own stream position but the same seed, so one
        # generator changing does not reshuffle the others.
        ctx.rng.seed(org.seed + i * 7919)
        for row in fn(ctx, count):
            table = row.pop("__table", default_table)
            by_table[table].append(row)

    if with_noise:
        ctx.rng.seed(org.seed + 104729)
        for row in noise.generate_all(ctx):
            # No default here on purpose. A noise generator that forgets
            # __table would otherwise dump its rows into whichever table the
            # default names, and the mistake is invisible until a hunt returns
            # nonsense — it cost one debugging round already.
            if "__table" not in row:
                raise ValueError(
                    f"noise row without __table: {sorted(row)[:6]}... "
                    "every noise generator must name its destination table")
            by_table[row.pop("__table")].append(row)

    # Clamp to the declared window. Timestamps are generated in each user's
    # local time, so a UTC+12 user starting at 09:00 lands on the previous UTC
    # day — correct, but it would put events outside the window a hunt filters
    # on. Clamping keeps `between (window)` honest.
    for rows in by_table.values():
        for r in rows:
            if r["TimeGenerated"] < org.window_start:
                r["TimeGenerated"] = org.window_start
            elif r["TimeGenerated"] > org.window_end:
                r["TimeGenerated"] = org.window_end

    # Kusto does not require sorted ingest, but sorting makes the extents
    # time-ordered, which keeps range queries fast and the data realistic.
    for rows in by_table.values():
        rows.sort(key=lambda r: r["TimeGenerated"])

    return dict(by_table), ctx.labels


async def build_campaign(
    client: KustoClient,
    database: str,
    *,
    preset: str = "midsize",
    seed: int = 1337,
    target_events: int = 300_000,
    window_days: int = 14,
    with_noise: bool = True,
    org: OrgProfile | None = None,
) -> BuildReport:
    """Create tables, generate benign telemetry and ingest it."""
    org = org or build_org(preset, seed, window_days=window_days)
    report = BuildReport(database=database, org_summary=org.summary())
    logger.info("building %s — %s", database, org.summary())

    started = time.perf_counter()
    by_table, labels = generate_benign(org, target_events, with_noise=with_noise)
    report.generate_s = time.perf_counter() - started
    report.labels = labels

    await ingest.create_tables(client, database, schemas.all_schemas())

    # ASIM parsers are created before ingest so the database is queryable both
    # ways the moment the last row lands.
    report.parsers = await asim.deploy(client, database)

    # Ingest tables concurrently. The engine is bound by parsing inline command
    # text, and it parallelises that across connections: measured 2.7 MB/s
    # sequential vs 5.1 MB/s at 3 concurrent and 5.3 at 6, so the useful gain is
    # spent by about four. Beyond that it only adds memory pressure.
    started = time.perf_counter()
    sem = asyncio.Semaphore(INGEST_CONCURRENCY)

    async def write(table: str, rows: list[dict]) -> None:
        async with sem:
            stats = await ingest.ingest_rows(client, database, schemas.get(table), rows)
        report.rows_by_table[table] = stats.rows
        report.bytes_sent += stats.bytes_sent
        logger.info("  %s", stats)

    await asyncio.gather(*(write(t, r) for t, r in sorted(by_table.items())))
    report.ingest_s = time.perf_counter() - started

    logger.info("built %s — %s", database, report.summary())
    return report
