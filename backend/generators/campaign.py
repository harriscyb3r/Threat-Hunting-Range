"""Compile a ScenarioSpec into a populated campaign.

The layering is what makes a hunt real:

    benign baseline   (build.py)      the haystack
  + ambient noise     (noise.py)      benign anomalies that look hunt-worthy
  + technique decoys  (decoys.py)     benign lookalikes of THIS hunt
  + attack chain      (attack/*)      the needles, ground-truth labelled

All four share one org and one time window, so the attack is genuinely buried
rather than sitting in a clean side-channel. Attack timestamps fall inside the
benign window, attack hosts are real org hosts, attack accounts are real org
accounts — an analyst pivoting from any attack event lands in plausible
surrounding activity.

The clean twin is the same call with `attack=False`: identical benign baseline
and decoys, no attack chain. A detection's false-positive rate against the twin
is therefore its FP rate against *this org's* benign behaviour, decoys included.
"""
from __future__ import annotations

import logging
import random
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from kusto import KustoClient, asim, ingest, schemas
from org import OrgProfile, build_org
from scenarios import attack as catalogue
from scenarios.models import ScenarioSpec

from . import decoys, noise
from .attack import EmitContext, StepPlan, build_intrusion, get as get_emitter, has as has_emitter
from .attack.base import Intrusion
from .build import GENERATORS, MIX, INGEST_CONCURRENCY
from .common import GenContext

logger = logging.getLogger("range.campaign")


@dataclass(slots=True)
class CampaignReport:
    database: str = ""
    spec_name: str = ""
    org_summary: str = ""
    rows_by_table: dict[str, int] = field(default_factory=dict)
    attack_rows: int = 0
    decoy_rows: int = 0
    noise_rows: int = 0
    benign_rows: int = 0
    labels: dict[str, dict[str, Any]] = field(default_factory=dict)
    steps: list[dict] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    generate_s: float = 0.0
    ingest_s: float = 0.0
    bytes_sent: int = 0
    parsers: list[str] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        return sum(self.rows_by_table.values())

    def summary(self) -> str:
        return (f"{self.total_rows:,} rows — {self.attack_rows} attack, "
                f"{self.decoy_rows} decoy, {self.noise_rows} noise across "
                f"{len(self.rows_by_table)} tables; generate {self.generate_s:.1f}s, "
                f"ingest {self.ingest_s:.1f}s")


# Context depth -> share of the full benign baseline to generate around the
# attack. `isolated` still needs *some* baseline or the attack stands alone.
_DEPTH_BENIGN = {"isolated": 0.15, "contextual": 1.0, "full-chain": 1.0}


def _plan_steps(spec: ScenarioSpec, org: OrgProfile,
                rng: random.Random) -> list[StepPlan]:
    """Turn spec steps into concrete plans with timestamps and variants."""
    plans: list[StepPlan] = []
    for i, step in enumerate(spec.steps):
        if not has_emitter(step.technique_id):
            continue
        emitter = get_emitter(step.technique_id)
        variant = step.variant or emitter.pick_variant(rng).key
        start = org.window_start + timedelta(
            days=step.day_offset,
            hours=rng.randint(9, 20),          # attacks happen during "business"
            minutes=rng.randint(0, 59),
        )
        # Keep inside the window.
        start = max(org.window_start, min(start, org.window_end - timedelta(hours=1)))
        plans.append(StepPlan(technique_id=step.technique_id, variant=variant,
                              start=start, loudness=step.loudness,
                              params=dict(step.params), step_index=i))
    plans.sort(key=lambda p: p.start)
    return plans


def generate_campaign(
    spec: ScenarioSpec, org: OrgProfile, *,
    target_events: int, attack: bool = True,
) -> tuple[dict[str, list[dict]], dict, list[dict]]:
    """Generate all rows for a campaign.

    Returns (rows_by_table, labels, step_summaries). With `attack=False` the
    attack chain is skipped — that is the clean twin.
    """
    by_table: dict[str, list[dict]] = defaultdict(list)

    # 1. Benign baseline, scaled by context depth.
    depth = _DEPTH_BENIGN.get(spec.context_depth, 1.0)
    benign_ctx = GenContext.create(org)
    benign_target = int(target_events * depth)
    for i, (key, share) in enumerate(MIX.items()):
        fn, default_table = GENERATORS[key]
        count = int(benign_target * share)
        if count <= 0:
            continue
        benign_ctx.rng.seed(org.seed + i * 7919)
        for row in fn(benign_ctx, count):
            by_table[row.pop("__table", default_table)].append(row)

    # 2. Ambient noise.
    benign_ctx.rng.seed(org.seed + 104729)
    for row in noise.generate_all(benign_ctx):
        if "__table" not in row:
            raise ValueError(f"noise row without __table: {sorted(row)[:6]}")
        by_table[row.pop("__table")].append(row)

    # 3. Technique decoys, for the techniques this campaign hunts.
    if spec.decoys:
        benign_ctx.rng.seed(org.seed + 26861)
        for row in decoys.generate(benign_ctx, spec.technique_ids):
            by_table[row.pop("__table", "SecurityEvent")].append(row)

    step_summaries: list[dict] = []

    # 4. The attack chain — one intrusion, threaded through every step so the
    #    story stays coherent.
    if attack:
        attack_ctx = GenContext.create(org, seed_offset=spec.seed_offset + 900)
        intrusion = build_intrusion(attack_ctx, seed_offset=spec.seed_offset)
        plans = _plan_steps(spec, org, attack_ctx.rng)
        for plan in plans:
            emitter = get_emitter(plan.technique_id)
            ectx = EmitContext(gen=attack_ctx, intrusion=intrusion, plan=plan)
            before = len(attack_ctx.labels)
            produced = 0
            for row in emitter.fn(ectx):
                by_table[row.pop("__table", "SecurityEvent")].append(row)
                produced += 1
            step_summaries.append({
                "technique_id": plan.technique_id,
                "technique_name": catalogue.get(plan.technique_id).name,
                "variant": plan.variant,
                "variant_label": emitter.variant(plan.variant).label,
                "loudness": plan.loudness,
                "start": plan.start.isoformat(),
                "rows": produced,
                "labelled": len(attack_ctx.labels) - before,
                "host": intrusion.current_host().name,
            })
        # Merge attack labels into the benign context's label map.
        benign_ctx.labels.update(attack_ctx.labels)

    # Clamp to the window and sort each table by time.
    for rows_list in by_table.values():
        for r in rows_list:
            if r["TimeGenerated"] < org.window_start:
                r["TimeGenerated"] = org.window_start
            elif r["TimeGenerated"] > org.window_end:
                r["TimeGenerated"] = org.window_end
        rows_list.sort(key=lambda r: r["TimeGenerated"])

    return dict(by_table), benign_ctx.labels, step_summaries


async def build_campaign_from_spec(
    client: KustoClient, database: str, spec: ScenarioSpec, *,
    preset: str = "midsize", seed: int = 1337,
    target_events: int = 300_000, attack: bool = True,
    org: OrgProfile | None = None,
) -> CampaignReport:
    """Full build: generate, create tables, deploy ASIM, ingest."""
    import asyncio

    org = org or build_org(preset, seed, window_days=spec.window_days)
    report = CampaignReport(database=database, spec_name=spec.name,
                            org_summary=org.summary())
    report.unresolved = spec.unresolved()
    events = spec.target_events or target_events

    t0 = time.perf_counter()
    by_table, labels, steps = generate_campaign(
        spec, org, target_events=events, attack=attack)
    report.generate_s = time.perf_counter() - t0
    report.labels = labels
    report.steps = steps

    kinds = Counter(v.get("kind") for v in labels.values())
    report.attack_rows = kinds.get("attack", 0)
    report.decoy_rows = kinds.get("decoy", 0)
    report.noise_rows = kinds.get("noise", 0)
    total = sum(len(v) for v in by_table.values())
    report.benign_rows = total - report.attack_rows - report.decoy_rows - report.noise_rows

    await ingest.create_tables(client, database, schemas.all_schemas())
    report.parsers = await asim.deploy(client, database)

    t0 = time.perf_counter()
    sem = asyncio.Semaphore(INGEST_CONCURRENCY)

    async def write(table: str, rows_list: list[dict]) -> None:
        async with sem:
            stats = await ingest.ingest_rows(client, database, schemas.get(table), rows_list)
        report.rows_by_table[table] = stats.rows
        report.bytes_sent += stats.bytes_sent

    await asyncio.gather(*(write(t, r) for t, r in sorted(by_table.items())))
    report.ingest_s = time.perf_counter() - t0

    logger.info("built %s from spec %r — %s", database, spec.name, report.summary())
    return report
