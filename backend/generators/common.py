"""Shared generation context and helpers.

Every generator takes a `GenContext` and yields plain dicts keyed by real column
name. Two rules hold throughout:

**Determinism.** Generators never touch the global `random` module. All
randomness comes from `ctx.rng`, seeded from the campaign seed, so a rebuild
produces byte-identical telemetry.

**Realistic timing.** Events cluster in each user's *local* working hours, not
UTC. A Perth user starting at 08:00 local is 00:00 UTC; if everything were
generated against UTC business hours, "logon outside business hours" would be a
meaningless hunt and the range would teach a false lesson.
"""
from __future__ import annotations

import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from org import Device, OrgProfile, User


@dataclass(slots=True)
class GenContext:
    org: OrgProfile
    rng: random.Random
    # Ground truth accumulates here: _ItemId -> label. Benign rows are not
    # recorded (absence means benign), which keeps this small.
    labels: dict[str, dict[str, Any]] = field(default_factory=dict)
    _counter: int = 0
    # Namespaces the row ids. A campaign builds several contexts against the same
    # org (benign baseline, attack chain), and if they shared an id space their
    # _ItemIds would collide — two different rows with the same id, and ground
    # truth pointing at the wrong one. `stream` keeps each context's ids disjoint
    # while staying fully deterministic.
    stream: int = 0

    @classmethod
    def create(cls, org: OrgProfile, seed_offset: int = 0) -> "GenContext":
        return cls(org=org, rng=random.Random(org.seed + seed_offset),
                   stream=seed_offset)

    def item_id(self) -> str:
        """A unique, deterministic row id.

        Folds org seed, the context's stream and the counter together, so the
        same build always produces the same ids (ground truth lines up on a
        re-roll) while ids from different contexts never collide.
        """
        self._counter += 1
        mixed = ((self.org.seed & 0xFFFFFFFF) << 96) \
            | ((self.stream & 0xFFFFFFFF) << 64) \
            | ((self._counter * 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF)
        return str(uuid.UUID(int=mixed & ((1 << 128) - 1), version=4))

    def label(self, item_id: str, **attrs: Any) -> None:
        """Mark a row as attack or decoy. Phase 2 uses this; benign rows never do."""
        self.labels[item_id] = attrs

    def platform(self, table: str, ts: datetime, resource_id: str = "") -> dict[str, Any]:
        return {
            "TenantId": self.org.tenant_id,
            "SourceSystem": "Azure",
            "TimeGenerated": ts,
            "Type": table,
            "_ItemId": self.item_id(),
            "_ResourceId": resource_id,
        }

    # ── Picking entities ─────────────────────────────────────────────────

    def pick_human(self) -> User:
        return self.rng.choice(self.org.humans)

    def pick_workstation(self) -> Device:
        return self.rng.choice(self.org.workstations)

    def device_for(self, user: User) -> Device | None:
        if not user.device_names:
            return None
        return self.org.device(user.device_names[0])

    def weighted(self, options: list[tuple]) -> tuple:
        return self.rng.choices(options, weights=[o[-1] for o in options], k=1)[0]


def days_in_window(org: OrgProfile) -> list[datetime]:
    """Midnight UTC for each day of the campaign window."""
    out, day = [], org.window_start
    while day < org.window_end:
        out.append(day)
        day += timedelta(days=1)
    return out


def day_weight(org: OrgProfile, day: datetime) -> float:
    """Relative activity for a day. Weekends and public holidays are quiet but
    never silent — someone always works Sunday, and that is a real hunting
    problem rather than a clean signal."""
    if (day.month, day.day) in _HOLIDAYS:
        return 0.10
    if day.weekday() == 5:
        return 0.13
    if day.weekday() == 6:
        return 0.09
    return 1.0


from org.catalog import PUBLIC_HOLIDAYS as _HOLIDAYS  # noqa: E402


def work_time(ctx: GenContext, day: datetime, user: User) -> datetime:
    """A timestamp on `day`, weighted to this user's local working hours.

    Roughly 88% land inside the working day, with a lunch dip and a small
    evening tail. The remainder is genuine off-hours work — which is why an
    "after hours logon" hunt has to be smarter than `hourofday() !between (9 .. 17)`.
    """
    rng = ctx.rng
    offset = user.location.utc_offset_h
    roll = rng.random()

    if roll < 0.88:
        span = max(1, user.work_end_h - user.work_start_h)
        local_h = user.work_start_h + rng.random() * span
        # Lunch dip: nudge a slice of midday activity outward.
        if 12.0 <= local_h < 13.0 and rng.random() < 0.45:
            local_h += rng.choice([-1.5, 1.5])
    elif roll < 0.97:
        # Evening catch-up.
        local_h = user.work_end_h + rng.random() * 4
    else:
        # Small hours. Real, and rare.
        local_h = rng.random() * 6

    utc_h = local_h - offset
    return day + timedelta(hours=utc_h, seconds=rng.randint(0, 59),
                           microseconds=rng.randint(0, 999999))


def any_time(ctx: GenContext, day: datetime) -> datetime:
    """Uniform across the day — for machine activity that has no working hours."""
    return day + timedelta(seconds=ctx.rng.randint(0, 86399),
                           microseconds=ctx.rng.randint(0, 999999))


def scheduled_time(ctx: GenContext, day: datetime, hour: int, jitter_min: int = 8) -> datetime:
    """A recurring job: same UTC hour daily, with a little jitter."""
    return day + timedelta(hours=hour,
                           minutes=ctx.rng.randint(0, 59),
                           seconds=ctx.rng.randint(-jitter_min * 60, jitter_min * 60) % 60)


def spread_over_days(ctx: GenContext, total: int) -> list[tuple[datetime, int]]:
    """Split a total event budget across the window, weighted by day."""
    days = days_in_window(ctx.org)
    weights = [day_weight(ctx.org, d) for d in days]
    tw = sum(weights) or 1.0
    out = []
    assigned = 0
    for i, (day, w) in enumerate(zip(days, weights)):
        n = int(total * w / tw) if i < len(days) - 1 else total - assigned
        assigned += n
        out.append((day, max(0, n)))
    return out


def rand_hex(rng: random.Random, length: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(length))


def file_hashes(rng: random.Random, name: str) -> tuple[str, str, str]:
    """Stable per-filename hashes: the same binary must hash the same everywhere,
    or hash-based pivoting silently breaks."""
    h = random.Random(f"hash:{name}")
    return rand_hex(h, 40), rand_hex(h, 64), rand_hex(h, 32)


def logon_id(rng: random.Random) -> str:
    return f"0x{rng.randint(0x10000, 0xFFFFFFF):x}"


def public_ip(rng: random.Random) -> str:
    """A plausible external address, avoiding reserved ranges."""
    first = rng.choice([13, 20, 23, 34, 40, 52, 54, 64, 72, 104, 140, 151, 172, 185, 199, 203])
    return f"{first}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def batched(iterator: Iterator[dict], size: int) -> Iterator[list[dict]]:
    batch: list[dict] = []
    for row in iterator:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch
