"""Attack emitter framework.

Three ideas hold this together.

**Intrusion state.** An attack is a chain, not a bag of events. If step 3
picks a random host, an analyst who pivots from step 2's host finds nothing and
the story falls apart. `Intrusion` carries the beachhead, the compromised
account, the credentials harvested so far and the hosts reached, so each step
builds on the last.

**Variants.** Every emitter offers several ways to perform the technique, and
the campaign builder picks a subset the analyst is not told. Some variants exist
specifically to break the obvious query — a single targeted kerberoast defeats
`count() > threshold`, an AES-only roast defeats `TicketEncryptionType == "0x17"`.
A detection only scores well if it survives a re-roll.

**Loudness.** A 1-5 dial controlling artefact count, dwell and cleanup. At 1 the
attacker is careful and slow; at 5 they are smashing through. The same technique
at different loudness is a genuinely different hunt.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterator

from org import Device, OrgProfile, User

from ..common import GenContext


@dataclass(frozen=True, slots=True)
class Variant:
    """One way of performing a technique."""

    key: str
    label: str
    tells: str          # what it looks like in telemetry
    defeats: str = ""   # the naive query this variant breaks, if any
    weight: float = 1.0


@dataclass(slots=True)
class Intrusion:
    """State shared across every step of one attack chain."""

    org: OrgProfile
    rng: random.Random

    # Entities the attacker holds.
    victim: User                      # the initially compromised user
    beachhead: Device                 # the first host
    c2_domain: str
    c2_ip: str

    stolen_creds: list[User] = field(default_factory=list)
    reached_hosts: list[Device] = field(default_factory=list)
    admin_creds: User | None = None
    staging_dir: str = r"C:\Windows\Temp"
    payload_name: str = "update.exe"

    def __post_init__(self) -> None:
        if self.beachhead not in self.reached_hosts:
            self.reached_hosts.append(self.beachhead)

    def current_host(self) -> Device:
        return self.reached_hosts[-1]

    def current_user(self) -> User:
        return self.admin_creds or (self.stolen_creds[-1] if self.stolen_creds else self.victim)

    def reach(self, device: Device) -> None:
        if device not in self.reached_hosts:
            self.reached_hosts.append(device)

    def steal(self, user: User) -> None:
        if user not in self.stolen_creds:
            self.stolen_creds.append(user)
        if user.is_admin and self.admin_creds is None:
            self.admin_creds = user

    def pick_target(self, *, servers: bool = False, exclude_reached: bool = True) -> Device:
        pool = self.org.servers if servers else self.org.devices
        if exclude_reached:
            pool = [d for d in pool if d not in self.reached_hosts] or pool
        return self.rng.choice(pool)


@dataclass(slots=True)
class StepPlan:
    """One technique execution within a campaign."""

    technique_id: str
    variant: str
    start: datetime
    loudness: int = 3
    params: dict = field(default_factory=dict)
    step_index: int = 0

    def jitter(self, rng: random.Random, minutes: int = 5) -> datetime:
        return self.start + timedelta(seconds=rng.randint(0, minutes * 60))


@dataclass(slots=True)
class EmitContext:
    """Everything an emitter needs, plus labelling."""

    gen: GenContext
    intrusion: Intrusion
    plan: StepPlan

    @property
    def rng(self) -> random.Random:
        return self.gen.rng

    @property
    def org(self) -> OrgProfile:
        return self.gen.org

    def mark(self, rows: list[dict] | dict, note: str = "") -> list[dict]:
        """Record rows as attack activity in ground truth.

        Keyed on `_ItemId`, a genuine Log Analytics column, so scoring is exact
        without a hidden grading field the analyst could notice.
        """
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            self.gen.label(
                row["_ItemId"],
                kind="attack",
                technique=self.plan.technique_id,
                variant=self.plan.variant,
                step=self.plan.step_index,
                note=note,
            )
        return rows


# An emitter takes a context and yields rows, each carrying `__table`.
EmitFn = Callable[[EmitContext], Iterator[dict]]


@dataclass(frozen=True, slots=True)
class Emitter:
    technique_id: str
    variants: tuple[Variant, ...]
    fn: EmitFn
    tables: tuple[str, ...] = ()

    def variant_keys(self) -> list[str]:
        return [v.key for v in self.variants]

    def variant(self, key: str) -> Variant:
        for v in self.variants:
            if v.key == key:
                return v
        raise KeyError(f"{self.technique_id} has no variant {key!r}; "
                       f"have {self.variant_keys()}")

    def pick_variant(self, rng: random.Random) -> Variant:
        return rng.choices(self.variants, weights=[v.weight for v in self.variants], k=1)[0]


_REGISTRY: dict[str, Emitter] = {}


def register(technique_id: str, variants: list[Variant], tables: tuple[str, ...] = ()):
    """Decorator registering an emitter for a technique."""
    def wrap(fn: EmitFn) -> EmitFn:
        if technique_id in _REGISTRY:
            raise ValueError(f"emitter for {technique_id} already registered")
        _REGISTRY[technique_id] = Emitter(technique_id, tuple(variants), fn, tables)
        return fn
    return wrap


def get(technique_id: str) -> Emitter:
    return _REGISTRY[technique_id]


def has(technique_id: str) -> bool:
    return technique_id in _REGISTRY


def all_emitters() -> dict[str, Emitter]:
    return dict(_REGISTRY)


def implemented_techniques() -> list[str]:
    return sorted(_REGISTRY)


# ── Shared helpers ───────────────────────────────────────────────────────

def loud_scale(loudness: int, low: int, high: int) -> int:
    """Map a 1-5 loudness dial onto a count range."""
    loudness = max(1, min(5, loudness))
    return int(low + (high - low) * (loudness - 1) / 4)


def dwell(rng: random.Random, loudness: int) -> timedelta:
    """Gap between actions. A careful attacker waits; a loud one does not."""
    base = {1: (40, 240), 2: (20, 120), 3: (5, 45), 4: (2, 15), 5: (0, 4)}
    lo, hi = base[max(1, min(5, loudness))]
    return timedelta(minutes=rng.randint(lo, hi), seconds=rng.randint(0, 59))


def build_intrusion(gen: GenContext, *, seed_offset: int = 0,
                    victim: User | None = None) -> Intrusion:
    """Choose the attacker's starting position.

    The victim is a plain user with a workstation, not an admin — an intrusion
    that starts with Domain Admin skips every interesting step.
    """
    rng = random.Random(gen.org.seed + 555 + seed_offset)
    org = gen.org
    candidates = [u for u in org.humans if not u.is_admin and u.device_names]
    victim = victim or rng.choice(candidates)
    beachhead = org.device(victim.device_names[0])
    c2_domain = rng.choice([
        "cdn-analytics-sync.com", "update-telemetry-svc.net", "static-content-dn.com",
        "cloud-metrics-api.net", "az-edge-delivery.com", "secure-doc-view.net",
    ])
    c2_ip = f"{rng.choice([45, 91, 104, 185, 194])}.{rng.randint(1, 254)}." \
            f"{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    return Intrusion(org=org, rng=rng, victim=victim, beachhead=beachhead,
                     c2_domain=c2_domain, c2_ip=c2_ip)
