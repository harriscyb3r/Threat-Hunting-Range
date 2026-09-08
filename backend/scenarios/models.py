"""ScenarioSpec — the editable definition of a campaign.

Everything that produces a campaign converges here: the behaviour-first "hunt
for X" flow, the actor-first CTI paste, and the shipped library all emit a
ScenarioSpec, which the compiler then executes deterministically. Keeping one
artifact in the middle means there is exactly one thing to review, edit, save
and re-roll.

A spec is fully declarative. Given the same spec and the same org seed, the
generated telemetry is byte-identical — which is what makes a hunt replayable
and a detection re-testable.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import attack


@dataclass(slots=True)
class ScenarioStep:
    """One technique in the chain.

    `variant` may be "" — the compiler then picks one per the emitter's weights,
    which is the usual case for a re-rollable campaign. Pinning a variant makes
    the step reproducible across re-rolls, used by the shipped library.
    """
    technique_id: str
    variant: str = ""
    loudness: int = 3
    day_offset: float = 0.0          # days into the window this step begins
    params: dict = field(default_factory=dict)
    note: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class ScenarioSpec:
    name: str
    hypothesis: str                   # what the hunter is told to look for
    steps: list[ScenarioStep] = field(default_factory=list)
    # Context depth: how much surrounds the technique.
    #   isolated    technique + its decoys only — fast drills
    #   contextual  a little before/after so entity pivots work (default)
    #   full-chain  embedded in a complete intrusion
    context_depth: str = "contextual"
    actor: str = ""                   # named threat actor, if any
    source: str = "behaviour"         # behaviour | cti | library
    seed_offset: int = 0              # varies the intrusion without changing the org
    window_days: int = 14
    # How many benign events to bury it in. Blank uses the campaign default.
    target_events: int | None = None
    decoys: bool = True               # plant technique-specific lookalikes

    @property
    def technique_ids(self) -> list[str]:
        return [s.technique_id for s in self.steps]

    def unresolved(self) -> list[str]:
        """Steps whose technique has no emitter — the compiler must fall back.

        The emitter registry lives in the generators layer, which imports this
        module; importing it back here would be a cycle, so it is looked up
        lazily at call time.
        """
        from generators.attack import has as has_emitter
        return [s.technique_id for s in self.steps if not has_emitter(s.technique_id)]

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "hypothesis": self.hypothesis,
            "steps": [s.as_dict() for s in self.steps],
            "context_depth": self.context_depth,
            "actor": self.actor,
            "source": self.source,
            "seed_offset": self.seed_offset,
            "window_days": self.window_days,
            "target_events": self.target_events,
            "decoys": self.decoys,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScenarioSpec":
        steps = [ScenarioStep(**s) for s in d.get("steps", [])]
        return cls(
            name=d["name"],
            hypothesis=d.get("hypothesis", ""),
            steps=steps,
            context_depth=d.get("context_depth", "contextual"),
            actor=d.get("actor", ""),
            source=d.get("source", "behaviour"),
            seed_offset=d.get("seed_offset", 0),
            window_days=d.get("window_days", 14),
            target_events=d.get("target_events"),
            decoys=d.get("decoys", True),
        )


# Kill-chain ordering, so a multi-technique request is sequenced plausibly
# rather than in the order the analyst happened to type it.
_TACTIC_STAGE = {t: i for i, t in enumerate(attack.TACTIC_ORDER)}


def order_techniques(technique_ids: list[str]) -> list[str]:
    """Sort techniques into kill-chain order, de-duplicated."""
    seen, unique = set(), []
    for tid in technique_ids:
        if tid not in seen:
            seen.add(tid)
            unique.append(tid)

    def key(tid: str) -> int:
        try:
            return _TACTIC_STAGE.get(attack.get(tid).tactic, 99)
        except KeyError:
            return 99

    return sorted(unique, key=key)


def spec_from_techniques(
    technique_ids: list[str],
    *,
    name: str = "",
    hypothesis: str = "",
    context_depth: str = "contextual",
    loudness: int = 3,
    window_days: int = 14,
    spread: bool = True,
) -> ScenarioSpec:
    """Build a spec from a bare list of techniques (the behaviour-first path).

    Steps are ordered along the kill chain and, if `spread`, dealt across the
    first two-thirds of the window so an analyst has to reconstruct a timeline
    rather than find everything at one timestamp.
    """
    ordered = order_techniques(technique_ids)
    n = len(ordered)
    steps: list[ScenarioStep] = []
    for i, tid in enumerate(ordered):
        offset = (window_days * 0.66 * i / max(1, n - 1)) if spread and n > 1 else \
                 window_days * 0.33
        steps.append(ScenarioStep(technique_id=tid, loudness=loudness,
                                  day_offset=round(offset, 2)))

    if not name:
        if n == 1:
            name = attack.get(ordered[0]).name
        else:
            name = f"{attack.get(ordered[0]).name} + {n - 1} more"
    if not hypothesis:
        names = ", ".join(attack.get(t).name for t in ordered)
        hypothesis = f"Evidence of {names} in the environment."

    return ScenarioSpec(name=name, hypothesis=hypothesis, steps=steps,
                        context_depth=context_depth, source="behaviour",
                        window_days=window_days)
