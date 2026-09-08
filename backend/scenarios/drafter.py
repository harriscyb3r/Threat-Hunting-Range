"""CTI report -> draft ScenarioSpec (actor-first campaign building).

The behaviour-first flow (`resolver.resolve`) turns "kerberoasting" into one
technique. This turns a whole threat report — a Mandiant writeup, an actor
profile, a CISA advisory — into a multi-technique kill chain.

It runs entirely locally by default (PLAN.md §5.2): the same resolver, applied
across the full text with a lower threshold and a higher cap so it catches every
technique the report mentions rather than just the top one. Vendor CTI almost
always names techniques explicitly (T-IDs, or phrases like "Kerberoasting",
"pass-the-hash"), so this covers the common case with no model and no API cost.

The drafter never invents a kill chain the report doesn't support — it extracts
what's named, orders it along the kill chain, and hands back a spec the analyst
reviews and edits before anything is generated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import attack, resolver
from .models import ScenarioSpec, spec_from_techniques

# Well-known actor names, matched case-insensitively as whole words. Not
# exhaustive — a fallback label scan (below) catches the rest. The point is to
# surface the actor in the draft so the campaign is recognisably "an APT29 hunt"
# rather than an anonymous chain.
_KNOWN_ACTORS = [
    "APT1", "APT3", "APT10", "APT28", "APT29", "APT32", "APT33", "APT34",
    "APT38", "APT39", "APT41", "FIN4", "FIN6", "FIN7", "FIN8", "FIN11",
    "Lazarus", "Kimsuky", "Sandworm", "Turla", "Cozy Bear", "Fancy Bear",
    "Wizard Spider", "Cobalt Group", "Carbanak", "TA505", "TA551", "TA542",
    "Conti", "LockBit", "BlackCat", "ALPHV", "Cl0p", "Clop", "Royal", "Akira",
    "Black Basta", "Play", "Vice Society", "Scattered Spider", "UNC2452",
    "Nobelium", "Midnight Blizzard", "Volt Typhoon", "Silk Typhoon",
    "Mustang Panda", "Gamaredon", "MuddyWater", "OilRig", "Charming Kitten",
    "Emotet", "TrickBot", "Qakbot", "IcedID", "BumbleBee", "Gootloader",
]

_ACTOR_LABEL_RE = re.compile(
    r"(?:threat\s+actor|actor|group|adversary|attribution|tracked\s+as)"
    r"\s*[:\-]?\s*([A-Z][A-Za-z0-9 .\-]{2,40})", re.IGNORECASE)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|top|xyz|co|dev|app|gov|edu|mil|au|uk|de)\b",
    re.IGNORECASE)
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")


@dataclass
class TechniqueHit:
    id: str
    name: str
    tactic: str
    confidence: str
    reason: str
    has_emitter: bool

    def as_dict(self) -> dict:
        return self.__dict__


@dataclass
class Draft:
    spec: ScenarioSpec
    actor: str = ""
    techniques: list[TechniqueHit] = field(default_factory=list)   # ordered, all hits
    playable: list[str] = field(default_factory=list)              # ids with emitters
    unresolved: list[str] = field(default_factory=list)            # named, no emitter
    ioc_counts: dict[str, int] = field(default_factory=dict)
    text_chars: int = 0

    def as_dict(self) -> dict:
        return {
            "spec": self.spec.as_dict(),
            "actor": self.actor,
            "techniques": [t.as_dict() for t in self.techniques],
            "playable": self.playable,
            "unresolved": self.unresolved,
            "ioc_counts": self.ioc_counts,
            "text_chars": self.text_chars,
        }


def _extract_actor(text: str) -> str:
    # Known names first — most reliable.
    for name in _KNOWN_ACTORS:
        if re.search(rf"\b{re.escape(name)}\b", text, re.IGNORECASE):
            return name
    # Fallback: a labelled attribution line.
    m = _ACTOR_LABEL_RE.search(text)
    if m:
        candidate = m.group(1).strip().rstrip(".,;")
        # Guard against grabbing a whole sentence.
        if 2 < len(candidate) <= 40 and candidate.lower() not in (
                "the", "this", "unknown", "a threat", "an adversary"):
            return candidate
    return ""


def _extract_iocs(text: str) -> dict[str, int]:
    ips = {m for m in _IPV4_RE.findall(text) if not m.startswith(("0.", "255."))}
    domains = {d.lower() for d in _DOMAIN_RE.findall(text)}
    hashes = set(_HASH_RE.findall(text))
    return {"ips": len(ips), "domains": len(domains), "hashes": len(hashes)}


def draft_from_cti(
    text: str, *, min_confidence: float = 0.6, max_techniques: int = 14,
    loudness: int = 3, window_days: int = 14, name: str = "",
) -> Draft:
    """Parse a CTI report into a draft campaign spec.

    `min_confidence` is on the resolver's medium-and-up band, so a passing
    mention of a word doesn't plant a technique — only an explicit ID, an alias
    phrase, or the official name does.
    """
    text = text or ""
    # Resolve across the whole report: wide net, then filter by confidence.
    candidates = resolver.resolve(text, limit=60, min_score=0.5)

    hits: list[TechniqueHit] = []
    for c in candidates:
        if c.score < min_confidence:
            continue
        hits.append(TechniqueHit(
            id=c.technique.id, name=c.technique.name, tactic=c.technique.tactic,
            confidence=c.confidence, reason=c.reason,
            has_emitter=attack.has_emitter(c.technique.id)
            if hasattr(attack, "has_emitter") else _has_emitter(c.technique.id),
        ))

    # Keep the strongest matches, THEN order along the kill chain. Selecting by
    # confidence first is deliberate: ordering-then-truncating would always drop
    # the impact stage (ransomware sits last in the chain) even when it's the
    # highest-confidence hit in the report. `hits` arrives score-sorted from the
    # resolver, so the head is the most certain.
    by_id = {h.id: h for h in hits}
    selected = hits[:max_techniques]
    ordered_ids = _order([h.id for h in selected])
    hits = [by_id[i] for i in ordered_ids]
    playable = [h.id for h in hits if h.has_emitter]
    unresolved = [h.id for h in hits if not h.has_emitter]

    actor = _extract_actor(text)
    iocs = _extract_iocs(text)

    spec_name = name or (f"{actor} campaign" if actor else "CTI campaign")
    hypothesis = _hypothesis(actor, hits)
    # Build the spec from the playable techniques (the ones that can be planted).
    spec = spec_from_techniques(
        playable or ordered_ids, name=spec_name, hypothesis=hypothesis,
        loudness=loudness, window_days=window_days)
    spec.source = "cti"
    spec.actor = actor

    return Draft(spec=spec, actor=actor, techniques=hits, playable=playable,
                 unresolved=unresolved, ioc_counts=iocs, text_chars=len(text))


def _has_emitter(tid: str) -> bool:
    from generators.attack import has as has_emitter
    return has_emitter(tid)


def _order(ids: list[str]) -> list[str]:
    from .models import order_techniques
    return order_techniques(ids)


def _hypothesis(actor: str, hits: list[TechniqueHit]) -> str:
    who = actor or "The reported actor"
    names = ", ".join(h.name for h in hits[:4])
    more = "" if len(hits) <= 4 else f", and {len(hits) - 4} more"
    return (f"{who} is active in the environment, using {names}{more}. "
            "Hunt for the kill chain end to end.")
