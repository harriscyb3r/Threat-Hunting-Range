"""Free text -> ranked ATT&CK candidates.

This is what turns "hunt for WMI abuse" into a campaign. It runs entirely
locally — no model, no API call — because CTI reports and hunt requests almost
always name techniques in one of three ways the machine can match directly:

    T1558.003                       an explicit technique ID
    Kerberoasting                   the official (sub)technique name
    "spn roasting", "rc4 ticket"    the words practitioners actually use

Deliberately returns **several ranked candidates rather than one answer**. When
someone types "WMI abuse" they have not yet decided whether they mean execution,
lateral movement or persistence, and those are three different hunts against
three different tables. Presenting the choice is the point; collapsing it to a
single guess would hide the distinction the analyst most needs to see.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import attack
from .attack import Technique

# T1558.003 / t1558.003 / T1047
_TID_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9_.\-]+")

# Words carrying no discriminating power. "attack" and "technique" appear in
# every CTI paragraph; matching on them would make everything look relevant.
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "for", "in", "on", "with", "via",
    "using", "used", "use", "by", "from", "then", "also", "attack", "attacker",
    "technique", "hunt", "hunting", "find", "look", "detect", "detection",
    "show", "me", "i", "want", "we", "they", "it", "is", "are", "was", "were",
    "this", "that", "any", "some", "all", "activity", "behaviour", "behavior",
    "threat", "malicious", "suspicious", "evidence", "signs",
}


@dataclass(slots=True)
class Candidate:
    technique: Technique
    score: float
    reason: str

    @property
    def confidence(self) -> str:
        if self.score >= 0.9:
            return "high"
        if self.score >= 0.6:
            return "medium"
        return "low"

    def as_dict(self) -> dict:
        return {
            "id": self.technique.id,
            "name": self.technique.name,
            "tactic": self.technique.tactic,
            "summary": self.technique.summary,
            "tables": list(self.technique.tables),
            "url": self.technique.attack_url,
            "score": round(self.score, 3),
            "confidence": self.confidence,
            "reason": self.reason,
        }


def _normalise(text: str) -> str:
    # Hyphens become spaces so "pass-the-hash" matches the alias "pass the hash"
    # — CTI writes techniques both ways. Technique IDs are matched on the raw
    # text before this runs, so "T1558.003" is unaffected. Dots are kept for
    # decimal-looking tokens but they don't participate in phrase matching.
    lowered = text.lower().replace("-", " ")
    return re.sub(r"[^a-z0-9\s.]", " ", lowered)


def _stem(word: str) -> str:
    """Crude suffix stripping, enough to match how people actually write.

    An analyst types "adding credentials to a service principal"; the catalogue
    alias reads "add credentials to service principal". Without this the two
    never meet. A real stemmer would be overkill — these are short technical
    phrases, not prose.
    """
    for suffix in ("ing", "ed", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            word = word[: -len(suffix)]
            break
    # Drop a trailing "e" so the stem of "disabled" (-> "disabl") and of
    # "disable" agree. Without this the two never match, which is exactly the
    # pairing an alias list runs into: catalogues are written in the infinitive
    # and analysts write in the past tense.
    if len(word) > 4 and word.endswith("e"):
        word = word[:-1]
    return word


def _tokens(text: str) -> set[str]:
    return {_stem(w) for w in _WORD_RE.findall(_normalise(text))
            if w not in _STOP and len(w) > 2}


def resolve(text: str, *, limit: int = 8, min_score: float = 0.35) -> list[Candidate]:
    """Rank techniques against free text.

    Scoring, highest wins per technique:
      1.00  explicit technique ID (exact, including subtechnique)
      0.85  parent ID matched but the text named no subtechnique
      alias weight, for an alias phrase appearing verbatim
      0.55  official name appears verbatim
      <=0.5 token overlap with the name, as a weak fallback
    """
    if not text or not text.strip():
        return []

    norm = _normalise(text)
    toks = _tokens(text)
    best: dict[str, Candidate] = {}

    def offer(t: Technique, score: float, reason: str) -> None:
        current = best.get(t.id)
        if current is None or score > current.score:
            best[t.id] = Candidate(t, score, reason)

    # 1. Explicit technique IDs anywhere in the text.
    for match in _TID_RE.finditer(text):
        base = f"T{match.group(1)}"
        full = f"{base}.{match.group(2)}" if match.group(2) else base
        if full.upper() in attack.BY_ID:
            offer(attack.BY_ID[full.upper()], 1.0, f"technique ID {full} named directly")
        elif not match.group(2):
            # A parent ID with no subtechnique: offer every subtechnique the
            # range knows, since the report did not narrow it down.
            for t in attack.CATALOGUE:
                if t.parent_id == base:
                    offer(t, 0.85, f"{base} named; this is one of its subtechniques")

    # 2. Alias and name matching.
    for t in attack.CATALOGUE:
        for phrase, weight in t.aliases:
            # Longer phrases are more specific: "wmi event subscription"
            # should beat a bare "wmi" for the persistence technique.
            specificity = min(0.08, 0.02 * len(phrase.split()))
            if phrase in norm:
                offer(t, min(1.0, weight + specificity), f'matched "{phrase}"')
                continue
            # Every significant word of the alias present, in any order or
            # inflection. Slightly discounted against a verbatim match.
            phrase_toks = _tokens(phrase)
            if len(phrase_toks) >= 2 and phrase_toks <= toks:
                offer(t, min(1.0, weight * 0.9 + specificity),
                      f'matched the words of "{phrase}"')

        if t.name.lower() in norm:
            offer(t, 0.9, f'matched technique name "{t.name}"')

        # 3. Weak fallback: overlap with words in the technique name. Requires
        #    at least two matching words — a single shared word like "service"
        #    is 50% of "Windows Service" and would otherwise drag in every
        #    service-related technique on any mention of the word.
        name_toks = _tokens(t.name)
        if len(name_toks) >= 2:
            shared = name_toks & toks
            overlap = len(shared) / len(name_toks)
            if overlap >= 0.5 and len(shared) >= 2:
                offer(t, min(0.55, 0.3 + overlap * 0.3),
                      f"overlaps the technique name ({int(overlap * 100)}%)")

    out = [c for c in best.values() if c.score >= min_score]
    # Ties resolve by kill-chain order so a multi-technique request comes back
    # in a plausible sequence rather than an arbitrary one.
    out.sort(key=lambda c: (-c.score, attack.tactic_sort_key(c.technique), c.technique.id))
    return out[:limit]


def resolve_ids(text: str, **kw) -> list[str]:
    return [c.technique.id for c in resolve(text, **kw)]


def ambiguous(candidates: list[Candidate]) -> bool:
    """Whether the analyst should be made to choose.

    True when two or more candidates are plausible and close together — the
    "WMI abuse" case. A single strong hit, or one clear winner, does not need a
    disambiguation step.
    """
    strong = [c for c in candidates if c.score >= 0.6]
    if len(strong) < 2:
        return False
    return strong[0].score - strong[1].score < 0.25
