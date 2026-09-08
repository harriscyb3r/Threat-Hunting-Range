"""Hunt scoring — grade a hunt against ground truth.

Because a campaign's ground truth records exactly which events are attack, decoy
and noise (keyed on the real `_ItemId`), a hunt can be graded objectively rather
than by feel. The metrics mirror what a hunt lead actually cares about:

    technique recall   did you identify the techniques that were planted?
    precision          of what you flagged, how much was the real attack vs a
                       decoy or benign anomaly you were fooled by?
    time to detection  how long from starting the hunt to your first true find?
    query efficiency   how many searches before you found it?
    rigor              did you follow the method — ABLE, evidence, write-up,
                       a saved detection?

The headline is **technique recall + precision**: did you find the attack, and
did the decoys fool you? Everything else contextualises those two.

None of this reaches into Kusto. It compares what the analyst recorded (evidence
item-ids, findings, searches, timings) against the SQLite ground truth. The
answer key returned alongside is what turns a score into a debrief: here is what
was planted, here is what you caught, here is what fooled you, here is what you
missed.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from store import HuntStore, Registry


@dataclass
class Score:
    hunt_id: str
    campaign_slug: str

    # Technique detection — the headline.
    planted_techniques: list[str] = field(default_factory=list)
    identified_techniques: list[str] = field(default_factory=list)
    missed_techniques: list[str] = field(default_factory=list)
    technique_recall: float = 0.0

    # Precision — were you fooled by decoys or noise?
    evidence_total: int = 0
    evidence_attack: int = 0        # pinned rows that are real attack
    evidence_decoy: int = 0         # pinned decoys (fooled)
    evidence_noise: int = 0         # pinned ambient noise (fooled)
    evidence_benign: int = 0        # pinned genuinely-benign rows
    precision: float = 0.0

    # Event-level recall (informational — pinning every attack row is not
    # expected, but a very low number means you barely sampled the activity).
    attack_events_total: int = 0
    attack_events_found: int = 0
    event_recall: float = 0.0

    # Timing and efficiency.
    started_at: float | None = None
    first_tp_at: float | None = None
    time_to_detection_s: float | None = None
    searches_total: int = 0
    searches_to_first_tp: int | None = None

    # Rigor — following the PEAK method.
    rigor_checks: dict[str, bool] = field(default_factory=dict)
    rigor_score: float = 0.0

    # Overall.
    overall: float = 0.0
    grade: str = "—"

    # The debrief: what was planted vs what happened.
    answer_key: dict[str, Any] = field(default_factory=dict)
    decoys_fooled_by: list[dict] = field(default_factory=list)

    def as_dict(self) -> dict:
        return self.__dict__


def scoreboard(hunts: HuntStore, registry: Registry) -> dict:
    """Aggregate across every hunt: progress, and ATT&CK coverage.

    Coverage is the map an interviewer wants to see — which techniques you have
    hunted and identified, and which you have a saved detection for. Techniques
    are only credited when actually identified in a scored hunt, not merely
    hunted, so the heatmap reflects skill rather than attempts.
    """
    all_hunts = hunts.list_hunts()
    scored = []
    identified: set[str] = set()
    for h in all_hunts:
        sc = score_hunt(hunts, registry, h["id"])
        if not sc:
            continue
        scored.append({
            "hunt_id": h["id"], "title": h["title"], "campaign_slug": h["campaign_slug"],
            "phase": h["phase"], "outcome": h["outcome"],
            "overall": sc.overall, "grade": sc.grade,
            "technique_recall": sc.technique_recall, "precision": sc.precision,
            "identified": sc.identified_techniques, "missed": sc.missed_techniques,
            "created_at": h["created_at"],
        })
        identified |= set(sc.identified_techniques)

    detections = hunts.list_detections()
    detected: set[str] = set()
    for d in detections:
        detected |= set(d.get("techniques", []))

    completed = [s for s in scored if s["overall"] > 0]
    avg = round(sum(s["overall"] for s in completed) / len(completed), 1) if completed else 0.0

    return {
        "hunts": scored,
        "totals": {
            "hunts": len(scored),
            "avg_score": avg,
            "techniques_identified": sorted(identified),
            "techniques_with_detection": sorted(detected),
            "detections": len(detections),
        },
    }


def _grade(pct: float) -> str:
    if pct >= 90:
        return "A"
    if pct >= 80:
        return "B"
    if pct >= 70:
        return "C"
    if pct >= 60:
        return "D"
    return "F"


def score_hunt(hunts: HuntStore, registry: Registry, hunt_id: str) -> Score | None:
    hunt = hunts.get_hunt(hunt_id)
    if not hunt:
        return None
    slug = hunt["campaign_slug"]
    s = Score(hunt_id=hunt_id, campaign_slug=slug)

    # ── Ground truth for this campaign ───────────────────────────────────
    s.planted_techniques = registry.planted_techniques(slug)
    attack_ids = registry.attack_item_ids(slug)
    s.attack_events_total = len(attack_ids)
    tech_events = registry.technique_events(slug)

    # ── Evidence: classify every pinned row against ground truth ─────────
    evidence = hunts.list_evidence(hunt_id)
    ev_item_ids = [e["item_id"] for e in evidence if e["item_id"]]
    classified = registry.classify_item_ids(slug, ev_item_ids)

    found_attack_ids: set[str] = set()
    found_techniques: set[str] = set()
    fooled: dict[str, dict] = {}
    for e in evidence:
        s.evidence_total += 1
        info = classified.get(e["item_id"])
        kind = info["kind"] if info else "benign"
        if kind == "attack":
            s.evidence_attack += 1
            found_attack_ids.add(e["item_id"])
            if info and info["technique"]:
                found_techniques.add(info["technique"])
        elif kind == "decoy":
            s.evidence_decoy += 1
            key = (info or {}).get("pattern") or (info or {}).get("mimics") or "decoy"
            fooled.setdefault(key, {
                "pattern": key, "mimics": (info or {}).get("mimics"), "count": 0,
            })
            fooled[key]["count"] += 1
        elif kind == "noise":
            s.evidence_noise += 1
            key = (info or {}).get("pattern") or "noise"
            fooled.setdefault(key, {"pattern": key, "mimics": None, "count": 0})
            fooled[key]["count"] += 1
        else:
            s.evidence_benign += 1

    # ── Findings also count as identifying a technique ───────────────────
    # An analyst who tags a finding with the right technique has identified it,
    # even if the specific rows they pinned were a representative sample.
    for f in hunts.list_findings(hunt_id):
        if f["technique"] and f["technique"] in s.planted_techniques:
            found_techniques.add(f["technique"])

    s.identified_techniques = sorted(found_techniques & set(s.planted_techniques))
    s.missed_techniques = sorted(set(s.planted_techniques) - found_techniques)
    s.technique_recall = (
        len(s.identified_techniques) / len(s.planted_techniques)
        if s.planted_techniques else 0.0
    )

    # Precision: of everything pinned, the share that is the real attack. Decoys
    # and noise count against you; genuinely-benign pins are neutral-ish but
    # still not the attack, so they lower precision too.
    s.precision = s.evidence_attack / s.evidence_total if s.evidence_total else 0.0

    s.attack_events_found = len(found_attack_ids)
    s.event_recall = (
        s.attack_events_found / s.attack_events_total if s.attack_events_total else 0.0
    )

    s.decoys_fooled_by = sorted(fooled.values(), key=lambda x: -x["count"])

    # ── Timing and efficiency ────────────────────────────────────────────
    s.started_at = hunt.get("started_at")
    searches = hunts.list_searches(hunt_id)
    s.searches_total = len(searches)

    # First true positive = earliest pinned attack evidence.
    attack_ev = [e for e in evidence
                 if classified.get(e["item_id"], {}).get("kind") == "attack"]
    if attack_ev:
        first = min(e["pinned_at"] for e in attack_ev)
        s.first_tp_at = first
        if s.started_at:
            s.time_to_detection_s = max(0.0, first - s.started_at)
        # Searches run before the first true positive was pinned.
        s.searches_to_first_tp = sum(1 for q in searches if q["ran_at"] <= first)

    # ── Rigor: following the method ──────────────────────────────────────
    able_done = all(hunt.get(k, "").strip() for k in
                    ("actor", "behavior", "location", "evidence_expected"))
    findings = hunts.list_findings(hunt_id)
    findings_have_evidence = bool(findings) and all(
        f["evidence_ids"] for f in findings)
    detections = hunts.list_detections(slug)
    s.rigor_checks = {
        "ABLE hypothesis complete": able_done,
        "evidence pinned": s.evidence_total > 0,
        "findings recorded": bool(findings),
        "findings backed by evidence": findings_have_evidence,
        "write-up present": bool(hunt.get("writeup", "").strip()),
        "outcome recorded": bool(hunt.get("outcome", "").strip()),
        "detection saved": bool(detections),
    }
    s.rigor_score = sum(s.rigor_checks.values()) / len(s.rigor_checks)

    # ── Overall: weighted toward finding the attack without being fooled ──
    # 45% technique recall, 25% precision, 15% rigor, 15% efficiency proxy.
    efficiency = 0.0
    if s.searches_to_first_tp:
        # 1.0 if found within 3 searches, decaying after.
        efficiency = max(0.0, min(1.0, 3.0 / s.searches_to_first_tp))
    elif s.technique_recall == 0:
        efficiency = 0.0
    s.overall = round(100 * (
        0.45 * s.technique_recall
        + 0.25 * s.precision
        + 0.15 * s.rigor_score
        + 0.15 * efficiency
    ), 1)
    s.grade = _grade(s.overall)

    # ── Answer key — the correct answers, for the debrief ────────────────
    stored = registry.get_spec(slug)
    steps = []
    hypothesis = ""
    if stored:
        try:
            hypothesis = json.loads(stored[0]).get("hypothesis", "")
            steps = json.loads(stored[1])
        except json.JSONDecodeError:
            pass
    # Annotate each planted step with whether the analyst identified it.
    for step in steps:
        step["identified"] = step.get("technique_id") in s.identified_techniques
        step["events"] = tech_events.get(step.get("technique_id"), 0)
    s.answer_key = {
        "hypothesis": hypothesis,
        "steps": steps,
        "technique_events": tech_events,
        "counts": registry.ground_truth_counts(slug),
    }
    return s
