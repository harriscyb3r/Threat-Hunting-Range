"""Validate a saved detection: true positives on the campaign, false positives
on the clean twin.

This is what makes a saved detection more than a query that worked once. Two
runs:

    against the campaign   -> which attack _ItemIds does it return? (recall)
    against the clean twin -> how many rows does it return at all? (FP rate)

The twin holds the same benign baseline and the same decoys with the attack
removed, so any row the detection returns there is, by construction, a false
positive against this org's real behaviour. A detection that lights up the twin
is one that will page a SOC at 3am for nothing.

The detection has to project `_ItemId` for TP grading to work, so this appends
a normalisation step rather than trusting the analyst's query to carry it. If
the query aggregates away `_ItemId` (summarize/make-series), TP can't be graded
by row and the result says so instead of guessing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from kusto import KustoClient, KustoError


@dataclass
class ValidationResult:
    tp_item_ids: list[str] = field(default_factory=list)   # attack rows returned
    fp_count: int = 0                                        # rows on the clean twin
    twin_total_rows: int = 0                                 # rows the query returns on twin
    campaign_rows: int = 0                                   # rows on the live campaign
    can_grade_tp: bool = True
    error: str = ""

    @property
    def tp_count(self) -> int:
        return len(self.tp_item_ids)

    def as_dict(self) -> dict:
        return {
            "tp_count": self.tp_count,
            "tp_item_ids": self.tp_item_ids,
            "fp_count": self.fp_count,
            "twin_total_rows": self.twin_total_rows,
            "campaign_rows": self.campaign_rows,
            "can_grade_tp": self.can_grade_tp,
            "error": self.error,
        }


# Queries that reduce rows away can't have their output rows mapped to _ItemIds.
_AGGREGATES = re.compile(r"\b(summarize|make-series|count\s*\(\s*\)|evaluate)\b", re.IGNORECASE)


def _returns_itemid(csl: str) -> bool:
    """Whether the query's output could carry _ItemId.

    An aggregate collapses rows, so its output has no _ItemId to grade against.
    We still measure FP volume on the twin (a firing detection is a firing
    detection), but TP is then measured differently — see grade_by_itemid.
    """
    return not _AGGREGATES.search(csl)


async def _row_count(client: KustoClient, db: str, csl: str) -> int:
    """Run a query and count its rows, robust to it already ending in a pipe."""
    wrapped = f"{csl.rstrip().rstrip('|')}\n| count"
    result = await client.query(db, wrapped)
    return int(result.scalar() or 0)


async def _returned_item_ids(client: KustoClient, db: str, csl: str,
                             cap: int = 5000) -> list[str]:
    """The _ItemIds a query returns, if it carries the column."""
    wrapped = (f"{csl.rstrip().rstrip('|')}\n"
               f"| where isnotempty(_ItemId)\n| project _ItemId\n| take {cap}")
    result = await client.query(db, wrapped)
    return [row[0] for row in result.rows]


async def validate(
    client: KustoClient, csl: str, *,
    campaign_db: str, twin_db: str,
    attack_item_ids: set[str],
) -> ValidationResult:
    """Run one detection against the campaign and its twin."""
    res = ValidationResult()

    try:
        res.campaign_rows = await _row_count(client, campaign_db, csl)
    except KustoError as exc:
        res.error = f"campaign query failed: {exc}"
        return res

    # False positives: any row on the twin is benign by construction.
    try:
        res.twin_total_rows = await _row_count(client, twin_db, csl)
        res.fp_count = res.twin_total_rows
    except KustoError as exc:
        res.error = f"twin query failed: {exc}"
        return res

    # True positives: attack _ItemIds the detection surfaced on the campaign.
    if _returns_itemid(csl):
        try:
            returned = await _returned_item_ids(client, campaign_db, csl)
            res.tp_item_ids = [i for i in returned if i in attack_item_ids]
        except KustoError:
            # The query resisted the _ItemId projection (e.g. renamed columns);
            # fall back to "cannot grade" rather than reporting a wrong number.
            res.can_grade_tp = False
    else:
        res.can_grade_tp = False

    return res
