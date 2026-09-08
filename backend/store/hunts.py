"""Hunt records — the PEAK workspace persistence.

PEAK (Prepare, Execute, Act, with Knowledge threaded through) is the workflow
this models. The data mirrors it:

    Hunt        one hunt against one campaign, in a PEAK phase
    Hypothesis  the ABLE-framed statement (Actor, Behavior, Location, Evidence)
    Search      every query the analyst ran, auto-logged with its timing
    Evidence    result rows the analyst pinned as relevant
    Finding     evidence promoted to a claim, tagged with a technique
    Detection   a successful query saved as a reusable detection

Kept in the same SQLite database as the campaign registry, on its own
connection, so a hunt and its campaign are one file to back up or delete.

Scoring (phase 6) reads Search timing and Evidence item-ids against ground
truth. Nothing here reaches into Kusto — the workspace records what the analyst
did; the engine holds what they did it against.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HUNT_SCHEMA = """
CREATE TABLE IF NOT EXISTS hunts (
    id            TEXT PRIMARY KEY,
    campaign_slug TEXT NOT NULL,
    title         TEXT NOT NULL,
    hunt_type     TEXT NOT NULL DEFAULT 'hypothesis',  -- hypothesis | baseline | model-assisted
    phase         TEXT NOT NULL DEFAULT 'prepare',     -- prepare | execute | act | closed
    -- ABLE hypothesis fields, each nullable until the analyst fills them in.
    actor         TEXT DEFAULT '',
    behavior      TEXT DEFAULT '',
    location      TEXT DEFAULT '',
    evidence_expected TEXT DEFAULT '',
    scope         TEXT DEFAULT '',
    data_sources  TEXT DEFAULT '',        -- JSON list of table names
    success_criteria TEXT DEFAULT '',
    techniques    TEXT DEFAULT '[]',      -- JSON list of expected ATT&CK ids
    -- Act phase.
    writeup       TEXT DEFAULT '',
    outcome       TEXT DEFAULT '',        -- proven | disproven | inconclusive
    started_at    REAL,                   -- when the analyst entered Execute
    created_at    REAL NOT NULL,
    updated_at    REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_hunts_campaign ON hunts(campaign_slug);

CREATE TABLE IF NOT EXISTS searches (
    id         TEXT PRIMARY KEY,
    hunt_id    TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    csl        TEXT NOT NULL,
    db_name    TEXT NOT NULL,
    row_count  INTEGER NOT NULL DEFAULT 0,
    elapsed_ms REAL NOT NULL DEFAULT 0,
    ok         INTEGER NOT NULL DEFAULT 1,
    error      TEXT DEFAULT '',
    ran_at     REAL NOT NULL,
    note       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ix_searches_hunt ON searches(hunt_id, ran_at);

CREATE TABLE IF NOT EXISTS evidence (
    id         TEXT PRIMARY KEY,
    hunt_id    TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    search_id  TEXT REFERENCES searches(id) ON DELETE SET NULL,
    item_id    TEXT DEFAULT '',           -- the row's Kusto _ItemId, if present
    table_name TEXT DEFAULT '',
    row_json   TEXT NOT NULL,             -- the pinned row
    note       TEXT DEFAULT '',
    pinned_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_evidence_hunt ON evidence(hunt_id);

CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    hunt_id     TEXT NOT NULL REFERENCES hunts(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    technique   TEXT DEFAULT '',          -- ATT&CK id the analyst assigns
    confidence  TEXT DEFAULT 'medium',    -- low | medium | high
    description TEXT DEFAULT '',
    evidence_ids TEXT DEFAULT '[]',       -- JSON list of evidence ids
    created_at  REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_findings_hunt ON findings(hunt_id);

CREATE TABLE IF NOT EXISTS detections (
    id           TEXT PRIMARY KEY,
    hunt_id      TEXT REFERENCES hunts(id) ON DELETE SET NULL,
    campaign_slug TEXT DEFAULT '',
    title        TEXT NOT NULL,
    csl          TEXT NOT NULL,
    techniques   TEXT DEFAULT '[]',       -- JSON list of ATT&CK ids
    description  TEXT DEFAULT '',
    fp_notes     TEXT DEFAULT '',
    severity     TEXT DEFAULT 'medium',   -- informational | low | medium | high | critical
    -- Validation results (phase 6 fills these; nullable until then).
    fp_count     INTEGER,                 -- hits against the clean twin
    tp_count     INTEGER,                 -- attack _ItemIds the query returned
    validated_at REAL,
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_detections_campaign ON detections(campaign_slug);

-- Curriculum progress: one row per completed lesson.
CREATE TABLE IF NOT EXISTS lesson_progress (
    lesson_id    TEXT PRIMARY KEY,
    completed_at REAL NOT NULL
);
"""


def _id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    # Decode the JSON-encoded list columns transparently.
    for col in ("data_sources", "techniques", "evidence_ids"):
        if col in d and isinstance(d[col], str) and d[col].startswith("["):
            try:
                d[col] = json.loads(d[col])
            except json.JSONDecodeError:
                pass
    return d


class HuntStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._conn.executescript(HUNT_SCHEMA)
        self._conn.commit()

    # ── Hunts ────────────────────────────────────────────────────────────

    def create_hunt(self, campaign_slug: str, title: str, *,
                    hunt_type: str = "hypothesis", seed: dict | None = None) -> dict:
        now = time.time()
        hid = _id("hunt")
        self._conn.execute(
            "INSERT INTO hunts(id, campaign_slug, title, hunt_type, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?)",
            (hid, campaign_slug, title, hunt_type, now, now))
        self._conn.commit()
        # A pre-seeded first-draft hypothesis (ABLE + data sources) so Prepare
        # opens on something to edit rather than a blank form. Only ever the
        # public technique reference — never the planted variant/host/counts —
        # so it stays a starting point, not the answer key.
        if seed:
            self.update_hunt(hid, seed)
        return self.get_hunt(hid)  # type: ignore[return-value]

    def get_hunt(self, hid: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM hunts WHERE id = ?", (hid,)).fetchone()
        return _row_to_dict(row) if row else None

    def list_hunts(self, campaign_slug: str | None = None) -> list[dict]:
        if campaign_slug:
            rows = self._conn.execute(
                "SELECT * FROM hunts WHERE campaign_slug = ? ORDER BY updated_at DESC",
                (campaign_slug,)).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM hunts ORDER BY updated_at DESC").fetchall()
        return [_row_to_dict(r) for r in rows]

    # Columns the client may patch. Enumerated rather than free-form to keep
    # the update path from becoming an arbitrary SQL sink.
    _PATCHABLE = {
        "title", "hunt_type", "phase", "actor", "behavior", "location",
        "evidence_expected", "scope", "data_sources", "success_criteria",
        "techniques", "writeup", "outcome",
    }

    def update_hunt(self, hid: str, fields: dict) -> dict | None:
        sets, vals = [], []
        for k, v in fields.items():
            if k not in self._PATCHABLE:
                continue
            if k in ("data_sources", "techniques") and isinstance(v, list):
                v = json.dumps(v)
            sets.append(f"{k} = ?")
            vals.append(v)
        if not sets:
            return self.get_hunt(hid)
        # Entering Execute stamps started_at once, for time-to-first-finding.
        if fields.get("phase") == "execute":
            sets.append("started_at = COALESCE(started_at, ?)")
            vals.append(time.time())
        sets.append("updated_at = ?")
        vals.append(time.time())
        vals.append(hid)
        self._conn.execute(f"UPDATE hunts SET {', '.join(sets)} WHERE id = ?", vals)
        self._conn.commit()
        return self.get_hunt(hid)

    def delete_hunt(self, hid: str) -> None:
        self._conn.execute("DELETE FROM hunts WHERE id = ?", (hid,))
        self._conn.commit()

    # ── Searches ─────────────────────────────────────────────────────────

    def log_search(self, hunt_id: str, csl: str, db_name: str, *,
                   row_count: int, elapsed_ms: float, ok: bool,
                   error: str = "") -> dict:
        sid = _id("search")
        self._conn.execute(
            "INSERT INTO searches(id, hunt_id, csl, db_name, row_count, elapsed_ms, ok, "
            "error, ran_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (sid, hunt_id, csl, db_name, row_count, elapsed_ms, int(ok), error, time.time()))
        self._conn.commit()
        row = self._conn.execute("SELECT * FROM searches WHERE id = ?", (sid,)).fetchone()
        return dict(row)

    def list_searches(self, hunt_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM searches WHERE hunt_id = ? ORDER BY ran_at", (hunt_id,)).fetchall()
        return [dict(r) for r in rows]

    # ── Evidence ─────────────────────────────────────────────────────────

    def pin_evidence(self, hunt_id: str, row: dict, *, search_id: str = "",
                     note: str = "") -> dict:
        eid = _id("ev")
        item_id = str(row.get("_ItemId", ""))
        table_name = str(row.get("Type", ""))
        self._conn.execute(
            "INSERT INTO evidence(id, hunt_id, search_id, item_id, table_name, row_json, "
            "note, pinned_at) VALUES(?,?,?,?,?,?,?,?)",
            (eid, hunt_id, search_id or None, item_id, table_name,
             json.dumps(row), note, time.time()))
        self._conn.commit()
        r = self._conn.execute("SELECT * FROM evidence WHERE id = ?", (eid,)).fetchone()
        return self._evidence_row(r)

    def list_evidence(self, hunt_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM evidence WHERE hunt_id = ? ORDER BY pinned_at", (hunt_id,)).fetchall()
        return [self._evidence_row(r) for r in rows]

    def unpin_evidence(self, eid: str) -> None:
        self._conn.execute("DELETE FROM evidence WHERE id = ?", (eid,))
        self._conn.commit()

    def evidence_item_ids(self, hunt_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT item_id FROM evidence WHERE hunt_id = ? AND item_id != ''",
            (hunt_id,)).fetchall()
        return [r["item_id"] for r in rows]

    @staticmethod
    def _evidence_row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["row"] = json.loads(d.pop("row_json"))
        return d

    # ── Findings ─────────────────────────────────────────────────────────

    def create_finding(self, hunt_id: str, title: str, *, technique: str = "",
                       confidence: str = "medium", description: str = "",
                       evidence_ids: list[str] | None = None) -> dict:
        fid = _id("find")
        self._conn.execute(
            "INSERT INTO findings(id, hunt_id, title, technique, confidence, description, "
            "evidence_ids, created_at) VALUES(?,?,?,?,?,?,?,?)",
            (fid, hunt_id, title, technique, confidence, description,
             json.dumps(evidence_ids or []), time.time()))
        self._conn.commit()
        return self.get_finding(fid)  # type: ignore[return-value]

    def get_finding(self, fid: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?", (fid,)).fetchone()
        return _row_to_dict(row) if row else None

    def list_findings(self, hunt_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE hunt_id = ? ORDER BY created_at", (hunt_id,)).fetchall()
        return [_row_to_dict(r) for r in rows]

    def delete_finding(self, fid: str) -> None:
        self._conn.execute("DELETE FROM findings WHERE id = ?", (fid,))
        self._conn.commit()

    # ── Detections ───────────────────────────────────────────────────────

    def save_detection(self, title: str, csl: str, *, hunt_id: str = "",
                       campaign_slug: str = "", techniques: list[str] | None = None,
                       description: str = "", fp_notes: str = "",
                       severity: str = "medium") -> dict:
        did = _id("det")
        now = time.time()
        self._conn.execute(
            "INSERT INTO detections(id, hunt_id, campaign_slug, title, csl, techniques, "
            "description, fp_notes, severity, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (did, hunt_id or None, campaign_slug, title, csl,
             json.dumps(techniques or []), description, fp_notes, severity, now, now))
        self._conn.commit()
        return self.get_detection(did)  # type: ignore[return-value]

    def get_detection(self, did: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM detections WHERE id = ?", (did,)).fetchone()
        return _row_to_dict(row) if row else None

    def list_detections(self, campaign_slug: str | None = None) -> list[dict]:
        if campaign_slug:
            rows = self._conn.execute(
                "SELECT * FROM detections WHERE campaign_slug = ? ORDER BY updated_at DESC",
                (campaign_slug,)).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM detections ORDER BY updated_at DESC").fetchall()
        return [_row_to_dict(r) for r in rows]

    def update_detection_validation(self, did: str, *, fp_count: int,
                                    tp_count: int) -> None:
        self._conn.execute(
            "UPDATE detections SET fp_count = ?, tp_count = ?, validated_at = ?, "
            "updated_at = ? WHERE id = ?",
            (fp_count, tp_count, time.time(), time.time(), did))
        self._conn.commit()

    def delete_detection(self, did: str) -> None:
        self._conn.execute("DELETE FROM detections WHERE id = ?", (did,))
        self._conn.commit()

    # ── Curriculum progress ──────────────────────────────────────────────

    def complete_lesson(self, lesson_id: str) -> None:
        self._conn.execute(
            "INSERT INTO lesson_progress(lesson_id, completed_at) VALUES(?, ?) "
            "ON CONFLICT(lesson_id) DO NOTHING", (lesson_id, time.time()))
        self._conn.commit()

    def uncomplete_lesson(self, lesson_id: str) -> None:
        self._conn.execute("DELETE FROM lesson_progress WHERE lesson_id = ?", (lesson_id,))
        self._conn.commit()

    def completed_lessons(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT lesson_id FROM lesson_progress").fetchall()
        return [r["lesson_id"] for r in rows]
