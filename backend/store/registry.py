"""Campaign registry — SQLite.

This is the authoritative list of what the range owns. The Kusto engine cannot
answer "which databases should exist?" (persisted-but-unattached databases are
invisible to `.show databases`), so the registry answers it instead and drives
reconciliation at startup.

Phase 0 keeps the schema deliberately thin: enough to create, track and
reattach databases. Hunts, hypotheses, evidence, detections and scores land in
later phases against the same connection.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("range.store")

SCHEMA_VERSION = 3

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    slug         TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    db_name      TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL DEFAULT 'campaign',   -- campaign | clean_twin
    twin_of      TEXT REFERENCES campaigns(slug) ON DELETE CASCADE,
    seed         INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'empty',      -- empty | building | ready | missing
    -- The live persist path and its generation. Recorded rather than derived
    -- because `.drop database` leaves files behind, so a reset moves the
    -- database to a new generation directory (see kusto/admin.py).
    generation   INTEGER NOT NULL DEFAULT 1,
    md_path      TEXT NOT NULL DEFAULT '',
    data_path    TEXT NOT NULL DEFAULT '',
    created_at   REAL NOT NULL,
    updated_at   REAL NOT NULL,
    spec_json    TEXT
);

CREATE INDEX IF NOT EXISTS ix_campaigns_kind ON campaigns(kind);

-- Ground truth: one row per planted event, keyed on the Kusto _ItemId.
-- This is what scoring (phase 6) grades a hunt against. Kept in SQLite rather
-- than in Kusto so the answer key is never visible to a query the analyst runs.
CREATE TABLE IF NOT EXISTS ground_truth (
    campaign_slug TEXT NOT NULL REFERENCES campaigns(slug) ON DELETE CASCADE,
    item_id       TEXT NOT NULL,
    kind          TEXT NOT NULL,        -- attack | decoy | noise
    technique     TEXT,                 -- attack: the technique id
    variant       TEXT,
    mimics        TEXT,                 -- decoy: the technique it imitates
    pattern       TEXT,                 -- noise/decoy: the named pattern
    step_index    INTEGER,
    note          TEXT,
    PRIMARY KEY (campaign_slug, item_id)
);

CREATE INDEX IF NOT EXISTS ix_gt_campaign ON ground_truth(campaign_slug, kind);
CREATE INDEX IF NOT EXISTS ix_gt_technique ON ground_truth(campaign_slug, technique);

-- The scenario spec a campaign was built from, so it can be re-rolled or edited.
CREATE TABLE IF NOT EXISTS specs (
    campaign_slug TEXT PRIMARY KEY REFERENCES campaigns(slug) ON DELETE CASCADE,
    spec_json     TEXT NOT NULL,
    steps_json    TEXT NOT NULL DEFAULT '[]'
);
"""


@dataclass(slots=True)
class Campaign:
    slug: str
    display_name: str
    db_name: str
    kind: str
    twin_of: str | None
    seed: int
    status: str
    generation: int
    md_path: str
    data_path: str
    created_at: float
    updated_at: float

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Campaign":
        return cls(
            slug=row["slug"],
            display_name=row["display_name"],
            db_name=row["db_name"],
            kind=row["kind"],
            twin_of=row["twin_of"],
            seed=row["seed"],
            status=row["status"],
            generation=row["generation"],
            md_path=row["md_path"],
            data_path=row["data_path"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


class Registry:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: FastAPI runs sync endpoints on worker
        # threads. Writes are short and serialised by SQLite's own lock.
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate()
        self._conn.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
        self._conn.commit()

    def _migrate(self) -> None:
        """Bring an existing database up to SCHEMA_VERSION.

        `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so new
        columns have to be added explicitly — otherwise a registry created by an
        earlier version fails at the first INSERT with "no such column", which
        is a confusing way to learn you needed a migration.

        Driven by the table's actual shape, not the recorded version. The
        version is written during __init__ before any caller can fail, so a run
        that died mid-upgrade leaves a database stamped with the new version and
        the old columns — and a version check would then skip the migration
        forever. PRAGMA table_info cannot lie, and the per-column guard makes
        this idempotent.
        """
        have = {r["name"] for r in self._conn.execute("PRAGMA table_info(campaigns)")}
        # v1 -> v2: generation-scoped persist paths (see kusto/admin.py).
        for column, ddl in (
            ("generation", "INTEGER NOT NULL DEFAULT 1"),
            ("md_path", "TEXT NOT NULL DEFAULT ''"),
            ("data_path", "TEXT NOT NULL DEFAULT ''"),
        ):
            if column not in have:
                self._conn.execute(f"ALTER TABLE campaigns ADD COLUMN {column} {ddl}")
                logger.info("registry migration: added campaigns.%s", column)
        self._conn.commit()

    @property
    def connection(self) -> sqlite3.Connection:
        """The underlying connection, shared with HuntStore so hunts and
        campaigns live in one file with one lock."""
        return self._conn

    def close(self) -> None:
        self._conn.close()

    # ── Campaigns ────────────────────────────────────────────────────────

    def add(
        self,
        slug: str,
        display_name: str,
        db_name: str,
        *,
        kind: str = "campaign",
        twin_of: str | None = None,
        seed: int = 0,
        status: str = "empty",
        generation: int = 1,
        md_path: str = "",
        data_path: str = "",
    ) -> Campaign:
        now = time.time()
        self._conn.execute(
            "INSERT INTO campaigns(slug, display_name, db_name, kind, twin_of, seed, "
            "status, generation, md_path, data_path, created_at, updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (slug, display_name, db_name, kind, twin_of, seed, status,
             generation, md_path, data_path, now, now),
        )
        self._conn.commit()
        return self.get(slug)  # type: ignore[return-value]

    def get(self, slug: str) -> Campaign | None:
        row = self._conn.execute(
            "SELECT * FROM campaigns WHERE slug = ?", (slug,)
        ).fetchone()
        return Campaign.from_row(row) if row else None

    def list(self) -> list[Campaign]:
        rows = self._conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC"
        ).fetchall()
        return [Campaign.from_row(r) for r in rows]

    def db_names(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT db_name FROM campaigns ORDER BY created_at"
        ).fetchall()
        return [r["db_name"] for r in rows]

    def attach_entries(self) -> list[tuple[str, str]]:
        """[(db_name, md_path)] for every registered database — what reconcile()
        reads. Rows with no recorded path are skipped rather than guessed at;
        guessing would risk attaching a superseded generation."""
        rows = self._conn.execute(
            "SELECT db_name, md_path FROM campaigns WHERE md_path != '' ORDER BY created_at"
        ).fetchall()
        return [(r["db_name"], r["md_path"]) for r in rows]

    def set_paths(self, slug: str, generation: int, md_path: str, data_path: str) -> None:
        self._conn.execute(
            "UPDATE campaigns SET generation = ?, md_path = ?, data_path = ?, "
            "updated_at = ? WHERE slug = ?",
            (generation, md_path, data_path, time.time(), slug),
        )
        self._conn.commit()

    # ── Ground truth ─────────────────────────────────────────────────────

    def store_ground_truth(self, slug: str, labels: dict[str, dict]) -> int:
        """Replace a campaign's ground truth with a fresh label set.

        Deletes first so a re-roll never leaves stale labels pointing at
        _ItemIds that no longer exist.
        """
        self._conn.execute("DELETE FROM ground_truth WHERE campaign_slug = ?", (slug,))
        rows = [
            (slug, item_id, lab.get("kind", ""), lab.get("technique"),
             lab.get("variant"), lab.get("mimics"), lab.get("pattern"),
             lab.get("step"), lab.get("note"))
            for item_id, lab in labels.items()
        ]
        self._conn.executemany(
            "INSERT INTO ground_truth(campaign_slug, item_id, kind, technique, variant, "
            "mimics, pattern, step_index, note) VALUES(?,?,?,?,?,?,?,?,?)", rows)
        self._conn.commit()
        return len(rows)

    def ground_truth_counts(self, slug: str) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT kind, COUNT(*) c FROM ground_truth WHERE campaign_slug = ? GROUP BY kind",
            (slug,)).fetchall()
        return {r["kind"]: r["c"] for r in rows}

    def attack_item_ids(self, slug: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT item_id FROM ground_truth WHERE campaign_slug = ? AND kind = 'attack'",
            (slug,)).fetchall()
        return {r["item_id"] for r in rows}

    def planted_techniques(self, slug: str) -> list[str]:
        """Distinct ATT&CK techniques actually planted as attack in a campaign —
        the set a hunt is graded on identifying."""
        rows = self._conn.execute(
            "SELECT DISTINCT technique FROM ground_truth "
            "WHERE campaign_slug = ? AND kind = 'attack' AND technique IS NOT NULL "
            "ORDER BY technique", (slug,)).fetchall()
        return [r["technique"] for r in rows]

    def classify_item_ids(self, slug: str, item_ids: list[str]) -> dict[str, dict]:
        """Look up the ground truth for specific rows — used to grade what an
        analyst pinned. Returns {item_id: {kind, technique, variant, mimics,
        pattern}} for the ones that are labelled; an id absent from the result
        is genuinely benign (not attack, decoy or noise)."""
        if not item_ids:
            return {}
        out: dict[str, dict] = {}
        # Chunk to stay under SQLite's variable limit on large evidence sets.
        for i in range(0, len(item_ids), 400):
            chunk = item_ids[i:i + 400]
            q = ("SELECT item_id, kind, technique, variant, mimics, pattern "
                 "FROM ground_truth WHERE campaign_slug = ? AND item_id IN "
                 f"({','.join('?' * len(chunk))})")
            for r in self._conn.execute(q, [slug, *chunk]).fetchall():
                out[r["item_id"]] = {
                    "kind": r["kind"], "technique": r["technique"],
                    "variant": r["variant"], "mimics": r["mimics"],
                    "pattern": r["pattern"],
                }
        return out

    def technique_events(self, slug: str) -> dict[str, int]:
        """Attack event count per planted technique, for the debrief."""
        rows = self._conn.execute(
            "SELECT technique, COUNT(*) c FROM ground_truth "
            "WHERE campaign_slug = ? AND kind = 'attack' GROUP BY technique", (slug,)).fetchall()
        return {r["technique"]: r["c"] for r in rows}

    def store_spec(self, slug: str, spec_json: str, steps_json: str = "[]") -> None:
        self._conn.execute(
            "INSERT INTO specs(campaign_slug, spec_json, steps_json) VALUES(?,?,?) "
            "ON CONFLICT(campaign_slug) DO UPDATE SET spec_json=excluded.spec_json, "
            "steps_json=excluded.steps_json",
            (slug, spec_json, steps_json))
        self._conn.commit()

    def get_spec(self, slug: str) -> tuple[str, str] | None:
        row = self._conn.execute(
            "SELECT spec_json, steps_json FROM specs WHERE campaign_slug = ?",
            (slug,)).fetchone()
        return (row["spec_json"], row["steps_json"]) if row else None

    def set_status(self, slug: str, status: str) -> None:
        self._conn.execute(
            "UPDATE campaigns SET status = ?, updated_at = ? WHERE slug = ?",
            (status, time.time(), slug),
        )
        self._conn.commit()

    def set_status_many(self, slugs: Iterable[str], status: str) -> None:
        now = time.time()
        self._conn.executemany(
            "UPDATE campaigns SET status = ?, updated_at = ? WHERE slug = ?",
            [(status, now, s) for s in slugs],
        )
        self._conn.commit()

    def statuses_by_db(self, db_names: Iterable[str], status: str) -> None:
        now = time.time()
        self._conn.executemany(
            "UPDATE campaigns SET status = ?, updated_at = ? WHERE db_name = ?",
            [(status, now, d) for d in db_names],
        )
        self._conn.commit()

    def remove(self, slug: str) -> None:
        self._conn.execute("DELETE FROM campaigns WHERE slug = ?", (slug,))
        self._conn.commit()
