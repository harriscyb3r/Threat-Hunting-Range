"""Backend configuration.

Every setting can be overridden by a RANGE_-prefixed environment variable, which
is how docker-compose points the containerised backend at the `kusto` service
instead of localhost.
"""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent
_PROJECT_DIR = _BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        env_prefix="RANGE_",
        extra="ignore",
    )

    # ── Paths ────────────────────────────────────────────────────────────
    data_dir: Path = _PROJECT_DIR / "data"
    db_path: Path = _PROJECT_DIR / "data" / "range.db"

    # ── Server ───────────────────────────────────────────────────────────
    host: str = "127.0.0.1"      # loopback only; local practice tool, no auth
    port: int = 8780             # 8770 is sherlog, 8765 is skill-cti

    # ── Kusto engine ─────────────────────────────────────────────────────
    kusto_url: str = "http://localhost:8080"

    # Path *inside the engine container* where persistent databases live. It is
    # the mount point of the hr_kusto volume, not a host path — the backend may
    # never see these files at all, which is why the campaign registry rather
    # than a disk scan drives reconciliation (see store/registry.py).
    kusto_data_dir: str = "/kustodata/dbs"

    # Where this process can see the Kusto volume, if at all. The containerised
    # backend mounts it; a backend run on the host against a named volume
    # cannot, and then deleting a campaign detaches it but leaves the files.
    # Empty means "no access" — purging is skipped and reported honestly.
    kusto_volume_mount: str = ""

    # Generous: a 10k-row .set-or-append is ~1.8 MB of command text, and a cold
    # engine can take a few seconds to answer its first query.
    kusto_timeout_s: float = 120.0
    kusto_ready_timeout_s: float = 120.0

    # ── Scenario drafting ────────────────────────────────────────────────
    # "local" and "claude-code" cost nothing. "api" is the only setting that
    # can spend money, and it is never reached unless set here explicitly.
    drafter: str = "local"

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
settings.ensure_dirs()
