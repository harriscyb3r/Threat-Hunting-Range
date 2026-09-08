"""HTTP client for the Kusto engine.

The emulator exposes two endpoints and no authentication:

    POST /v1/rest/query   — KQL queries
    POST /v1/rest/mgmt    — control commands (.create, .ingest, .show, ...)

Both take {"db": ..., "csl": ...} and answer with a Tables[] envelope. Table_0
is the result set; the rest is query metadata we discard.

Error handling gets more care than the happy path here. This client eventually
backs the Query Lab, where a returned error message *is* the product — an
analyst mistyping a column name needs Kusto's own diagnostic, not "HTTP 400".
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger("range.kusto")


class KustoError(RuntimeError):
    """A query or command the engine rejected.

    Carries the failing CSL so callers can log or surface it without having to
    thread the original text through their own error handling.
    """

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        database: str | None = None,
        csl: str | None = None,
        status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.database = database
        self.csl = csl
        self.status = status

    def __str__(self) -> str:
        prefix = f"[{self.code}] " if self.code else ""
        return f"{prefix}{self.message}"


class KustoUnavailable(RuntimeError):
    """The engine could not be reached at all — not running, or still booting."""


@dataclass(slots=True)
class KustoResult:
    """A single result set."""

    columns: list[str] = field(default_factory=list)
    column_types: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    elapsed_ms: float = 0.0

    def __len__(self) -> int:
        return len(self.rows)

    def dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row)) for row in self.rows]

    def scalar(self) -> Any:
        """First cell of the first row, or None when the result set is empty."""
        if not self.rows or not self.rows[0]:
            return None
        return self.rows[0][0]

    def column(self, name: str) -> list[Any]:
        idx = self.columns.index(name)
        return [row[idx] for row in self.rows]


class KustoClient:
    """Async client over a single Kusto engine.

    One instance is shared for the process lifetime; httpx pools connections,
    which matters when ingest fires fifty 1.8 MB commands back to back.
    """

    def __init__(self, base_url: str, *, timeout: float = 120.0) -> None:
        self.base_url = base_url.rstrip("/")
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    # ── Public API ───────────────────────────────────────────────────────

    async def query(self, db: str, csl: str, *, timeout: float | None = None) -> KustoResult:
        return await self._execute("query", db, csl, timeout=timeout)

    async def mgmt(self, db: str, csl: str, *, timeout: float | None = None) -> KustoResult:
        return await self._execute("mgmt", db, csl, timeout=timeout)

    async def wait_ready(self, *, timeout: float = 120.0, poll_s: float = 1.0) -> float:
        """Block until the engine answers a trivial query.

        Returns seconds waited. Raises KustoUnavailable on timeout. A cold
        kustainer is typically ready in about two seconds, but a first-ever
        start that has to lay out /kustodata takes longer.
        """
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        last: Exception | None = None
        while time.monotonic() < deadline:
            try:
                await self._execute("query", "NetDefaultDB", "print ready=1", timeout=5.0)
                return time.monotonic() - started
            except (KustoUnavailable, KustoError, httpx.HTTPError) as exc:
                last = exc
                await _sleep(poll_s)
        raise KustoUnavailable(
            f"Kusto at {self.base_url} did not become ready within {timeout:.0f}s "
            f"(last error: {last})"
        )

    async def is_up(self) -> bool:
        try:
            await self._execute("query", "NetDefaultDB", "print 1", timeout=5.0)
            return True
        except (KustoUnavailable, KustoError, httpx.HTTPError):
            return False

    # ── Internals ────────────────────────────────────────────────────────

    async def _execute(
        self, endpoint: str, db: str, csl: str, *, timeout: float | None = None
    ) -> KustoResult:
        payload = {"db": db, "csl": csl}
        started = time.perf_counter()
        try:
            resp = await self._http.post(
                f"/v1/rest/{endpoint}",
                json=payload,
                timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT,
            )
        except httpx.HTTPError as exc:
            raise KustoUnavailable(f"cannot reach Kusto at {self.base_url}: {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000

        if resp.status_code >= 400:
            raise _parse_error(resp, db=db, csl=csl)

        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise KustoError(
                f"engine returned non-JSON ({resp.status_code}): {resp.text[:300]}",
                database=db, csl=csl, status=resp.status_code,
            ) from exc

        return _parse_result(body, elapsed_ms, db=db, csl=csl)


def _parse_result(body: Any, elapsed_ms: float, *, db: str, csl: str) -> KustoResult:
    tables = body.get("Tables") if isinstance(body, dict) else None
    if not tables:
        # Some control commands answer with an empty envelope; that is a
        # success with no rows, not a failure.
        return KustoResult(elapsed_ms=elapsed_ms)

    primary = tables[0]
    columns = [c["ColumnName"] for c in primary.get("Columns", [])]
    types = [c.get("ColumnType") or c.get("DataType", "") for c in primary.get("Columns", [])]
    return KustoResult(
        columns=columns,
        column_types=types,
        rows=primary.get("Rows", []),
        elapsed_ms=elapsed_ms,
    )


def _parse_error(resp: httpx.Response, *, db: str, csl: str) -> KustoError:
    """Turn an error response into a KustoError.

    The engine is inconsistent: some rejections come back as a JSON error
    envelope, others as a plain-text block starting "BadRequest: ...". Both
    shapes are handled, and anything unrecognised falls through to the raw body
    so no diagnostic detail is ever swallowed.
    """
    text = resp.text or ""
    try:
        body = resp.json()
    except (json.JSONDecodeError, ValueError):
        body = None

    if isinstance(body, dict):
        err = body.get("error")
        if isinstance(err, dict):
            message = (
                err.get("@message")
                or err.get("message")
                or err.get("@type")
                or text[:500]
            )
            inner = err.get("@innererror") or {}
            if isinstance(inner, dict) and inner.get("@message"):
                message = f"{message} — {inner['@message']}"
            return KustoError(
                str(message).strip(),
                code=err.get("code") or err.get("@type"),
                database=db, csl=csl, status=resp.status_code,
            )
        if body.get("Message"):
            return KustoError(
                str(body["Message"]).strip(),
                database=db, csl=csl, status=resp.status_code,
            )

    # Plain-text form. Keep the first line (the actual reason) and drop the
    # ClientRequestId/ActivityId trailer, which is noise to an analyst.
    first = text.strip().split("\n", 1)[0] if text.strip() else f"HTTP {resp.status_code}"
    return KustoError(first.strip(), database=db, csl=csl, status=resp.status_code)


async def _sleep(seconds: float) -> None:
    import asyncio
    await asyncio.sleep(seconds)
