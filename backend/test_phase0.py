"""Phase 0 verification — engine, client, database lifecycle, reconciler.

The exit test that matters is the last one: destroy the container entirely,
bring it back, and prove that campaign data returns. Persisted databases are
not auto-attached, so without the reconciler a `docker compose down` is
indistinguishable from total data loss. Everything before it is scaffolding for
that check.

Run: .venv/Scripts/python test_phase0.py
     .venv/Scripts/python test_phase0.py --skip-restart    (fast, no docker)
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from config import settings
from kusto import KustoClient, KustoError, KustoUnavailable
from kusto import admin
from store import Registry

# Windows consoles default to cp1252 and mangle the em-dashes in this output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT = Path(__file__).resolve().parent.parent
TEST_SLUG = "phase0-selftest"
TEST_DB = "HR_phase0_selftest"

failures: list[str] = []


def rule(title: str) -> None:
    print(f"\n{'-' * 74}\n{title}\n{'-' * 74}")


def check(label: str, got, want) -> None:
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"          got:  {got!r}")
        print(f"          want: {want!r}")
        failures.append(label)


def check_true(label: str, got, detail: str = "") -> None:
    ok = bool(got)
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        if detail:
            print(f"          {detail}")
        failures.append(label)


def compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(PROJECT), capture_output=True, text=True,
    )


async def main(skip_restart: bool) -> int:
    client = KustoClient(settings.kusto_url, timeout=60.0)

    rule("Engine reachable")
    try:
        waited = await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
        print(f"  ok    engine ready at {settings.kusto_url} ({waited:.1f}s)")
    except KustoUnavailable as exc:
        print(f"  FAIL  {exc}")
        print("\n  Start it with:  docker compose up -d")
        await client.aclose()
        return 1

    rule("Client — results and errors")
    result = await client.query("NetDefaultDB", "print result = 1 + 1")
    check("print 1+1 returns 2", result.scalar(), 2)
    check("columns parsed", result.columns, ["result"])

    multi = await client.query(
        "NetDefaultDB",
        'datatable(a:string, b:long) ["x", 1, "y", 2] | order by b asc',
    )
    check("row count", len(multi), 2)
    check("dicts()", multi.dicts()[0], {"a": "x", "b": 1})
    check("column()", multi.column("a"), ["x", "y"])

    try:
        await client.query("NetDefaultDB", "ThisTableDoesNotExist | count")
        check_true("bad query raises KustoError", False, "no exception raised")
    except KustoError as exc:
        check_true("bad query raises KustoError", True)
        check_true(
            "error message is diagnostic, not 'HTTP 400'",
            "400" not in exc.message and len(exc.message) > 10,
            f"got: {exc.message!r}",
        )
        check("failing CSL is attached to the error", exc.csl, "ThisTableDoesNotExist | count")

    rule("Database name validation")
    for bad in ["", "1abc", "has-hyphen", "has space", "semi;colon", "drop`tick", "a" * 64]:
        try:
            admin.validate_db_name(bad)
            check_true(f"rejects {bad!r}", False, "accepted a bad name")
        except admin.InvalidDatabaseName:
            check_true(f"rejects {bad!r}", True)
    check("accepts HR_apt29_drill", admin.validate_db_name("HR_apt29_drill"), "HR_apt29_drill")

    rule("Database lifecycle")
    # Detach, then take a fresh generation. A prior run's files persist on the
    # volume (drop only detaches), so ensure_database would reattach the old
    # data and the row counts below would climb with every run. A clean
    # generation is the guaranteed-empty starting point — the same reason reset
    # exists in production.
    await admin.detach_database(client, TEST_DB)
    paths = await admin.next_generation(client, TEST_DB, settings.kusto_data_dir, 0)
    check_true("fresh generation created", TEST_DB in await admin.show_databases(client))
    again, _ = await admin.ensure_database(client, TEST_DB, settings.kusto_data_dir)
    check("ensure_database is idempotent when present", again, "present")
    check_true("persist path is generation-scoped", "/gen" in paths.md, paths.md)

    await client.mgmt(TEST_DB, ".create table Marker (TimeGenerated:datetime, Note:string)")
    await client.mgmt(
        TEST_DB,
        '.set-or-append Marker <| datatable(TimeGenerated:datetime, Note:string) '
        '[datetime(2026-08-26T00:00:00Z), "phase0"]',
    )
    await client.mgmt(
        TEST_DB,
        '.create-or-alter function MarkerNote() { Marker | project Note }',
    )
    check("data ingested", (await client.query(TEST_DB, "Marker | count")).scalar(), 1)
    check("function created", (await client.query(TEST_DB, "MarkerNote")).scalar(), "phase0")

    rule("Registry")
    with tempfile.TemporaryDirectory() as tmp:
        reg = Registry(Path(tmp) / "t.db")
        reg.add(TEST_SLUG, "Phase 0 self-test", TEST_DB, seed=42,
                md_path="/kustodata/dbs/x/gen1/md", data_path="/kustodata/dbs/x/gen1/data")
        reg.add(f"{TEST_SLUG}-clean", "twin", f"{TEST_DB}_clean",
                kind="clean_twin", twin_of=TEST_SLUG,
                md_path="/kustodata/dbs/y/gen1/md", data_path="/kustodata/dbs/y/gen1/data")
        check("db_names() lists both", sorted(reg.db_names()),
              sorted([TEST_DB, f"{TEST_DB}_clean"]))
        check("attach_entries carries paths", len(reg.attach_entries()), 2)
        reg.set_paths(TEST_SLUG, 3, "/new/md", "/new/data")
        check("set_paths updates generation", reg.get(TEST_SLUG).generation, 3)
        check("get() round-trips seed", reg.get(TEST_SLUG).seed, 42)
        reg.set_status(TEST_SLUG, "ready")
        check("status updated", reg.get(TEST_SLUG).status, "ready")
        reg.remove(TEST_SLUG)
        check("cascade removes the twin", reg.db_names(), [])
        reg.close()

    rule("Detach does not delete — the finding that shapes reset")
    await admin.detach_database(client, TEST_DB)
    check_true("gone from .show databases",
               TEST_DB not in await admin.show_databases(client))
    await admin.attach_database(client, TEST_DB, paths.md)
    check("data survived detach + reattach",
          (await client.query(TEST_DB, "Marker | count")).scalar(), 1)
    try:
        await admin.create_database(client, TEST_DB, paths)
        check_true("recreating over a used path is rejected", False, "it succeeded")
    except KustoError:
        check_true("recreating over a used path is rejected", True)

    rule("Reset moves to a clean generation")
    new_paths = await admin.reset_database(client, TEST_DB, settings.kusto_data_dir,
                                           paths.generation)
    check_true("generation advanced", new_paths.generation > paths.generation,
               f"{paths.generation} -> {new_paths.generation}")
    check("reset database is empty",
          (await client.query(TEST_DB, ".show tables | count")).scalar()
          if False else (await client.mgmt(TEST_DB, ".show tables")).rows, [])

    rule("Reconciler — no-op when everything is attached")
    report = await admin.reconcile(client, [(TEST_DB, new_paths.md)])
    check("already present", report.already_present, [TEST_DB])
    check("nothing attached", report.attached, [])
    check_true("report.ok", report.ok)

    report = await admin.reconcile(client, [("HR_never_existed", "/kustodata/dbs/nope/gen1/md")])
    check_true(
        "unknown database reported as missing, not crashed",
        report.missing == ["HR_never_existed"] or bool(report.failed),
        f"missing={report.missing} failed={report.failed}",
    )

    if skip_restart:
        print("\n  (skipping container restart test — --skip-restart)")
        await client.aclose()
        return report_result()

    rule("EXIT TEST — data survives destroying and recreating the container")
    print("  docker compose down ...")
    down = compose("down")
    if down.returncode != 0:
        print(f"  FAIL  compose down: {down.stderr.strip()[:300]}")
        failures.append("compose down")
        await client.aclose()
        return report_result()

    print("  docker compose up -d ...")
    up = compose("up", "-d")
    if up.returncode != 0:
        print(f"  FAIL  compose up: {up.stderr.strip()[:300]}")
        failures.append("compose up")
        await client.aclose()
        return report_result()

    await client.aclose()
    client = KustoClient(settings.kusto_url, timeout=60.0)
    waited = await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
    print(f"  engine back ({waited:.1f}s)")

    # This assertion is the point of the whole exercise. If it ever starts
    # failing because the database IS listed, the emulator gained auto-attach
    # and the reconciler became belt-and-braces rather than load-bearing.
    visible = await admin.show_databases(client)
    check_true(
        "database is NOT auto-attached after recreate (the problem is real)",
        TEST_DB not in visible,
        f"unexpectedly present: {sorted(visible)}",
    )

    report = await admin.reconcile(client, [(TEST_DB, paths.md)])
    check("reconciler reattaches it", report.attached, [TEST_DB])
    check("rows survived", (await client.query(TEST_DB, "Marker | count")).scalar(), 1)
    check("functions survived", (await client.query(TEST_DB, "MarkerNote")).scalar(), "phase0")

    rule("Teardown")
    await admin.detach_database(client, TEST_DB)
    check_true("dropped", TEST_DB not in await admin.show_databases(client))
    await client.aclose()
    return report_result()


def report_result() -> int:
    print("\n" + "=" * 74)
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("Phase 0 verified.")
    return 0


if __name__ == "__main__":
    started = time.time()
    code = asyncio.run(main("--skip-restart" in sys.argv))
    print(f"({time.time() - started:.1f}s)")
    sys.exit(code)
