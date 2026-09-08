"""Phase 1 verification — schemas, org model, generators, ingest, ASIM.

The exit test is the last section: `_Im_Authentication` and `SigninLogs` must
agree. An ASIM parser that silently drops or duplicates rows is worse than no
parser at all, because every hunt written against it is quietly wrong.

Run: .venv/Scripts/python test_phase1.py
     .venv/Scripts/python test_phase1.py --events 50000    (faster)
"""
from __future__ import annotations

import asyncio
import sys
import time

from config import settings
from generators.build import build_campaign, generate_benign
from kusto import KustoClient, KustoError, KustoUnavailable, admin, schemas
from org import build_org

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TEST_DB = "HR_phase1_selftest"
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
    print(f"  {'ok  ' if got else 'FAIL'}  {label}")
    if not got:
        if detail:
            print(f"          {detail}")
        failures.append(label)


def check_between(label: str, got: float, lo: float, hi: float, unit: str = "") -> None:
    ok = lo <= got <= hi
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}: {got:,.1f}{unit}")
    if not ok:
        print(f"          want between {lo:,}{unit} and {hi:,}{unit}")
        failures.append(label)


async def main(target_events: int) -> int:
    client = KustoClient(settings.kusto_url, timeout=180.0)

    rule("Schemas")
    all_s = schemas.all_schemas()
    check("20 tables registered", len(all_s), 20)
    problems: list[str] = []
    for s in all_s:
        problems += s.validate()
    check("all schemas valid", problems, [])
    check_true("every schema has a docs URL", all(s.docs.startswith("https://") for s in all_s))
    check_true("_ItemId present everywhere",
               all("_ItemId" in s.column_names for s in all_s))
    print(f"        {sum(len(s.columns) for s in all_s)} columns across {len(all_s)} tables")

    rule("Org model")
    org = build_org("midsize", seed=1337, window_days=14)
    check("200 humans", len(org.humans), 200)
    check("6 service accounts", len(org.service_accounts), 6)
    check("2 domain controllers", len(org.domain_controllers), 2)
    check_true("every human has a workstation",
               all(u.device_names for u in org.humans))
    check_true("deterministic", build_org("midsize", 1337).tenant_id == org.tenant_id)
    check_true("seed changes the org", build_org("midsize", 99).tenant_id != org.tenant_id)
    check_true("users span multiple timezones",
               len({u.location.utc_offset_h for u in org.humans}) > 1)

    rule("Value serialisation")
    from kusto.ingest import kql_string, kql_value
    check("backslashes escaped", kql_string(r"C:\temp"), r'"C:\\temp"')
    check("quotes escaped", kql_string('say "hi"'), '"say \\"hi\\""')
    check("newlines escaped", kql_string("a\nb"), '"a\\nb"')
    check("null string", kql_value(None, "string"), '""')
    check("null long", kql_value(None, "long"), "long(null)")
    check("bool", kql_value(True, "bool"), "true")
    check("dynamic", kql_value({"a": 1}, "dynamic"), 'dynamic({"a":1})')

    rule(f"Generation ({target_events:,} target events)")
    t0 = time.perf_counter()
    by_table, labels = generate_benign(org, target_events)
    gen_s = time.perf_counter() - t0
    total = sum(len(v) for v in by_table.values())
    print(f"        {total:,} rows in {gen_s:.1f}s ({total/gen_s:,.0f}/s)")

    ids = [r["_ItemId"] for rows in by_table.values() for r in rows]
    check("_ItemId globally unique", len(ids), len(set(ids)))

    bad_cols: list[str] = []
    for table, rows in by_table.items():
        valid = set(schemas.get(table).column_names)
        for row in rows:
            extra = set(row) - valid
            if extra:
                bad_cols.append(f"{table}: {sorted(extra)}")
                break
    check("every row conforms to its schema", bad_cols, [])

    ts = [r["TimeGenerated"] for rows in by_table.values() for r in rows]
    check_true("all timestamps inside the window",
               all(org.window_start <= t <= org.window_end for t in ts),
               f"{min(ts)} .. {max(ts)} vs {org.window_start} .. {org.window_end}")

    rule("Realism — the baseline has to be hard to hunt")
    sl = by_table["SigninLogs"]
    fail_rate = sum(1 for r in sl if r.get("ResultType") != "0") / len(sl) * 100
    check_between("SigninLogs failure rate", fail_rate, 5, 25, "%")

    sec = by_table["SecurityEvent"]
    n4688 = [r for r in sec if r["EventID"] == 4688]
    no_cmd = sum(1 for r in n4688 if not r.get("CommandLine"))
    check_between("4688 rows with no CommandLine (audit-policy gap)",
                  no_cmd / len(n4688) * 100, 15, 45, "%")

    kerb = [r for r in sec if r["EventID"] in (4768, 4769)]
    rc4 = sum(1 for r in kerb if r.get("TicketEncryptionType") == "0x17")
    check_between("RC4 share of Kerberos tickets", rc4 / len(kerb) * 100, 1, 20, "%")

    dns = by_table["DnsEvents"]
    check_between("distinct DNS names as share of queries",
                  len({r["Name"] for r in dns}) / len(dns) * 100, 10, 60, "%")

    fw = by_table["CommonSecurityLog"]
    denies = sum(1 for r in fw if r["DeviceAction"] == "deny") / len(fw) * 100
    check_between("firewall deny rate", denies, 2, 30, "%")

    patterns = {v["pattern"] for v in labels.values()}
    check("all 6 ambient noise patterns present", len(patterns), 6)
    print(f"        {sorted(patterns)}")

    # Every noise pattern must be reachable by the query it is meant to defeat.
    enc = [r for r in by_table["DeviceProcessEvents"]
           if "-EncodedCommand" in (r.get("ProcessCommandLine") or "")]
    check_true("benign encoded PowerShell exists (defeats a naive -enc query)",
               len(enc) > 20, f"only {len(enc)}")

    rule("Engine — build the campaign")
    try:
        await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
    except KustoUnavailable as exc:
        print(f"  FAIL  {exc}\n\n  Start it with:  docker compose up -d")
        await client.aclose()
        return 1

    # Detach then take a fresh generation: dropping leaves files behind, so a
    # re-run cannot reuse the previous path.
    await admin.detach_database(client, TEST_DB)
    paths = await admin.next_generation(client, TEST_DB, settings.kusto_data_dir, 0)
    print(f"        building at {paths.md}")
    report = await build_campaign(client, TEST_DB, target_events=target_events, org=org)
    print(f"        {report.summary()}")
    print(report.table_breakdown())
    check("13 ASIM parsers deployed", len(report.parsers), 13)
    # Measured in MB/s: rows/s is meaningless across tables 18 to 60 columns
    # wide, and the engine's limit is bytes of command text, not row count.
    check_between("ingest throughput", report.mb_per_second, 3.0, 100.0, " MB/s")

    rule("Round trip — what went in is what comes back")
    for table in ("SigninLogs", "DeviceProcessEvents", "DnsEvents", "SecurityEvent"):
        got = (await client.query(TEST_DB, f"{table} | count")).scalar()
        check(f"{table} row count", got, report.rows_by_table[table])

    cmd = (await client.query(
        TEST_DB,
        'DeviceProcessEvents | where ProcessCommandLine has "chrome.exe" '
        "| take 1 | project ProcessCommandLine")).scalar()
    check_true("backslashes survived ingest", cmd and "\\" in cmd, f"got {cmd!r}")

    dyn = (await client.query(
        TEST_DB,
        "SigninLogs | where isnotempty(tostring(LocationDetails.countryOrRegion)) "
        "| take 1 | project c = tostring(LocationDetails.countryOrRegion)")).scalar()
    check_true("dynamic columns are queryable", bool(dyn), f"got {dyn!r}")

    rule("EXIT TEST — ASIM agrees with the native tables")
    native_signin = (await client.query(TEST_DB, "SigninLogs | count")).scalar()
    asim_signin = (await client.query(
        TEST_DB, 'vimAuthenticationSigninLogs | count')).scalar()
    check("vimAuthenticationSigninLogs == SigninLogs", asim_signin, native_signin)

    native_all = (await client.query(TEST_DB,
        "let a = toscalar(SigninLogs | count); "
        "let b = toscalar(AADNonInteractiveUserSignInLogs | count); "
        "let c = toscalar(SecurityEvent | where EventID in (4624,4625) | count); "
        "let d = toscalar(DeviceLogonEvents | count); "
        "print total = a + b + c + d")).scalar()
    asim_all = (await client.query(TEST_DB, "_Im_Authentication | count")).scalar()
    check("_Im_Authentication == sum of its four sources", asim_all, native_all)

    # Filtering parameters must actually filter, and match the native equivalent.
    native_fail = (await client.query(
        TEST_DB, 'SigninLogs | where ResultType != "0" | count')).scalar()
    asim_fail = (await client.query(
        TEST_DB, 'vimAuthenticationSigninLogs(eventresult="Failure") | count')).scalar()
    check("eventresult=Failure matches native", asim_fail, native_fail)
    check_true("the filter actually narrows", asim_fail < asim_signin,
               f"{asim_fail} vs {asim_signin}")

    upn = (await client.query(TEST_DB, "SigninLogs | take 1 | project UserPrincipalName")).scalar()
    n_native = (await client.query(
        TEST_DB, f'SigninLogs | where UserPrincipalName has "{upn}" | count')).scalar()
    n_asim = (await client.query(
        TEST_DB, f'vimAuthenticationSigninLogs(targetusername_has="{upn}") | count')).scalar()
    check("targetusername_has matches native", n_asim, n_native)

    fields = (await client.query(
        TEST_DB, "_Im_Authentication | take 1")).columns
    for required in ("EventVendor", "EventProduct", "EventResult", "EventType",
                     "TargetUsername", "SrcIpAddr", "Dvc", "EventSchema"):
        check_true(f"ASIM field {required} present", required in fields)

    rule("ASIM — the other three schemas")
    proc_native = (await client.query(TEST_DB,
        'let a = toscalar(DeviceProcessEvents | where ActionType == "ProcessCreated" | count); '
        "let b = toscalar(SecurityEvent | where EventID == 4688 | count); "
        "print total = a + b")).scalar()
    proc_asim = (await client.query(TEST_DB, "_Im_ProcessCreate | count")).scalar()
    check("_Im_ProcessCreate == DeviceProcessEvents + 4688", proc_asim, proc_native)

    dns_native = (await client.query(TEST_DB, "DnsEvents | count")).scalar()
    dns_asim = (await client.query(TEST_DB, "_Im_Dns | count")).scalar()
    check("_Im_Dns == DnsEvents", dns_asim, dns_native)

    net_native = (await client.query(TEST_DB,
        "let a = toscalar(DeviceNetworkEvents | count); "
        'let b = toscalar(CommonSecurityLog | where DeviceVendor == "Palo Alto Networks" | count); '
        "print total = a + b")).scalar()
    net_asim = (await client.query(TEST_DB, "_Im_NetworkSession | count")).scalar()
    check("_Im_NetworkSession == DeviceNetworkEvents + Palo Alto CEF", net_asim, net_native)

    encoded = (await client.query(
        TEST_DB,
        '_Im_ProcessCreate(commandline_has_any=dynamic(["-EncodedCommand"])) | count')).scalar()
    check_true("_Im_ProcessCreate commandline_has_any filters", encoded > 0, f"got {encoded}")

    nx = (await client.query(
        TEST_DB, '_Im_Dns(responsecodename="NXDOMAIN") | count')).scalar()
    check_true("_Im_Dns responsecodename filters", 0 < nx < dns_asim, f"got {nx}/{dns_asim}")

    rule("A real hunt runs, both ways")
    q_native = """
        SigninLogs
        | where ResultType == "50126"
        | summarize Failures = count(), Apps = dcount(AppDisplayName) by UserPrincipalName
        | where Failures > 1
        | order by Failures desc
        | take 5
    """
    q_asim = """
        _Im_Authentication(eventresult="Failure")
        | where EventResultDetails == "Incorrect password"
        | summarize Failures = count() by TargetUsername
        | where Failures > 1
        | order by Failures desc
        | take 5
    """
    rn = await client.query(TEST_DB, q_native)
    ra = await client.query(TEST_DB, q_asim)
    check_true("native hunt returns rows", len(rn) > 0)
    check_true("ASIM hunt returns rows", len(ra) > 0)
    print(f"        native {len(rn)} rows in {rn.elapsed_ms:.0f}ms, "
          f"ASIM {len(ra)} rows in {ra.elapsed_ms:.0f}ms")

    ac = await client.query(TEST_DB,
        'DeviceProcessEvents | where FileName == "powershell.exe" | evaluate autocluster()')
    check_true("autocluster runs on generated data", len(ac) >= 0)

    rule("Teardown")
    await admin.detach_database(client, TEST_DB)
    check_true("dropped", TEST_DB not in await admin.show_databases(client))
    await client.aclose()

    print("\n" + "=" * 74)
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("Phase 1 verified.")
    return 0


if __name__ == "__main__":
    events = 300_000
    if "--events" in sys.argv:
        events = int(sys.argv[sys.argv.index("--events") + 1])
    started = time.time()
    code = asyncio.run(main(events))
    print(f"({time.time() - started:.1f}s)")
    sys.exit(code)
