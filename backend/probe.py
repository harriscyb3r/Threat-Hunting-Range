"""KQL capability probe — regression test for the engine.

The range's curriculum depends on a specific set of KQL features being present
in the emulator. All of them were verified before the design was fixed, but the
image is `:latest` and a future pull could quietly withdraw one. Run this after
any image update.

The three that matter most are `autocluster`, `basket` and `diffpatterns` —
PEAK Baseline and Model-Assisted hunts are built on them, and losing them would
cut two of the three PEAK hunt types.

Run: .venv/Scripts/python probe.py
"""
from __future__ import annotations

import asyncio
import sys

from config import settings
from kusto import KustoClient, KustoError, KustoUnavailable
from kusto import admin

# Windows consoles default to cp1252 and mangle the em-dashes in this output.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROBE_DB = "HR_probe_capability"

# (label, csl) — each must return rows without erroring.
CHECKS: list[tuple[str, str]] = [
    ("let + toscalar + arg_max",
     "let x = toscalar(Probe | count); "
     "Probe | summarize arg_max(TimeGenerated, *) by Account | project Account"),
    ("summarize / bin / make_set / dcount",
     "Probe | summarize c=count(), u=make_set(Account), d=dcount(SrcIp) "
     "by bin(TimeGenerated, 1h)"),
    ("join kind=leftanti",
     'Probe | join kind=leftanti (Probe | where Result == "Success") on Account'),
    ("union wildcard", "union Prob* | count"),
    ("materialize + mv-expand",
     "let m = materialize(Probe); m | mv-expand Extra | count"),
    ("bag_unpack", "Probe | evaluate bag_unpack(Extra) | count"),
    ("ipv4_is_in_range", 'Probe | where ipv4_is_in_range(SrcIp, "185.220.0.0/16") | count'),
    ("ipv4_is_private", "Probe | where not(ipv4_is_private(SrcIp)) | count"),
    ("geo_info_from_ip_address", 'print geo_info_from_ip_address("8.8.8.8")'),
    ("series_decompose_anomalies",
     "Probe | make-series c=count() on TimeGenerated step 1h "
     "| extend a=series_decompose_anomalies(c)"),
    ("series_fit_line",
     "Probe | make-series c=count() on TimeGenerated step 1h | extend series_fit_line(c)"),
    ("autocluster plugin  [PEAK Baseline]", "Probe | evaluate autocluster()"),
    ("basket plugin  [PEAK Baseline]", "Probe | evaluate basket()"),
    ("diffpatterns plugin  [PEAK M-ATH]",
     'Probe | extend f=(Result != "Success") | evaluate diffpatterns(f, "false", "true")'),
    ("scan operator",
     "Probe | sort by TimeGenerated asc "
     "| scan declare(s:long=0) with (step a: true => s = 1;)"),
    ("row_window_session",
     "Probe | sort by Account, TimeGenerated asc "
     "| extend ses=row_window_session(TimeGenerated, 1h, 10m, Account != prev(Account))"),
    ("matches regex / extract",
     'Probe | where Account matches regex "^svc-" '
     '| extend d=extract("@(.+)$", 1, Account) | count'),
    ("has_any / in~",
     'Probe | where Client has_any ("Other clients", "IMAP") and Result in~ ("Failure") | count'),
    ("externaldata", 'externaldata(x:string) [@"https://example.com/x.csv"] | count'),
    ("top-nested", "Probe | top-nested 2 of Account by count()"),
    ("pivot plugin", "Probe | evaluate pivot(Result)"),
    ("todynamic / parse_json", 'print p=todynamic(\'{"a":1}\') | extend v=p.a'),
    ("hash_sha256 / base64",
     'print h=hash_sha256("a"), b=base64_encode_tostring("a"), d=base64_decode_tostring("YQ==")'),
    ("datetime_diff / format_datetime",
     'Probe | extend g=datetime_diff("minute", now(), TimeGenerated), '
     'f=format_datetime(TimeGenerated, "HH:mm") | count'),
    ("dayofweek / hourofday",
     "Probe | extend dow=dayofweek(TimeGenerated), h=hourofday(TimeGenerated) | count"),
]

_SCHEMA = ("TimeGenerated:datetime, Account:string, SrcIp:string, "
           "Result:string, Client:string, Extra:dynamic")

_SEED = (
    f".set-or-append Probe <| datatable({_SCHEMA}) [\n"
    '  datetime(2026-08-20T09:14:00Z), "jane.doe@contoso.com", "203.0.113.44", '
    '"Success", "Browser", dynamic({"country":"AU","city":"Melbourne"}),\n'
    '  datetime(2026-08-20T02:41:00Z), "svc-backup@contoso.com", "185.220.101.9", '
    '"Failure", "Other clients", dynamic({"country":"RU","city":"Moscow"}),\n'
    '  datetime(2026-08-20T03:02:00Z), "svc-backup@contoso.com", "185.220.101.9", '
    '"Failure", "IMAP", dynamic({"country":"RU","city":"Moscow"})\n'
    "]"
)

# ASIM must work the way Sentinel does: a source parser with defaulted
# parameters, unioned by an _Im_* function, callable bare or with named filters.
_ASIM_SOURCE = """
.create-or-alter function with (FolderName="ASIM/Authentication")
vimAuthenticationProbe(starttime:datetime=datetime(null), endtime:datetime=datetime(null),
                       eventresult:string="*") {
    Probe
    | where (isnull(starttime) or TimeGenerated >= starttime)
        and (isnull(endtime) or TimeGenerated <= endtime)
    | extend EventResult = Result
    | where (eventresult == "*" or EventResult == eventresult)
    | extend EventVendor="Microsoft", EventProduct="Probe", EventSchema="Authentication",
             TargetUsername=Account, SrcIpAddr=SrcIp
    | project TimeGenerated, EventVendor, EventProduct, EventSchema, EventResult,
              TargetUsername, SrcIpAddr
}
"""

_ASIM_UNIFIER = """
.create-or-alter function with (FolderName="ASIM/Authentication")
_Im_AuthenticationProbe(starttime:datetime=datetime(null), endtime:datetime=datetime(null),
                        eventresult:string="*") {
    union isfuzzy=true vimAuthenticationProbe(starttime, endtime, eventresult)
}
"""


async def main() -> int:
    client = KustoClient(settings.kusto_url, timeout=60.0)
    passed: list[str] = []
    failed: list[tuple[str, str]] = []

    try:
        print(f"Kusto: {settings.kusto_url}")
        waited = await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
        print(f"engine ready ({waited:.1f}s)\n")

        await admin.drop_database(client, PROBE_DB)
        await admin.create_database(client, PROBE_DB, settings.kusto_data_dir)
        await client.mgmt(PROBE_DB, f".create table Probe ({_SCHEMA})")
        await client.mgmt(PROBE_DB, _SEED)

        print(f"{'KQL feature':<42} result")
        print("-" * 74)
        for label, csl in CHECKS:
            try:
                await client.query(PROBE_DB, csl)
                passed.append(label)
                print(f"{label:<42} ok")
            except (KustoError, KustoUnavailable) as exc:
                failed.append((label, str(exc)))
                print(f"{label:<42} FAIL — {exc}")

        print(f"\n{'ASIM parser behaviour':<42} result")
        print("-" * 74)
        for label, run in (
            ("source parser w/ default params", lambda: client.mgmt(PROBE_DB, _ASIM_SOURCE)),
            ("unifying _Im_ parser (union)", lambda: client.mgmt(PROBE_DB, _ASIM_UNIFIER)),
            ("call bare (no args)",
             lambda: client.query(PROBE_DB, "_Im_AuthenticationProbe | count")),
            ("call with named filter param",
             lambda: client.query(
                 PROBE_DB,
                 '_Im_AuthenticationProbe(eventresult="Failure") '
                 '| summarize c=count() | where c == 2')),
        ):
            try:
                result = await run()
                if label == "call with named filter param" and not result.rows:
                    raise KustoError("filter parameter did not narrow the result set")
                passed.append(f"ASIM: {label}")
                print(f"{label:<42} ok")
            except (KustoError, KustoUnavailable) as exc:
                failed.append((f"ASIM: {label}", str(exc)))
                print(f"{label:<42} FAIL — {exc}")

        await admin.drop_database(client, PROBE_DB)
    finally:
        await client.aclose()

    total = len(passed) + len(failed)
    print("\n" + "=" * 74)
    if failed:
        print(f"{len(passed)}/{total} passed — {len(failed)} FAILED")
        for label, err in failed:
            print(f"  - {label}: {err}")
        print("\nA lost feature may invalidate part of the curriculum. Check PLAN.md §3.1.")
        return 1
    print(f"{total}/{total} passed — engine supports everything the range needs")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
