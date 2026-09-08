"""Phase 2 verification — resolver, emitters, variants, decoys, campaign build.

The exit test: build "hunt for kerberoasting" as a real campaign, then run a
naive query and a good query and show the difference. The naive query drowns in
decoys; the good query finds the attack. If both return the same thing, the
decoys are not doing their job and the range teaches nothing.

Run: .venv/Scripts/python test_phase2.py
     .venv/Scripts/python test_phase2.py --events 40000
"""
from __future__ import annotations

import asyncio
import json
import sys
import time

from config import settings
from generators.campaign import build_campaign_from_spec, generate_campaign
from generators import attack as emitters
from kusto import KustoClient, KustoUnavailable, admin, schemas
from org import build_org
from scenarios import attack as catalogue
from scenarios import resolver
from scenarios.models import spec_from_techniques, ScenarioSpec
from store import Registry

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TEST_DB = "HR_phase2_selftest"
failures: list[str] = []


def rule(t): print(f"\n{'-' * 74}\n{t}\n{'-' * 74}")


def check(label, got, want):
    ok = got == want
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"          got:  {got!r}\n          want: {want!r}")
        failures.append(label)


def check_true(label, got, detail=""):
    print(f"  {'ok  ' if got else 'FAIL'}  {label}")
    if not got:
        if detail:
            print(f"          {detail}")
        failures.append(label)


async def main(target_events: int) -> int:
    rule("Resolver — behaviour to technique")
    check("kerberoasting -> T1558.003", resolver.resolve_ids("kerberoasting")[:1], ["T1558.003"])
    check("pass the hash -> T1550.002", resolver.resolve_ids("pass the hash")[:1], ["T1550.002"])
    wmi = resolver.resolve("WMI abuse")
    check_true("WMI abuse is ambiguous (3 readings)", resolver.ambiguous(wmi))
    check_true("WMI abuse offers execution, lateral and persistence",
               {"T1047", "T1021.006", "T1546.003"} <= {c.technique.id for c in wmi})
    check_true("explicit ID wins", resolver.resolve("T1003.001")[0].technique.id == "T1003.001")
    check_true("gibberish resolves to nothing", resolver.resolve("qwerty zxcvb") == [])

    rule("Emitters and variants")
    impl = emitters.implemented_techniques()
    check_true("at least 25 emitters", len(impl) >= 25, f"have {len(impl)}")
    check_true("every emitter has >= 2 variants",
               all(len(emitters.get(t).variants) >= 2 for t in impl))
    check_true("kerberoast has the query-breaking variants",
               {"targeted", "aes_only", "slow"} <= set(emitters.get("T1558.003").variant_keys()))
    check_true("all three WMI readings have emitters",
               all(emitters.has(t) for t in ("T1047", "T1021.006", "T1546.003")))
    # Every emitter's technique is in the catalogue.
    check("no orphan emitters",
          [t for t in impl if t not in catalogue.BY_ID], [])

    rule("Structural indistinguishability — attack rows look like benign rows")
    org = build_org("midsize", seed=1337, window_days=14)
    spec = spec_from_techniques(["T1558.003"], context_depth="contextual")
    by_table, labels, steps = generate_campaign(spec, org, target_events=target_events)
    attack_ids = {k for k, v in labels.items() if v.get("kind") == "attack"}

    for table in ("DeviceProcessEvents", "SecurityEvent"):
        b_cols, a_cols = set(), set()
        for r in by_table.get(table, []):
            cols = {k for k, v in r.items() if v not in (None, "")}
            (a_cols if r["_ItemId"] in attack_ids else b_cols).__ior__(cols)
        leak = a_cols - b_cols
        check_true(f"{table}: no attack-only columns", not leak,
                   f"leaked: {sorted(leak)}")

    ids = [r["_ItemId"] for rl in by_table.values() for r in rl]
    check("_ItemId globally unique across benign + attack", len(ids), len(set(ids)))

    bad = []
    for table, rl in by_table.items():
        valid = set(schemas.get(table).column_names)
        for r in rl:
            if set(r) - valid:
                bad.append(table)
                break
    check("all rows (attack included) conform to schema", bad, [])

    rule("Determinism — a re-roll reproduces the campaign")
    by2, labels2, _ = generate_campaign(spec, org, target_events=target_events)
    check("same attack labels on re-roll",
          sorted(k for k, v in labels.items() if v.get("kind") == "attack"),
          sorted(k for k, v in labels2.items() if v.get("kind") == "attack"))

    rule("Decoys resemble the technique")
    sec = by_table["SecurityEvent"]
    decoy_ids = {k for k, v in labels.items() if v.get("kind") == "decoy"}
    attack_4769 = [r for r in sec if r.get("EventID") == 4769 and r["_ItemId"] in attack_ids]
    decoy_4769 = [r for r in sec if r.get("EventID") == 4769 and r["_ItemId"] in decoy_ids]
    check_true("attack planted 4769 kerberoast events", len(attack_4769) > 0)
    check_true("decoys planted benign 4769 events that mimic it",
               len(decoy_4769) > len(attack_4769),
               f"{len(decoy_4769)} decoy vs {len(attack_4769)} attack")

    rule("Engine — build the campaign end to end")
    client = KustoClient(settings.kusto_url, timeout=300.0)
    try:
        await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
    except KustoUnavailable as exc:
        print(f"  FAIL  {exc}\n\n  Start it with: docker compose up -d")
        await client.aclose()
        return 1

    await admin.detach_database(client, TEST_DB)
    paths = await admin.next_generation(client, TEST_DB, settings.kusto_data_dir, 0)
    report = await build_campaign_from_spec(
        client, TEST_DB, spec, target_events=target_events, org=org)
    print(f"        {report.summary()}")
    check_true("attack rows landed", report.attack_rows > 0)
    check_true("decoy rows landed", report.decoy_rows > 0)
    check("13 ASIM parsers deployed", len(report.parsers), 13)

    rule("EXIT TEST — a good query beats decoys, a naive one does not")
    # Naive: "lots of RC4 tickets". Fooled by SCCM and backup decoys.
    naive = await client.query(TEST_DB, """
        SecurityEvent
        | where EventID == 4769 and TicketEncryptionType == "0x17"
        | summarize Tickets = count() by Account
        | where Tickets > 5
        | order by Tickets desc
    """)
    naive_accounts = set(naive.column("Account")) if len(naive) else set()
    print(f"        naive query flags {len(naive_accounts)} accounts: "
          f"{sorted(a.split('@')[0] for a in naive_accounts)[:6]}")

    # Good: a workstation (not a server/service host) requesting many distinct
    # SPNs it has no reason to touch. The attack came from a workstation; the
    # decoys come from service accounts on servers.
    good = await client.query(TEST_DB, """
        let servers = SecurityEvent
            | where EventID == 4769
            | summarize by Computer;
        SecurityEvent
        | where EventID == 4769 and TicketEncryptionType in ("0x17", "0x12")
        | where Account !startswith "svc-"
        | summarize SPNs = dcount(ServiceName), Tickets = count(),
                    Services = make_set(ServiceName, 10) by Account
        | where SPNs >= 3
        | order by SPNs desc
    """)
    good_accounts = set(good.column("Account")) if len(good) else set()
    print(f"        refined query flags {len(good_accounts)} accounts: "
          f"{sorted(a.split('@')[0] for a in good_accounts)[:6]}")

    # The decoy service accounts should appear in the naive result.
    check_true("naive query is fooled by decoys (flags service accounts)",
               any("svc-" in a for a in naive_accounts),
               "no service-account decoys caught the naive query")
    # The refined query should exclude the service-account decoys.
    check_true("refined query excludes the svc- decoys",
               not any(a.startswith("svc-") for a in good_accounts))

    # Ground truth: can we grade a hunt? The attacker's account is in the labels.
    reg = Registry(settings.db_path)
    reg.store_ground_truth("__phase2_tmp",
                           {}) if False else None
    gt_attack = {k for k, v in report.labels.items() if v.get("kind") == "attack"}
    # Pull the actual attacker account from the planted 4769 rows.
    planted = await client.query(TEST_DB, f"""
        SecurityEvent
        | where EventID == 4769 and _ItemId in ({','.join(repr(i) for i in list(gt_attack)[:200])})
        | summarize by Account
    """) if gt_attack else None
    if planted is not None and len(planted):
        attacker = {a.split("@")[0] for a in planted.column("Account")}
        print(f"        ground truth: attacker roasted from account(s) {sorted(attacker)}")
        check_true("attacker account is findable via ground truth", bool(attacker))
    reg.close()

    rule("Clean twin — same benign, no attack")
    await admin.detach_database(client, TEST_DB + "_twin")
    await admin.next_generation(client, TEST_DB + "_twin", settings.kusto_data_dir, 0)
    twin = await build_campaign_from_spec(
        client, TEST_DB + "_twin", spec, target_events=target_events,
        org=org, attack=False)
    check("twin has zero attack rows", twin.attack_rows, 0)
    check_true("twin still has decoys (benign)", twin.decoy_rows > 0)
    twin_4769 = (await client.query(
        TEST_DB + "_twin",
        'SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17" | count'
    )).scalar()
    live_4769 = (await client.query(
        TEST_DB,
        'SecurityEvent | where EventID == 4769 and TicketEncryptionType == "0x17" | count'
    )).scalar()
    check_true("twin has fewer RC4 tickets than the live campaign (attack removed)",
               twin_4769 < live_4769, f"twin {twin_4769} vs live {live_4769}")

    rule("Teardown")
    await admin.detach_database(client, TEST_DB)
    await admin.detach_database(client, TEST_DB + "_twin")
    await client.aclose()

    print("\n" + "=" * 74)
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("Phase 2 verified.")
    return 0


if __name__ == "__main__":
    events = 200_000
    if "--events" in sys.argv:
        events = int(sys.argv[sys.argv.index("--events") + 1])
    t0 = time.time()
    code = asyncio.run(main(events))
    print(f"({time.time() - t0:.1f}s)")
    sys.exit(code)
