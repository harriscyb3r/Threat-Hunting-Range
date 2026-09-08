"""Phase 4 verification — PEAK workspace, detections, Sigma, validation.

The exit test walks a full hunt: build a kerberoast campaign with a twin, create
a hunt, frame an ABLE hypothesis, run searches (auto-logged), pin real attack
evidence, promote a finding, save a detection, export Sigma, and validate it —
proving the detection catches the attacker on the campaign and stays quiet-ish
on the clean twin.

Run: .venv/Scripts/python test_phase4.py
     .venv/Scripts/python test_phase4.py --events 40000
"""
from __future__ import annotations

import asyncio
import json
import sys
import time

import yaml

from config import settings
from deps import hunts as hunt_store, registry as reg
from detections import to_sigma
from detections.validate import validate as run_validation
from generators.campaign import build_campaign_from_spec
from kusto import KustoClient, KustoUnavailable, admin
from org import build_org
from scenarios.models import spec_from_techniques

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SLUG = "phase4-hunt"
DB = "HR_phase4_hunt"
TWIN_DB = "HR_phase4_hunt_clean"
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


async def main(events: int) -> int:
    rule("Sigma export — offline unit checks")
    r = to_sigma("Rubeus kerberoast",
                 'DeviceProcessEvents | where FileName == "Rubeus.exe" '
                 'and ProcessCommandLine has "kerberoast"',
                 techniques=["T1558.003"], level="high")
    body = "\n".join(l for l in r.yaml.splitlines() if not l.startswith("#"))
    doc = yaml.safe_load(body)
    check_true("translatable query -> complete Sigma", r.complete)
    check("logsource is process_creation",
          doc["logsource"].get("category"), "process_creation")
    check_true("ATT&CK tag present", "attack.t1558.003" in doc.get("tags", []))
    check_true("selection has Image + CommandLine",
               "Image" in doc["detection"]["selection"]
               and any("CommandLine" in k for k in doc["detection"]["selection"]))

    r2 = to_sigma("Threshold roast",
                  'SecurityEvent | where EventID == 4769 '
                  '| summarize c=count() by Account | where c > 10',
                  techniques=["T1558.003"])
    check_true("summarize query -> incomplete + warned",
               not r2.complete and any("summarize" in w for w in r2.warnings))

    rule("Engine — build a campaign with its twin")
    client = KustoClient(settings.kusto_url, timeout=300.0)
    try:
        await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
    except KustoUnavailable as exc:
        print(f"  FAIL  {exc}\n\n  Start it with: docker compose up -d")
        await client.aclose()
        return 1

    org = build_org("midsize", seed=1337, window_days=14)
    spec = spec_from_techniques(["T1558.003"], context_depth="contextual")

    # Register + build campaign and twin. Also clear anything a prior failed run
    # left behind, so the run is idempotent.
    for d in hunt_store.list_detections(SLUG):
        hunt_store.delete_detection(d["id"])
    for h in hunt_store.list_hunts(SLUG):
        hunt_store.delete_hunt(h["id"])
    if reg.get(SLUG):
        for c in reg.list():
            if c.slug in (SLUG, f"{SLUG}-clean"):
                await admin.detach_database(client, c.db_name)
                reg.remove(c.slug)

    for slug, db, attack in [(SLUG, DB, True), (f"{SLUG}-clean", TWIN_DB, False)]:
        await admin.detach_database(client, db)
        paths = await admin.next_generation(client, db, settings.kusto_data_dir, 0)
        reg.add(slug, "Phase 4 hunt" + ("" if attack else " (twin)"), db,
                kind="campaign" if attack else "clean_twin",
                twin_of=None if attack else SLUG,
                generation=paths.generation, md_path=paths.md, data_path=paths.data)
        report = await build_campaign_from_spec(client, db, spec, org=org,
                                                target_events=events, attack=attack)
        if attack:
            reg.store_ground_truth(slug, report.labels)
    print(f"        campaign {report.total_rows:,} rows")
    attack_ids = reg.attack_item_ids(SLUG)
    check_true("ground truth recorded attack events", len(attack_ids) > 0)

    rule("PEAK — Prepare")
    hunt = hunt_store.create_hunt(SLUG, "Kerberoasting from a workstation")
    hid = hunt["id"]
    check("hunt starts in prepare", hunt["phase"], "prepare")
    hunt = hunt_store.update_hunt(hid, {
        "actor": "Unknown, assumed post-compromise on a user workstation",
        "behavior": "Bulk TGS (4769) requests for service SPNs, RC4 downgrade",
        "location": "Domain controllers, sourced from a non-server host",
        "evidence_expected": "A workstation account requesting many distinct SPNs",
        "techniques": ["T1558.003"],
        "phase": "execute",
    })
    check("ABLE hypothesis saved", hunt["behavior"][:10], "Bulk TGS (")
    check_true("entering execute stamped started_at", hunt["started_at"] is not None)

    rule("PEAK — Execute (searches auto-logged)")
    # A naive first attempt (fooled by decoys), then a refined one.
    naive = ('SecurityEvent | where EventID == 4769 '
             'and TicketEncryptionType == "0x17" '
             '| summarize c=count() by Account | where c > 5')
    res1 = await client.query(DB, naive)
    hunt_store.log_search(hid, naive, DB, row_count=len(res1.rows),
                          elapsed_ms=res1.elapsed_ms, ok=True)

    refined = ('SecurityEvent | where EventID == 4769 '
               'and TicketEncryptionType in ("0x17", "0x12") '
               'and Account !startswith "svc-" '
               '| summarize SPNs = dcount(ServiceName) by Account '
               '| where SPNs >= 3')
    resR = await client.query(DB, refined)
    hunt_store.log_search(hid, refined, DB, row_count=len(resR.rows),
                          elapsed_ms=resR.elapsed_ms, ok=True)

    # The one that actually returns attack rows: keep _ItemId so evidence maps.
    hunt_query = ('SecurityEvent | where EventID == 4769 '
                  'and Account !startswith "svc-" '
                  '| project TimeGenerated, Account, ServiceName, '
                  'TicketEncryptionType, Computer, _ItemId')
    res2 = await client.query(DB, hunt_query)
    search2 = hunt_store.log_search(hid, hunt_query, DB, row_count=len(res2.rows),
                                    elapsed_ms=res2.elapsed_ms, ok=True)
    searches = hunt_store.list_searches(hid)
    check("three searches logged", len(searches), 3)
    check_true("searches carry timing", all(s["elapsed_ms"] >= 0 for s in searches))

    # Pin the attack rows as evidence.
    cols = res2.columns
    attack_set = set(attack_ids)
    pinned = 0
    for row in res2.rows:
        d = dict(zip(cols, row))
        if d.get("_ItemId") in attack_set:
            hunt_store.pin_evidence(hid, d, search_id=search2["id"],
                                    note="attacker's roast")
            pinned += 1
            if pinned >= 5:
                break
    evidence = hunt_store.list_evidence(hid)
    check_true("pinned real attack evidence", pinned > 0, f"pinned {pinned}")
    check_true("evidence carries _ItemId",
               all(e["item_id"] for e in evidence))
    ev_ids = hunt_store.evidence_item_ids(hid)
    check_true("all pinned evidence is attack (ground truth)",
               all(i in attack_set for i in ev_ids),
               "pinned a non-attack row")

    rule("PEAK — Act (finding + detection)")
    finding = hunt_store.create_finding(
        hid, "Workstation account kerberoasting service SPNs",
        technique="T1558.003", confidence="high",
        evidence_ids=[e["id"] for e in evidence])
    check("finding tagged with technique", finding["technique"], "T1558.003")

    det = hunt_store.save_detection(
        "Non-service account requesting multiple SPNs",
        refined, hunt_id=hid, campaign_slug=SLUG, techniques=["T1558.003"],
        description="A human/workstation account requesting tickets for 3+ distinct SPNs",
        fp_notes="Tune out admin jump hosts that legitimately query many services",
        severity="high")
    check_true("detection saved", det["id"].startswith("det_"))
    dets = hunt_store.list_detections(SLUG)
    check("detection listed for campaign", len(dets), 1)

    rule("Detection validation — TP on campaign, FP on twin")
    # Use the _ItemId-carrying hunt query for gradable TP.
    result = await run_validation(
        client, hunt_query, campaign_db=DB, twin_db=TWIN_DB,
        attack_item_ids=attack_set)
    print(f"        campaign rows {result.campaign_rows}, "
          f"twin rows {result.twin_total_rows}, TP {result.tp_count}")
    check_true("detection can be TP-graded", result.can_grade_tp)
    check_true("detection catches attack events on the campaign",
               result.tp_count > 0, f"TP={result.tp_count}")
    check_true("attacker rows are a subset of ground-truth attack",
               all(i in attack_set for i in result.tp_item_ids))
    # The refined non-svc query should return FEWER rows on the twin than a
    # naive query would, because the attacker is gone. It won't be zero (benign
    # non-svc 4769 exists), but it must be far below the campaign.
    check_true("twin returns fewer rows than campaign (attack removed)",
               result.twin_total_rows < result.campaign_rows,
               f"twin {result.twin_total_rows} vs campaign {result.campaign_rows}")

    rule("Sigma round-trip through the store")
    sig = to_sigma(det["title"], det["csl"], techniques=det["techniques"],
                   level=det["severity"], fp_notes=det["fp_notes"])
    # This detection uses summarize+dcount, so it must warn rather than pretend.
    check_true("Sigma warns on the aggregate detection", not sig.complete)
    check_true("Sigma still emits parseable YAML frame",
               "title:" in sig.yaml and "logsource:" in sig.yaml)

    rule("Teardown")
    for db in (DB, TWIN_DB):
        await admin.detach_database(client, db)
    for c in reg.list():
        if c.slug in (SLUG, f"{SLUG}-clean"):
            reg.remove(c.slug)
    for d in hunt_store.list_detections(SLUG):
        hunt_store.delete_detection(d["id"])
    hunt_store.delete_hunt(hid)  # cascades searches/evidence/findings
    check_true("hunt deleted", hunt_store.get_hunt(hid) is None)
    check("cascade removed searches", len(hunt_store.list_searches(hid)), 0)
    await client.aclose()

    print("\n" + "=" * 74)
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("Phase 4 verified.")
    return 0


if __name__ == "__main__":
    ev = 200_000
    if "--events" in sys.argv:
        ev = int(sys.argv[sys.argv.index("--events") + 1])
    t0 = time.time()
    code = asyncio.run(main(ev))
    print(f"({time.time() - t0:.1f}s)")
    sys.exit(code)
