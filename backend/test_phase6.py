"""Phase 6 verification — hunt scoring and the answer key.

The exit test: run a realistic hunt against a kerberoast campaign — pin real
attack evidence AND a decoy (to prove the score penalises being fooled), tag a
finding, write it up, save a detection — then score it and check every metric
reflects what actually happened, and that the answer key reveals the planted
technique.

Run: .venv/Scripts/python test_phase6.py
     .venv/Scripts/python test_phase6.py --events 40000
"""
from __future__ import annotations

import asyncio
import sys
import time

from config import settings
from deps import hunts as hunt_store, registry as reg
from generators.campaign import build_campaign_from_spec
from hunts.scoring import score_hunt, scoreboard
from kusto import KustoClient, KustoUnavailable, admin
from org import build_org
from scenarios.models import spec_from_techniques

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SLUG = "phase6-hunt"
DB = "HR_phase6_hunt"
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
    client = KustoClient(settings.kusto_url, timeout=300.0)
    try:
        await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
    except KustoUnavailable as exc:
        print(f"  FAIL  {exc}\n\n  Start it with: docker compose up -d")
        await client.aclose()
        return 1

    rule("Build a kerberoast campaign")
    # Clean any prior run.
    for d in hunt_store.list_detections(SLUG):
        hunt_store.delete_detection(d["id"])
    for h in hunt_store.list_hunts(SLUG):
        hunt_store.delete_hunt(h["id"])
    if reg.get(SLUG):
        await admin.detach_database(client, DB)
        reg.remove(SLUG)

    org = build_org("midsize", seed=1337, window_days=14)
    spec = spec_from_techniques(["T1558.003"], context_depth="contextual")
    await admin.detach_database(client, DB)
    paths = await admin.next_generation(client, DB, settings.kusto_data_dir, 0)
    reg.add(SLUG, "Phase 6 hunt", DB, generation=paths.generation,
            md_path=paths.md, data_path=paths.data)
    report = await build_campaign_from_spec(client, DB, spec, org=org,
                                            target_events=events, attack=True)
    reg.store_ground_truth(SLUG, report.labels)
    reg.store_spec(SLUG, __import__("json").dumps(spec.as_dict()),
                   __import__("json").dumps(report.steps))
    attack_ids = list(reg.attack_item_ids(SLUG))
    check_true("planted technique recorded", reg.planted_techniques(SLUG) == ["T1558.003"])
    print(f"        {len(attack_ids)} attack events planted")

    rule("Run a hunt — pin real attack evidence AND one decoy")
    hunt = hunt_store.create_hunt(SLUG, "Kerberoasting hunt")
    hid = hunt["id"]
    hunt_store.update_hunt(hid, {
        "actor": "post-compromise workstation user",
        "behavior": "bulk 4769 TGS requests for service SPNs",
        "location": "domain controllers, from a workstation",
        "evidence_expected": "non-service account requesting many SPNs",
        "phase": "execute",
    })
    # log a couple of searches (so efficiency has something to measure)
    for q in ("SecurityEvent | where EventID == 4769 | take 5",
              'SecurityEvent | where EventID == 4769 and Account !startswith "svc-" '
              '| project Account, ServiceName, TicketEncryptionType, _ItemId'):
        r = await client.query(DB, q)
        hunt_store.log_search(hid, q, DB, row_count=len(r.rows),
                              elapsed_ms=r.elapsed_ms, ok=True)

    # Pull the actual attack rows and a decoy row from the engine to pin.
    att = await client.query(
        DB, f"SecurityEvent | where _ItemId in "
            f"({','.join(repr(i) for i in attack_ids[:200])}) "
            f"| project Account, ServiceName, TicketEncryptionType, Type, _ItemId | take 4")
    for row in att.rows:
        hunt_store.pin_evidence(hid, dict(zip(att.columns, row)))
    # A decoy: a benign svc-account RC4 ticket (kerberoast decoy).
    decoy_ids = [k for k, v in report.labels.items() if v.get("kind") == "decoy"]
    dec = await client.query(
        DB, f"SecurityEvent | where _ItemId in "
            f"({','.join(repr(i) for i in decoy_ids[:50])}) "
            f"| project Account, ServiceName, Type, _ItemId | take 1")
    fooled_count = 0
    for row in dec.rows:
        hunt_store.pin_evidence(hid, dict(zip(dec.columns, row)), note="looked suspicious")
        fooled_count += 1

    hunt_store.create_finding(hid, "Workstation kerberoasting", technique="T1558.003",
                              confidence="high",
                              evidence_ids=[e["id"] for e in hunt_store.list_evidence(hid)])
    hunt_store.update_hunt(hid, {"writeup": "Found a workstation roasting SPNs.",
                                 "outcome": "proven", "phase": "act"})
    hunt_store.save_detection("Non-svc SPN spread", "SecurityEvent | where EventID==4769",
                              hunt_id=hid, campaign_slug=SLUG, techniques=["T1558.003"])

    rule("Score the hunt")
    sc = score_hunt(hunt_store, reg, hid)
    assert sc is not None
    print(f"        grade {sc.grade} ({sc.overall}) | recall {sc.technique_recall:.0%} | "
          f"precision {sc.precision:.0%}")

    check("identified the planted technique", sc.identified_techniques, ["T1558.003"])
    check("no missed techniques", sc.missed_techniques, [])
    check("technique recall is 100%", sc.technique_recall, 1.0)
    check_true("pinned real attack evidence", sc.evidence_attack >= 4)
    check("pinned one decoy (fooled)", sc.evidence_decoy, fooled_count)
    check_true("precision reflects the decoy pin", sc.precision < 1.0,
               f"precision {sc.precision}")
    check_true("decoy is named in 'fooled by'", len(sc.decoys_fooled_by) == fooled_count)
    check_true("time to detection measured", sc.time_to_detection_s is not None)
    check_true("searches-to-first-TP measured", sc.searches_to_first_tp is not None)
    check_true("rigor near complete",
               sc.rigor_score >= 0.85, f"rigor {sc.rigor_score}")
    check_true("overall grade is respectable", sc.overall >= 70,
               f"overall {sc.overall}")

    rule("Answer key — the correct answers")
    ak = sc.answer_key
    check_true("answer key has the planted step", len(ak["steps"]) == 1)
    step = ak["steps"][0]
    check("answer key names the technique", step["technique_id"], "T1558.003")
    check("answer key names the variant", "variant" in step, True)
    check_true("planted step marked identified", step["identified"])
    check_true("answer key reports event counts", step["events"] > 0)
    check_true("answer key carries the hypothesis", bool(ak["hypothesis"]))
    print(f"        planted: {step['technique_id']} [{step.get('variant')}] "
          f"{step['events']} events on {step.get('host')}")

    rule("A worse hunt scores lower")
    # A second hunt that identifies nothing and pins only a decoy.
    bad = hunt_store.create_hunt(SLUG, "Weak hunt")
    hunt_store.update_hunt(bad["id"], {"phase": "execute"})
    for row in dec.rows:
        hunt_store.pin_evidence(bad["id"], dict(zip(dec.columns, row)))
    sc_bad = score_hunt(hunt_store, reg, bad["id"])
    check_true("weak hunt missed the technique",
               sc_bad.technique_recall == 0.0)
    check_true("weak hunt scores below the good one", sc_bad.overall < sc.overall,
               f"{sc_bad.overall} vs {sc.overall}")
    check("weak hunt grade is F", sc_bad.grade, "F")

    rule("Scoreboard aggregate")
    board = scoreboard(hunt_store, reg)
    check_true("scoreboard lists both hunts",
               len([h for h in board["hunts"] if h["campaign_slug"] == SLUG]) >= 2)
    check_true("coverage credits the identified technique",
               "T1558.003" in board["totals"]["techniques_identified"])
    check_true("coverage credits the saved detection",
               "T1558.003" in board["totals"]["techniques_with_detection"])

    rule("Teardown")
    for d in hunt_store.list_detections(SLUG):
        hunt_store.delete_detection(d["id"])
    hunt_store.delete_hunt(hid)
    hunt_store.delete_hunt(bad["id"])
    await admin.detach_database(client, DB)
    reg.remove(SLUG)
    await client.aclose()

    print("\n" + "=" * 74)
    if failures:
        print(f"{len(failures)} FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("Phase 6 verified.")
    return 0


if __name__ == "__main__":
    ev = 200_000
    if "--events" in sys.argv:
        ev = int(sys.argv[sys.argv.index("--events") + 1])
    t0 = time.time()
    code = asyncio.run(main(ev))
    print(f"({time.time() - t0:.1f}s)")
    sys.exit(code)
