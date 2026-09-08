"""Build an attack campaign from a behaviour description.

    python -m generators.campaign_cli kerberoast-drill "kerberoasting"
    python -m generators.campaign_cli wmi-hunt "WMI abuse" --pick T1047
    python -m generators.campaign_cli apt "pass the hash then wmi lateral then ransomware" \
        --twin --events 300000
    python -m generators.campaign_cli kerberoast-drill "kerberoasting" --reset

Resolves the behaviour to techniques, builds a ScenarioSpec, generates the
campaign (with the clean twin if --twin), stores ground truth, and registers it
for the startup reconciler. This is the behaviour-first loop the UI will drive
in phase 3, exercised from the command line first.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from config import settings
from kusto import KustoClient, KustoUnavailable, admin
from scenarios import resolver
from scenarios.models import spec_from_techniques
from store import Registry

from .campaign import build_campaign_from_spec

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def db_name_for(slug: str) -> str:
    return "HR_" + slug.replace("-", "_")


async def run(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    # Resolve behaviour -> techniques.
    candidates = resolver.resolve(args.behaviour)
    if not candidates:
        print(f"Could not resolve any technique from {args.behaviour!r}.")
        print("Try a technique name, an ID like T1558.003, or a phrase like 'kerberoasting'.")
        return 2

    if args.pick:
        chosen = [c for c in candidates if c.technique.id in args.pick]
        if not chosen:
            print(f"None of --pick {args.pick} matched. Candidates were:")
            for c in candidates:
                print(f"  {c.technique.id}  {c.technique.name}")
            return 2
    elif resolver.ambiguous(candidates) and not args.all:
        print(f"{args.behaviour!r} is ambiguous — these are different hunts:\n")
        for c in candidates[:6]:
            print(f"  {c.technique.id:<11} {c.technique.name:<44} ({c.confidence})")
            print(f"              {c.technique.summary}")
        print("\nRe-run with --pick T#### [T####...] to choose, or --all to include the "
              "strong matches.")
        return 3
    else:
        threshold = 0.6 if not args.all else 0.5
        chosen = [c for c in candidates if c.score >= threshold] or candidates[:1]

    technique_ids = [c.technique.id for c in chosen]
    spec = spec_from_techniques(
        technique_ids, name=args.name or None, context_depth=args.depth,
        loudness=args.loudness, window_days=args.days)
    print(f"Campaign: {spec.name}")
    print(f"Hypothesis: {spec.hypothesis}")
    print("Techniques:", ", ".join(f"{s.technique_id}" for s in spec.steps))
    if spec.unresolved():
        print(f"NOTE: no emitter yet for {spec.unresolved()} — these steps are skipped.")

    client = KustoClient(settings.kusto_url, timeout=600.0)
    registry = Registry(settings.db_path)
    try:
        try:
            await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
        except KustoUnavailable as exc:
            print(f"\nKusto unreachable: {exc}\nStart it with: docker compose up -d")
            return 1

        targets = [(args.slug, db_name_for(args.slug), True)]
        if args.twin:
            targets.append((f"{args.slug}-clean", db_name_for(f"{args.slug}-clean"), False))

        from org import build_org
        org = build_org(args.preset, args.seed, window_days=spec.window_days)

        for slug, db, with_attack in targets:
            existing = registry.get(slug)
            if existing and args.reset:
                paths = await admin.reset_database(
                    client, db, settings.kusto_data_dir, existing.generation)
                registry.set_paths(slug, paths.generation, paths.md, paths.data)
            elif existing:
                print(f"\ncampaign {slug!r} exists — use --reset to rebuild.")
                return 4
            else:
                _a, paths = await admin.ensure_database(client, db, settings.kusto_data_dir)
                registry.add(slug, spec.name if with_attack else f"{spec.name} (clean twin)",
                             db, seed=args.seed,
                             kind="campaign" if with_attack else "clean_twin",
                             twin_of=None if with_attack else args.slug,
                             generation=paths.generation, md_path=paths.md,
                             data_path=paths.data)

            registry.set_status(slug, "building")
            report = await build_campaign_from_spec(
                client, db, spec, preset=args.preset, seed=args.seed,
                target_events=args.events, attack=with_attack, org=org)
            registry.set_status(slug, "ready")

            if with_attack:
                registry.store_ground_truth(slug, report.labels)
                registry.store_spec(slug, json.dumps(spec.as_dict()),
                                    json.dumps(report.steps))

            print(f"\n  {db}: {report.summary()}")
            if with_attack:
                print("  Attack steps planted:")
                for s in report.steps:
                    print(f"    {s['technique_id']} [{s['variant']}] "
                          f"{s['rows']} rows, {s['labelled']} labelled, on {s['host']}")
                counts = registry.ground_truth_counts(slug)
                print(f"  Ground truth: {counts}")

        print(f"\nDone. Hunt it:  {db_name_for(args.slug)}")
        print(f"  Hypothesis given to the analyst: {spec.hypothesis}")
        return 0
    finally:
        registry.close()
        await client.aclose()


def main() -> int:
    p = argparse.ArgumentParser(description="Build an attack campaign from a behaviour.")
    p.add_argument("slug", help="campaign slug, e.g. kerberoast-drill")
    p.add_argument("behaviour", help='what to hunt, e.g. "kerberoasting" or "WMI abuse"')
    p.add_argument("--pick", nargs="+", default=[], metavar="TID",
                   help="choose specific techniques when the behaviour is ambiguous")
    p.add_argument("--all", action="store_true",
                   help="include all strong matches without prompting")
    p.add_argument("--events", type=int, default=200_000)
    p.add_argument("--preset", default="midsize", choices=["smb", "midsize", "enterprise"])
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--days", type=int, default=14)
    p.add_argument("--loudness", type=int, default=3, choices=[1, 2, 3, 4, 5])
    p.add_argument("--depth", default="contextual",
                   choices=["isolated", "contextual", "full-chain"])
    p.add_argument("--name", default="")
    p.add_argument("--twin", action="store_true", help="also build the clean twin")
    p.add_argument("--reset", action="store_true", help="rebuild an existing campaign")
    return asyncio.run(run(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
