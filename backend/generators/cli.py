"""Build a campaign from the command line.

    python -m generators.cli demo
    python -m generators.cli apt29-drill --events 500000 --preset enterprise --seed 42
    python -m generators.cli demo --reset          # rebuild from scratch
    python -m generators.cli demo --twin           # also build the benign-only twin

Registers the campaign so the backend's startup reconciler reattaches it after a
`docker compose down`. Without registration the database would still exist on
the volume but come back invisible.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from config import settings
from kusto import KustoClient, KustoUnavailable, admin
from store import Registry

from .build import build_campaign

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def db_name_for(slug: str) -> str:
    return "HR_" + slug.replace("-", "_")


async def build(args: argparse.Namespace) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)-7s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)

    client = KustoClient(settings.kusto_url, timeout=600.0)
    registry = Registry(settings.db_path)
    try:
        try:
            await client.wait_ready(timeout=settings.kusto_ready_timeout_s)
        except KustoUnavailable as exc:
            print(f"Kusto unreachable: {exc}\nStart it with: docker compose up -d")
            return 1

        targets = [(args.slug, db_name_for(args.slug), True)]
        if args.twin:
            targets.append((f"{args.slug}-clean", db_name_for(f"{args.slug}-clean"), False))

        for slug, db, with_attack in targets:
            existing = registry.get(slug)
            if existing and args.reset:
                paths = await admin.reset_database(
                    client, db, settings.kusto_data_dir, existing.generation)
                registry.set_paths(slug, paths.generation, paths.md, paths.data)
            elif existing:
                print(f"campaign {slug!r} already exists "
                      f"(generation {existing.generation}). Use --reset to rebuild.")
                return 2
            else:
                _action, paths = await admin.ensure_database(
                    client, db, settings.kusto_data_dir)
                registry.add(slug, args.name or slug, db, seed=args.seed,
                             kind="campaign" if with_attack else "clean_twin",
                             twin_of=None if with_attack else args.slug,
                             generation=paths.generation,
                             md_path=paths.md, data_path=paths.data)

            registry.set_status(slug, "building")
            report = await build_campaign(
                client, db,
                preset=args.preset, seed=args.seed,
                target_events=args.events, window_days=args.days,
                with_noise=not args.no_noise,
            )
            registry.set_status(slug, "ready")
            print(f"\n{report.org_summary}")
            print(report.summary())
            print(report.table_breakdown())
            print(f"\n  {db} is ready. Try:")
            print(f'    SigninLogs | where ResultType != "0" '
                  f'| summarize count() by UserPrincipalName | top 10 by count_')
            print(f'    _Im_Authentication(eventresult="Failure") '
                  f'| summarize count() by TargetUsername, EventProduct')
        return 0
    finally:
        registry.close()
        await client.aclose()


def main() -> int:
    p = argparse.ArgumentParser(description="Build a hunting range campaign.")
    p.add_argument("slug", help="campaign slug, e.g. apt29-drill")
    p.add_argument("--events", type=int, default=300_000, help="target event count")
    p.add_argument("--preset", default="midsize", choices=["smb", "midsize", "enterprise"])
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--days", type=int, default=14, help="campaign window in days")
    p.add_argument("--name", default="", help="display name")
    p.add_argument("--reset", action="store_true", help="rebuild an existing campaign")
    p.add_argument("--twin", action="store_true",
                   help="also build the benign-only twin used for FP measurement")
    p.add_argument("--no-noise", action="store_true",
                   help="omit ambient benign anomalies (makes hunts artificially easy)")
    return asyncio.run(build(p.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
