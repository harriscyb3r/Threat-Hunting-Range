"""Smoke-test every newly added coverage emitter, each variant.

Drives emitters the same way the campaign builder does (build_intrusion +
StepPlan + EmitContext) but without Kusto — so it catches logic bugs fast.
Asserts each variant yields rows, every row carries `__table` and `_ItemId`,
and every row is labelled in ground truth (the scoring contract).
"""
from __future__ import annotations

from datetime import timedelta

from org import build_org
from generators.common import GenContext
from generators.attack import build_intrusion, get as get_emitter, StepPlan, EmitContext

NEW = [
    "T1566.002", "T1133", "T1190", "T1204.002", "T1059.003", "T1059.007",
    "T1218.011", "T1027", "T1068", "T1548.002", "T1018", "T1482", "T1552.001",
    "T1090", "T1573", "T1041", "T1030",
]


def main() -> int:
    org = build_org("midsize", 1337, window_days=14)
    fails = 0
    total_rows = 0
    for tid in NEW:
        emitter = get_emitter(tid)
        for variant in emitter.variant_keys():
            ctx = GenContext.create(org, seed_offset=900)
            intr = build_intrusion(ctx)
            start = org.window_start + timedelta(days=3)
            plan = StepPlan(technique_id=tid, variant=variant, start=start, loudness=3)
            ectx = EmitContext(gen=ctx, intrusion=intr, plan=plan)
            try:
                rows = list(emitter.fn(ectx))
            except Exception as exc:  # noqa: BLE001
                print(f"  FAIL {tid}/{variant}: {type(exc).__name__}: {exc}")
                fails += 1
                continue
            if not rows:
                print(f"  FAIL {tid}/{variant}: produced no rows")
                fails += 1
                continue
            bad = [r for r in rows if "__table" not in r or "_ItemId" not in r]
            if bad:
                print(f"  FAIL {tid}/{variant}: {len(bad)} rows missing __table/_ItemId")
                fails += 1
                continue
            labelled = sum(1 for r in rows if r["_ItemId"] in ctx.labels)
            if labelled != len(rows):
                print(f"  FAIL {tid}/{variant}: {len(rows) - labelled}/{len(rows)} rows unlabelled")
                fails += 1
                continue
            total_rows += len(rows)
            tables = sorted({r["__table"] for r in rows})
            print(f"  ok   {tid}/{variant:<20} {len(rows):>4} rows  {tables}")

    print(f"\n{'PASS' if fails == 0 else 'FAIL'} — "
          f"{len(NEW)} techniques, {total_rows} rows, {fails} failures")
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
