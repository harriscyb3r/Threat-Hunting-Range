"""Technique-specific decoys — benign activity that resembles the hunt.

Distinct from `noise.py`. Ambient noise is planted regardless of the campaign;
decoys are chosen to look like *the specific technique being hunted*, so a lazy
query returns them and a good one does not.

Hunting kerberoasting? A naive `4769 | where TicketEncryptionType == "0x17"`
should return the SCCM service account's legitimate RC4 tickets and the backup
account's bulk TGS requests — because those exist in the data, planted here.

Decoys are labelled `decoy` in ground truth with the technique they mimic, so
scoring can tell the analyst *which* lookalike fooled them rather than just
marking a finding wrong. That specific feedback is the teaching moment.

Each decoy function maps to one or more technique IDs. A campaign plants decoys
for the techniques in its spec, plus a small always-on set.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Callable, Iterator

from . import rows
from .common import GenContext, days_in_window, scheduled_time

DECOY_KIND = "decoy"


def _mark(ctx: GenContext, rowset, technique: str, pattern: str, why: str):
    if isinstance(rowset, dict):
        rowset = [rowset]
    for r in rowset:
        ctx.label(r["_ItemId"], kind=DECOY_KIND, mimics=technique,
                  pattern=pattern, why=why)
    return rowset


# ── Kerberoasting decoys (T1558.003) ─────────────────────────────────────

def kerberoast_decoys(ctx: GenContext) -> Iterator[dict]:
    org = ctx.org
    dc = org.domain_controllers[0] if org.domain_controllers else org.servers[0]
    sccm = next((u for u in org.service_accounts if u.sam == "svc-sccm"), None)
    backup = next((u for u in org.service_accounts if u.sam == "svc-backup"), None)
    sql_spns = [f"MSSQLSvc/{d.name.lower()}.{org.domain}:1433"
                for d in org.devices_by_role("sql")] or [f"MSSQLSvc/{org.domain}:1433"]

    for day in days_in_window(org):
        # SCCM legitimately requests SQL service tickets in bulk every day — and
        # a genuine legacy app still negotiates RC4. This is the exact shape of a
        # kerberoast to a threshold-or-encryption query.
        if sccm:
            base = scheduled_time(ctx, day, hour=6)
            for i in range(ctx.rng.randint(8, 20)):
                when = base + timedelta(minutes=i * ctx.rng.randint(1, 4))
                enc = "0x17" if ctx.rng.random() < 0.4 else "0x12"
                yield from _mark(ctx, rows.security_kerberos(
                    ctx, dc, sccm, when, event_id=4769,
                    spn=ctx.rng.choice(sql_spns), encryption=enc,
                    src_ip=org.servers[0].ip),
                    "T1558.003", "sccm-bulk-tgs",
                    "SCCM service account's daily bulk TGS requests, some RC4")
        if backup:
            base = scheduled_time(ctx, day, hour=2)
            for i in range(ctx.rng.randint(4, 10)):
                when = base + timedelta(minutes=i * ctx.rng.randint(1, 3))
                yield from _mark(ctx, rows.security_kerberos(
                    ctx, dc, backup, when, event_id=4769,
                    spn=ctx.rng.choice(sql_spns), encryption="0x17",
                    src_ip=org.servers[-1].ip),
                    "T1558.003", "backup-rc4-tgs",
                    "Backup service account negotiating RC4 tickets nightly")


# ── LSASS-dump decoys (T1003.001) ────────────────────────────────────────

def lsass_decoys(ctx: GenContext) -> Iterator[dict]:
    org = ctx.org
    admins = [u for u in org.admins if not u.is_service]
    if not admins:
        return
    for day in days_in_window(org):
        if day.weekday() not in (1, 4) or ctx.rng.random() > 0.5:
            continue
        admin = ctx.rng.choice(admins)
        host = ctx.rng.choice(org.servers)
        when = scheduled_time(ctx, day, hour=15)
        # A genuine crash-dump troubleshooting session: procdump against a
        # non-lsass process, or a full memory dump for a support case.
        yield from _mark(ctx, rows.execution(
            ctx, host, admin, when, "procdump64.exe",
            r"procdump64.exe -accepteula -ma sqlservr.exe C:\temp\sql.dmp",
            parent="cmd.exe", integrity="High",
            ProcessVersionInfoCompanyName="Microsoft Corporation"),
            "T1003.001", "legit-procdump",
            "IT using procdump on a hung SQL process for a support case")


# ── WMI decoys (T1047 / T1021.006 / T1546.003) ───────────────────────────

def wmi_decoys(ctx: GenContext) -> Iterator[dict]:
    org = ctx.org
    monitor = next((u for u in org.service_accounts if u.sam == "svc-monitor"), None)
    sccm = next((u for u in org.service_accounts if u.sam == "svc-sccm"), None)
    for day in days_in_window(org):
        # The monitoring platform runs Win32_Process inventory across the estate
        # every night — the same wmic/CIM shape as WMI execution abuse.
        if monitor:
            base = scheduled_time(ctx, day, hour=3)
            for i in range(ctx.rng.randint(6, 14)):
                host = ctx.rng.choice(org.servers)
                when = base + timedelta(minutes=i * ctx.rng.randint(1, 5))
                yield from _mark(ctx, rows.execution(
                    ctx, host, monitor, when, "wmic.exe",
                    "wmic /node:localhost process get Name,ProcessId,CommandLine",
                    parent="CcmExec.exe"),
                    "T1047", "monitoring-wmi-inventory",
                    "Monitoring platform's nightly Win32_Process inventory")
        # SCCM uses WinRM/Invoke-Command for legitimate remote administration.
        if sccm and day.weekday() in (0, 3):
            host = org.servers[0]
            target = ctx.rng.choice(org.servers[1:]) if len(org.servers) > 1 else host
            when = scheduled_time(ctx, day, hour=20)
            yield from _mark(ctx, rows.execution(
                ctx, host, sccm, when, "powershell.exe",
                f"powershell.exe -Command Invoke-Command -ComputerName {target.name} "
                "-ScriptBlock {Get-Service} -Credential $cred",
                parent="CcmExec.exe"),
                "T1021.006", "sccm-winrm-admin",
                "Configuration Manager's scheduled WinRM administration")


# ── Password-spray / cloud-account decoys (T1110.003 / T1078.004) ────────

def signin_decoys(ctx: GenContext) -> Iterator[dict]:
    from .benign.identity import _signin_row
    org = ctx.org
    # A shared mailbox that many staff sign into from one NAT IP looks like a
    # spray source; a genuinely mobile salesperson looks like account takeover.
    travellers = [u for u in org.humans if u.travels]
    for day in days_in_window(org):
        if ctx.rng.random() > 0.4 or not travellers:
            continue
        user = ctx.rng.choice(travellers)
        when = scheduled_time(ctx, day, hour=ctx.rng.randint(8, 18))
        # A short burst of failures then success — a user who forgot their new
        # password after a reset. Exactly a low-and-slow spray's shape.
        for i in range(ctx.rng.randint(3, 6)):
            success = i == ctx.rng.randint(2, 5)
            row = _signin_row(ctx, "SigninLogs", when + timedelta(minutes=i * 2),
                              user, True)
            row.update({
                "ResultType": "0" if success else "50126",
                "ResultDescription": "" if success else "Invalid username or password.",
                "Status": {"errorCode": 0 if success else 50126},
            })
            row["__table"] = "SigninLogs"
            yield from _mark(ctx, row, "T1110.003", "post-reset-fumble",
                             "A user fumbling their password after a reset")


# ── Ransomware / mass-file decoys (T1486) ────────────────────────────────

def massfile_decoys(ctx: GenContext) -> Iterator[dict]:
    org = ctx.org
    svc = next((u for u in org.service_accounts if u.sam == "svc-backup"), None)
    file_servers = org.devices_by_role("file")
    if not svc or not file_servers:
        return
    # A migration tool re-writing thousands of files with a new extension — the
    # exact mass-FileModified shape ransomware produces.
    for day in days_in_window(org):
        if day.weekday() != 5 or ctx.rng.random() > 0.5:
            continue
        server = ctx.rng.choice(file_servers)
        when = scheduled_time(ctx, day, hour=1)
        for i in range(ctx.rng.randint(60, 150)):
            when += timedelta(milliseconds=ctx.rng.randint(50, 500))
            orig = f"archive_{ctx.rng.randint(1, 9999)}.pst"
            yield from _mark(ctx, rows.device_file_event(
                ctx, server, svc, when, filename=f"{orig}.migrated",
                folder=rf"E:\Archive\{orig}.migrated", action="FileModified",
                process="ArchiveMigrator.exe", PreviousFileName=orig),
                "T1486", "archive-migration",
                "Weekend archive-migration tool renaming files in bulk")


# technique id -> decoy functions that mimic it
_DECOY_MAP: dict[str, list[Callable[[GenContext], Iterator[dict]]]] = {
    "T1558.003": [kerberoast_decoys],
    "T1003.001": [lsass_decoys],
    "T1047": [wmi_decoys],
    "T1021.006": [wmi_decoys],
    "T1546.003": [wmi_decoys],
    "T1110.003": [signin_decoys],
    "T1078.004": [signin_decoys],
    "T1486": [massfile_decoys],
}


def decoys_for(technique_ids: list[str]) -> list[Callable]:
    """The decoy functions relevant to a campaign, de-duplicated."""
    fns: list[Callable] = []
    for tid in technique_ids:
        for fn in _DECOY_MAP.get(tid, []):
            if fn not in fns:
                fns.append(fn)
    return fns


def generate(ctx: GenContext, technique_ids: list[str]) -> Iterator[dict]:
    for fn in decoys_for(technique_ids):
        yield from fn(ctx)
