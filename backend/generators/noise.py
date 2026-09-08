"""Ambient benign anomalies — the things that look like attacks and are not.

This module exists because a range built only from clean baseline plus clean
attack teaches a false skill. Every hunt becomes `where CommandLine has "-enc"`
and returns exactly the planted events, and the analyst learns a query that
drowns in false positives the first time it meets production.

So the baseline deliberately contains the usual suspects:

* a developer who runs base64-encoded PowerShell every day
* IT using PsExec and WMI at 2am during the patch window
* a vulnerability scanner sweeping SMB and RDP across the estate
* a backup agent reading thousands of files in bulk overnight
* an executive signing in from Singapore mid-trip
* an asset inventory tool enumerating SPNs and domain admins

Each is labelled `noise` in ground truth (distinct from phase 2's technique
`decoys`), so scoring can tell an analyst *which* benign pattern fooled them
rather than just marking a finding wrong.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from .common import (GenContext, days_in_window, file_hashes, logon_id,
                     public_ip, scheduled_time)

NOISE_KIND = "noise"


def _label(ctx: GenContext, row: dict, pattern: str, why: str) -> dict:
    ctx.label(row["_ItemId"], kind=NOISE_KIND, pattern=pattern, why=why)
    return row


def _proc_row(ctx: GenContext, device, user, ts, image, cmdline,
              parent="explorer.exe", integrity="Medium") -> dict:
    org = ctx.org
    sha1, sha256, md5 = file_hashes(ctx.rng, image)
    row = ctx.platform("DeviceProcessEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": "ProcessCreated",
        "FileName": image,
        "FolderPath": rf"c:\windows\system32\{image}",
        "SHA1": sha1, "SHA256": sha256, "MD5": md5,
        "FileSize": ctx.rng.randint(40_000, 900_000),
        "ProcessVersionInfoCompanyName": "Microsoft Corporation",
        "ProcessId": ctx.rng.randint(600, 32000),
        "ProcessCommandLine": cmdline,
        "ProcessIntegrityLevel": integrity,
        "ProcessTokenElevation": ("TokenElevationTypeFull" if integrity == "High"
                                  else "TokenElevationTypeLimited"),
        "ProcessCreationTime": ts,
        "AccountDomain": org.netbios,
        "AccountName": user.sam,
        "AccountSid": user.sid,
        "AccountUpn": user.upn,
        "AccountObjectId": user.object_id,
        "LogonId": logon_id(ctx.rng),
        "InitiatingProcessFileName": parent,
        "InitiatingProcessFolderPath": rf"c:\windows\{parent}",
        "InitiatingProcessId": ctx.rng.randint(500, 12000),
        "InitiatingProcessCommandLine": parent,
        "InitiatingProcessAccountName": user.sam,
        "InitiatingProcessAccountDomain": org.netbios,
        "InitiatingProcessAccountSid": user.sid,
        "InitiatingProcessIntegrityLevel": integrity,
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Corporate",
    })
    row["__table"] = "DeviceProcessEvents"
    return row


def developer_encoded_powershell(ctx: GenContext) -> Iterator[dict]:
    """A build script that legitimately uses -EncodedCommand, every working day.

    Defeats: `ProcessCommandLine has "-enc"`.
    """
    org = ctx.org
    devs = [u for u in org.humans if u.department == "Engineering"]
    if not devs:
        return
    dev = devs[0]
    device = ctx.device_for(dev)
    if device is None:
        return
    blobs = [
        "SQBuAHYAbwBrAGUALQBCAHUAaQBsAGQAIAAtAEMAbwBuAGYAaQBnACAAUgBlAGwAZQBhAHMAZQA=",
        "RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAC0AUgBlAGMAdQByAHMAZQAgAC0ARgBpAGwAdABlAHIAIAAqAC4AZABsAGwA",
        "VABlAHMAdAAtAE4AZQB0AEMAbwBuAG4AZQBjAHQAaQBvAG4AIABiAHUAaQBsAGQALgBpAG4AdABlAHIAbgBhAGwA",
    ]
    for day in days_in_window(ctx.org):
        if not org.is_working_day(day):
            continue
        for _ in range(ctx.rng.randint(2, 6)):
            ts = day + timedelta(hours=ctx.rng.randint(0, 8),
                                 minutes=ctx.rng.randint(0, 59))
            cmd = (f"powershell.exe -NoProfile -ExecutionPolicy Bypass "
                   f"-EncodedCommand {ctx.rng.choice(blobs)}")
            yield _label(ctx, _proc_row(ctx, device, dev, ts, "powershell.exe", cmd,
                                        parent="Code.exe"),
                         "dev-encoded-powershell",
                         "Engineering build script using -EncodedCommand daily")


def it_admin_tooling(ctx: GenContext) -> Iterator[dict]:
    """PsExec and WMI from the IT team during the overnight patch window.

    Defeats: `FileName in ("psexec.exe","wmic.exe")` and most
    "admin tool outside business hours" queries.
    """
    org = ctx.org
    admins = [u for u in org.admins if not u.is_service]
    if not admins:
        return
    targets = org.servers or org.workstations
    for day in days_in_window(ctx.org):
        # Patch window: Tuesday and Thursday nights.
        if day.weekday() not in (1, 3):
            continue
        admin = ctx.rng.choice(admins)
        jump = next((d for d in org.devices_by_role("jump")), org.servers[0] if org.servers else None)
        if jump is None:
            return
        for _ in range(ctx.rng.randint(6, 18)):
            target = ctx.rng.choice(targets)
            ts = day + timedelta(hours=ctx.rng.choice([14, 15, 16]),  # 00:00-02:00 AEST
                                 minutes=ctx.rng.randint(0, 59))
            style = ctx.rng.random()
            if style < 0.4:
                image, cmd = "PsExec64.exe", (
                    rf"psexec64.exe \\{target.name} -s -accepteula "
                    r"cmd /c wusa /quiet /norestart")
            elif style < 0.7:
                image, cmd = "wmic.exe", (
                    f"wmic /node:{target.name} process call create "
                    r'"cmd.exe /c gpupdate /force"')
            else:
                image, cmd = "powershell.exe", (
                    f"powershell.exe -NoProfile -Command "
                    f"Invoke-Command -ComputerName {target.name} "
                    r"-ScriptBlock {Get-HotFix}")
            yield _label(ctx, _proc_row(ctx, jump, admin, ts, image, cmd,
                                        parent="cmd.exe", integrity="High"),
                         "it-patch-window",
                         "IT remote administration during the scheduled patch window")


def vulnerability_scanner(ctx: GenContext) -> Iterator[dict]:
    """Weekly authenticated scan: network logons to every host, SMB and RDP probes.

    Defeats: "one account authenticating to many hosts" — the classic lateral
    movement query, which this triggers perfectly every Sunday.
    """
    org = ctx.org
    scanner = next((u for u in org.service_accounts if u.sam == "svc-scanner"), None)
    if scanner is None:
        return
    scan_host = org.servers[-1] if org.servers else None
    if scan_host is None:
        return

    for day in days_in_window(ctx.org):
        if day.weekday() != 6:            # Sundays
            continue
        for target in org.devices:
            if ctx.rng.random() > 0.6:
                continue
            ts = day + timedelta(hours=ctx.rng.randint(16, 22),
                                 minutes=ctx.rng.randint(0, 59),
                                 seconds=ctx.rng.randint(0, 59))
            lid = logon_id(ctx.rng)
            row = ctx.platform("SecurityEvent", ts)
            row.update({
                "Computer": f"{target.name.lower()}.{org.domain}",
                "EventID": 4624,
                "Activity": "4624 - An account was successfully logged on.",
                "EventSourceName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Level": "8",
                "Account": f"{org.netbios}\\{scanner.sam}",
                "AccountType": "User",
                "TargetAccount": f"{org.netbios}\\{scanner.sam}",
                "TargetUserName": scanner.sam,
                "TargetDomainName": org.netbios,
                "TargetUserSid": scanner.sid,
                "TargetLogonId": lid,
                "SubjectUserName": "-", "SubjectDomainName": "-",
                "SubjectUserSid": "S-1-0-0", "SubjectLogonId": "0x0",
                "LogonType": 3,
                "LogonTypeName": "3 - Network",
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": "NTLM",
                "Status": "0x0",
                "WorkstationName": scan_host.name,
                "IpAddress": scan_host.ip,
                "IpPort": str(ctx.rng.randint(49152, 65535)),
            })
            row["__table"] = "SecurityEvent"
            yield _label(ctx, row, "vuln-scanner-sweep",
                         "Authenticated vulnerability scan touching every host weekly")


def backup_bulk_file_access(ctx: GenContext) -> Iterator[dict]:
    """Nightly backup agent reading files in bulk.

    Defeats: "mass file access by one account" — the standard staging /
    ransomware-precursor query.
    """
    org = ctx.org
    svc = next((u for u in org.service_accounts if u.sam == "svc-backup"), None)
    file_servers = org.devices_by_role("file")
    if svc is None or not file_servers:
        return
    names = ["ledger.xlsx", "contract.pdf", "payroll.csv", "design.dwg",
             "minutes.docx", "archive.pst", "database.bak", "photos.zip"]

    for day in days_in_window(ctx.org):
        server = ctx.rng.choice(file_servers)
        base = scheduled_time(ctx, day, hour=16)      # 02:00 AEST
        for i in range(ctx.rng.randint(40, 90)):
            ts = base + timedelta(seconds=i * ctx.rng.randint(1, 8))
            fname = ctx.rng.choice(names)
            sha1, sha256, md5 = file_hashes(ctx.rng, fname)
            row = ctx.platform("DeviceFileEvents", ts)
            row.update({
                "DeviceId": server.device_id,
                "DeviceName": f"{server.name.lower()}.{org.domain}",
                "ActionType": "FileAccessed",
                "FileName": fname,
                "FolderPath": rf"E:\Shares\Finance\{fname}",
                "SHA1": sha1, "SHA256": sha256, "MD5": md5,
                "FileSize": ctx.rng.randint(4096, 40_000_000),
                "ShareName": "Finance",
                "RequestAccountName": svc.sam,
                "RequestAccountDomain": org.netbios,
                "RequestAccountSid": svc.sid,
                "InitiatingProcessFileName": "Veeam.Backup.Service.exe",
                "InitiatingProcessAccountName": svc.sam,
                "InitiatingProcessAccountDomain": org.netbios,
                "InitiatingProcessAccountSid": svc.sid,
                "InitiatingProcessId": ctx.rng.randint(600, 9000),
                "InitiatingProcessIntegrityLevel": "System",
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Servers",
            })
            row["__table"] = "DeviceFileEvents"
            yield _label(ctx, row, "backup-bulk-read",
                         "Nightly Veeam backup reading every file on the share")


def travelling_executive(ctx: GenContext) -> Iterator[dict]:
    """A genuine business trip: sign-ins from another country, mid-week.

    Defeats: impossible travel and "sign-in from unusual country".
    """
    from org import catalog as cat
    org = ctx.org
    travellers = [u for u in org.humans if u.travels]
    if not travellers:
        return
    days = days_in_window(ctx.org)
    for traveller in travellers[:3]:
        if len(days) < 6:
            break
        start = ctx.rng.randint(1, max(1, len(days) - 4))
        city, country, cc, offset = ctx.rng.choice(cat.TRAVEL_DESTINATIONS)
        trip_ip = public_ip(ctx.rng)
        for day in days[start:start + ctx.rng.randint(2, 4)]:
            for _ in range(ctx.rng.randint(3, 9)):
                local_h = 8 + ctx.rng.random() * 11
                ts = day + timedelta(hours=local_h - offset,
                                     minutes=ctx.rng.randint(0, 59))
                app, app_id, _ = ctx.weighted(cat.ENTRA_APPS)
                row = ctx.platform("SigninLogs", ts)
                row.update({
                    "OperationName": "Sign-in activity",
                    "Category": "SignInLogs",
                    "ResultType": "0",
                    "ResultDescription": "",
                    "DurationMs": ctx.rng.randint(40, 700),
                    "CorrelationId": ctx.item_id(),
                    "Identity": traveller.display_name,
                    "Level": "4",
                    "Location": cc,
                    "AppDisplayName": app,
                    "AppId": app_id,
                    "AuthenticationRequirement": "multiFactorAuthentication",
                    "ClientAppUsed": "Browser",
                    "ConditionalAccessStatus": "success",
                    "CreatedDateTime": ts,
                    "DeviceDetail": {"operatingSystem": "Windows 11", "browser": "Chrome 131.0.0",
                                     "isCompliant": True, "isManaged": True},
                    "IPAddress": trip_ip,
                    "IsInteractive": True,
                    "IsRisky": False,
                    "LocationDetails": {"city": city, "countryOrRegion": cc, "state": city},
                    "RiskDetail": "none",
                    "RiskLevelDuringSignIn": "none",
                    "RiskState": "none",
                    "Status": {"errorCode": 0},
                    "UserAgent": traveller.user_agent,
                    "UserDisplayName": traveller.display_name,
                    "UserId": traveller.object_id,
                    "UserPrincipalName": traveller.upn,
                    "UserType": "Member",
                    "HomeTenantId": org.tenant_id,
                    "ResourceTenantId": org.tenant_id,
                    "ResourceDisplayName": app,
                    "SignInIdentifier": traveller.upn,
                })
                row["__table"] = "SigninLogs"
                yield _label(ctx, row, "business-travel",
                             f"{traveller.display_name} genuinely working from {city}")


def asset_inventory_discovery(ctx: GenContext) -> Iterator[dict]:
    """An inventory tool enumerating SPNs, domain admins and hosts.

    Defeats: SPN enumeration and domain reconnaissance hunts — this runs the
    same LDAP queries an attacker does, on a schedule, from a known host.
    """
    org = ctx.org
    svc = next((u for u in org.service_accounts if u.sam == "svc-sccm"), None)
    if svc is None or not org.servers:
        return
    host = org.servers[0]
    commands = [
        r'powershell.exe -NoProfile -Command "Get-ADUser -Filter {ServicePrincipalName -like \"*\"} -Properties ServicePrincipalName"',
        r'powershell.exe -NoProfile -Command "Get-ADGroupMember -Identity \"Domain Admins\""',
        r'powershell.exe -NoProfile -Command "Get-ADComputer -Filter * -Properties OperatingSystem"',
        r"setspn.exe -T harbourline -Q */*",
        r"nltest.exe /dclist:harbourline",
    ]
    for day in days_in_window(ctx.org):
        if day.weekday() not in (0, 3):
            continue
        base = scheduled_time(ctx, day, hour=19)
        for i, cmd in enumerate(commands):
            ts = base + timedelta(minutes=i * ctx.rng.randint(1, 4))
            image = cmd.split(".exe")[0].split("\\")[-1] + ".exe"
            yield _label(ctx, _proc_row(ctx, host, svc, ts, image, cmd,
                                        parent="CcmExec.exe", integrity="System"),
                         "asset-inventory",
                         "Configuration Manager inventory enumerating AD twice weekly")


ALL_NOISE = [
    developer_encoded_powershell,
    it_admin_tooling,
    vulnerability_scanner,
    backup_bulk_file_access,
    travelling_executive,
    asset_inventory_discovery,
]


def generate_all(ctx: GenContext) -> Iterator[dict]:
    for fn in ALL_NOISE:
        yield from fn(ctx)
