"""Benign endpoint telemetry: Defender device tables and the Windows Security log.

**Cross-table coherence is the point.** A process execution is not one row —
it is a `DeviceProcessEvents` row *and* a `SecurityEvent` 4688 for the same
execution, sharing device, account, process id, command line and timestamp.
Emitting them independently produces telemetry that falls apart the instant an
analyst joins the two tables, which is exactly the pivot a real hunt makes.

So `process_events()` is a single generator that fans one logical execution out
across both tables, and the volume budget for 4688 is derived from it rather
than allocated separately.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Iterator

from org import catalog

from ..common import (GenContext, any_time, file_hashes, logon_id, public_ip,
                      rand_hex, scheduled_time, spread_over_days, work_time)

LOGON_TYPE_NAMES = {
    2: "Interactive", 3: "Network", 4: "Batch", 5: "Service",
    7: "Unlock", 8: "NetworkCleartext", 9: "NewCredentials",
    10: "RemoteInteractive", 11: "CachedInteractive",
}

# Only a fraction of environments have command-line auditing switched on for
# 4688. Modelling that gap is deliberate: it is the single most common reason a
# "detect encoded PowerShell via SecurityEvent" hunt returns nothing in the real
# world, and an analyst should meet it here first.
CMDLINE_AUDIT_COVERAGE = 0.72


def _proc_paths(image: str) -> str:
    if image in ("svchost.exe", "services.exe", "taskhostw.exe", "SearchIndexer.exe",
                 "wermgr.exe", "cmd.exe", "powershell.exe", "ntoskrnl.exe"):
        return r"c:\windows\system32"
    if image in ("explorer.exe", "wininit.exe"):
        return r"c:\windows"
    if image == "w3wp.exe":
        return r"c:\windows\system32\inetsrv"
    return r"c:\program files"


def _company(image: str) -> str:
    if image.lower().endswith((".exe",)) and image in (
            "chrome.exe",): return "Google LLC"
    if image in ("Code.exe", "msedge.exe", "OUTLOOK.EXE", "EXCEL.EXE", "WINWORD.EXE",
                 "Teams.exe", "OneDrive.exe", "MsMpEng.exe", "svchost.exe", "services.exe",
                 "explorer.exe", "cmd.exe", "powershell.exe", "SenseIR.exe", "CcmExec.exe"):
        return "Microsoft Corporation"
    return ""


def process_events(ctx: GenContext, count: int) -> Iterator[dict]:
    """Yields rows for BOTH DeviceProcessEvents and SecurityEvent (4688).

    Each dict carries a `__table` key naming its destination; the builder routes
    on it. `count` is the number of *executions*, not rows.
    """
    org = ctx.org
    workstations = org.workstations
    servers = org.servers

    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            on_server = ctx.rng.random() < 0.18
            if on_server and servers:
                device = ctx.rng.choice(servers)
                user = ctx.rng.choice(org.service_accounts or org.humans)
                image, cmdline = ctx.rng.choice(catalog.ADMIN_PROCESSES)
                parent = "services.exe"
                ts = any_time(ctx, day)
            else:
                device = ctx.rng.choice(workstations)
                user = org.user(device.primary_user) if device.primary_user else ctx.pick_human()
                parent, image, cmdline, _ = ctx.weighted(catalog.PROCESS_TREE)
                ts = work_time(ctx, day, user)

            cmdline = cmdline.replace("{user}", user.sam).replace("{host}", device.name)
            folder = _proc_paths(image)
            path = f"{folder}\\{image}"
            sha1, sha256, md5 = file_hashes(ctx.rng, image)
            p_sha1, p_sha256, p_md5 = file_hashes(ctx.rng, parent)
            pid = ctx.rng.randint(600, 32000)
            ppid = ctx.rng.randint(500, 12000)
            lid = logon_id(ctx.rng)
            created = ts - timedelta(milliseconds=ctx.rng.randint(1, 800))
            parent_created = ts - timedelta(minutes=ctx.rng.randint(2, 900))

            initiating = {
                "InitiatingProcessAccountDomain": org.netbios,
                "InitiatingProcessAccountName": user.sam,
                "InitiatingProcessAccountSid": user.sid,
                "InitiatingProcessAccountUpn": user.upn,
                "InitiatingProcessAccountObjectId": user.object_id,
                "InitiatingProcessLogonId": lid,
                "InitiatingProcessIntegrityLevel": "Medium",
                "InitiatingProcessTokenElevation": "TokenElevationTypeLimited",
                "InitiatingProcessSHA1": p_sha1,
                "InitiatingProcessSHA256": p_sha256,
                "InitiatingProcessMD5": p_md5,
                "InitiatingProcessFileName": parent,
                "InitiatingProcessFileSize": ctx.rng.randint(40_000, 4_000_000),
                "InitiatingProcessFolderPath": f"{_proc_paths(parent)}\\{parent}",
                "InitiatingProcessId": ppid,
                "InitiatingProcessCommandLine": parent,
                "InitiatingProcessCreationTime": parent_created,
                "InitiatingProcessParentId": ctx.rng.randint(400, 900),
                "InitiatingProcessParentFileName": "services.exe",
                "InitiatingProcessParentCreationTime": parent_created - timedelta(minutes=5),
            }

            row = ctx.platform("DeviceProcessEvents", ts)
            row.update({
                "DeviceId": device.device_id,
                "DeviceName": f"{device.name.lower()}.{org.domain}",
                "ActionType": "ProcessCreated",
                "FileName": image,
                "FolderPath": path,
                "SHA1": sha1, "SHA256": sha256, "MD5": md5,
                "FileSize": ctx.rng.randint(20_000, 12_000_000),
                "ProcessVersionInfoCompanyName": _company(image),
                "ProcessVersionInfoProductName": image.rsplit(".", 1)[0],
                "ProcessVersionInfoOriginalFileName": image,
                "ProcessId": pid,
                "ProcessCommandLine": cmdline,
                "ProcessIntegrityLevel": "System" if device.is_server else "Medium",
                "ProcessTokenElevation": "TokenElevationTypeDefault",
                "ProcessCreationTime": created,
                "AccountDomain": org.netbios,
                "AccountName": user.sam,
                "AccountSid": user.sid,
                "AccountUpn": user.upn,
                "AccountObjectId": user.object_id,
                "LogonId": lid,
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Corporate",
                **initiating,
            })
            row["__table"] = "DeviceProcessEvents"
            yield row

            # The same execution as Windows sees it.
            has_cmdline = ctx.rng.random() < CMDLINE_AUDIT_COVERAGE
            sec = ctx.platform("SecurityEvent", ts)
            sec.update({
                "Computer": f"{device.name.lower()}.{org.domain}",
                "EventID": 4688,
                "Activity": "4688 - A new process has been created.",
                "EventSourceName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Task": 13312,
                "Level": "8",
                "Account": f"{org.netbios}\\{user.sam}",
                "AccountType": "User",
                "SubjectAccount": f"{org.netbios}\\{user.sam}",
                "SubjectUserName": user.sam,
                "SubjectDomainName": org.netbios,
                "SubjectUserSid": user.sid,
                "SubjectLogonId": lid,
                "NewProcessName": path,
                "NewProcessId": f"0x{pid:x}",
                "ProcessName": f"{_proc_paths(parent)}\\{parent}",
                "ProcessId": f"0x{ppid:x}",
                "ParentProcessName": f"{_proc_paths(parent)}\\{parent}",
                "CommandLine": cmdline if has_cmdline else "",
                "TokenElevationType": "%%1938",
                "MandatoryLabel": "S-1-16-8192",
            })
            sec["__table"] = "SecurityEvent"
            yield sec


def logon_events(ctx: GenContext, count: int) -> Iterator[dict]:
    """DeviceLogonEvents plus matching SecurityEvent 4624/4625."""
    org = ctx.org
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            device = ctx.rng.choice(org.devices)
            if device.primary_user:
                user = org.user(device.primary_user)
                logon_type, type_name = ctx.weighted(
                    [(2, "Interactive", 0.55), (11, "CachedInteractive", 0.20),
                     (7, "Unlock", 0.15), (3, "Network", 0.10)])[:2]
            else:
                user = ctx.rng.choice(org.service_accounts or org.humans)
                logon_type, type_name = ctx.weighted(
                    [(3, "Network", 0.50), (5, "Service", 0.25),
                     (4, "Batch", 0.15), (10, "RemoteInteractive", 0.10)])[:2]

            ts = work_time(ctx, day, user) if not user.is_service else any_time(ctx, day)
            failed = ctx.rng.random() < 0.045
            lid = logon_id(ctx.rng)
            remote_ip = (device.ip if logon_type in (2, 7, 11)
                         else ctx.rng.choice([d.ip for d in org.devices[:40]]))

            row = ctx.platform("DeviceLogonEvents", ts)
            row.update({
                "DeviceId": device.device_id,
                "DeviceName": f"{device.name.lower()}.{org.domain}",
                "ActionType": "LogonFailed" if failed else "LogonSuccess",
                "LogonType": type_name,
                "AccountDomain": org.netbios,
                "AccountName": user.sam,
                "AccountSid": user.sid,
                "AccountUpn": user.upn,
                "AccountObjectId": user.object_id,
                "LogonId": lid,
                "IsLocalAdmin": user.is_admin,
                "Protocol": "NTLM" if logon_type == 3 and ctx.rng.random() < 0.3 else "Kerberos",
                "FailureReason": "InvalidUserNameOrPassword" if failed else "",
                "IsLocalLogon": logon_type in (2, 7, 11),
                "RemoteIP": remote_ip,
                "RemoteIPType": "Private",
                "RemotePort": ctx.rng.randint(49152, 65535) if logon_type == 3 else 0,
                "RemoteDeviceName": "" if logon_type in (2, 7, 11) else device.name,
                "AdditionalFields": {},
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Corporate",
                "InitiatingProcessFileName": "lsass.exe" if logon_type == 3 else "winlogon.exe",
                "InitiatingProcessAccountName": "SYSTEM",
                "InitiatingProcessAccountDomain": "NT AUTHORITY",
                "InitiatingProcessId": ctx.rng.randint(500, 900),
            })
            row["__table"] = "DeviceLogonEvents"
            yield row

            sec = ctx.platform("SecurityEvent", ts)
            sec.update({
                "Computer": f"{device.name.lower()}.{org.domain}",
                "EventID": 4625 if failed else 4624,
                "Activity": ("4625 - An account failed to log on."
                             if failed else "4624 - An account was successfully logged on."),
                "EventSourceName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Level": "8",
                "Account": f"{org.netbios}\\{user.sam}",
                "AccountType": "User",
                "TargetAccount": f"{org.netbios}\\{user.sam}",
                "TargetUserName": user.sam,
                "TargetDomainName": org.netbios,
                "TargetUserSid": user.sid,
                "TargetLogonId": lid,
                "SubjectUserName": "-", "SubjectDomainName": "-",
                "SubjectUserSid": "S-1-0-0", "SubjectLogonId": "0x0",
                "LogonType": logon_type,
                "LogonTypeName": f"{logon_type} - {type_name}",
                "LogonProcessName": "Kerberos" if logon_type != 2 else "User32",
                "AuthenticationPackageName": "Kerberos" if logon_type != 3 else "NTLM",
                "Status": "0xc000006d" if failed else "0x0",
                "SubStatus": "0xc000006a" if failed else "0x0",
                "WorkstationName": device.name,
                "IpAddress": remote_ip,
                "IpPort": str(ctx.rng.randint(49152, 65535)),
            })
            sec["__table"] = "SecurityEvent"
            yield sec


def kerberos_events(ctx: GenContext, count: int) -> Iterator[dict]:
    """4768/4769 service ticket activity on the DCs.

    This is the baseline any kerberoasting hunt has to separate signal from:
    hundreds of legitimate TGS requests an hour, mostly AES, from real users to
    real SPNs — plus a few RC4 tickets from a genuine legacy application."""
    org = ctx.org
    dcs = org.domain_controllers or org.servers[:1]
    if not dcs:
        return
    spns = [f"HOST/{d.name.lower()}.{org.domain}" for d in org.servers]
    spns += [f"MSSQLSvc/{d.name.lower()}.{org.domain}:1433"
             for d in org.devices_by_role("sql")]
    spns += [f"HTTP/{d.name.lower()}.{org.domain}" for d in org.devices_by_role("web")]
    spns += ["krbtgt", f"cifs/{org.domain}"]
    legacy_spn = spns[0] if spns else "krbtgt"

    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            user = ctx.rng.choice(org.humans + org.service_accounts)
            dc = ctx.rng.choice(dcs)
            ts = work_time(ctx, day, user) if not user.is_service else any_time(ctx, day)
            spn = ctx.rng.choice(spns)
            event_id = 4769 if ctx.rng.random() < 0.82 else 4768
            # AES is the norm. A genuine legacy app still asks for RC4 — which
            # is why "TicketEncryptionType == 0x17" alone is not a detection.
            if spn == legacy_spn and ctx.rng.random() < 0.35:
                enc = "0x17"
            else:
                enc = ctx.rng.choices(["0x12", "0x11", "0x17"], weights=[0.80, 0.15, 0.05])[0]

            sec = ctx.platform("SecurityEvent", ts)
            sec.update({
                "Computer": f"{dc.name.lower()}.{org.domain}",
                "EventID": event_id,
                "Activity": (f"{event_id} - A Kerberos service ticket was requested."
                             if event_id == 4769
                             else f"{event_id} - A Kerberos authentication ticket (TGT) was requested."),
                "EventSourceName": "Microsoft-Windows-Security-Auditing",
                "Channel": "Security",
                "Level": "8",
                "Account": f"{user.sam}@{org.domain.upper()}",
                "AccountType": "User",
                "TargetUserName": f"{user.sam}@{org.domain.upper()}",
                "TargetDomainName": org.domain.upper(),
                "TargetUserSid": user.sid,
                "ServiceName": spn,
                "ServiceID": org.domain_sid + "-512",
                "TicketEncryptionType": enc,
                "TicketOptions": "0x40810000",
                "Status": "0x0",
                "IpAddress": f"::ffff:{ctx.rng.choice([d.ip for d in org.workstations[:60]])}",
                "IpPort": str(ctx.rng.randint(49152, 65535)),
                "PreAuthType": "2" if event_id == 4768 else "",
            })
            sec["__table"] = "SecurityEvent"
            yield sec


def device_network_events(ctx: GenContext, count: int) -> Iterator[dict]:
    """Outbound connections attributed to a process."""
    org = ctx.org
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            device = ctx.rng.choice(org.workstations)
            user = org.user(device.primary_user) if device.primary_user else ctx.pick_human()
            ts = work_time(ctx, day, user)
            domain = ctx.weighted(catalog.POPULAR_DOMAINS)[0]
            proc = ctx.rng.choices(
                ["chrome.exe", "msedge.exe", "OUTLOOK.EXE", "Teams.exe",
                 "OneDrive.exe", "svchost.exe", "MsMpEng.exe", "Code.exe"],
                weights=[0.30, 0.20, 0.14, 0.12, 0.09, 0.08, 0.04, 0.03])[0]
            sha1, sha256, md5 = file_hashes(ctx.rng, proc)
            port = ctx.rng.choices([443, 80, 8443], weights=[0.90, 0.08, 0.02])[0]

            row = ctx.platform("DeviceNetworkEvents", ts)
            row.update({
                "DeviceId": device.device_id,
                "DeviceName": f"{device.name.lower()}.{org.domain}",
                "ActionType": "ConnectionSuccess",
                "RemoteIP": public_ip(ctx.rng),
                "RemotePort": port,
                "RemoteUrl": domain,
                "LocalIP": device.ip,
                "LocalPort": ctx.rng.randint(49152, 65535),
                "Protocol": "Tcp",
                "LocalIPType": "Private",
                "RemoteIPType": "Public",
                "InitiatingProcessAccountDomain": org.netbios,
                "InitiatingProcessAccountName": user.sam,
                "InitiatingProcessAccountSid": user.sid,
                "InitiatingProcessAccountUpn": user.upn,
                "InitiatingProcessAccountObjectId": user.object_id,
                "InitiatingProcessSHA1": sha1,
                "InitiatingProcessSHA256": sha256,
                "InitiatingProcessMD5": md5,
                "InitiatingProcessFileName": proc,
                "InitiatingProcessFolderPath": f"{_proc_paths(proc)}\\{proc}",
                "InitiatingProcessId": ctx.rng.randint(600, 32000),
                "InitiatingProcessCommandLine": proc,
                "InitiatingProcessCreationTime": ts - timedelta(minutes=ctx.rng.randint(1, 400)),
                "InitiatingProcessParentFileName": "explorer.exe",
                "InitiatingProcessIntegrityLevel": "Medium",
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Corporate",
            })
            yield row


def device_file_events(ctx: GenContext, count: int) -> Iterator[dict]:
    org = ctx.org
    names = ["report.docx", "budget.xlsx", "notes.txt", "deck.pptx", "archive.zip",
             "invoice.pdf", "config.json", "backup.bak", "photo.png", "script.ps1"]
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            device = ctx.rng.choice(org.workstations)
            user = org.user(device.primary_user) if device.primary_user else ctx.pick_human()
            ts = work_time(ctx, day, user)
            fname = ctx.rng.choice(names)
            action = ctx.rng.choices(["FileCreated", "FileModified", "FileRenamed", "FileDeleted"],
                                     weights=[0.42, 0.38, 0.10, 0.10])[0]
            sha1, sha256, md5 = file_hashes(ctx.rng, fname)
            proc = ctx.rng.choice(["EXCEL.EXE", "WINWORD.EXE", "chrome.exe",
                                   "OneDrive.exe", "explorer.exe", "Code.exe"])
            row = ctx.platform("DeviceFileEvents", ts)
            row.update({
                "DeviceId": device.device_id,
                "DeviceName": f"{device.name.lower()}.{org.domain}",
                "ActionType": action,
                "FileName": fname,
                "FolderPath": rf"C:\Users\{user.sam}\Documents\{fname}",
                "SHA1": sha1, "SHA256": sha256, "MD5": md5,
                "FileSize": ctx.rng.randint(1024, 8_000_000),
                "InitiatingProcessAccountDomain": org.netbios,
                "InitiatingProcessAccountName": user.sam,
                "InitiatingProcessAccountSid": user.sid,
                "InitiatingProcessAccountUpn": user.upn,
                "InitiatingProcessFileName": proc,
                "InitiatingProcessFolderPath": f"{_proc_paths(proc)}\\{proc}",
                "InitiatingProcessId": ctx.rng.randint(600, 32000),
                "InitiatingProcessCommandLine": proc,
                "InitiatingProcessIntegrityLevel": "Medium",
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Corporate",
            })
            yield row


def device_registry_events(ctx: GenContext, count: int) -> Iterator[dict]:
    org = ctx.org
    keys = [
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Signature Updates",
         "SignatureLastUpdated"),
        (r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\16.0\Common\Identity", "LastKnownUser"),
        (r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate",
         "LastSuccessTime"),
        (r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
         "MRUListEx"),
        (r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CcmExec", "Start"),
    ]
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            device = ctx.rng.choice(org.workstations)
            user = org.user(device.primary_user) if device.primary_user else ctx.pick_human()
            key, value = ctx.rng.choice(keys)
            ts = work_time(ctx, day, user)
            row = ctx.platform("DeviceRegistryEvents", ts)
            row.update({
                "DeviceId": device.device_id,
                "DeviceName": f"{device.name.lower()}.{org.domain}",
                "ActionType": ctx.rng.choice(["RegistryValueSet", "RegistryKeyCreated"]),
                "RegistryKey": key,
                "RegistryValueType": "String",
                "RegistryValueName": value,
                "RegistryValueData": str(ctx.rng.randint(1, 999999)),
                "InitiatingProcessAccountDomain": org.netbios,
                "InitiatingProcessAccountName": user.sam,
                "InitiatingProcessAccountSid": user.sid,
                "InitiatingProcessFileName": ctx.rng.choice(
                    ["svchost.exe", "MsMpEng.exe", "CcmExec.exe", "explorer.exe"]),
                "InitiatingProcessId": ctx.rng.randint(600, 32000),
                "InitiatingProcessIntegrityLevel": "System",
                "ReportId": str(ctx.rng.randint(1, 999999)),
                "MachineGroup": "Corporate",
            })
            yield row
