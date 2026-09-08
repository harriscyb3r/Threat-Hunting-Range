"""Canonical row builders, shared by benign, noise and attack generators.

**Why this module exists.** If attack emitters built their rows independently,
malicious events would differ structurally from benign ones — a field populated
here and empty there — and an analyst could find the attack by spotting the
artefact rather than the behaviour. That is a range that teaches nothing.

Every generator therefore builds rows through the same functions. The only
difference between a benign `powershell.exe` and an attacker's is the *content*:
the command line, the parent, the timing, the account. Which is exactly the
difference a real hunt has to work with.

`test_phase2.py` asserts this: for each table, the set of populated columns from
benign rows and from attack rows must match.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from org import Device, User

from .common import GenContext, file_hashes, logon_id

# Folders for well-known images, so paths are consistent everywhere.
_SYSTEM32 = {
    "svchost.exe", "services.exe", "taskhostw.exe", "SearchIndexer.exe", "wermgr.exe",
    "cmd.exe", "powershell.exe", "ntoskrnl.exe", "rundll32.exe", "wmic.exe",
    "net.exe", "net1.exe", "nltest.exe", "whoami.exe", "schtasks.exe", "sc.exe",
    "reg.exe", "wevtutil.exe", "vssadmin.exe", "bcdedit.exe", "wbadmin.exe",
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe", "cscript.exe",
    "wscript.exe", "tasklist.exe", "systeminfo.exe", "ipconfig.exe", "arp.exe",
    "route.exe", "netstat.exe", "quser.exe", "klist.exe", "setspn.exe",
    "lsass.exe", "winlogon.exe", "conhost.exe", "dsquery.exe", "makecab.exe",
}
_WINDOWS = {"explorer.exe", "wininit.exe", "system"}


def folder_for(image: str) -> str:
    if image in _SYSTEM32:
        return r"c:\windows\system32"
    if image.lower() in {w.lower() for w in _WINDOWS}:
        return r"c:\windows"
    if image == "w3wp.exe":
        return r"c:\windows\system32\inetsrv"
    if image.lower().startswith("powershell") and image.endswith("_ise.exe"):
        return r"c:\windows\system32\windowspowershell\v1.0"
    return r"c:\program files"


def _company(image: str) -> str:
    if image == "chrome.exe":
        return "Google LLC"
    microsoft = {
        "Code.exe", "msedge.exe", "OUTLOOK.EXE", "EXCEL.EXE", "WINWORD.EXE",
        "Teams.exe", "OneDrive.exe", "MsMpEng.exe", "svchost.exe", "services.exe",
        "explorer.exe", "cmd.exe", "powershell.exe", "SenseIR.exe", "CcmExec.exe",
        "rundll32.exe", "wmic.exe", "net.exe", "schtasks.exe", "sc.exe", "reg.exe",
        "wevtutil.exe", "vssadmin.exe", "certutil.exe", "mshta.exe", "regsvr32.exe",
        "cscript.exe", "wscript.exe", "nltest.exe", "whoami.exe", "setspn.exe",
    }
    return "Microsoft Corporation" if image in microsoft else ""


def device_process_event(
    ctx: GenContext, device: Device, user: User, ts: datetime,
    image: str, cmdline: str, *,
    parent: str = "explorer.exe",
    parent_cmdline: str | None = None,
    integrity: str = "Medium",
    pid: int | None = None,
    ppid: int | None = None,
    grandparent: str = "services.exe",
    **overrides: Any,
) -> dict:
    org = ctx.org
    sha1, sha256, md5 = file_hashes(ctx.rng, image)
    p_sha1, p_sha256, p_md5 = file_hashes(ctx.rng, parent)
    pid = pid if pid is not None else ctx.rng.randint(600, 32000)
    ppid = ppid if ppid is not None else ctx.rng.randint(500, 12000)
    lid = logon_id(ctx.rng)
    parent_created = ts - timedelta(minutes=ctx.rng.randint(2, 900))

    row = ctx.platform("DeviceProcessEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": "ProcessCreated",
        "FileName": image,
        "FolderPath": f"{folder_for(image)}\\{image}",
        "SHA1": sha1, "SHA256": sha256, "MD5": md5,
        "FileSize": ctx.rng.randint(20_000, 12_000_000),
        "ProcessVersionInfoCompanyName": _company(image),
        "ProcessVersionInfoProductName": image.rsplit(".", 1)[0],
        "ProcessVersionInfoOriginalFileName": image,
        "ProcessId": pid,
        "ProcessCommandLine": cmdline,
        "ProcessIntegrityLevel": integrity,
        "ProcessTokenElevation": ("TokenElevationTypeFull" if integrity in ("High", "System")
                                  else "TokenElevationTypeLimited"),
        "ProcessCreationTime": ts,
        "AccountDomain": org.netbios,
        "AccountName": user.sam,
        "AccountSid": user.sid,
        "AccountUpn": user.upn,
        "AccountObjectId": user.object_id,
        "LogonId": lid,
        "InitiatingProcessAccountDomain": org.netbios,
        "InitiatingProcessAccountName": user.sam,
        "InitiatingProcessAccountSid": user.sid,
        "InitiatingProcessAccountUpn": user.upn,
        "InitiatingProcessAccountObjectId": user.object_id,
        "InitiatingProcessLogonId": lid,
        "InitiatingProcessIntegrityLevel": integrity,
        "InitiatingProcessTokenElevation": ("TokenElevationTypeFull"
                                            if integrity in ("High", "System")
                                            else "TokenElevationTypeLimited"),
        "InitiatingProcessSHA1": p_sha1,
        "InitiatingProcessSHA256": p_sha256,
        "InitiatingProcessMD5": p_md5,
        "InitiatingProcessFileName": parent,
        "InitiatingProcessFileSize": ctx.rng.randint(40_000, 4_000_000),
        "InitiatingProcessFolderPath": f"{folder_for(parent)}\\{parent}",
        "InitiatingProcessId": ppid,
        "InitiatingProcessCommandLine": parent_cmdline or parent,
        "InitiatingProcessCreationTime": parent_created,
        "InitiatingProcessParentId": ctx.rng.randint(400, 900),
        "InitiatingProcessParentFileName": grandparent,
        "InitiatingProcessParentCreationTime": parent_created - timedelta(minutes=5),
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Servers" if device.is_server else "Corporate",
    })
    row.update(overrides)
    row["__table"] = "DeviceProcessEvents"
    return row


def security_4688(
    ctx: GenContext, device: Device, user: User, ts: datetime,
    image: str, cmdline: str, *, parent: str = "explorer.exe",
    pid: int | None = None, ppid: int | None = None,
    has_cmdline: bool = True, **overrides: Any,
) -> dict:
    """The same execution as the Windows Security log records it.

    `has_cmdline` models the audit-policy gap: command-line auditing is off in
    a lot of environments, so 4688 often carries no CommandLine at all. An
    attacker gets the same coverage gap a benign process does.
    """
    org = ctx.org
    pid = pid if pid is not None else ctx.rng.randint(600, 32000)
    ppid = ppid if ppid is not None else ctx.rng.randint(500, 12000)
    row = ctx.platform("SecurityEvent", ts)
    row.update({
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
        "SubjectLogonId": logon_id(ctx.rng),
        "NewProcessName": f"{folder_for(image)}\\{image}",
        "NewProcessId": f"0x{pid:x}",
        "ProcessName": f"{folder_for(parent)}\\{parent}",
        "ProcessId": f"0x{ppid:x}",
        "ParentProcessName": f"{folder_for(parent)}\\{parent}",
        "CommandLine": cmdline if has_cmdline else "",
        "TokenElevationType": "%%1938",
        "MandatoryLabel": "S-1-16-8192",
    })
    row.update(overrides)
    row["__table"] = "SecurityEvent"
    return row


def execution(
    ctx: GenContext, device: Device, user: User, ts: datetime,
    image: str, cmdline: str, *, parent: str = "explorer.exe",
    integrity: str = "Medium", cmdline_audit: float = 0.72, **kw: Any,
) -> list[dict]:
    """One logical execution, fanned out across both tables coherently.

    Shared pid/ppid and identical timestamp, so `DeviceProcessEvents` and
    `SecurityEvent` 4688 join correctly — the pivot a real hunt makes.
    """
    pid = ctx.rng.randint(600, 32000)
    ppid = ctx.rng.randint(500, 12000)
    return [
        device_process_event(ctx, device, user, ts, image, cmdline,
                             parent=parent, integrity=integrity,
                             pid=pid, ppid=ppid, **kw),
        security_4688(ctx, device, user, ts, image, cmdline, parent=parent,
                      pid=pid, ppid=ppid,
                      has_cmdline=ctx.rng.random() < cmdline_audit),
    ]


def security_logon(
    ctx: GenContext, device: Device, user: User, ts: datetime, *,
    logon_type: int = 3, failed: bool = False,
    src_ip: str = "", workstation: str = "",
    auth_package: str = "Kerberos", logon_process: str = "Kerberos",
    lid: str | None = None, **overrides: Any,
) -> dict:
    org = ctx.org
    names = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 7: "Unlock",
             8: "NetworkCleartext", 9: "NewCredentials", 10: "RemoteInteractive",
             11: "CachedInteractive"}
    row = ctx.platform("SecurityEvent", ts)
    row.update({
        "Computer": f"{device.name.lower()}.{org.domain}",
        "EventID": 4625 if failed else 4624,
        "Activity": ("4625 - An account failed to log on." if failed
                     else "4624 - An account was successfully logged on."),
        "EventSourceName": "Microsoft-Windows-Security-Auditing",
        "Channel": "Security",
        "Level": "8",
        "Account": f"{org.netbios}\\{user.sam}",
        "AccountType": "User",
        "TargetAccount": f"{org.netbios}\\{user.sam}",
        "TargetUserName": user.sam,
        "TargetDomainName": org.netbios,
        "TargetUserSid": user.sid,
        "TargetLogonId": lid or logon_id(ctx.rng),
        "SubjectUserName": "-", "SubjectDomainName": "-",
        "SubjectUserSid": "S-1-0-0", "SubjectLogonId": "0x0",
        "LogonType": logon_type,
        "LogonTypeName": f"{logon_type} - {names.get(logon_type, 'Unknown')}",
        "LogonProcessName": logon_process,
        "AuthenticationPackageName": auth_package,
        "Status": "0xc000006d" if failed else "0x0",
        "SubStatus": "0xc000006a" if failed else "0x0",
        "WorkstationName": workstation or device.name,
        "IpAddress": src_ip or device.ip,
        "IpPort": str(ctx.rng.randint(49152, 65535)),
    })
    row.update(overrides)
    row["__table"] = "SecurityEvent"
    return row


def device_logon_event(
    ctx: GenContext, device: Device, user: User, ts: datetime, *,
    logon_type: str = "Network", failed: bool = False,
    remote_ip: str = "", remote_device: str = "", protocol: str = "Kerberos",
    **overrides: Any,
) -> dict:
    org = ctx.org
    row = ctx.platform("DeviceLogonEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": "LogonFailed" if failed else "LogonSuccess",
        "LogonType": logon_type,
        "AccountDomain": org.netbios,
        "AccountName": user.sam,
        "AccountSid": user.sid,
        "AccountUpn": user.upn,
        "AccountObjectId": user.object_id,
        "LogonId": logon_id(ctx.rng),
        "IsLocalAdmin": user.is_admin,
        "Protocol": protocol,
        "FailureReason": "InvalidUserNameOrPassword" if failed else "",
        "IsLocalLogon": logon_type in ("Interactive", "CachedInteractive", "Unlock"),
        "RemoteIP": remote_ip or device.ip,
        "RemoteIPType": "Private",
        "RemotePort": ctx.rng.randint(49152, 65535),
        "RemoteDeviceName": remote_device,
        "AdditionalFields": {},
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Servers" if device.is_server else "Corporate",
        "InitiatingProcessFileName": "lsass.exe",
        "InitiatingProcessAccountName": "SYSTEM",
        "InitiatingProcessAccountDomain": "NT AUTHORITY",
        "InitiatingProcessId": ctx.rng.randint(500, 900),
    })
    row.update(overrides)
    row["__table"] = "DeviceLogonEvents"
    return row


def security_kerberos(
    ctx: GenContext, dc: Device, user: User, ts: datetime, *,
    event_id: int = 4769, spn: str = "krbtgt",
    encryption: str = "0x12", src_ip: str = "", status: str = "0x0",
    **overrides: Any,
) -> dict:
    org = ctx.org
    row = ctx.platform("SecurityEvent", ts)
    row.update({
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
        "TicketEncryptionType": encryption,
        "TicketOptions": "0x40810000",
        "Status": status,
        "IpAddress": f"::ffff:{src_ip}" if src_ip else "",
        "IpPort": str(ctx.rng.randint(49152, 65535)),
        "PreAuthType": "2" if event_id == 4768 else "",
    })
    row.update(overrides)
    row["__table"] = "SecurityEvent"
    return row


def device_network_event(
    ctx: GenContext, device: Device, user: User, ts: datetime, *,
    remote_ip: str, remote_port: int = 443, remote_url: str = "",
    process: str = "chrome.exe", action: str = "ConnectionSuccess",
    protocol: str = "Tcp", **overrides: Any,
) -> dict:
    org = ctx.org
    sha1, sha256, md5 = file_hashes(ctx.rng, process)
    row = ctx.platform("DeviceNetworkEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": action,
        "RemoteIP": remote_ip,
        "RemotePort": remote_port,
        "RemoteUrl": remote_url,
        "LocalIP": device.ip,
        "LocalPort": ctx.rng.randint(49152, 65535),
        "Protocol": protocol,
        "LocalIPType": "Private",
        "RemoteIPType": "Private" if remote_ip.startswith(("10.", "192.168.")) else "Public",
        "InitiatingProcessAccountDomain": org.netbios,
        "InitiatingProcessAccountName": user.sam,
        "InitiatingProcessAccountSid": user.sid,
        "InitiatingProcessAccountUpn": user.upn,
        "InitiatingProcessAccountObjectId": user.object_id,
        "InitiatingProcessSHA1": sha1,
        "InitiatingProcessSHA256": sha256,
        "InitiatingProcessMD5": md5,
        "InitiatingProcessFileName": process,
        "InitiatingProcessFolderPath": f"{folder_for(process)}\\{process}",
        "InitiatingProcessId": ctx.rng.randint(600, 32000),
        "InitiatingProcessCommandLine": process,
        "InitiatingProcessCreationTime": ts - timedelta(minutes=ctx.rng.randint(1, 400)),
        "InitiatingProcessParentFileName": "explorer.exe",
        "InitiatingProcessIntegrityLevel": "Medium",
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Servers" if device.is_server else "Corporate",
    })
    row.update(overrides)
    row["__table"] = "DeviceNetworkEvents"
    return row


def device_file_event(
    ctx: GenContext, device: Device, user: User, ts: datetime, *,
    filename: str, folder: str, action: str = "FileCreated",
    process: str = "explorer.exe", size: int | None = None, **overrides: Any,
) -> dict:
    org = ctx.org
    sha1, sha256, md5 = file_hashes(ctx.rng, filename)
    row = ctx.platform("DeviceFileEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": action,
        "FileName": filename,
        "FolderPath": folder,
        "SHA1": sha1, "SHA256": sha256, "MD5": md5,
        "FileSize": size if size is not None else ctx.rng.randint(1024, 8_000_000),
        "InitiatingProcessAccountDomain": org.netbios,
        "InitiatingProcessAccountName": user.sam,
        "InitiatingProcessAccountSid": user.sid,
        "InitiatingProcessAccountUpn": user.upn,
        "InitiatingProcessFileName": process,
        "InitiatingProcessFolderPath": f"{folder_for(process)}\\{process}",
        "InitiatingProcessId": ctx.rng.randint(600, 32000),
        "InitiatingProcessCommandLine": process,
        "InitiatingProcessIntegrityLevel": "Medium",
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Servers" if device.is_server else "Corporate",
    })
    row.update(overrides)
    row["__table"] = "DeviceFileEvents"
    return row


def device_registry_event(
    ctx: GenContext, device: Device, user: User, ts: datetime, *,
    key: str, value_name: str, value_data: str,
    action: str = "RegistryValueSet", process: str = "reg.exe",
    integrity: str = "Medium", **overrides: Any,
) -> dict:
    org = ctx.org
    row = ctx.platform("DeviceRegistryEvents", ts)
    row.update({
        "DeviceId": device.device_id,
        "DeviceName": f"{device.name.lower()}.{org.domain}",
        "ActionType": action,
        "RegistryKey": key,
        "RegistryValueType": "String",
        "RegistryValueName": value_name,
        "RegistryValueData": value_data,
        "InitiatingProcessAccountDomain": org.netbios,
        "InitiatingProcessAccountName": user.sam,
        "InitiatingProcessAccountSid": user.sid,
        "InitiatingProcessFileName": process,
        "InitiatingProcessId": ctx.rng.randint(600, 32000),
        "InitiatingProcessIntegrityLevel": integrity,
        "ReportId": str(ctx.rng.randint(1, 999999)),
        "MachineGroup": "Servers" if device.is_server else "Corporate",
    })
    row.update(overrides)
    row["__table"] = "DeviceRegistryEvents"
    return row


def dns_event(
    ctx: GenContext, device: Device, ts: datetime, *,
    name: str, query_type: str = "A", result_code: int = 0,
    answers: str = "", **overrides: Any,
) -> dict:
    org = ctx.org
    dc = org.domain_controllers[0] if org.domain_controllers else org.servers[0]
    row = ctx.platform("DnsEvents", ts)
    row.update({
        "Computer": f"{dc.name.lower()}.{org.domain}",
        "SubType": "LookupQuery",
        "ClientIP": device.ip,
        "Name": name,
        "QueryType": query_type,
        "ResultCode": result_code,
        "Result": "NXDOMAIN" if result_code == 3 else "Success",
        "IPAddresses": answers,
        "EventOriginalType": "256",
        "Port": 53,
        "Protocol": "UDP",
        "TransactionID": ctx.rng.randint(1, 65535),
    })
    row.update(overrides)
    row["__table"] = "DnsEvents"
    return row


def firewall_event(
    ctx: GenContext, ts: datetime, *,
    src_ip: str, dst_ip: str, dst_port: int = 443,
    action: str = "allow", direction: str = "Outbound",
    app: str = "ssl", sent: int = 0, received: int = 0,
    src_host: str = "", **overrides: Any,
) -> dict:
    net = ctx.org.network
    row = ctx.platform("CommonSecurityLog", ts)
    row.update({
        "DeviceVendor": net.firewall_vendor,
        "DeviceProduct": net.firewall_product,
        "DeviceVersion": "11.1.2",
        "DeviceEventClassID": "traffic",
        "Activity": "TRAFFIC",
        "LogSeverity": "3" if action == "allow" else "5",
        "DeviceName": net.firewall_name,
        "DeviceAction": action,
        "SimplifiedDeviceAction": action.capitalize(),
        "CommunicationDirection": direction,
        "SourceIP": src_ip,
        "SourcePort": ctx.rng.randint(1024, 65535),
        "SourceHostName": src_host,
        "DestinationIP": dst_ip,
        "DestinationPort": dst_port,
        "DestinationTranslatedAddress": (ctx.rng.choice(net.egress_ips)
                                         if direction == "Outbound" else ""),
        "Protocol": "TCP" if dst_port != 53 else "UDP",
        "ApplicationProtocol": app,
        "SentBytes": sent or ctx.rng.randint(200, 400_000),
        "ReceivedBytes": received or (ctx.rng.randint(200, 3_000_000)
                                      if action == "allow" else 0),
        "DeviceInboundInterface": "ethernet1/2" if direction == "Outbound" else "ethernet1/1",
        "DeviceOutboundInterface": "ethernet1/1" if direction == "Outbound" else "ethernet1/2",
        "ExternalID": str(ctx.rng.randint(100000, 999999)),
        "Computer": net.firewall_name,
        "DeviceCustomString1": ("trust-to-untrust" if direction == "Outbound"
                                else "untrust-to-trust"),
        "DeviceCustomString1Label": "Rule",
        "DeviceCustomString2": app,
        "DeviceCustomString2Label": "Application",
    })
    row.update(overrides)
    row["__table"] = "CommonSecurityLog"
    return row
