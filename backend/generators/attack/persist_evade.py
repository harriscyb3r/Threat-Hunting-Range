"""Persistence, privilege escalation and defence-evasion emitters."""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, loud_scale, register


# ── T1543.003 Windows service ────────────────────────────────────────────

SERVICE_VARIANTS = [
    Variant("sc_create", "sc.exe create",
            "sc.exe create with binPath, then a 7045 service-install event",
            "", weight=1.0),
    Variant("powershell_service", "New-Service",
            "No sc.exe: the service is created from PowerShell",
            "defeats sc.exe detection", weight=0.9),
    Variant("service_hijack", "Repoint an existing service binary",
            "Registry write to an existing service's ImagePath, no 7045",
            "defeats 7045-based detection", weight=0.8),
]


@register("T1543.003", SERVICE_VARIANTS,
          tables=("SecurityEvent", "DeviceProcessEvents", "DeviceRegistryEvents"))
def windows_service(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    svc = rng.choice(["WinDefendUpdate", "NetSvcHost", "TelemetrySync", "SysMonitor"])
    binpath = rf"{intr.staging_dir}\{intr.payload_name}"

    if plan.variant == "sc_create":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "sc.exe",
            f'sc.exe create {svc} binPath= "{binpath}" start= auto',
            parent="cmd.exe", integrity="High"), "sc create")
        yield from ctx.mark(rows.security_logon(
            ctx.gen, host, user, ts + timedelta(seconds=2), logon_type=5,
            EventID=7045, Activity="7045 - A service was installed in the system.",
            ServiceName=svc, ServiceFileName=binpath, ServiceType="user mode service",
            ServiceStartType="auto start", ServiceAccount="LocalSystem"), "service installed")
    elif plan.variant == "powershell_service":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            f'powershell.exe -Command New-Service -Name {svc} -BinaryPathName "{binpath}" '
            f"-StartupType Automatic", parent="cmd.exe", integrity="High"),
            "New-Service")
        yield from ctx.mark(rows.security_logon(
            ctx.gen, host, user, ts + timedelta(seconds=2), logon_type=5,
            EventID=7045, Activity="7045 - A service was installed in the system.",
            ServiceName=svc, ServiceFileName=binpath, ServiceType="user mode service",
            ServiceStartType="auto start", ServiceAccount="LocalSystem"), "service installed")
    else:
        existing = rng.choice(["Spooler", "BITS", "Winmgmt", "Schedule"])
        yield from ctx.mark(rows.device_registry_event(
            ctx.gen, host, user, ts,
            key=rf"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{existing}",
            value_name="ImagePath", value_data=binpath,
            process="reg.exe", integrity="System"), "service binary repointed")


# ── T1547.001 Registry run key ───────────────────────────────────────────

RUNKEY_VARIANTS = [
    Variant("hkcu_run", "HKCU Run key",
            "reg.exe adding a value under HKCU...\\Run",
            "", weight=1.0),
    Variant("hklm_run", "HKLM Run key (requires admin)",
            "Machine-wide Run key, needs elevation",
            "", weight=0.9),
    Variant("startup_folder", "Startup-folder shortcut",
            "A .lnk written to the Startup folder - no registry event at all",
            "defeats Run-key registry detection", weight=0.8),
]


@register("T1547.001", RUNKEY_VARIANTS,
          tables=("DeviceRegistryEvents", "DeviceProcessEvents", "DeviceFileEvents"))
def run_key(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    name = rng.choice(["OneDriveSync", "SecurityHealth", "EdgeUpdate", "AdobeAAMUpdater"])
    payload = rf"{intr.staging_dir}\{intr.payload_name}"

    if plan.variant == "startup_folder":
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ts, filename=f"{name}.lnk",
            folder=rf"C:\Users\{user.sam}\AppData\Roaming\Microsoft\Windows"
                   rf"\Start Menu\Programs\Startup\{name}.lnk",
            action="FileCreated", process="cmd.exe"), "startup-folder persistence")
        return

    hive = "HKEY_CURRENT_USER" if plan.variant == "hkcu_run" else "HKEY_LOCAL_MACHINE"
    integrity = "Medium" if plan.variant == "hkcu_run" else "High"
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, "reg.exe",
        rf'reg.exe add "{hive}\Software\Microsoft\Windows\CurrentVersion\Run" '
        rf'/v {name} /t REG_SZ /d "{payload}" /f',
        parent="cmd.exe", integrity=integrity), "run key added")
    yield from ctx.mark(rows.device_registry_event(
        ctx.gen, host, user, ts + timedelta(seconds=1),
        key=rf"{hive}\Software\Microsoft\Windows\CurrentVersion\Run",
        value_name=name, value_data=payload, process="reg.exe",
        integrity=integrity), "run key value set")


# ── T1136.001 Create local account ───────────────────────────────────────

ACCOUNT_VARIANTS = [
    Variant("net_user", "net user /add then net localgroup",
            "net.exe adding a user, then adding it to Administrators; 4720 + 4732",
            "", weight=1.0),
    Variant("powershell_account", "New-LocalUser",
            "PowerShell cmdlets, no net.exe",
            "defeats net.exe detection", weight=0.9),
    Variant("hidden_account", "Account name ending in $",
            "Account name ends with $ so it hides from 'net user'",
            "defeats enumeration; still visible in 4720", weight=0.8),
]


@register("T1136.001", ACCOUNT_VARIANTS,
          tables=("SecurityEvent", "DeviceProcessEvents"))
def create_account(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    acct = rng.choice(["helpdesk", "svc_backup2", "adminsvc", "support"])
    if plan.variant == "hidden_account":
        acct += "$"

    if plan.variant == "powershell_account":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            f'powershell.exe -Command "New-LocalUser -Name {acct} -Password '
            f"(ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force); "
            f'Add-LocalGroupMember -Group Administrators -Member {acct}"',
            parent="cmd.exe", integrity="High"), "local admin created via PowerShell")
    else:
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "net.exe",
            f"net user {acct} P@ssw0rd! /add", parent="cmd.exe",
            integrity="High"), "net user /add")
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(seconds=4), "net.exe",
            f"net localgroup Administrators {acct} /add", parent="cmd.exe",
            integrity="High"), "added to Administrators")

    # 4720 fires regardless of tooling — the durable signal.
    yield from ctx.mark(rows.security_logon(
        ctx.gen, host, user, ts + timedelta(seconds=1), logon_type=5,
        EventID=4720, Activity="4720 - A user account was created.",
        TargetUserName=acct, TargetDomainName=host.name,
        SubjectUserName=user.sam, SubjectDomainName=org.netbios), "4720 account created")


# ── T1098.001 Add cloud credentials ──────────────────────────────────────

APP_CRED_VARIANTS = [
    Variant("add_secret", "Add a client secret to an app",
            "AuditLogs 'Update application - Certificates and secrets management'",
            "", weight=1.0),
    Variant("add_certificate", "Add a certificate to a service principal",
            "AuditLogs 'Add service principal credentials' with a KeyType of AsymmetricX509Cert",
            "", weight=0.9),
    Variant("consent_then_use", "Add secret then authenticate as the SP",
            "The AuditLogs change, then an AADServicePrincipalSignInLogs sign-in from a new IP",
            "the sign-in is the confirmation a change-only query misses", weight=0.9),
]


@register("T1098.001", APP_CRED_VARIANTS,
          tables=("AuditLogs", "AADServicePrincipalSignInLogs"))
def add_cloud_credentials(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    actor = intr.stolen_creds[-1] if intr.stolen_creds else intr.victim
    sp = rng.choice(org.service_principals)
    ts = plan.start

    is_cert = plan.variant == "add_certificate"
    row = ctx.gen.platform("AuditLogs", ts)
    row.update({
        "OperationName": ("Add service principal credentials" if is_cert
                          else "Update application - Certificates and secrets management"),
        "OperationVersion": "1.0",
        "Category": "ApplicationManagement",
        "ResultType": "success",
        "ResultDescription": "",
        "ResultReason": "",
        "CorrelationId": ctx.gen.item_id(),
        "Level": "4",
        "DurationMs": 0,
        "Identity": actor.display_name,
        "ActivityDisplayName": ("Add service principal credentials" if is_cert
                                else "Update application - Certificates and secrets management"),
        "ActivityDateTime": ts,
        "LoggedByService": "Core Directory",
        "AADOperationType": "Update",
        "InitiatedBy": {"user": {"id": actor.object_id, "displayName": actor.display_name,
                                 "userPrincipalName": actor.upn, "ipAddress": intr.c2_ip}},
        "TargetResources": [{
            "id": sp.object_id, "displayName": sp.display_name,
            "type": "ServicePrincipal",
            "modifiedProperties": [{
                "displayName": "KeyDescription",
                "newValue": f'["[KeyType=AsymmetricX509Cert' if is_cert
                            else '["[KeyType=Password',
            }],
        }],
        "AdditionalDetails": [],
    })
    row["__table"] = "AuditLogs"
    yield from ctx.mark(row, "credential added to application")

    if plan.variant == "consent_then_use":
        later = ts + timedelta(hours=rng.randint(1, 6))
        sp_row = ctx.gen.platform("AADServicePrincipalSignInLogs", later)
        sp_row.update({
            "OperationName": "Sign-in activity",
            "Category": "ServicePrincipalSignInLogs",
            "ResultType": "0",
            "ResultDescription": "",
            "CorrelationId": ctx.gen.item_id(),
            "Identity": sp.display_name,
            "Location": "DE",
            "AppId": sp.app_id,
            "IPAddress": intr.c2_ip,
            "ResourceDisplayName": "Microsoft Graph",
            "ServicePrincipalId": sp.object_id,
            "ServicePrincipalName": sp.display_name,
            "ServicePrincipalCredentialKeyId": ctx.gen.item_id(),
            "ConditionalAccessStatus": "notApplied",
            "LocationDetails": {"city": "Frankfurt", "countryOrRegion": "DE"},
            "Status": {"errorCode": 0},
            "UniqueTokenIdentifier": ctx.gen.item_id(),
        })
        sp_row["__table"] = "AADServicePrincipalSignInLogs"
        yield from ctx.mark(sp_row, "authenticated as the service principal from a new IP")


# ── T1562.001 Impair defenses ────────────────────────────────────────────

IMPAIR_VARIANTS = [
    Variant("set_mppreference", "Set-MpPreference exclusions",
            "PowerShell adding a Defender exclusion path or disabling real-time monitoring",
            "", weight=1.0),
    Variant("stop_service", "Stop and disable the Defender service",
            "sc.exe stop/config WinDefend, or net stop",
            "", weight=0.9),
    Variant("registry_disable", "Disable via registry",
            "DisableAntiSpyware / DisableRealtimeMonitoring registry writes",
            "defeats Set-MpPreference detection", weight=0.9),
]


@register("T1562.001", IMPAIR_VARIANTS,
          tables=("DeviceProcessEvents", "DeviceRegistryEvents", "SecurityEvent"))
def impair_defenses(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "set_mppreference":
        for cmd in [
            "powershell.exe -Command Set-MpPreference -DisableRealtimeMonitoring $true",
            f"powershell.exe -Command Add-MpPreference -ExclusionPath '{intr.staging_dir}'",
        ]:
            ts += timedelta(seconds=ctx.rng.randint(3, 30))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, "powershell.exe", cmd,
                parent="cmd.exe", integrity="High"), "Defender weakened")
    elif plan.variant == "stop_service":
        for cmd in ["sc.exe stop WinDefend", "sc.exe config WinDefend start= disabled"]:
            ts += timedelta(seconds=ctx.rng.randint(3, 30))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, "sc.exe", cmd,
                parent="cmd.exe", integrity="High"), "Defender service stopped")
    else:
        yield from ctx.mark(rows.device_registry_event(
            ctx.gen, host, user, ts,
            key=r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender",
            value_name="DisableAntiSpyware", value_data="1",
            process="reg.exe", integrity="System"), "Defender disabled via registry")


# ── T1070.001 Clear event logs ───────────────────────────────────────────

CLEARLOG_VARIANTS = [
    Variant("wevtutil", "wevtutil cl",
            "wevtutil.exe clearing Security/System, plus a 1102 audit-cleared event",
            "", weight=1.0),
    Variant("powershell_clear", "Clear-EventLog",
            "PowerShell clearing logs, still produces 1102",
            "defeats wevtutil.exe detection", weight=0.9),
    Variant("selective", "Clear only the Security log",
            "A single 1102 with no accompanying process - cleared via API",
            "defeats process-based detection; 1102 is the only trace", weight=0.8),
]


@register("T1070.001", CLEARLOG_VARIANTS,
          tables=("SecurityEvent", "DeviceProcessEvents"))
def clear_logs(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "wevtutil":
        for log in ["Security", "System"]:
            ts += timedelta(seconds=ctx.rng.randint(2, 20))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, "wevtutil.exe", f"wevtutil.exe cl {log}",
                parent="cmd.exe", integrity="High"), f"{log} log cleared")
    elif plan.variant == "powershell_clear":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            'powershell.exe -Command "Clear-EventLog -LogName Security,System"',
            parent="cmd.exe", integrity="High"), "logs cleared via PowerShell")

    # 1102 is emitted no matter how the clear was performed.
    yield from ctx.mark(rows.security_logon(
        ctx.gen, host, user, ts + timedelta(seconds=1), logon_type=5,
        EventID=1102, Activity="1102 - The audit log was cleared.",
        Channel="Security", SubjectUserName=user.sam,
        SubjectDomainName=ctx.org.netbios), "1102 audit log cleared")


# ── T1546.003 WMI event subscription persistence ─────────────────────────
#
# The third reading of "WMI abuse": a permanent WMI event filter+consumer
# binding that survives reboots and runs the payload with no scheduled task,
# service or run key to find.

WMI_PERSIST_VARIANTS = [
    Variant("powershell_binding", "Register-WmiEvent / mof via PowerShell",
            "powershell.exe creating __EventFilter and CommandLineEventConsumer",
            "", weight=1.0),
    Variant("wmic_mof", "wmic + .mof compile",
            "mofcomp.exe compiling a .mof that registers the binding",
            "defeats PowerShell-based detection", weight=0.9),
    Variant("registry_only", "Direct registry write",
            "The subscription written straight into the WMI repository - subtlest of the three",
            "defeats process-based detection; only the registry write remains", weight=0.7),
]


@register("T1546.003", WMI_PERSIST_VARIANTS,
          tables=("DeviceProcessEvents", "DeviceRegistryEvents"))
def wmi_persistence(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    payload = rf"{intr.staging_dir}\{intr.payload_name}"

    if plan.variant == "powershell_binding":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            r'powershell.exe -NoProfile -Command "$f=Set-WmiInstance -Namespace root\subscription '
            r"-Class __EventFilter -Arguments @{Name='Updater';EventNamespace='root\cimv2';"
            r"QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 "
            r'WHERE TargetInstance ISA \"Win32_PerfFormattedData_PerfOS_System\"' + "'}; "
            r"$c=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer "
            f"-Arguments @{{Name='Updater';CommandLineTemplate='{payload}'}}\"",
            parent="cmd.exe", integrity="High"), "WMI event subscription created")
    elif plan.variant == "wmic_mof":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "mofcomp.exe",
            rf"mofcomp.exe {intr.staging_dir}\evil.mof",
            parent="cmd.exe", integrity="High"), "malicious MOF compiled")

    # The binding also lands as a registry write under the WMI repository.
    yield from ctx.mark(rows.device_registry_event(
        ctx.gen, host, user, ts + timedelta(seconds=2),
        key=r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WBEM\CIMOM"
            r"\List of event-active namespaces",
        value_name=r"root\subscription", value_data=payload,
        process="svchost.exe", integrity="System"), "WMI subscription persisted in registry")


# ── T1489 Service stop ───────────────────────────────────────────────────

SERVICE_STOP_VARIANTS = [
    Variant("net_stop", "net stop / sc stop",
            "net.exe or sc.exe stopping database and backup services before impact",
            "", weight=1.0),
    Variant("taskkill", "taskkill by image name",
            "taskkill /f /im against sqlserver.exe, veeam, etc.",
            "defeats service-control detection", weight=0.9),
    Variant("powershell_stop", "Stop-Service loop",
            "PowerShell stopping a list of services",
            "", weight=0.8),
]


@register("T1489", SERVICE_STOP_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent"))
def service_stop(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    services = ["MSSQLSERVER", "SQLSERVERAGENT", "VeeamBackupSvc", "Veeam.Backup.Service",
                "MSExchangeIS", "BackupExecAgentAccelerator"]
    targets = services[:loud_scale(plan.loudness, 2, len(services))]

    for svc in targets:
        ts += timedelta(seconds=rng.randint(2, 20))
        if plan.variant == "net_stop":
            img, cmd = "net.exe", f"net stop {svc} /y"
        elif plan.variant == "taskkill":
            img, cmd = "taskkill.exe", f"taskkill /f /im {svc.lower()}.exe"
        else:
            img, cmd = "powershell.exe", f"powershell.exe -Command Stop-Service -Name {svc} -Force"
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, img, cmd, parent="cmd.exe",
            integrity="High"), f"stopped {svc}")
