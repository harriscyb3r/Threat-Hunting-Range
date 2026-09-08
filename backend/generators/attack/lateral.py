"""Lateral movement and remote-execution emitters."""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, dwell, loud_scale, register

# ── T1550.002 Pass the Hash ──────────────────────────────────────────────
#
# The tell is NTLM where Kerberos is expected: logon type 3 with
# AuthenticationPackageName NTLM, LogonProcessName NtLmSsp, from a workstation
# rather than a server. The variants change how visible that is.

PTH_VARIANTS = [
    Variant("sekurlsa_pth", "Mimikatz sekurlsa::pth",
            "NTLM network logons from the beachhead, logon process NtLmSsp, "
            "and a 4624 with logon type 9 (NewCredentials) on the source host",
            "", weight=1.0),
    Variant("smbexec", "Impacket smbexec / psexec with a hash",
            "NTLM logon plus a service install (7045) on each target",
            "", weight=1.0),
    Variant("single_hop", "One hop only",
            "A single NTLM authentication to one server",
            "defeats 'account authenticating to many hosts' queries", weight=0.9),
    Variant("overpass", "Overpass-the-hash to Kerberos",
            "Hash converted to a TGT: 4768 from an odd host, then Kerberos logons - "
            "no NTLM anywhere",
            'defeats AuthenticationPackageName == "NTLM"', weight=0.9),
]


@register("T1550.002", PTH_VARIANTS,
          tables=("SecurityEvent", "DeviceLogonEvents", "DeviceProcessEvents"))
def pass_the_hash(ctx: EmitContext) -> Iterator[dict]:
    org, rng, plan = ctx.org, ctx.rng, ctx.plan
    intr = ctx.intrusion
    source = intr.current_host()
    # Whose hash: an admin if one has been stolen, else the victim's.
    identity = intr.admin_creds or intr.current_user()
    ts = plan.start

    n_hops = 1 if plan.variant == "single_hop" else loud_scale(plan.loudness, 2, 7)
    targets = [intr.pick_target(servers=True) for _ in range(n_hops)]

    if plan.variant in ("sekurlsa_pth", "overpass"):
        cmd = (rf'{intr.staging_dir}\mimikatz.exe "sekurlsa::pth /user:{identity.sam} '
               rf'/domain:{org.domain} /ntlm:{"a" * 32} /run:cmd.exe" "exit"')
        if plan.variant == "overpass":
            cmd = (rf'{intr.staging_dir}\Rubeus.exe asktgt /user:{identity.sam} '
                   rf'/rc4:{"b" * 32} /ptt')
        yield from ctx.mark(rows.execution(
            ctx.gen, source, identity, ts,
            "mimikatz.exe" if plan.variant == "sekurlsa_pth" else "Rubeus.exe",
            cmd, parent="cmd.exe", integrity="High"), "hash injected into a logon session")

        # Logon type 9 on the *source* host: a new set of credentials attached
        # to the current session. Quiet, local, and the strongest single tell.
        yield from ctx.mark(rows.security_logon(
            ctx.gen, source, identity, ts + timedelta(seconds=2),
            logon_type=9, auth_package="Negotiate", logon_process="Advapi  ",
            src_ip="-", workstation=source.name), "NewCredentials logon on the source host")

    for i, target in enumerate(targets):
        ts += dwell(rng, plan.loudness)
        if plan.variant == "overpass":
            # Kerberos, not NTLM — a TGT request from a host that has no
            # business asking for one on this account's behalf.
            dc = org.domain_controllers[0] if org.domain_controllers else org.servers[0]
            yield from ctx.mark(rows.security_kerberos(
                ctx.gen, dc, identity, ts, event_id=4768, spn="krbtgt",
                encryption="0x17", src_ip=source.ip), "TGT from the hash (overpass)")
            yield from ctx.mark(rows.security_logon(
                ctx.gen, target, identity, ts + timedelta(seconds=4),
                logon_type=3, auth_package="Kerberos", logon_process="Kerberos",
                src_ip=source.ip, workstation=source.name), f"Kerberos hop {i + 1}")
        else:
            yield from ctx.mark(rows.security_logon(
                ctx.gen, target, identity, ts,
                logon_type=3, auth_package="NTLM", logon_process="NtLmSsp ",
                src_ip=source.ip, workstation=source.name), f"NTLM hop {i + 1}")

        yield from ctx.mark(rows.device_logon_event(
            ctx.gen, target, identity, ts + timedelta(seconds=1),
            logon_type="Network",
            protocol="Kerberos" if plan.variant == "overpass" else "NTLM",
            remote_ip=source.ip, remote_device=source.name), f"hop {i + 1}")

        if plan.variant == "smbexec":
            svc = f"BTOBTO{rng.randint(1000, 9999)}"
            yield from ctx.mark(rows.security_logon(
                ctx.gen, target, identity, ts + timedelta(seconds=3),
                logon_type=3, auth_package="NTLM", logon_process="NtLmSsp ",
                src_ip=source.ip, workstation=source.name,
                EventID=7045, Activity="7045 - A service was installed in the system.",
                ServiceName=svc,
                ServiceFileName=r"%COMSPEC% /Q /c echo cd ^> \\127.0.0.1\ADMIN$\__out 2^>^&1 "
                                r"> %TEMP%\execute.bat & %COMSPEC% /Q /c %TEMP%\execute.bat",
                ServiceType="user mode service", ServiceStartType="demand start",
                ServiceAccount="LocalSystem"), "smbexec service install")

        intr.reach(target)


# ── T1021.006 WinRM / remote WMI ─────────────────────────────────────────
#
# One of the three techniques "WMI abuse" can mean. This is the lateral-movement
# reading: execution against a *remote* host over WinRM or DCOM.

WINRM_VARIANTS = [
    Variant("invoke_command", "PowerShell Invoke-Command over WinRM",
            "wsmprovhost.exe spawned on the target, port 5985 connection from the source",
            "", weight=1.0),
    Variant("wmic_node", "wmic /node process call create",
            "WmiPrvSE.exe as parent of the payload on the target",
            "", weight=1.0),
    Variant("winrs", "winrs -r:host cmd",
            "Same WinRM channel, different client binary",
            "defeats detections keyed on powershell.exe", weight=0.8),
    Variant("dcom", "DCOM MMC20.Application",
            "mmc.exe spawning the payload, no WinRM port involved at all",
            "defeats port-5985 based detection", weight=0.8),
]


@register("T1021.006", WINRM_VARIANTS,
          tables=("DeviceProcessEvents", "DeviceNetworkEvents",
                  "SecurityEvent", "DeviceLogonEvents"))
def winrm_lateral(ctx: EmitContext) -> Iterator[dict]:
    org, rng, plan = ctx.org, ctx.rng, ctx.plan
    intr = ctx.intrusion
    source = intr.current_host()
    user = intr.current_user()
    ts = plan.start
    n = loud_scale(plan.loudness, 1, 5)
    payload = r"cmd.exe /c whoami & hostname & net group ""Domain Admins"" /domain"

    for i in range(n):
        target = intr.pick_target(servers=True)
        ts += dwell(rng, plan.loudness)

        # Client side.
        if plan.variant == "invoke_command":
            client_cmd = (f"powershell.exe -NoProfile -Command Invoke-Command "
                          f"-ComputerName {target.name} -ScriptBlock {{{payload}}}")
            client_img = "powershell.exe"
        elif plan.variant == "wmic_node":
            client_cmd = (f'wmic /node:{target.name} /user:{org.netbios}\\{user.sam} '
                          f'process call create "{payload}"')
            client_img = "wmic.exe"
        elif plan.variant == "winrs":
            client_cmd = f'winrs -r:{target.name} "{payload}"'
            client_img = "winrs.exe"
        else:
            client_cmd = ("powershell.exe -NoProfile -Command "
                          f"$c=[activator]::CreateInstance([type]::GetTypeFromProgID("
                          f"'MMC20.Application','{target.name}')); "
                          f"$c.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,"
                          f"'/c {payload}','7')")
            client_img = "powershell.exe"

        yield from ctx.mark(rows.execution(
            ctx.gen, source, user, ts, client_img, client_cmd,
            parent="cmd.exe"), f"remote execution client -> {target.name}")

        # Network leg. DCOM does not use 5985 — that is the point of the variant.
        port = 135 if plan.variant == "dcom" else 5985
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, source, user, ts + timedelta(seconds=1),
            remote_ip=target.ip, remote_port=port, remote_url=target.name,
            process=client_img), f"{'DCOM' if port == 135 else 'WinRM'} connection")

        # Server side: the parent process is the giveaway.
        parent = {"invoke_command": "wsmprovhost.exe", "winrs": "wsmprovhost.exe",
                  "wmic_node": "WmiPrvSE.exe", "dcom": "mmc.exe"}[plan.variant]
        yield from ctx.mark(rows.execution(
            ctx.gen, target, user, ts + timedelta(seconds=3), "cmd.exe", payload,
            parent=parent, integrity="High"), f"payload on {target.name}")

        yield from ctx.mark(rows.security_logon(
            ctx.gen, target, user, ts + timedelta(seconds=2),
            logon_type=3, auth_package="Kerberos", logon_process="Kerberos",
            src_ip=source.ip, workstation=source.name), "remote logon")

        intr.reach(target)


# ── T1021.002 SMB / admin shares ─────────────────────────────────────────

SMB_VARIANTS = [
    Variant("psexec", "PsExec to ADMIN$",
            "File written to ADMIN$, service install (7045), NTLM network logon",
            "", weight=1.0),
    Variant("copy_sc", "copy to C$ then sc create",
            "Two separate steps: file copy, then remote service creation",
            "defeats single-binary detections", weight=0.9),
    Variant("share_recon_only", "Share enumeration without execution",
            "5140 share access with no follow-on execution",
            "looks like an admin browsing shares", weight=0.7),
]


@register("T1021.002", SMB_VARIANTS,
          tables=("SecurityEvent", "DeviceFileEvents", "DeviceLogonEvents"))
def smb_lateral(ctx: EmitContext) -> Iterator[dict]:
    org, rng, plan = ctx.org, ctx.rng, ctx.plan
    intr = ctx.intrusion
    source = intr.current_host()
    user = intr.admin_creds or intr.current_user()
    ts = plan.start
    n = loud_scale(plan.loudness, 1, 5)

    for i in range(n):
        target = intr.pick_target(servers=True)
        ts += dwell(rng, plan.loudness)

        yield from ctx.mark(rows.security_logon(
            ctx.gen, target, user, ts, logon_type=3,
            auth_package="NTLM", logon_process="NtLmSsp ",
            src_ip=source.ip, workstation=source.name), f"SMB logon to {target.name}")

        # 5140: a network share was accessed.
        yield from ctx.mark(rows.security_logon(
            ctx.gen, target, user, ts + timedelta(seconds=1),
            logon_type=3, src_ip=source.ip, workstation=source.name,
            EventID=5140, Activity="5140 - A network share object was accessed.",
            ShareName=r"\\*\ADMIN$", ShareLocalPath=r"\??\C:\Windows",
            AccessMask="0x1"), "ADMIN$ accessed")

        if plan.variant == "share_recon_only":
            intr.reach(target)
            continue

        yield from ctx.mark(rows.device_file_event(
            ctx.gen, target, user, ts + timedelta(seconds=4),
            filename=intr.payload_name,
            folder=rf"C:\Windows\{intr.payload_name}",
            action="FileCreated", process="System",
            ShareName="ADMIN$", RequestAccountName=user.sam,
            RequestAccountDomain=org.netbios,
            RequestAccountSid=user.sid), "payload written to ADMIN$")

        svc = "PSEXESVC" if plan.variant == "psexec" else f"SysUpdate{rng.randint(10, 99)}"
        yield from ctx.mark(rows.security_logon(
            ctx.gen, target, user, ts + timedelta(seconds=6),
            logon_type=3, src_ip=source.ip, workstation=source.name,
            EventID=7045, Activity="7045 - A service was installed in the system.",
            ServiceName=svc, ServiceFileName=rf"%SystemRoot%\{intr.payload_name}",
            ServiceType="user mode service", ServiceStartType="demand start",
            ServiceAccount="LocalSystem"), f"{svc} service installed")

        intr.reach(target)


# ── T1021.001 RDP ────────────────────────────────────────────────────────

RDP_VARIANTS = [
    Variant("interactive", "Interactive RDP session",
            "Logon type 10 from an internal host, outside business hours",
            "", weight=1.0),
    Variant("hijack", "RDP session hijack via tscon",
            "tscon.exe run as SYSTEM to attach to another user's session - no logon event",
            "defeats logon-type-10 detection entirely", weight=0.8),
    Variant("chained", "RDP chained through a jump host",
            "Two hops: workstation -> jump host -> server",
            "defeats single-hop analysis", weight=0.9),
]


@register("T1021.001", RDP_VARIANTS,
          tables=("SecurityEvent", "DeviceLogonEvents", "DeviceNetworkEvents"))
def rdp_lateral(ctx: EmitContext) -> Iterator[dict]:
    org, rng, plan = ctx.org, ctx.rng, ctx.plan
    intr = ctx.intrusion
    user = intr.admin_creds or intr.current_user()
    source = intr.current_host()
    ts = plan.start

    hops = [intr.pick_target(servers=True)]
    if plan.variant == "chained":
        jump = next((d for d in org.devices_by_role("jump")), None)
        if jump:
            hops.insert(0, jump)

    for target in hops:
        ts += dwell(rng, plan.loudness)
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, source, user, ts, remote_ip=target.ip, remote_port=3389,
            remote_url=target.name, process="mstsc.exe"), "RDP connection")
        yield from ctx.mark(rows.security_logon(
            ctx.gen, target, user, ts + timedelta(seconds=3), logon_type=10,
            auth_package="Negotiate", logon_process="User32 ",
            src_ip=source.ip, workstation=source.name), "RDP logon")
        yield from ctx.mark(rows.device_logon_event(
            ctx.gen, target, user, ts + timedelta(seconds=3),
            logon_type="RemoteInteractive", remote_ip=source.ip,
            remote_device=source.name), "RDP logon")
        intr.reach(target)
        source = target

    if plan.variant == "hijack":
        # No logon event at all: tscon as SYSTEM attaches to an existing session.
        target = hops[-1]
        yield from ctx.mark(rows.execution(
            ctx.gen, target, user, ts + timedelta(minutes=rng.randint(2, 20)),
            "tscon.exe", f"tscon.exe {rng.randint(2, 6)} /dest:rdp-tcp#{rng.randint(1, 9)}",
            parent="cmd.exe", integrity="System"), "session hijack, no logon generated")
