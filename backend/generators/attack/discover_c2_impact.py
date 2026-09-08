"""Discovery, C2, exfiltration and impact emitters."""
from __future__ import annotations

import base64
from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, loud_scale, register


# ── T1087.002 Domain account discovery ───────────────────────────────────

DISCOVERY_VARIANTS = [
    Variant("net_commands", "net user/group /domain",
            "A cluster of net.exe and nltest.exe discovery commands close together",
            "", weight=1.0),
    Variant("powershell_ad", "PowerShell AD cmdlets",
            "Get-ADUser / Get-ADGroupMember - collides with the benign inventory tool",
            "collides with the scheduled asset-inventory job", weight=1.0),
    Variant("ldap_query", "Direct LDAP queries",
            "A single process making many LDAP queries; no net.exe at all",
            "defeats net.exe detection", weight=0.8),
]


@register("T1087.002", DISCOVERY_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent"))
def account_discovery(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "net_commands":
        cmds = [("net.exe", "net user /domain"),
                ("net.exe", 'net group "Domain Admins" /domain'),
                ("net.exe", 'net group "Enterprise Admins" /domain'),
                ("nltest.exe", f"nltest /dclist:{org.netbios.lower()}"),
                ("whoami.exe", "whoami /groups")]
    elif plan.variant == "powershell_ad":
        cmds = [("powershell.exe",
                 'powershell.exe -Command "Get-ADUser -Filter * -Properties LastLogonDate"'),
                ("powershell.exe",
                 'powershell.exe -Command "Get-ADGroupMember -Identity \'Domain Admins\'"'),
                ("powershell.exe",
                 'powershell.exe -Command "Get-ADComputer -Filter * -Properties OperatingSystem"')]
    else:
        cmds = [("powershell.exe",
                 'powershell.exe -Command "([adsisearcher]\'(objectClass=user)\').FindAll()"')]

    for img, cmd in cmds[:loud_scale(plan.loudness, 2, len(cmds))]:
        ts += timedelta(seconds=rng.randint(2, 40))
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, img, cmd, parent="cmd.exe"), "domain discovery")


# ── T1046 Network service discovery ──────────────────────────────────────

SCAN_VARIANTS = [
    Variant("port_sweep", "Fast port sweep",
            "One host connecting to many hosts on common ports in seconds",
            "", weight=1.0),
    Variant("slow_scan", "Slow, spread-out scan",
            "The same connections, spread over hours",
            "defeats connection-rate thresholds", weight=0.9),
    Variant("targeted_smb", "Targeted SMB/RDP check",
            "Only 445 and 3389, only against servers - collides with the vuln scanner",
            "collides with the weekly authenticated scan", weight=0.8),
]


@register("T1046", SCAN_VARIANTS, tables=("DeviceNetworkEvents", "CommonSecurityLog"))
def network_scan(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start
    ports = ([445, 3389] if plan.variant == "targeted_smb"
             else [22, 80, 135, 139, 443, 445, 3389, 5985, 8080])
    targets = [d for d in org.devices if d != host]
    n = loud_scale(plan.loudness, 10, 60)

    for i in range(n):
        target = rng.choice(targets)
        port = rng.choice(ports)
        if plan.variant == "slow_scan":
            ts += timedelta(minutes=rng.randint(3, 20))
        else:
            ts += timedelta(milliseconds=rng.randint(50, 900))
        succeeded = rng.random() < 0.25
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, host, user, ts, remote_ip=target.ip, remote_port=port,
            remote_url=target.name, process="powershell.exe",
            action="ConnectionSuccess" if succeeded else "ConnectionFailed"),
            f"scan {target.name}:{port}")


# ── T1071.001 HTTP C2 beaconing ──────────────────────────────────────────

HTTP_C2_VARIANTS = [
    Variant("regular_beacon", "Fixed-interval beacon",
            "Connections to one domain at a near-constant interval",
            "", weight=1.0),
    Variant("jittered_beacon", "Jittered beacon",
            "Same domain, interval varies +/- 30% each time",
            "defeats exact-interval detection", weight=1.0),
    Variant("domain_fronting", "Beacon via a CDN domain",
            "Beacon to a legitimate-looking CDN hostname",
            "defeats reputation/blocklist detection", weight=0.8),
    Variant("low_and_slow", "One beacon per hour",
            "Long interval, very few connections total",
            "defeats volume-based detection", weight=0.9),
]


@register("T1071.001", HTTP_C2_VARIANTS,
          tables=("DeviceNetworkEvents", "CommonSecurityLog", "DnsEvents"))
def http_c2(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.victim
    domain = (rng.choice(["cdn.content-delivery.net", "static.cloudfront-cdn.com"])
              if plan.variant == "domain_fronting" else intr.c2_domain)

    interval = {"regular_beacon": 60, "jittered_beacon": 60,
                "domain_fronting": 45, "low_and_slow": 3600}[plan.variant]
    duration_h = loud_scale(plan.loudness, 4, 48)
    n = min(400, int(duration_h * 3600 / interval))
    ts = plan.start

    for i in range(n):
        if plan.variant == "jittered_beacon":
            step = int(interval * rng.uniform(0.7, 1.3))
        elif plan.variant == "domain_fronting":
            step = int(interval * rng.uniform(0.9, 1.1))
        else:
            step = interval
        ts += timedelta(seconds=step)

        if i % 5 == 0:
            yield from ctx.mark(rows.dns_event(
                ctx.gen, host, ts, name=domain, answers=intr.c2_ip), "C2 lookup")
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, host, user, ts, remote_ip=intr.c2_ip, remote_port=443,
            remote_url=domain, process=rng.choice(["svchost.exe", "rundll32.exe"])),
            f"beacon {i + 1}")
        yield from ctx.mark(rows.firewall_event(
            ctx.gen, ts, src_ip=host.ip, dst_ip=intr.c2_ip, dst_port=443,
            action="allow", app="ssl", src_host=host.name,
            sent=rng.randint(200, 1500), received=rng.randint(200, 4000)),
            "beacon egress")


# ── T1071.004 DNS tunnelling ─────────────────────────────────────────────

DNS_C2_VARIANTS = [
    Variant("txt_tunnel", "TXT-record tunnel",
            "Many TXT queries to subdomains of one apex, high-entropy labels",
            "", weight=1.0),
    Variant("subdomain_exfil", "Data in subdomain labels",
            "Long encoded subdomains under one apex, A queries",
            "", weight=1.0),
    Variant("low_volume", "Low-volume DNS C2",
            "A handful of encoded queries per hour",
            "defeats query-count thresholds", weight=0.9),
]


@register("T1071.004", DNS_C2_VARIANTS, tables=("DnsEvents", "DeviceNetworkEvents"))
def dns_tunnel(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host = intr.beachhead
    apex = rng.choice(["sync-cdn.net", "telemetry-dns.com", "resolve-api.net"])
    n = loud_scale(plan.loudness, 20, 200) if plan.variant != "low_volume" else \
        loud_scale(plan.loudness, 5, 30)
    ts = plan.start
    qtype = "TXT" if plan.variant == "txt_tunnel" else "A"

    for i in range(n):
        if plan.variant == "low_volume":
            ts += timedelta(minutes=rng.randint(8, 40))
        else:
            ts += timedelta(seconds=rng.randint(1, 20))
        label = base64.b32encode(rng.randbytes(rng.randint(20, 45))).decode().rstrip("=").lower()
        name = f"{label}.{apex}"
        yield from ctx.mark(rows.dns_event(
            ctx.gen, host, ts, name=name, query_type=qtype,
            answers="" if qtype == "TXT" else intr.c2_ip), f"tunnel query {i + 1}")


# ── T1567.002 Exfiltration to cloud storage ──────────────────────────────

EXFIL_VARIANTS = [
    Variant("large_upload", "Single large upload",
            "One big outbound transfer to a cloud-storage domain",
            "", weight=1.0),
    Variant("chunked", "Chunked upload",
            "Many fixed-size uploads to the same destination",
            "defeats single-large-transfer thresholds", weight=1.0),
    Variant("legit_service", "Upload to a sanctioned service",
            "Exfil to a service the org actually uses (OneDrive/SharePoint)",
            "hides in legitimate SaaS traffic", weight=0.9),
]


@register("T1567.002", EXFIL_VARIANTS,
          tables=("DeviceNetworkEvents", "CommonSecurityLog", "DnsEvents"))
def cloud_exfil(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    domain = ("harbourline.sharepoint.com" if plan.variant == "legit_service"
              else rng.choice(["mega.nz", "anonfiles.com", "transfer.sh"]))
    dst_ip = f"{rng.choice([104, 152, 185])}.{rng.randint(1, 254)}." \
             f"{rng.randint(1, 254)}.{rng.randint(1, 254)}"
    ts = plan.start

    if plan.variant == "chunked":
        chunk = 10_000_000
        for i in range(loud_scale(plan.loudness, 5, 30)):
            ts += timedelta(seconds=rng.randint(20, 120))
            yield from ctx.mark(rows.firewall_event(
                ctx.gen, ts, src_ip=host.ip, dst_ip=dst_ip, dst_port=443,
                action="allow", app="ssl", src_host=host.name,
                sent=chunk + rng.randint(-500, 500), received=rng.randint(200, 2000)),
                f"exfil chunk {i + 1}")
    else:
        total = rng.randint(200_000_000, 2_000_000_000)
        yield from ctx.mark(rows.dns_event(
            ctx.gen, host, ts, name=domain, answers=dst_ip), "exfil destination lookup")
        yield from ctx.mark(rows.firewall_event(
            ctx.gen, ts + timedelta(seconds=2), src_ip=host.ip, dst_ip=dst_ip,
            dst_port=443, action="allow", app="ssl", src_host=host.name,
            sent=total, received=rng.randint(1000, 20000)), "bulk exfil upload")
    yield from ctx.mark(rows.device_network_event(
        ctx.gen, host, user, ts, remote_ip=dst_ip, remote_port=443,
        remote_url=domain, process=rng.choice(["chrome.exe", "powershell.exe", "rclone.exe"])),
        "exfil connection")


# ── T1486 Ransomware ─────────────────────────────────────────────────────

RANSOM_VARIANTS = [
    Variant("mass_encrypt", "Mass file encryption",
            "Thousands of FileModified events with a new extension, one process, minutes",
            "", weight=1.0),
    Variant("shadow_delete_first", "Delete shadow copies then encrypt",
            "vssadmin delete first, then encryption - the recovery-inhibit is the early warning",
            "", weight=1.0),
    Variant("slow_burn", "Slow encryption to evade rate detection",
            "The same encryption, throttled over hours",
            "defeats file-modification-rate thresholds", weight=0.8),
]


@register("T1486", RANSOM_VARIANTS,
          tables=("DeviceFileEvents", "DeviceProcessEvents", "SecurityEvent"))
def ransomware(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host = intr.current_host()
    user = intr.current_user()
    ts = plan.start
    ext = rng.choice([".locked", ".crypt", ".harbour", ".enc"])

    if plan.variant == "shadow_delete_first":
        for cmd in ["vssadmin.exe delete shadows /all /quiet",
                    "wbadmin.exe delete catalog -quiet",
                    "bcdedit.exe /set {default} recoveryenabled No"]:
            ts += timedelta(seconds=rng.randint(2, 15))
            img = cmd.split(".exe")[0].split("\\")[-1] + ".exe"
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, img, cmd, parent="cmd.exe",
                integrity="High"), "recovery inhibited")

    ransomware_proc = "svchost.exe" if rng.random() < 0.3 else intr.payload_name
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts + timedelta(seconds=2), ransomware_proc,
        rf"{intr.staging_dir}\{ransomware_proc}", parent="cmd.exe",
        integrity="High"), "ransomware launched")

    n_files = loud_scale(plan.loudness, 200, 3000)
    exts = ["docx", "xlsx", "pdf", "pptx", "jpg", "csv", "sql", "bak", "zip"]
    ft = ts + timedelta(seconds=5)
    for i in range(n_files):
        if plan.variant == "slow_burn":
            ft += timedelta(seconds=rng.randint(2, 15))
        else:
            ft += timedelta(milliseconds=rng.randint(30, 400))
        base = rng.choice(["report", "invoice", "data", "backup", "photo", "budget"])
        orig = f"{base}_{rng.randint(1, 9999)}.{rng.choice(exts)}"
        yield from ctx.mark(rows.device_file_event(
            ctx.gen, host, user, ft, filename=f"{orig}{ext}",
            folder=rf"C:\Users\{user.sam}\Documents\{orig}{ext}",
            action="FileModified", process=ransomware_proc,
            PreviousFileName=orig), f"encrypted {orig}")

    yield from ctx.mark(rows.device_file_event(
        ctx.gen, host, user, ft + timedelta(seconds=2), filename="README_RESTORE.txt",
        folder=rf"C:\Users\{user.sam}\Documents\README_RESTORE.txt",
        action="FileCreated", process=ransomware_proc), "ransom note dropped")


# ── T1490 Inhibit system recovery ────────────────────────────────────────

RECOVERY_VARIANTS = [
    Variant("vssadmin", "vssadmin delete shadows",
            "vssadmin.exe delete shadows /all /quiet",
            "", weight=1.0),
    Variant("wmic_shadowcopy", "wmic shadowcopy delete",
            "No vssadmin.exe - shadows deleted through WMI",
            "defeats vssadmin.exe detection", weight=0.9),
    Variant("powershell_recovery", "PowerShell recovery inhibit",
            "Get-WmiObject Win32_ShadowCopy | Remove-WmiObject",
            "defeats both vssadmin and wmic detection", weight=0.8),
]


@register("T1490", RECOVERY_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def inhibit_recovery(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "vssadmin":
        cmds = [("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
                ("bcdedit.exe", "bcdedit.exe /set {default} recoveryenabled No"),
                ("wbadmin.exe", "wbadmin.exe delete catalog -quiet")]
    elif plan.variant == "wmic_shadowcopy":
        cmds = [("wmic.exe", "wmic.exe shadowcopy delete")]
    else:
        cmds = [("powershell.exe",
                 'powershell.exe -Command "Get-WmiObject Win32_ShadowCopy | '
                 'Remove-WmiObject"')]

    for img, cmd in cmds:
        ts += timedelta(seconds=ctx.rng.randint(2, 20))
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, img, cmd, parent="cmd.exe",
            integrity="High"), "system recovery inhibited")
