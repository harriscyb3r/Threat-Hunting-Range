"""MITRE ATT&CK technique catalogue for the range.

Every technique the range knows about, with the words practitioners actually use
for it. The aliases matter more than the names: nobody types "Steal or Forge
Kerberos Tickets: Kerberoasting", they type "kerberoasting".

Aliases carry a weight because ambiguity is the interesting case. "WMI abuse" is
three different hunts — execution (T1047), lateral movement (T1021.006) and
persistence (T1546.003) — and the resolver should offer all three rather than
guess. So `wmi` appears in all three catalogues at different weights, and the
UI makes the analyst choose. That choice is part of the training.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Weighted alias: (phrase, weight). Weight 1.0 means "this phrase means exactly
# this technique"; lower weights mean "this phrase might mean this technique".
Alias = tuple[str, float]


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str
    aliases: tuple[Alias, ...]
    summary: str
    tables: tuple[str, ...] = ()
    url: str = ""

    @property
    def attack_url(self) -> str:
        if self.url:
            return self.url
        base = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"

    @property
    def parent_id(self) -> str:
        return self.id.split(".")[0]


def _t(tid, name, tactic, aliases, summary, tables=()) -> Technique:
    return Technique(tid, name, tactic, tuple(aliases), summary, tuple(tables))


# ── Initial access ───────────────────────────────────────────────────────
CATALOGUE: list[Technique] = [
    _t("T1566.001", "Spearphishing Attachment", "initial-access",
       [("spearphishing attachment", 1.0), ("malicious attachment", 1.0),
        ("phishing attachment", 1.0), ("macro document", 0.9), ("maldoc", 0.9),
        ("phishing", 0.6), ("email attachment", 0.8)],
       "A user opens a weaponised document that spawns a child process.",
       ["DeviceProcessEvents", "SecurityEvent", "OfficeActivity", "DeviceFileEvents"]),

    _t("T1566.002", "Spearphishing Link", "initial-access",
       [("spearphishing link", 1.0), ("phishing link", 1.0),
        ("credential harvesting page", 0.9), ("phishing", 0.5)],
       "A user clicks a link to a credential-harvesting or payload-hosting page.",
       ["DeviceNetworkEvents", "DnsEvents", "CommonSecurityLog", "OfficeActivity"]),

    _t("T1078.004", "Valid Accounts: Cloud Accounts", "initial-access",
       [("valid accounts", 0.8), ("cloud account", 1.0), ("compromised account", 0.9),
        ("stolen credentials", 0.8), ("account takeover", 0.9),
        ("suspicious sign-in", 0.7), ("impossible travel", 0.8)],
       "An attacker signs in to Entra ID with legitimate stolen credentials.",
       ["SigninLogs", "AADNonInteractiveUserSignInLogs", "OfficeActivity"]),

    _t("T1190", "Exploit Public-Facing Application", "initial-access",
       [("exploit public facing application", 1.0), ("web exploitation", 0.9),
        ("web shell drop", 0.8), ("vulnerable web app", 0.8), ("exploitation", 0.6)],
       "Exploitation of an internet-facing service, often ending in a web shell.",
       ["W3CIISLog", "DeviceProcessEvents", "CommonSecurityLog"]),

    _t("T1133", "External Remote Services", "initial-access",
       [("external remote services", 1.0), ("vpn access", 0.8),
        ("rdp from internet", 0.9), ("remote access", 0.6)],
       "Access through VPN or exposed RDP using valid credentials.",
       ["CommonSecurityLog", "SecurityEvent", "DeviceLogonEvents"]),

    # ── Execution ────────────────────────────────────────────────────────
    _t("T1059.001", "PowerShell", "execution",
       [("powershell", 1.0), ("encoded powershell", 1.0), ("powershell abuse", 1.0),
        ("encodedcommand", 1.0), ("download cradle", 0.9), ("iex", 0.8),
        ("obfuscated powershell", 0.9), ("powershell script block", 0.9)],
       "Malicious PowerShell execution, usually encoded or downloading a payload.",
       ["DeviceProcessEvents", "SecurityEvent", "DeviceNetworkEvents"]),

    _t("T1059.003", "Windows Command Shell", "execution",
       [("cmd.exe", 1.0), ("command shell", 1.0), ("batch script", 0.9),
        ("command line abuse", 0.8)],
       "cmd.exe used to chain discovery or execution commands.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    _t("T1059.007", "JavaScript", "execution",
       [("javascript", 1.0), ("wscript", 0.9), ("cscript", 0.9), ("jscript", 1.0),
        ("scripting engine", 0.7)],
       "Script host execution via wscript/cscript.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    _t("T1047", "Windows Management Instrumentation", "execution",
       [("wmi", 0.95), ("wmi abuse", 0.95), ("wmi execution", 1.0), ("wmic", 1.0),
        ("windows management instrumentation", 1.0), ("win32_process", 1.0),
        ("wmi process create", 1.0)],
       "WMI used to execute commands, locally or against a remote host.",
       ["DeviceProcessEvents", "SecurityEvent", "DeviceNetworkEvents"]),

    _t("T1204.002", "User Execution: Malicious File", "execution",
       [("user execution", 1.0), ("malicious file", 0.9), ("user opened file", 0.9)],
       "A user runs a delivered payload.",
       ["DeviceProcessEvents", "DeviceFileEvents"]),

    _t("T1053.005", "Scheduled Task", "execution",
       [("scheduled task", 1.0), ("schtasks", 1.0), ("task scheduler", 1.0),
        ("cron", 0.5), ("persistence via task", 0.9)],
       "A scheduled task created for execution or persistence.",
       ["DeviceProcessEvents", "SecurityEvent", "DeviceRegistryEvents"]),

    # ── Persistence ──────────────────────────────────────────────────────
    _t("T1547.001", "Registry Run Keys / Startup Folder", "persistence",
       [("run key", 1.0), ("registry run key", 1.0), ("autorun", 0.9),
        ("startup folder", 1.0), ("asep", 0.8), ("persistence registry", 0.8)],
       "Persistence through a Run key or the Startup folder.",
       ["DeviceRegistryEvents", "DeviceProcessEvents", "DeviceFileEvents"]),

    _t("T1543.003", "Windows Service", "persistence",
       [("malicious service", 1.0), ("service creation", 1.0), ("new service", 0.9),
        ("sc create", 1.0), ("7045", 0.9), ("service persistence", 1.0)],
       "A new Windows service installed for persistence or lateral execution.",
       ["SecurityEvent", "DeviceProcessEvents", "DeviceRegistryEvents"]),

    _t("T1136.001", "Create Account: Local Account", "persistence",
       [("create account", 1.0), ("local account creation", 1.0), ("net user add", 1.0),
        ("new user", 0.8), ("rogue account", 0.9), ("4720", 0.9)],
       "A local account created and often added to a privileged group.",
       ["SecurityEvent", "DeviceProcessEvents"]),

    _t("T1098.001", "Account Manipulation: Additional Cloud Credentials", "persistence",
       [("app credential", 1.0), ("service principal credential", 1.0),
        ("add credentials to service principal", 1.0), ("application persistence", 0.9),
        ("add secret to app", 1.0), ("certificate added to app", 0.9),
        ("account manipulation", 0.8)],
       "A secret or certificate added to an Entra application or service principal, "
       "giving persistent non-interactive access.",
       ["AuditLogs", "AADServicePrincipalSignInLogs"]),

    _t("T1546.003", "WMI Event Subscription", "persistence",
       [("wmi event subscription", 1.0), ("wmi persistence", 1.0),
        ("permanent event consumer", 1.0), ("wmi", 0.55), ("wmi abuse", 0.55)],
       "A permanent WMI event filter/consumer binding for stealthy persistence.",
       ["DeviceProcessEvents", "DeviceRegistryEvents"]),

    # ── Privilege escalation ─────────────────────────────────────────────
    _t("T1548.002", "Bypass User Account Control", "privilege-escalation",
       [("uac bypass", 1.0), ("bypass uac", 1.0), ("fodhelper", 1.0),
        ("elevation", 0.6)],
       "UAC bypass via an auto-elevating binary and a hijacked registry key.",
       ["DeviceRegistryEvents", "DeviceProcessEvents"]),

    _t("T1068", "Exploitation for Privilege Escalation", "privilege-escalation",
       [("privilege escalation exploit", 1.0), ("kernel exploit", 0.9),
        ("local privilege escalation", 1.0), ("privesc", 0.8)],
       "A local exploit yielding SYSTEM.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    # ── Defence evasion ──────────────────────────────────────────────────
    _t("T1070.001", "Clear Windows Event Logs", "defense-evasion",
       [("clear event logs", 1.0), ("wevtutil", 1.0), ("log clearing", 1.0),
        ("1102", 0.9), ("anti-forensics", 0.7)],
       "Event logs cleared to destroy evidence.",
       ["SecurityEvent", "DeviceProcessEvents"]),

    _t("T1027", "Obfuscated Files or Information", "defense-evasion",
       [("obfuscation", 1.0), ("base64 encoded payload", 0.9), ("packed binary", 0.8),
        ("encoded command", 0.8)],
       "Payloads encoded or obfuscated to evade detection.",
       ["DeviceProcessEvents", "DeviceFileEvents"]),

    _t("T1562.001", "Impair Defenses: Disable or Modify Tools", "defense-evasion",
       [("disable defender", 1.0), ("impair defenses", 1.0), ("disable antivirus", 1.0),
        ("tamper protection", 0.9), ("set-mppreference", 1.0),
        ("disable security tools", 1.0)],
       "Defender or another security tool disabled or excluded.",
       ["DeviceProcessEvents", "DeviceRegistryEvents", "SecurityEvent"]),

    _t("T1218.011", "Signed Binary Proxy Execution: Rundll32", "defense-evasion",
       [("rundll32", 1.0), ("lolbin", 0.8), ("signed binary proxy", 0.9),
        ("living off the land", 0.7), ("lolbas", 0.8)],
       "Execution proxied through rundll32 to hide from image-name detections.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    # ── Credential access ────────────────────────────────────────────────
    _t("T1003.001", "OS Credential Dumping: LSASS Memory", "credential-access",
       [("lsass", 1.0), ("credential dumping", 1.0), ("mimikatz", 1.0),
        ("dump lsass", 1.0), ("procdump lsass", 1.0), ("comsvcs minidump", 1.0),
        ("memory dump credentials", 0.9)],
       "LSASS memory dumped to harvest credentials.",
       ["DeviceProcessEvents", "SecurityEvent", "DeviceFileEvents"]),

    _t("T1110.003", "Password Spraying", "credential-access",
       [("password spray", 1.0), ("password spraying", 1.0), ("spray", 0.8),
        ("brute force", 0.7), ("credential stuffing", 0.7),
        ("many users one password", 0.9)],
       "One password tried against many accounts, staying under lockout thresholds.",
       ["SigninLogs", "SecurityEvent", "AADNonInteractiveUserSignInLogs"]),

    _t("T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "credential-access",
       [("kerberoasting", 1.0), ("kerberoast", 1.0), ("spn roasting", 1.0),
        ("service ticket request", 0.9), ("4769", 0.85), ("rc4 ticket", 0.9),
        ("tgs-rep", 0.9), ("rubeus kerberoast", 1.0)],
       "Service tickets requested in bulk and cracked offline for service account "
       "passwords.",
       ["SecurityEvent", "DeviceProcessEvents", "IdentityLogonEvents"]),

    _t("T1552.001", "Unsecured Credentials: Credentials in Files", "credential-access",
       [("credentials in files", 1.0), ("password in file", 1.0),
        ("unsecured credentials", 1.0), ("hardcoded credentials", 0.9),
        ("searching for passwords", 0.9)],
       "Filesystem searched for credentials in scripts and config files.",
       ["DeviceProcessEvents", "DeviceFileEvents"]),

    # ── Discovery ────────────────────────────────────────────────────────
    _t("T1087.002", "Account Discovery: Domain Account", "discovery",
       [("account discovery", 1.0), ("domain account enumeration", 1.0),
        ("net user domain", 1.0), ("enumerate users", 0.9),
        ("ad enumeration", 0.9), ("bloodhound", 0.85), ("sharphound", 0.9)],
       "Domain accounts and groups enumerated.",
       ["DeviceProcessEvents", "SecurityEvent", "IdentityLogonEvents"]),

    _t("T1018", "Remote System Discovery", "discovery",
       [("remote system discovery", 1.0), ("host enumeration", 1.0),
        ("net view", 1.0), ("find hosts", 0.8), ("network discovery", 0.85)],
       "Other hosts on the network enumerated.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    _t("T1046", "Network Service Discovery", "discovery",
       [("network service discovery", 1.0), ("port scan", 1.0), ("scanning", 0.8),
        ("service scan", 0.9), ("nmap", 0.9)],
       "Ports and services scanned across the network.",
       ["DeviceNetworkEvents", "CommonSecurityLog"]),

    _t("T1482", "Domain Trust Discovery", "discovery",
       [("domain trust discovery", 1.0), ("nltest", 1.0), ("trust enumeration", 1.0),
        ("forest trust", 0.9)],
       "Domain and forest trust relationships enumerated.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    # ── Lateral movement ─────────────────────────────────────────────────
    _t("T1021.001", "Remote Desktop Protocol", "lateral-movement",
       [("rdp", 1.0), ("remote desktop", 1.0), ("lateral movement rdp", 1.0),
        ("logon type 10", 0.9), ("mstsc", 0.9)],
       "Interactive lateral movement over RDP.",
       ["SecurityEvent", "DeviceLogonEvents", "DeviceNetworkEvents"]),

    _t("T1021.002", "SMB / Windows Admin Shares", "lateral-movement",
       [("smb lateral movement", 1.0), ("admin shares", 1.0), ("psexec", 1.0),
        ("admin$", 1.0), ("c$", 0.9), ("smbexec", 1.0), ("service exec", 0.8)],
       "Lateral movement via admin shares and remote service creation.",
       ["SecurityEvent", "DeviceLogonEvents", "DeviceFileEvents"]),

    _t("T1021.006", "Windows Remote Management", "lateral-movement",
       [("winrm", 1.0), ("windows remote management", 1.0), ("powershell remoting", 1.0),
        ("invoke-command", 1.0), ("wsman", 0.9), ("wmi lateral", 0.95),
        ("remote wmi", 0.95), ("wmi", 0.85), ("wmi abuse", 0.85), ("port 5985", 0.9)],
       "Remote execution over WinRM or remote WMI.",
       ["DeviceProcessEvents", "DeviceNetworkEvents", "SecurityEvent", "DeviceLogonEvents"]),

    _t("T1550.002", "Use Alternate Authentication Material: Pass the Hash",
       "lateral-movement",
       [("pass the hash", 1.0), ("pth", 1.0), ("passthehash", 1.0),
        ("ntlm hash reuse", 1.0), ("overpass the hash", 0.85),
        ("alternate authentication material", 0.8), ("hash reuse", 0.9)],
       "An NTLM hash reused to authenticate without knowing the password.",
       ["SecurityEvent", "DeviceLogonEvents", "IdentityLogonEvents"]),

    # ── Command and control ──────────────────────────────────────────────
    _t("T1071.001", "Application Layer Protocol: Web", "command-and-control",
       [("http c2", 1.0), ("web c2", 1.0), ("beacon", 0.95), ("beaconing", 0.95),
        ("command and control", 0.8), ("c2", 0.85), ("cobalt strike", 0.9)],
       "C2 over HTTP/HTTPS, typically beaconing on a jittered interval.",
       ["DeviceNetworkEvents", "CommonSecurityLog", "DnsEvents"]),

    _t("T1071.004", "Application Layer Protocol: DNS", "command-and-control",
       [("dns tunnelling", 1.0), ("dns tunneling", 1.0), ("dns c2", 1.0),
        ("dns exfil", 0.9), ("txt record c2", 1.0), ("dns beacon", 1.0)],
       "C2 or exfiltration encoded into DNS queries.",
       ["DnsEvents", "DeviceNetworkEvents"]),

    _t("T1090", "Proxy", "command-and-control",
       [("proxy", 0.9), ("socks proxy", 1.0), ("tunnelling tool", 0.9),
        ("ngrok", 0.9), ("reverse tunnel", 0.9)],
       "Traffic relayed through a proxy or tunnel.",
       ["DeviceNetworkEvents", "CommonSecurityLog"]),

    _t("T1573", "Encrypted Channel", "command-and-control",
       [("encrypted channel", 1.0), ("tls c2", 0.9), ("custom encryption", 0.8)],
       "C2 wrapped in encryption to defeat inspection.",
       ["DeviceNetworkEvents", "CommonSecurityLog"]),

    # ── Exfiltration ─────────────────────────────────────────────────────
    _t("T1567.002", "Exfiltration to Cloud Storage", "exfiltration",
       [("exfiltration to cloud storage", 1.0), ("cloud exfil", 1.0),
        ("upload to dropbox", 1.0), ("mega upload", 0.9), ("data exfiltration", 0.85),
        ("exfil", 0.8)],
       "Data uploaded to a third-party cloud storage service.",
       ["DeviceNetworkEvents", "CommonSecurityLog", "DnsEvents"]),

    _t("T1041", "Exfiltration Over C2 Channel", "exfiltration",
       [("exfiltration over c2", 1.0), ("exfil over c2", 1.0),
        ("data theft over beacon", 0.9)],
       "Data sent out through the existing C2 channel.",
       ["DeviceNetworkEvents", "CommonSecurityLog"]),

    _t("T1030", "Data Transfer Size Limits", "exfiltration",
       [("data transfer size limits", 1.0), ("chunked exfil", 1.0),
        ("split upload", 0.9)],
       "Exfiltration split into fixed-size chunks to avoid volume thresholds.",
       ["DeviceNetworkEvents", "CommonSecurityLog"]),

    # ── Impact ───────────────────────────────────────────────────────────
    _t("T1486", "Data Encrypted for Impact", "impact",
       [("ransomware", 1.0), ("data encrypted for impact", 1.0), ("encryption attack", 0.9),
        ("mass file encryption", 1.0), ("ransom note", 0.9), ("encrypt files", 0.95),
        ("file encryption", 0.9), ("encrypted files", 0.95)],
       "Files encrypted en masse and a ransom note dropped.",
       ["DeviceFileEvents", "DeviceProcessEvents"]),

    _t("T1490", "Inhibit System Recovery", "impact",
       [("inhibit system recovery", 1.0), ("delete shadow copies", 1.0),
        ("vssadmin delete", 1.0), ("bcdedit recovery", 0.9),
        ("destroy backups", 0.9)],
       "Shadow copies and recovery options destroyed before encryption.",
       ["DeviceProcessEvents", "SecurityEvent"]),

    _t("T1489", "Service Stop", "impact",
       [("service stop", 1.0), ("stop services", 1.0), ("kill database service", 0.9),
        ("net stop", 0.9)],
       "Services stopped to unlock files or disrupt operations.",
       ["DeviceProcessEvents", "SecurityEvent"]),
]

BY_ID: dict[str, Technique] = {t.id: t for t in CATALOGUE}

TACTIC_ORDER = [
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "command-and-control", "exfiltration", "impact",
]


def get(tid: str) -> Technique:
    return BY_ID[tid.upper()]


def by_tactic(tactic: str) -> list[Technique]:
    return [t for t in CATALOGUE if t.tactic == tactic]


def tactic_sort_key(t: Technique) -> int:
    try:
        return TACTIC_ORDER.index(t.tactic)
    except ValueError:
        return len(TACTIC_ORDER)
