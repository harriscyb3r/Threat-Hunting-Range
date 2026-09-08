"""Static reference data for org generation.

Names, domains, process trees and user agents. Kept apart from model.py so the
generation logic stays readable and this can grow without burying it.

Nothing here is sensitive or real: the people are invented, and the external
domains are the genuinely popular ones any corporate network resolves all day
(that part has to be real, or DNS beaconing hunts become trivial — a random
made-up domain would stand out from a made-up baseline just as much as the C2).
"""
from __future__ import annotations

GIVEN_NAMES = [
    "Aisha", "Liam", "Priya", "Noah", "Chloe", "Ethan", "Mia", "Lachlan", "Zara", "Hamish",
    "Isla", "Declan", "Anika", "Ruby", "Tomas", "Amara", "Callum", "Sienna", "Rafael", "Nadia",
    "Oscar", "Freya", "Kiri", "Marcus", "Leila", "Hugo", "Willow", "Dmitri", "Grace", "Ibrahim",
    "Charlotte", "Aaron", "Tessa", "Jarrah", "Yuki", "Bianca", "Felix", "Rosa", "Kai", "Elena",
    "Nathan", "Talia", "Owen", "Maya", "Angus", "Farah", "Julian", "Indira", "Blake", "Simone",
]

SURNAMES = [
    "Nguyen", "Patel", "Wilson", "Okafor", "Rossi", "Kaur", "Thompson", "Silva", "Murphy", "Chen",
    "Kowalski", "Haddad", "Brennan", "Fernandez", "Lindqvist", "Ahmed", "Whitfield", "Kumar",
    "Delacroix", "Barnes", "Petrov", "Tanaka", "Mbeki", "Callaghan", "Reyes", "Novak", "Fitzgerald",
    "Sharma", "Andersen", "Vasquez", "Bennett", "Osman", "Kirby", "Moreau", "Yilmaz", "Doyle",
    "Ferreira", "Larsen", "Mahoney", "Rahman",
]

# (department, share of headcount, [job titles])
DEPARTMENTS: list[tuple[str, float, list[str]]] = [
    ("Sales",       0.18, ["Account Executive", "Sales Manager", "Sales Development Rep"]),
    ("Engineering", 0.22, ["Software Engineer", "Senior Engineer", "Engineering Manager",
                           "Platform Engineer", "QA Engineer"]),
    ("Finance",     0.09, ["Accountant", "Financial Analyst", "Payroll Officer", "CFO"]),
    ("Operations",  0.14, ["Operations Analyst", "Logistics Coordinator", "Ops Manager"]),
    ("Marketing",   0.08, ["Marketing Specialist", "Content Manager", "Brand Manager"]),
    ("HR",          0.06, ["HR Advisor", "Recruiter", "HR Manager"]),
    ("IT",          0.10, ["Service Desk Analyst", "Systems Administrator", "Network Engineer",
                           "IT Manager"]),
    ("Legal",       0.04, ["Legal Counsel", "Contracts Manager"]),
    ("Executive",   0.03, ["Chief Executive Officer", "Chief Operating Officer",
                           "Chief Financial Officer", "Chief Information Officer"]),
    ("Support",     0.06, ["Support Engineer", "Customer Success Manager"]),
]

# (city, country, ISO code, UTC offset hours)
LOCATIONS = [
    ("Melbourne", "Australia", "AU", 10),
    ("Sydney", "Australia", "AU", 10),
    ("Brisbane", "Australia", "AU", 10),
    ("Perth", "Australia", "AU", 8),
    ("Adelaide", "Australia", "AU", 9),
    ("Auckland", "New Zealand", "NZ", 12),
    ("Singapore", "Singapore", "SG", 8),
]

# Destinations for the occasional genuine business trip. A sign-in from one of
# these is benign — and is exactly the kind of thing an impossible-travel query
# fires on, so the range needs them present.
TRAVEL_DESTINATIONS = [
    ("Singapore", "Singapore", "SG", 8),
    ("Auckland", "New Zealand", "NZ", 12),
    ("London", "United Kingdom", "GB", 0),
    ("San Francisco", "United States", "US", -8),
    ("Tokyo", "Japan", "JP", 9),
    ("Kuala Lumpur", "Malaysia", "MY", 8),
    ("Dubai", "United Arab Emirates", "AE", 4),
]

# Entra applications users actually sign in to, with real first-party app IDs
# where they are well-known constants. Weight is relative sign-in frequency.
ENTRA_APPS: list[tuple[str, str, float]] = [
    ("Office 365 Exchange Online",   "00000002-0000-0ff1-ce00-000000000000", 0.30),
    ("Microsoft Teams",              "1fec8e78-bce4-4aaf-ab1b-5451cc387264", 0.22),
    ("SharePoint Online",            "00000003-0000-0ff1-ce00-000000000000", 0.14),
    ("OneDrive SyncEngine",          "ab9b8c07-8f02-4f72-87fa-80105867a763", 0.10),
    ("Microsoft Authentication Broker", "29d9ed98-a469-4536-ade2-f981bc1d605e", 0.08),
    ("Azure Portal",                 "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", 0.05),
    ("Microsoft Office",             "d3590ed6-52b3-4102-aeff-aad2292ab01c", 0.05),
    ("Salesforce",                   "8e0e8db5-b713-4e91-98e6-470fed0aa4c2", 0.03),
    ("Atlassian Cloud",              "5f8ea6f9-d2f4-4b1e-9d21-9a2f4e5b1c33", 0.02),
    ("Xero",                         "3b1e0f2a-77c1-4c6a-9a1a-77c9d0c5b8e1", 0.01),
]

# Service principals — the workload identities an attacker adds credentials to.
SERVICE_PRINCIPALS = [
    ("Backup Orchestrator", "b1f0c9a2-4d3e-4a7b-9c81-0f6d2e5a7b39"),
    ("HR Sync Connector", "c72d1e84-9b0a-4f36-8e15-3a9c4d1b6f02"),
    ("Invoice Automation", "d94a6b71-2c58-4e19-b703-8f5e1a2d9c46"),
    ("Monitoring Agent", "e05b8c93-7a14-4d62-9f38-2b7c6e0a4d51"),
]

# Domains a corporate network resolves constantly. Weight is relative query
# share; the long tail is generated around these.
POPULAR_DOMAINS: list[tuple[str, float]] = [
    ("login.microsoftonline.com", 0.055), ("outlook.office365.com", 0.050),
    ("teams.microsoft.com", 0.045), ("graph.microsoft.com", 0.038),
    ("sharepoint.com", 0.032), ("officeapps.live.com", 0.030),
    ("windowsupdate.com", 0.028), ("msftconnecttest.com", 0.026),
    ("google.com", 0.026), ("googleapis.com", 0.024),
    ("gstatic.com", 0.022), ("cloudflare.com", 0.020),
    ("amazonaws.com", 0.020), ("akamaiedge.net", 0.019),
    ("github.com", 0.018), ("slack.com", 0.017),
    ("atlassian.net", 0.016), ("salesforce.com", 0.015),
    ("zoom.us", 0.015), ("linkedin.com", 0.014),
    ("doubleclick.net", 0.014), ("googlesyndication.com", 0.013),
    ("cdn.jsdelivr.net", 0.012), ("fonts.googleapis.com", 0.012),
    ("apple.com", 0.011), ("icloud.com", 0.010),
    ("dropbox.com", 0.010), ("adobe.com", 0.010),
    ("youtube.com", 0.010), ("bing.com", 0.009),
    ("news.com.au", 0.009), ("abc.net.au", 0.008),
    ("commbank.com.au", 0.008), ("ato.gov.au", 0.007),
    ("seek.com.au", 0.007), ("xero.com", 0.007),
    ("myob.com", 0.006), ("telstra.com", 0.006),
    ("sentry.io", 0.006), ("datadoghq.com", 0.006),
    ("npmjs.org", 0.006), ("pypi.org", 0.005),
    ("docker.io", 0.005), ("ubuntu.com", 0.005),
    ("mozilla.org", 0.005), ("wikipedia.org", 0.005),
    ("stackoverflow.com", 0.005), ("reddit.com", 0.004),
    ("spotify.com", 0.004), ("netflix.com", 0.004),
]

DNS_QUERY_TYPES = [("A", 0.62), ("AAAA", 0.24), ("CNAME", 0.06),
                   ("TXT", 0.03), ("MX", 0.02), ("SRV", 0.02), ("PTR", 0.01)]

# Benign process tree: (parent, child, command template, weight).
# {user}, {host}, {domain} are substituted at generation time. These are the
# shapes a real workstation produces all day, and they are what an attacker's
# execution has to hide inside.
PROCESS_TREE: list[tuple[str, str, str, float]] = [
    ("explorer.exe", "chrome.exe",
     r'"C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer', 0.10),
    ("explorer.exe", "msedge.exe",
     r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --type=gpu-process', 0.08),
    ("explorer.exe", "OUTLOOK.EXE",
     r'"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"', 0.07),
    ("explorer.exe", "Teams.exe",
     r'"C:\Users\{user}\AppData\Local\Microsoft\Teams\current\Teams.exe"', 0.06),
    ("explorer.exe", "EXCEL.EXE",
     r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" /dde', 0.05),
    ("explorer.exe", "WINWORD.EXE",
     r'"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n', 0.04),
    ("services.exe", "svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p", 0.11),
    ("services.exe", "MsMpEng.exe",
     r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe"', 0.04),
    ("svchost.exe", "taskhostw.exe", r"taskhostw.exe {C0C1F3C6-1234-4B0A-9F1E-4A7B2D9C0E11}", 0.05),
    ("svchost.exe", "SearchIndexer.exe", r"C:\Windows\system32\SearchIndexer.exe /Embedding", 0.03),
    ("services.exe", "SenseIR.exe",
     r'"C:\Program Files\Windows Defender Advanced Threat Protection\SenseIR.exe"', 0.03),
    ("wininit.exe", "services.exe", r"C:\Windows\system32\services.exe", 0.02),
    ("explorer.exe", "OneDrive.exe",
     r'"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background', 0.05),
    ("services.exe", "SCNotification.exe",
     r'"C:\Windows\CCM\SCNotification.exe" -Embedding', 0.03),
    ("svchost.exe", "CcmExec.exe", r"C:\Windows\CCM\CcmExec.exe", 0.03),
    ("services.exe", "TrustedInstaller.exe",
     r"C:\Windows\servicing\TrustedInstaller.exe", 0.02),
    ("explorer.exe", "cmd.exe", r"cmd.exe /c ipconfig /all", 0.02),
    ("explorer.exe", "powershell.exe",
     r"powershell.exe -NoProfile -Command Get-MailboxStatistics", 0.02),
    ("svchost.exe", "wermgr.exe", r"C:\Windows\system32\wermgr.exe -upload", 0.02),
    ("explorer.exe", "Code.exe",
     r'"C:\Users\{user}\AppData\Local\Programs\Microsoft VS Code\Code.exe"', 0.03),
    ("explorer.exe", "python.exe", r'"C:\Python313\python.exe" build.py', 0.02),
    ("explorer.exe", "git.exe", r'"C:\Program Files\Git\cmd\git.exe" fetch --all', 0.02),
]

# Processes IT genuinely runs on servers, on a schedule.
ADMIN_PROCESSES = [
    ("powershell.exe", r"powershell.exe -NoProfile -File C:\Scripts\Backup-Verify.ps1"),
    ("powershell.exe", r"powershell.exe -NoProfile -File C:\Scripts\Get-DiskSpace.ps1"),
    ("sqlservr.exe", r'"C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER'),
    ("veeam.backup.service.exe", r'"C:\Program Files\Veeam\Backup and Replication\Backup\Veeam.Backup.Service.exe"'),
    ("w3wp.exe", r"c:\windows\system32\inetsrv\w3wp.exe -ap DefaultAppPool"),
    ("ntoskrnl.exe", r"C:\Windows\system32\ntoskrnl.exe"),
]

USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36", 0.42),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0", 0.28),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
     "Version/17.6 Safari/605.1.15", 0.08),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Mobile/15E148", 0.10),
    ("Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)", 0.09),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
     "Chrome/130.0.0.0 Safari/537.36", 0.03),
]

CLIENT_APPS = [
    ("Browser", 0.52), ("Mobile Apps and Desktop clients", 0.40),
    ("Exchange ActiveSync", 0.04), ("Other clients", 0.02),
    ("IMAP4", 0.01), ("SMTP", 0.01),
]

WORKSTATION_OS = [
    ("Windows10", "10.0.19045.5011", 0.30),
    ("Windows11", "10.0.22631.4460", 0.62),
    ("macOS", "14.6.1", 0.08),
]

SERVER_ROLES = [
    ("dc", "Domain Controller", 2),
    ("file", "File Server", 2),
    ("sql", "SQL Server", 2),
    ("web", "IIS Web Server", 2),
    ("app", "Application Server", 3),
    ("bkp", "Backup Server", 1),
    ("jump", "Jump Host", 1),
]

# Australian national public holidays, as month/day. Approximate on purpose —
# the point is that activity drops, not calendar exactness.
PUBLIC_HOLIDAYS = {(1, 1), (1, 27), (3, 10), (4, 18), (4, 21), (4, 25),
                   (6, 9), (11, 4), (12, 25), (12, 26)}
