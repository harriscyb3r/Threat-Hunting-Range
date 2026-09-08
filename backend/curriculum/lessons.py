"""Guided KQL curriculum, aligned to Microsoft SC-200.

The modules track the KQL-heavy objectives of the SC-200 study guide
(learn.microsoft.com/credentials/certifications/resources/study-guides/sc-200):
KQL fundamentals, summarizing and aggregating, time and string operations,
multi-table queries, Defender XDR advanced hunting, and Sentinel analytics /
ASIM. Each lesson pairs an explanation with a runnable query and an exercise the
analyst does against a real campaign in the range — so the KQL is practised on
live data, not read.

A lesson carries:
    starter   a query to run as-is and read
    task      what to change/find yourself
    solution  a worked answer (revealed on demand)
    campaign  a library slug the lesson is best practised against (optional)

Difficulty rises through the modules; the last module applies everything to a
full intrusion.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Lesson:
    id: str
    title: str
    objective: str                 # SC-200 skill this builds
    concept: str                   # short teaching text (markdown)
    starter: str                   # query to run and read
    task: str                      # the exercise
    solution: str                  # worked answer
    campaign: str = ""             # library slug to practise against
    tables: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "objective": self.objective,
            "concept": self.concept, "starter": self.starter, "task": self.task,
            "solution": self.solution, "campaign": self.campaign,
            "tables": list(self.tables),
        }


@dataclass(frozen=True, slots=True)
class Module:
    id: str
    title: str
    sc200_area: str                # which SC-200 objective domain
    summary: str
    lessons: list[Lesson] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "sc200_area": self.sc200_area,
            "summary": self.summary, "lessons": [l.as_dict() for l in self.lessons],
        }


MODULES: list[Module] = [
    Module(
        id="fundamentals",
        title="KQL fundamentals",
        sc200_area="Create and manage KQL — filtering, projection, ordering",
        summary="The core pipeline: take a table, filter it, choose columns, "
                "sort and limit. Everything else builds on this.",
        lessons=[
            Lesson(
                id="f1-where",
                title="Filter rows with where",
                objective="Filter a table down to the rows that matter",
                concept="A KQL query starts with a table and pipes (`|`) it through "
                        "operators. `where` keeps only rows matching a condition. "
                        "Chain multiple `where`s or combine with `and`/`or`.",
                starter='SigninLogs\n| where ResultType != "0"\n| take 20',
                task="Narrow it further: show only failed sign-ins where "
                     "`ClientAppUsed` is a legacy protocol (e.g. contains "
                     '"IMAP" or "Other clients").',
                solution='SigninLogs\n| where ResultType != "0"\n'
                         '| where ClientAppUsed has_any ("IMAP", "Other clients", '
                         '"Exchange ActiveSync")\n| take 20',
                tables=("SigninLogs",),
            ),
            Lesson(
                id="f2-project",
                title="Choose columns with project",
                objective="Shape output to the columns you care about",
                concept="`project` selects (and renames) columns. `project-away` "
                        "drops columns. Projecting early makes results readable and "
                        "queries faster.",
                starter="DeviceProcessEvents\n| where FileName == \"powershell.exe\"\n"
                        "| project TimeGenerated, DeviceName, AccountName, "
                        "ProcessCommandLine\n| take 20",
                task="Rename `ProcessCommandLine` to `Cmd` and add the parent "
                     "process (`InitiatingProcessFileName`) to the output.",
                solution="DeviceProcessEvents\n| where FileName == \"powershell.exe\"\n"
                         "| project TimeGenerated, DeviceName, AccountName, "
                         "Parent=InitiatingProcessFileName, Cmd=ProcessCommandLine\n"
                         "| take 20",
                tables=("DeviceProcessEvents",),
            ),
            Lesson(
                id="f3-sort-top",
                title="Order and limit with sort and top",
                objective="Surface the most relevant rows first",
                concept="`sort by <col> desc` orders results; `top N by <col>` is "
                        "sort + take in one. Use `top` to answer 'the 10 busiest…'.",
                starter="DeviceNetworkEvents\n| summarize Connections=count() by "
                        "RemoteUrl\n| top 10 by Connections",
                task="Find the 10 devices making the most distinct DNS-style "
                     "connections (hint: `dcount(RemoteUrl)` by `DeviceName`).",
                solution="DeviceNetworkEvents\n| summarize Domains=dcount(RemoteUrl) "
                         "by DeviceName\n| top 10 by Domains",
                tables=("DeviceNetworkEvents",),
            ),
        ],
    ),
    Module(
        id="aggregation",
        title="Summarizing and aggregating",
        sc200_area="Create and manage KQL — summarize, aggregation functions, bin",
        summary="`summarize` collapses many rows into grouped aggregates — the "
                "single most important operator for hunting at scale.",
        lessons=[
            Lesson(
                id="a1-summarize-count",
                title="Group and count with summarize by",
                objective="Aggregate events into counts per entity",
                concept="`summarize <agg> by <cols>` groups rows and computes an "
                        "aggregate per group. `count()` is the most common; the "
                        "`by` clause names the grouping keys.",
                starter='SecurityEvent\n| where EventID == 4769\n'
                        "| summarize Tickets=count() by Account\n"
                        "| sort by Tickets desc",
                task="Kerberoasting shows as many distinct SPNs per account. "
                     "Change the aggregate to `dcount(ServiceName)` and keep only "
                     "accounts requesting 3 or more distinct SPNs.",
                solution='SecurityEvent\n| where EventID == 4769\n'
                         "| summarize SPNs=dcount(ServiceName) by Account\n"
                         "| where SPNs >= 3\n| sort by SPNs desc",
                campaign="kerberoast-starter",
                tables=("SecurityEvent",),
            ),
            Lesson(
                id="a2-multi-agg",
                title="Multiple aggregates and make_set",
                objective="Compute several aggregates in one summarize",
                concept="A single `summarize` can produce many aggregates: "
                        "`count()`, `dcount()`, `min()/max()`, and `make_set()` "
                        "which collects distinct values into a list — perfect for "
                        "'which services did this account touch?'.",
                starter='SecurityEvent\n| where EventID == 4769\n'
                        "| summarize Tickets=count(), SPNs=dcount(ServiceName), "
                        "Services=make_set(ServiceName, 10), "
                        "FirstSeen=min(TimeGenerated) by Account",
                task="Add the set of distinct encryption types "
                     "(`make_set(TicketEncryptionType)`) so you can spot accounts "
                     "using RC4 (0x17).",
                solution='SecurityEvent\n| where EventID == 4769\n'
                         "| summarize Tickets=count(), SPNs=dcount(ServiceName), "
                         "Enc=make_set(TicketEncryptionType), "
                         "FirstSeen=min(TimeGenerated) by Account",
                campaign="kerberoast-starter",
                tables=("SecurityEvent",),
            ),
            Lesson(
                id="a3-bin-timechart",
                title="Time buckets with bin",
                objective="Aggregate over time windows to spot bursts and beacons",
                concept="`bin(TimeGenerated, 1h)` rounds timestamps into buckets, so "
                        "`summarize count() by bin(TimeGenerated, 1h)` gives a "
                        "per-hour volume — the basis of spotting bursts, spikes and "
                        "beaconing intervals.",
                starter="DeviceNetworkEvents\n| summarize Conns=count() by "
                        "bin(TimeGenerated, 1h), DeviceName\n| sort by Conns desc",
                task="A beacon connects at a near-constant rate. Bin by 10 minutes "
                     "for a single suspicious device and look for a flat, repeating "
                     "count.",
                solution="DeviceNetworkEvents\n| where RemoteUrl has \"cdn\" or "
                         'RemoteUrl has "sync"\n'
                         "| summarize Conns=count() by bin(TimeGenerated, 10m), "
                         "RemoteUrl\n| sort by RemoteUrl asc, TimeGenerated asc",
                campaign="dns-c2-intermediate",
                tables=("DeviceNetworkEvents",),
            ),
        ],
    ),
    Module(
        id="time-strings",
        title="Time and string operations",
        sc200_area="Create and manage KQL — datetime and string functions",
        summary="Real hunts filter by time window and match on message content. "
                "`ago`, `between`, `has`, `contains`, `extract` and `parse` are the "
                "workhorses.",
        lessons=[
            Lesson(
                id="t1-has-contains",
                title="String matching: has vs contains",
                objective="Match message content correctly and efficiently",
                concept="`has` matches whole terms and is indexed (fast); `contains` "
                        "matches any substring (slower). Prefer `has`/`has_any` for "
                        "words, `contains` only for partial strings. `startswith`/"
                        "`endswith` anchor the match.",
                starter='DeviceProcessEvents\n'
                        '| where ProcessCommandLine has "-enc"\n'
                        "| project TimeGenerated, DeviceName, AccountName, "
                        "ProcessCommandLine\n| take 20",
                task="Broaden to catch both `-enc` and `-EncodedCommand`, and "
                     "exclude the known benign developer account so the encoded "
                     "PowerShell that remains is worth looking at.",
                solution='DeviceProcessEvents\n'
                         '| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")\n'
                         '| where AccountName !startswith "svc-"\n'
                         "| project TimeGenerated, DeviceName, AccountName, "
                         "ProcessCommandLine",
                campaign="encoded-powershell-starter",
                tables=("DeviceProcessEvents",),
            ),
            Lesson(
                id="t2-extract",
                title="Pull fields out with extract",
                objective="Parse structured data from a string column",
                concept="`extract(regex, captureGroup, source)` pulls a substring "
                        "matching a regex. Use it to get the SPN service class from a "
                        "`ServiceName`, or a domain from a URL — turning free text "
                        "into a groupable field.",
                starter='SecurityEvent\n| where EventID == 4769\n'
                        '| extend ServiceClass = extract("^([^/]+)/", 1, ServiceName)\n'
                        "| summarize count() by ServiceClass",
                task="Extract just the target hostname from `ServiceName` "
                     "(the part after the `/` and before any `:`), and count "
                     "requests per host.",
                solution='SecurityEvent\n| where EventID == 4769\n'
                         '| extend TargetHost = extract("/([^:]+)", 1, ServiceName)\n'
                         "| summarize Requests=count() by TargetHost\n"
                         "| sort by Requests desc",
                campaign="kerberoast-starter",
                tables=("SecurityEvent",),
            ),
            Lesson(
                id="t3-time-window",
                title="Time windows with ago and between",
                objective="Scope a hunt to a time range",
                concept="`where TimeGenerated > ago(1d)` filters to the last day; "
                        "`between (datetime(..) .. datetime(..))` scopes an exact "
                        "window. Scoping time first makes every later step cheaper "
                        "and focuses the hunt on the incident window.",
                starter="SecurityEvent\n| where TimeGenerated > ago(14d)\n"
                        "| where EventID == 4625\n"
                        "| summarize Failures=count() by Account\n"
                        "| sort by Failures desc",
                task="Restrict to a single day where you suspect activity and "
                     "compare the failure counts — bursts of 4625 in a tight window "
                     "matter more than the same number spread over two weeks.",
                solution="SecurityEvent\n"
                         "| where TimeGenerated between "
                         "(ago(14d) .. ago(13d))\n"
                         "| where EventID == 4625\n"
                         "| summarize Failures=count() by Account, "
                         "bin(TimeGenerated, 1h)\n| sort by Failures desc",
                tables=("SecurityEvent",),
            ),
        ],
    ),
    Module(
        id="multitable",
        title="Multi-table queries",
        sc200_area="Create and manage KQL — join, union, let",
        summary="Attacks span tables. `join` correlates two tables on a key; "
                "`union` stacks them; `let` names a subquery for reuse.",
        lessons=[
            Lesson(
                id="m1-let",
                title="Name subqueries with let",
                objective="Build readable, staged queries",
                concept="`let name = ...;` binds a value or a whole table expression "
                        "to a name. Use it to compute a set of suspicious accounts "
                        "once and reference it, instead of repeating a subquery.",
                starter='let suspicious = SecurityEvent\n'
                        '    | where EventID == 4769 and TicketEncryptionType == "0x17"\n'
                        "    | summarize SPNs=dcount(ServiceName) by Account\n"
                        "    | where SPNs >= 3\n    | project Account;\n"
                        "suspicious",
                task="Use the `suspicious` set to pull those accounts' logon events "
                     "from `SecurityEvent` (EventID 4624) — pivoting from 'who "
                     "roasted' to 'where did they log on'.",
                solution='let suspicious = SecurityEvent\n'
                         '    | where EventID == 4769 and TicketEncryptionType == "0x17"\n'
                         "    | summarize SPNs=dcount(ServiceName) by Account\n"
                         "    | where SPNs >= 3\n    | project Account;\n"
                         "SecurityEvent\n| where EventID == 4624\n"
                         "| where Account in (suspicious)\n"
                         "| project TimeGenerated, Account, Computer, IpAddress",
                campaign="kerberoast-starter",
                tables=("SecurityEvent",),
            ),
            Lesson(
                id="m2-join",
                title="Correlate tables with join",
                objective="Link a process to its network connection",
                concept="`join kind=inner (Table2) on Key` matches rows across "
                        "tables. `leftanti` keeps left rows with **no** match — "
                        "great for 'processes that never made a network call' or the "
                        "inverse. Join on a shared key like DeviceId or a process id.",
                starter="DeviceProcessEvents\n| where FileName == \"powershell.exe\"\n"
                        "| project DeviceId, DeviceName, ProcessId, "
                        "ProcessCommandLine, TimeGenerated\n"
                        "| take 20",
                task="Join PowerShell process events to `DeviceNetworkEvents` on "
                     "`DeviceId` to find PowerShell that also made an outbound "
                     "connection — a download cradle.",
                solution="DeviceProcessEvents\n| where FileName == \"powershell.exe\"\n"
                         "| join kind=inner (\n"
                         "    DeviceNetworkEvents\n"
                         "    | project DeviceId, RemoteUrl, RemoteIP, "
                         "NetTime=TimeGenerated\n"
                         ") on DeviceId\n"
                         "| project TimeGenerated, DeviceName, ProcessCommandLine, "
                         "RemoteUrl, RemoteIP\n| take 20",
                campaign="encoded-powershell-starter",
                tables=("DeviceProcessEvents", "DeviceNetworkEvents"),
            ),
            Lesson(
                id="m3-union",
                title="Stack tables with union",
                objective="Search across multiple tables at once",
                concept="`union Table1, Table2` combines rows from several tables. "
                        "`union withsource=T *` tags each row with its origin. Use it "
                        "to sweep a suspicious command line across process, network "
                        "and file events in one pass.",
                starter="union withsource=SourceTable\n"
                        "    DeviceProcessEvents, DeviceFileEvents\n"
                        '| where AccountName has "svc-"\n'
                        "| summarize count() by SourceTable\n",
                task="Sweep for the string \"mimikatz\" across "
                     "`DeviceProcessEvents` and `DeviceFileEvents` in one union, "
                     "showing which table each hit came from.",
                solution="union withsource=SourceTable\n"
                         "    DeviceProcessEvents, DeviceFileEvents\n"
                         '| where * has "mimikatz"\n'
                         "| project SourceTable, TimeGenerated, DeviceName, "
                         "AccountName=column_ifexists(\"AccountName\",\"\")\n"
                         "| take 20",
                campaign="pth-lateral-intermediate",
                tables=("DeviceProcessEvents", "DeviceFileEvents"),
            ),
        ],
    ),
    Module(
        id="defender-hunting",
        title="Defender XDR advanced hunting",
        sc200_area="Manage security operations — advanced hunting in Defender XDR",
        summary="The Device* and Identity tables are where endpoint hunting lives. "
                "Process trees, lateral movement, and identity events.",
        lessons=[
            Lesson(
                id="d1-process-tree",
                title="Follow the process tree",
                objective="Reconstruct parent-child process relationships",
                concept="Every `DeviceProcessEvents` row carries its parent in "
                        "`InitiatingProcess*` columns. Anomalous parentage — Office "
                        "spawning a shell, `WmiPrvSE.exe` spawning `cmd.exe` — is a "
                        "reliable execution signal.",
                starter="DeviceProcessEvents\n"
                        "| where InitiatingProcessFileName in "
                        '("WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE")\n'
                        "| where FileName in (\"cmd.exe\", \"powershell.exe\", "
                        "\"wscript.exe\")\n"
                        "| project TimeGenerated, DeviceName, "
                        "InitiatingProcessFileName, FileName, ProcessCommandLine",
                task="Find processes spawned by `WmiPrvSE.exe` (the WMI provider) — "
                     "a tell for remote WMI execution — and show the child command "
                     "line.",
                solution="DeviceProcessEvents\n"
                         '| where InitiatingProcessFileName == "WmiPrvSE.exe"\n'
                         "| project TimeGenerated, DeviceName, AccountName, "
                         "FileName, ProcessCommandLine\n| sort by TimeGenerated asc",
                campaign="wmi-abuse-intermediate",
                tables=("DeviceProcessEvents",),
            ),
            Lesson(
                id="d2-lateral",
                title="Spot lateral movement",
                objective="Find one account authenticating to many hosts",
                concept="Lateral movement shows as an account logging on to hosts it "
                        "doesn't normally touch. `DeviceLogonEvents` with a network "
                        "logon type, aggregated by account, surfaces the spread. NTLM "
                        "where Kerberos is expected is an extra tell.",
                starter="DeviceLogonEvents\n| where LogonType == \"Network\"\n"
                        "| summarize Hosts=dcount(DeviceName), "
                        "HostSet=make_set(DeviceName, 15) by AccountName\n"
                        "| sort by Hosts desc",
                task="Exclude the service accounts and the vulnerability scanner "
                     "(they log on everywhere legitimately), then find the human "
                     "account with an unusually wide spread.",
                solution="DeviceLogonEvents\n| where LogonType == \"Network\"\n"
                         '| where AccountName !startswith "svc-"\n'
                         "| summarize Hosts=dcount(DeviceName), "
                         "HostSet=make_set(DeviceName, 15) by AccountName\n"
                         "| where Hosts >= 3\n| sort by Hosts desc",
                campaign="pth-lateral-intermediate",
                tables=("DeviceLogonEvents",),
            ),
        ],
    ),
    Module(
        id="sentinel-asim",
        title="Sentinel analytics and ASIM",
        sc200_area="Configure Microsoft Sentinel — analytics rules, ASIM parsers",
        summary="Sentinel-side skills: normalise across sources with ASIM, and "
                "think in terms of an analytics rule that could fire on this.",
        lessons=[
            Lesson(
                id="s1-asim",
                title="Normalise sources with ASIM",
                objective="Query across products with one schema",
                concept="ASIM parsers (`_Im_Authentication`, `_Im_ProcessCreate`, "
                        "`_Im_Dns`, `_Im_NetworkSession`) present a normalised schema "
                        "over many source tables. `_Im_Authentication(eventresult="
                        "'Failure')` returns failed logons from SigninLogs, "
                        "SecurityEvent and Defender in one shape.",
                starter='_Im_Authentication(eventresult="Failure")\n'
                        "| summarize Failures=count() by TargetUsername, "
                        "EventProduct\n| sort by Failures desc",
                task="Use the ASIM authentication parser to find failed sign-ins "
                     "grouped by source IP and product — the same hunt you'd do on "
                     "native SigninLogs, but portable across sources.",
                solution='_Im_Authentication(eventresult="Failure")\n'
                         "| summarize Failures=count(), "
                         "Users=dcount(TargetUsername) by SrcIpAddr, EventProduct\n"
                         "| where Failures > 3\n| sort by Failures desc",
                campaign="cloud-account-operator",
                tables=("SigninLogs", "SecurityEvent"),
            ),
            Lesson(
                id="s2-detection-thinking",
                title="Think like an analytics rule",
                objective="Turn a hunt into a detection that could fire",
                concept="An analytics rule is a scheduled query that returns "
                        "something only when it's suspicious. Aim for a query that "
                        "returns **zero rows** on a normal day and a handful on a bad "
                        "one — high signal, low noise. That's also what the range's "
                        "detection validation measures against the clean twin.",
                starter="SecurityEvent\n| where EventID == 1102\n"
                        "| project TimeGenerated, Computer, "
                        "SubjectUserName, Activity",
                task="Write a would-be analytics rule for 'audit log cleared' "
                     "(EventID 1102) that also surfaces who did it and from where. "
                     "Then save it as a detection and validate it against the twin.",
                solution="SecurityEvent\n| where EventID == 1102\n"
                         "| project TimeGenerated, Computer, "
                         "ClearedBy=SubjectUserName, Activity\n"
                         "| sort by TimeGenerated desc",
                campaign="ransomware-operator",
                tables=("SecurityEvent",),
            ),
        ],
    ),
]

BY_ID = {m.id: m for m in MODULES}
LESSON_BY_ID = {l.id: (m, l) for m in MODULES for l in m.lessons}


def total_lessons() -> int:
    return sum(len(m.lessons) for m in MODULES)
