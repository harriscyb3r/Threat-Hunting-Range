"""Windows Security event log and Sysmon.

`SecurityEvent` is the agent-collected Windows Security log. It is deliberately
kept alongside `DeviceProcessEvents` rather than replaced by it: the same
process execution appears in both with different column names and different
fidelity, and knowing which to reach for — and that 4688 command lines are often
absent when audit policy was never configured — is part of the tradecraft.

`Event` is the generic Windows event table where Sysmon lands when collected via
the Log Analytics agent. Sysmon's real payload sits inside the `EventData` XML
blob, which is why hunting Sysmon in Sentinel means `parse_xml` or `extract`
rather than clean columns.
"""
from __future__ import annotations

from .base import PLATFORM, TableSchema, register

DOCS = "https://learn.microsoft.com/azure/azure-monitor/reference/tables"

SecurityEvent = register(TableSchema(
    name="SecurityEvent",
    family="windows",
    columns=PLATFORM + (
        ("Computer", "string"),
        ("EventID", "int"),
        ("Activity", "string"),
        ("EventSourceName", "string"),
        ("Channel", "string"),
        ("Task", "int"),
        ("Level", "string"),
        ("Keywords", "string"),
        ("EventData", "string"),
        ("SourceComputerId", "string"),
        # Subject (who performed the action)
        ("SubjectAccount", "string"),
        ("SubjectUserName", "string"),
        ("SubjectDomainName", "string"),
        ("SubjectUserSid", "string"),
        ("SubjectLogonId", "string"),
        # Target (who it was performed on)
        ("Account", "string"),
        ("AccountType", "string"),
        ("TargetAccount", "string"),
        ("TargetUserName", "string"),
        ("TargetDomainName", "string"),
        ("TargetUserSid", "string"),
        ("TargetLogonId", "string"),
        ("TargetSid", "string"),
        # Logon detail (4624 / 4625)
        ("LogonType", "int"),
        ("LogonTypeName", "string"),
        ("LogonProcessName", "string"),
        ("AuthenticationPackageName", "string"),
        ("LmPackageName", "string"),
        ("ImpersonationLevel", "string"),
        ("Status", "string"),
        ("SubStatus", "string"),
        ("WorkstationName", "string"),
        ("IpAddress", "string"),
        ("IpPort", "string"),
        # Process detail (4688)
        ("NewProcessName", "string"),
        ("NewProcessId", "string"),
        ("ProcessName", "string"),
        ("ProcessId", "string"),
        ("ParentProcessName", "string"),
        ("CommandLine", "string"),
        ("TokenElevationType", "string"),
        ("MandatoryLabel", "string"),
        # Service install (7045 / 4697)
        ("ServiceName", "string"),
        ("ServiceFileName", "string"),
        ("ServiceType", "string"),
        ("ServiceStartType", "string"),
        ("ServiceAccount", "string"),
        # Kerberos (4768 / 4769 / 4771)
        ("ServiceID", "string"),
        ("TicketEncryptionType", "string"),
        ("TicketOptions", "string"),
        ("TransmittedServices", "string"),
        ("PreAuthType", "string"),
        # Share access (5140 / 5145)
        ("ShareName", "string"),
        ("ShareLocalPath", "string"),
        ("RelativeTargetName", "string"),
        ("AccessMask", "string"),
        ("ObjectName", "string"),
        ("ObjectType", "string"),
    ),
    docs=f"{DOCS}/securityevent",
    description="Windows Security event log collected by the AMA/MMA agent.",
))

Event = register(TableSchema(
    name="Event",
    family="windows",
    columns=PLATFORM + (
        ("Computer", "string"),
        ("Source", "string"),
        ("EventLog", "string"),
        ("EventID", "int"),
        ("EventLevel", "int"),
        ("EventLevelName", "string"),
        ("EventCategory", "int"),
        ("UserName", "string"),
        ("RenderedDescription", "string"),
        ("ParameterXml", "string"),
        ("EventData", "string"),
        ("SourceSystemId", "string"),
        ("ManagementGroupName", "string"),
    ),
    docs=f"{DOCS}/event",
    description="Generic Windows event log. Sysmon lands here, payload inside EventData XML.",
))
