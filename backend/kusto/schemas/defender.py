"""Microsoft Defender XDR device tables."""
from __future__ import annotations

from .base import INITIATING_PROCESS, PLATFORM, TableSchema, register

DOCS = "https://learn.microsoft.com/defender-xdr/advanced-hunting"

# Every Device* table opens with these.
_DEVICE: tuple[tuple[str, str], ...] = (
    ("DeviceId", "string"),
    ("DeviceName", "string"),
    ("ActionType", "string"),
)
_TAIL: tuple[tuple[str, str], ...] = (
    ("ReportId", "string"),
    ("MachineGroup", "string"),
)

DeviceProcessEvents = register(TableSchema(
    name="DeviceProcessEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("FileName", "string"),
        ("FolderPath", "string"),
        ("SHA1", "string"),
        ("SHA256", "string"),
        ("MD5", "string"),
        ("FileSize", "long"),
        ("ProcessVersionInfoCompanyName", "string"),
        ("ProcessVersionInfoProductName", "string"),
        ("ProcessVersionInfoProductVersion", "string"),
        ("ProcessVersionInfoInternalFileName", "string"),
        ("ProcessVersionInfoOriginalFileName", "string"),
        ("ProcessVersionInfoFileDescription", "string"),
        ("ProcessId", "int"),
        ("ProcessCommandLine", "string"),
        ("ProcessIntegrityLevel", "string"),
        ("ProcessTokenElevation", "string"),
        ("ProcessCreationTime", "datetime"),
        ("AccountDomain", "string"),
        ("AccountName", "string"),
        ("AccountSid", "string"),
        ("AccountUpn", "string"),
        ("AccountObjectId", "string"),
        ("LogonId", "string"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-deviceprocessevents-table",
    description="Process creation on onboarded devices.",
))

DeviceNetworkEvents = register(TableSchema(
    name="DeviceNetworkEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("RemoteIP", "string"),
        ("RemotePort", "int"),
        ("RemoteUrl", "string"),
        ("LocalIP", "string"),
        ("LocalPort", "int"),
        ("Protocol", "string"),
        ("LocalIPType", "string"),
        ("RemoteIPType", "string"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-devicenetworkevents-table",
    description="Outbound and inbound network connections, attributed to a process.",
))

DeviceFileEvents = register(TableSchema(
    name="DeviceFileEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("FileName", "string"),
        ("FolderPath", "string"),
        ("SHA1", "string"),
        ("SHA256", "string"),
        ("MD5", "string"),
        ("FileOriginUrl", "string"),
        ("FileOriginReferrerUrl", "string"),
        ("FileOriginIP", "string"),
        ("PreviousFolderPath", "string"),
        ("PreviousFileName", "string"),
        ("FileSize", "long"),
        ("SensitivityLabel", "string"),
        ("IsAzureInfoProtectionApplied", "bool"),
        ("RequestProtocol", "string"),
        ("RequestSourceIP", "string"),
        ("RequestSourcePort", "int"),
        ("RequestAccountName", "string"),
        ("RequestAccountDomain", "string"),
        ("RequestAccountSid", "string"),
        ("ShareName", "string"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-devicefileevents-table",
    description="File create, modify, rename and delete.",
))

DeviceRegistryEvents = register(TableSchema(
    name="DeviceRegistryEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("RegistryKey", "string"),
        ("RegistryValueType", "string"),
        ("RegistryValueName", "string"),
        ("RegistryValueData", "string"),
        ("PreviousRegistryKey", "string"),
        ("PreviousRegistryValueName", "string"),
        ("PreviousRegistryValueData", "string"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-deviceregistryevents-table",
    description="Registry key and value changes.",
))

DeviceLogonEvents = register(TableSchema(
    name="DeviceLogonEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("LogonType", "string"),
        ("AccountDomain", "string"),
        ("AccountName", "string"),
        ("AccountSid", "string"),
        ("AccountUpn", "string"),
        ("AccountObjectId", "string"),
        ("LogonId", "string"),
        ("IsLocalAdmin", "bool"),
        ("Protocol", "string"),
        ("FailureReason", "string"),
        ("IsLocalLogon", "bool"),
        ("RemoteIP", "string"),
        ("RemoteIPType", "string"),
        ("RemotePort", "int"),
        ("RemoteDeviceName", "string"),
        ("AdditionalFields", "dynamic"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-devicelogonevents-table",
    description="Sign-ins to onboarded devices, including network and RDP logons.",
))

DeviceImageLoadEvents = register(TableSchema(
    name="DeviceImageLoadEvents",
    family="defender",
    columns=PLATFORM + _DEVICE + (
        ("FileName", "string"),
        ("FolderPath", "string"),
        ("SHA1", "string"),
        ("SHA256", "string"),
        ("MD5", "string"),
        ("FileSize", "long"),
    ) + INITIATING_PROCESS + _TAIL,
    docs=f"{DOCS}-deviceimageloadevents-table",
    description="DLL and module loads.",
))

IdentityLogonEvents = register(TableSchema(
    name="IdentityLogonEvents",
    family="defender",
    columns=PLATFORM + (
        ("ActionType", "string"),
        ("Application", "string"),
        ("LogonType", "string"),
        ("Protocol", "string"),
        ("FailureReason", "string"),
        ("AccountName", "string"),
        ("AccountDomain", "string"),
        ("AccountUpn", "string"),
        ("AccountSid", "string"),
        ("AccountObjectId", "string"),
        ("AccountDisplayName", "string"),
        ("DeviceName", "string"),
        ("DeviceType", "string"),
        ("OSPlatform", "string"),
        ("IPAddress", "string"),
        ("Port", "int"),
        ("DestinationDeviceName", "string"),
        ("DestinationIPAddress", "string"),
        ("DestinationPort", "int"),
        ("TargetDeviceName", "string"),
        ("TargetAccountDisplayName", "string"),
        ("Location", "string"),
        ("ISP", "string"),
        ("ReportId", "string"),
        ("AdditionalFields", "dynamic"),
    ),
    docs=f"{DOCS}-identitylogonevents-table",
    description="Defender for Identity: authentication seen on domain controllers.",
))

AlertEvidence = register(TableSchema(
    name="AlertEvidence",
    family="defender",
    columns=PLATFORM + (
        ("AlertId", "string"),
        ("Title", "string"),
        ("Categories", "dynamic"),
        ("AttackTechniques", "dynamic"),
        ("ServiceSource", "string"),
        ("DetectionSource", "string"),
        ("EntityType", "string"),
        ("EvidenceRole", "string"),
        ("EvidenceDirection", "string"),
        ("FileName", "string"),
        ("FolderPath", "string"),
        ("SHA1", "string"),
        ("SHA256", "string"),
        ("RemoteIP", "string"),
        ("RemoteUrl", "string"),
        ("AccountName", "string"),
        ("AccountDomain", "string"),
        ("AccountSid", "string"),
        ("AccountObjectId", "string"),
        ("AccountUpn", "string"),
        ("DeviceId", "string"),
        ("DeviceName", "string"),
        ("Severity", "string"),
        ("ProcessCommandLine", "string"),
        ("AdditionalFields", "dynamic"),
    ),
    docs=f"{DOCS}-alertevidence-table",
    description="Entities attached to Defender alerts. Useful for alert-to-hunt pivots.",
))
