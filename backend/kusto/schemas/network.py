"""DNS, firewall, proxy and IIS tables."""
from __future__ import annotations

from .base import PLATFORM, TableSchema, register

DOCS = "https://learn.microsoft.com/azure/azure-monitor/reference/tables"

DnsEvents = register(TableSchema(
    name="DnsEvents",
    family="network",
    columns=PLATFORM + (
        ("Computer", "string"),
        ("SubType", "string"),          # LookupQuery | DynamicRegistration | ...
        ("ClientIP", "string"),
        ("Name", "string"),             # the queried name
        ("QueryType", "string"),        # A | AAAA | TXT | CNAME | MX | NULL ...
        ("ResultCode", "int"),
        ("Result", "string"),
        ("IPAddresses", "string"),      # comma-separated answers
        ("EventOriginalType", "string"),
        ("Port", "int"),
        ("Protocol", "string"),
        ("TransactionID", "int"),
    ),
    docs=f"{DOCS}/dnsevents",
    description="Microsoft DNS server analytic logs. Primary source for tunnelling and C2 hunts.",
))

CommonSecurityLog = register(TableSchema(
    name="CommonSecurityLog",
    family="network",
    columns=PLATFORM + (
        ("DeviceVendor", "string"),
        ("DeviceProduct", "string"),
        ("DeviceVersion", "string"),
        ("DeviceEventClassID", "string"),
        ("Activity", "string"),
        ("LogSeverity", "string"),
        ("DeviceName", "string"),
        ("DeviceAction", "string"),
        ("SimplifiedDeviceAction", "string"),
        ("CommunicationDirection", "string"),
        ("SourceIP", "string"),
        ("SourcePort", "int"),
        ("SourceHostName", "string"),
        ("SourceUserName", "string"),
        ("SourceTranslatedAddress", "string"),
        ("SourceTranslatedPort", "int"),
        ("DestinationIP", "string"),
        ("DestinationPort", "int"),
        ("DestinationHostName", "string"),
        ("DestinationUserName", "string"),
        ("DestinationTranslatedAddress", "string"),
        ("Protocol", "string"),
        ("ApplicationProtocol", "string"),
        ("RequestURL", "string"),
        ("RequestMethod", "string"),
        ("RequestClientApplication", "string"),
        ("SentBytes", "long"),
        ("ReceivedBytes", "long"),
        ("DeviceInboundInterface", "string"),
        ("DeviceOutboundInterface", "string"),
        ("ExternalID", "string"),
        ("Message", "string"),
        ("Computer", "string"),
        ("DeviceCustomString1", "string"),
        ("DeviceCustomString1Label", "string"),
        ("DeviceCustomString2", "string"),
        ("DeviceCustomString2Label", "string"),
        ("DeviceCustomNumber1", "long"),
        ("DeviceCustomNumber1Label", "string"),
    ),
    docs=f"{DOCS}/commonsecuritylog",
    description="CEF from network appliances. Palo Alto and Fortinet firewalls in this range.",
))

W3CIISLog = register(TableSchema(
    name="W3CIISLog",
    family="network",
    columns=PLATFORM + (
        ("Computer", "string"),
        ("sSiteName", "string"),
        ("sComputerName", "string"),
        ("sIP", "string"),
        ("csMethod", "string"),
        ("csUriStem", "string"),
        ("csUriQuery", "string"),
        ("sPort", "int"),
        ("csUserName", "string"),
        ("cIP", "string"),
        ("csUserAgent", "string"),
        ("csReferer", "string"),
        ("csHost", "string"),
        ("scStatus", "int"),
        ("scSubStatus", "int"),
        ("scWin32Status", "int"),
        ("scBytes", "long"),
        ("csBytes", "long"),
        ("TimeTaken", "int"),
        ("csCookie", "string"),
    ),
    docs=f"{DOCS}/w3ciislog",
    description="IIS web server logs. Web shell and exploitation hunts.",
))

AzureNetworkAnalytics_CL = register(TableSchema(
    name="AzureNetworkAnalytics_CL",
    family="network",
    columns=PLATFORM + (
        ("FlowType_s", "string"),
        ("SrcIP_s", "string"),
        ("DestIP_s", "string"),
        ("DestPort_d", "real"),
        ("L4Protocol_s", "string"),
        ("L7Protocol_s", "string"),
        ("FlowDirection_s", "string"),
        ("FlowStatus_s", "string"),
        ("NSGRule_s", "string"),
        ("NSGList_s", "string"),
        ("AllowedOutFlows_d", "real"),
        ("DeniedOutFlows_d", "real"),
        ("AllowedInFlows_d", "real"),
        ("DeniedInFlows_d", "real"),
        ("OutboundBytes_d", "real"),
        ("InboundBytes_d", "real"),
        ("VM1_s", "string"),
        ("Subnet1_s", "string"),
        ("SubType_s", "string"),
    ),
    docs=f"{DOCS}/azurenetworkanalytics-cl",
    description="NSG flow logs via Traffic Analytics. Note the _s/_d custom-log "
                "suffixes — real, and a common source of query mistakes.",
))
