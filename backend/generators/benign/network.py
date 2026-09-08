"""Benign DNS and firewall telemetry.

DNS is the highest-volume table in the range, and deliberately so. It is where
tunnelling, DGA and beaconing hunts live, and all three depend on the *shape* of
the baseline: a realistic popularity curve with a long tail of one-off lookups,
plus CDN hostnames that are long, random-looking and completely benign.

Get that tail wrong and "high-entropy subdomain" becomes a perfect detector,
which is not how it behaves against a real network.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Iterator

from org import catalog

from ..common import (GenContext, any_time, public_ip, spread_over_days,
                      work_time)

# CDN and cloud hostnames that look like DGA output but are entirely routine.
# Without these, entropy-based DNS hunts return a clean answer and teach a
# lesson that does not survive contact with production.
CDN_PATTERNS = [
    "{h}.cloudfront.net", "{h}.akamaiedge.net", "{h}.azureedge.net",
    "{h}.blob.core.windows.net", "{h}.s3.amazonaws.com", "{h}.fastly.net",
    "{h}-atlas.cdn.dashhudson.com", "{h}.digitaloceanspaces.com",
    "{h}.trafficmanager.net", "{h}.cloudapp.azure.com",
]

INTERNAL_SUFFIXES = ["_ldap._tcp.dc._msdcs", "_kerberos._tcp.dc._msdcs",
                     "_gc._tcp", "wpad", "isatap"]


def _random_label(ctx: GenContext, length: int) -> str:
    return "".join(ctx.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                   for _ in range(length))


def dns_events(ctx: GenContext, count: int) -> Iterator[dict]:
    org = ctx.org
    workstations = org.workstations
    dns_server = f"{org.domain_controllers[0].name.lower()}.{org.domain}" \
        if org.domain_controllers else f"srv-dc-01.{org.domain}"

    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            device = ctx.rng.choice(workstations)
            user = org.user(device.primary_user) if device.primary_user else ctx.pick_human()
            ts = work_time(ctx, day, user)

            roll = ctx.rng.random()
            if roll < 0.62:
                name = ctx.weighted(catalog.POPULAR_DOMAINS)[0]
                if ctx.rng.random() < 0.45:
                    name = f"{ctx.rng.choice(['www', 'api', 'cdn', 'static', 'login', 'mail'])}.{name}"
            elif roll < 0.80:
                # CDN hostnames: long, high-entropy, benign.
                name = ctx.rng.choice(CDN_PATTERNS).format(
                    h=_random_label(ctx, ctx.rng.randint(8, 22)))
            elif roll < 0.92:
                # Internal AD lookups.
                name = f"{ctx.rng.choice(INTERNAL_SUFFIXES)}.{org.domain}"
            else:
                # Long tail: sites someone visited once.
                name = (f"{_random_label(ctx, ctx.rng.randint(4, 11))}."
                        f"{ctx.rng.choice(['com', 'net', 'io', 'com.au', 'org', 'co'])}")

            qtype = ctx.weighted(catalog.DNS_QUERY_TYPES)[0]
            nxdomain = ctx.rng.random() < 0.06
            result_code = 3 if nxdomain else 0

            row = ctx.platform("DnsEvents", ts)
            row.update({
                "Computer": dns_server,
                "SubType": "LookupQuery",
                "ClientIP": device.ip,
                "Name": name,
                "QueryType": qtype,
                "ResultCode": result_code,
                "Result": "NXDOMAIN" if nxdomain else "Success",
                "IPAddresses": "" if nxdomain else public_ip(ctx.rng),
                "EventOriginalType": "256",
                "Port": 53,
                "Protocol": "UDP",
                "TransactionID": ctx.rng.randint(1, 65535),
            })
            yield row


def firewall_events(ctx: GenContext, count: int) -> Iterator[dict]:
    """Palo Alto CEF through CommonSecurityLog.

    Includes a steady trickle of denies — port scans from the internet hitting
    the edge, and internal hosts reaching for things policy blocks. A range
    where every flow is allowed makes `DeviceAction == "deny"` a free win.
    """
    org = ctx.org
    net = org.network
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            outbound = ctx.rng.random() < 0.86
            device = ctx.rng.choice(org.devices)
            if outbound:
                src_ip, dst_ip = device.ip, public_ip(ctx.rng)
                dst_port = ctx.rng.choices([443, 80, 53, 22, 3389, 587, 993],
                                           weights=[.72, .12, .07, .03, .02, .02, .02])[0]
                direction = "Outbound"
                action = "allow" if ctx.rng.random() < 0.94 else "deny"
                app = {443: "ssl", 80: "web-browsing", 53: "dns", 22: "ssh",
                       3389: "ms-rdp", 587: "smtp", 993: "imap"}.get(dst_port, "unknown-tcp")
            else:
                src_ip, dst_ip = public_ip(ctx.rng), ctx.rng.choice(net.egress_ips)
                dst_port = ctx.rng.choices([443, 80, 22, 3389, 445, 1433, 8080],
                                           weights=[.35, .20, .12, .12, .10, .06, .05])[0]
                direction = "Inbound"
                # Most unsolicited inbound is dropped; some is legitimate traffic
                # to the published web server.
                action = "allow" if dst_port in (443, 80) and ctx.rng.random() < 0.7 else "deny"
                app = "ssl" if dst_port == 443 else "web-browsing" if dst_port == 80 else "not-applicable"

            ts = any_time(ctx, day)
            sent = ctx.rng.randint(200, 400_000)
            recv = ctx.rng.randint(200, 3_000_000) if action == "allow" else 0

            row = ctx.platform("CommonSecurityLog", ts)
            row.update({
                "DeviceVendor": net.firewall_vendor,
                "DeviceProduct": net.firewall_product,
                "DeviceVersion": "11.1.2",
                "DeviceEventClassID": "traffic",
                "Activity": "TRAFFIC",
                "LogSeverity": "3" if action == "allow" else "5",
                "DeviceName": net.firewall_name,
                "DeviceAction": action,
                "SimplifiedDeviceAction": action.capitalize(),
                "CommunicationDirection": direction,
                "SourceIP": src_ip,
                "SourcePort": ctx.rng.randint(1024, 65535),
                "SourceHostName": device.name if outbound else "",
                "DestinationIP": dst_ip,
                "DestinationPort": dst_port,
                "DestinationTranslatedAddress": ctx.rng.choice(net.egress_ips) if outbound else "",
                "Protocol": "TCP" if dst_port != 53 else "UDP",
                "ApplicationProtocol": app,
                "SentBytes": sent,
                "ReceivedBytes": recv,
                "DeviceInboundInterface": "ethernet1/2" if outbound else "ethernet1/1",
                "DeviceOutboundInterface": "ethernet1/1" if outbound else "ethernet1/2",
                "ExternalID": str(ctx.rng.randint(100000, 999999)),
                "Computer": net.firewall_name,
                "DeviceCustomString1": "trust-to-untrust" if outbound else "untrust-to-trust",
                "DeviceCustomString1Label": "Rule",
                "DeviceCustomString2": app,
                "DeviceCustomString2Label": "Application",
            })
            yield row
