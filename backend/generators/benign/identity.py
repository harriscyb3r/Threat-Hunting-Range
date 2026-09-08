"""Benign Entra ID and Microsoft 365 telemetry.

The realism that matters here is the *failure* mix. A tenant where every
sign-in succeeds makes "failed logons" a perfect attack signal, which teaches
exactly the wrong instinct. Real tenants are full of benign failure:

* 50126 — wrong password, constantly, from people who just got back from leave
* 50058 — silent sign-in failure, enormous volume, entirely uninteresting
* 50076/50079 — MFA required / MFA registration, routine
* 53003 — blocked by conditional access, routine when someone is off-network
* 50173 — expired refresh token after a password change

Legacy authentication is present too, from two service accounts that genuinely
still need it. Any "legacy auth = compromise" query has to reckon with them.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Iterator

from org import catalog

from ..common import (GenContext, day_weight, days_in_window, public_ip,
                      spread_over_days, work_time)

# (ResultType, ResultDescription, weight)
SIGNIN_RESULTS = [
    ("0", "", 0.855),
    ("50126", "Invalid username or password or Invalid on-premise username or password.", 0.045),
    ("50058", "Session information is not sufficient for single-sign-on.", 0.035),
    ("50076", "Due to a configuration change made by your administrator, or because you moved to "
              "a new location, you must use multi-factor authentication.", 0.020),
    ("50173", "The provided grant has expired due to it being revoked.", 0.015),
    ("53003", "Access has been blocked by Conditional Access policies.", 0.012),
    ("50074", "Strong Authentication is required.", 0.010),
    ("50079", "User needs to enroll for second factor authentication.", 0.005),
    ("500121", "Authentication failed during strong authentication request.", 0.003),
]

NONINTERACTIVE_RESULTS = [
    ("0", "", 0.94),
    ("50058", "Session information is not sufficient for single-sign-on.", 0.030),
    ("50173", "The provided grant has expired due to it being revoked.", 0.015),
    ("700082", "The refresh token has expired due to inactivity.", 0.010),
    ("50097", "Device authentication is required.", 0.005),
]

# Service accounts that legitimately use legacy protocols. Their presence is the
# whole reason a legacy-auth hunt needs judgement rather than a one-line filter.
LEGACY_AUTH_ACCOUNTS = {"svc-scanner", "svc-iis"}


def _location_details(ctx: GenContext, city: str, country: str, cc: str) -> dict:
    return {
        "city": city,
        "state": {"Melbourne": "Victoria", "Sydney": "New South Wales",
                  "Brisbane": "Queensland", "Perth": "Western Australia",
                  "Adelaide": "South Australia"}.get(city, city),
        "countryOrRegion": cc,
        "geoCoordinates": {
            "latitude": round(ctx.rng.uniform(-45, 1), 4),
            "longitude": round(ctx.rng.uniform(112, 178), 4),
        },
    }


def _device_detail(ctx: GenContext, user, device) -> dict:
    if device is None:
        return {"deviceId": "", "operatingSystem": "", "browser": "", "isCompliant": False}
    browser = "Edge 131.0.0" if "Edg" in user.user_agent else "Chrome 131.0.0"
    return {
        "deviceId": device.device_id,
        "displayName": device.name,
        "operatingSystem": {"Windows11": "Windows 11", "Windows10": "Windows 10",
                            "macOS": "MacOs"}.get(device.os, device.os),
        "browser": browser,
        "isCompliant": True,
        "isManaged": True,
        "trustType": "Azure AD joined",
    }


def _signin_row(ctx: GenContext, table: str, ts, user, interactive: bool) -> dict[str, Any]:
    org = ctx.org
    device = ctx.device_for(user)
    app_name, app_id, _ = ctx.weighted(catalog.ENTRA_APPS)

    results = SIGNIN_RESULTS if interactive else NONINTERACTIVE_RESULTS
    result_type, result_desc, _ = ctx.weighted(results)
    success = result_type == "0"

    # Where from: mostly the office egress, sometimes home, rarely travelling.
    city, country, cc = user.location.city, user.location.country, user.location.country_code
    roll = ctx.rng.random()
    if roll < 0.62:
        ip = ctx.rng.choice(org.network.egress_ips)
    elif roll < 0.93:
        ip = user.home_ip
    else:
        ip = public_ip(ctx.rng)
        if user.travels and ctx.rng.random() < 0.5:
            city, country, cc, _off = ctx.rng.choice(catalog.TRAVEL_DESTINATIONS)

    if user.sam in LEGACY_AUTH_ACCOUNTS:
        client_app = ctx.rng.choice(["Exchange ActiveSync", "IMAP4", "Other clients"])
    else:
        client_app = ctx.weighted(catalog.CLIENT_APPS)[0]

    mfa_used = interactive and success and ctx.rng.random() < 0.72
    ca_status = "success" if ctx.rng.random() < 0.93 else "notApplied"

    row = ctx.platform(table, ts)
    row.update({
        "OperationName": "Sign-in activity",
        "OperationVersion": "1.0",
        "Category": "SignInLogs" if interactive else "NonInteractiveUserSignInLogs",
        "ResultType": result_type,
        "ResultSignature": "None",
        "ResultDescription": result_desc,
        "DurationMs": ctx.rng.randint(20, 900),
        "CorrelationId": ctx.item_id(),
        "Identity": user.display_name,
        "Level": "4",
        "Location": cc,
        "AppDisplayName": app_name,
        "AppId": app_id,
        "AppliedConditionalAccessPolicies": [],
        "AuthenticationDetails": [{
            "authenticationStepDateTime": ts.isoformat(),
            "authenticationMethod": "Previously satisfied" if not mfa_used
                                    else ctx.rng.choice(["Microsoft Authenticator push notification",
                                                         "Mobile app notification",
                                                         "Password", "Windows Hello for Business"]),
            "succeeded": success,
        }],
        "AuthenticationMethodsUsed": [],
        "AuthenticationRequirement": "multiFactorAuthentication" if mfa_used
                                     else "singleFactorAuthentication",
        "ClientAppUsed": client_app,
        "ConditionalAccessStatus": ca_status,
        "CreatedDateTime": ts,
        "DeviceDetail": _device_detail(ctx, user, device),
        "HomeTenantId": org.tenant_id,
        "IPAddress": ip,
        "IsInteractive": interactive,
        "IsRisky": False,
        "LocationDetails": _location_details(ctx, city, country, cc),
        "NetworkLocationDetails": [],
        "ProcessingTimeInMs": ctx.rng.randint(10, 320),
        "ResourceDisplayName": app_name,
        "ResourceTenantId": org.tenant_id,
        "RiskDetail": "none",
        "RiskEventTypes_V2": [],
        "RiskLevelAggregated": "none",
        "RiskLevelDuringSignIn": "none",
        "RiskState": "none",
        "SignInIdentifier": user.upn,
        "SignInIdentifierType": "userPrincipalName",
        "Status": {"errorCode": int(result_type), "failureReason": result_desc or "Other."},
        "TokenIssuerType": "AzureAD",
        "UserAgent": user.user_agent,
        "UserDisplayName": user.display_name,
        "UserId": user.object_id,
        "UserPrincipalName": user.upn,
        "UserType": "Member",
    })
    return row


def signin_logs(ctx: GenContext, count: int) -> Iterator[dict]:
    """Interactive sign-ins."""
    humans = ctx.org.humans
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            user = ctx.rng.choice(humans)
            yield _signin_row(ctx, "SigninLogs", work_time(ctx, day, user), user, True)


def non_interactive_signin_logs(ctx: GenContext, count: int) -> Iterator[dict]:
    """Token refreshes. Bursty — a client refreshes several times in a few
    minutes, which is why naive per-user rate thresholds fire on nothing useful."""
    humans = ctx.org.humans
    for day, n in spread_over_days(ctx, count):
        emitted = 0
        while emitted < n:
            user = ctx.rng.choice(humans)
            base = work_time(ctx, day, user)
            burst = min(ctx.rng.randint(1, 5), n - emitted)
            for i in range(burst):
                ts = base + timedelta(seconds=ctx.rng.randint(0, 240) + i * 3)
                yield _signin_row(ctx, "AADNonInteractiveUserSignInLogs", ts, user, False)
                emitted += 1


def audit_logs(ctx: GenContext, count: int) -> Iterator[dict]:
    """Directory changes. Low volume, high value — this is where an attacker
    adding app credentials or a role assignment shows up."""
    org = ctx.org
    admins = org.admins or org.humans[:1]
    activities = [
        ("Add member to group", "GroupManagement", 0.26),
        ("Update user", "UserManagement", 0.20),
        ("Remove member from group", "GroupManagement", 0.14),
        ("Add user", "UserManagement", 0.08),
        ("Reset user password", "UserManagement", 0.08),
        ("Update group", "GroupManagement", 0.06),
        ("Delete user", "UserManagement", 0.04),
        ("Update application", "ApplicationManagement", 0.04),
        ("Update device", "DeviceManagement", 0.04),
        ("Consent to application", "ApplicationManagement", 0.03),
        ("Add app role assignment to service principal", "ApplicationManagement", 0.02),
        ("Update conditional access policy", "Policy", 0.01),
    ]
    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            actor = ctx.rng.choice(admins)
            target = ctx.rng.choice(org.humans)
            activity, category, _ = ctx.weighted(activities)
            ts = work_time(ctx, day, actor)

            row = ctx.platform("AuditLogs", ts)
            row.update({
                "OperationName": activity,
                "OperationVersion": "1.0",
                "Category": category,
                "ResultType": "",
                "ResultDescription": "",
                "ResultReason": "",
                "CorrelationId": ctx.item_id(),
                "Level": "4",
                "DurationMs": 0,
                "Identity": actor.display_name,
                "ActivityDisplayName": activity,
                "ActivityDateTime": ts,
                "LoggedByService": "Core Directory",
                "AADOperationType": ("Add" if activity.startswith("Add")
                                     else "Delete" if activity.startswith("Delete")
                                     else "Update"),
                "InitiatedBy": {"user": {
                    "id": actor.object_id,
                    "displayName": actor.display_name,
                    "userPrincipalName": actor.upn,
                    "ipAddress": ctx.rng.choice(org.network.egress_ips),
                }},
                "TargetResources": [{
                    "id": target.object_id,
                    "displayName": target.display_name,
                    "type": "User",
                    "userPrincipalName": target.upn,
                    "modifiedProperties": [],
                }],
                "AdditionalDetails": [],
            })
            yield row


def office_activity(ctx: GenContext, count: int) -> Iterator[dict]:
    """Exchange, SharePoint and OneDrive."""
    org = ctx.org
    ops = [
        ("MailItemsAccessed", "Exchange", "ExchangeItemAggregated", 0.24),
        ("FileAccessed", "SharePoint", "SharePointFileOperation", 0.18),
        ("FileModified", "SharePoint", "SharePointFileOperation", 0.12),
        ("Send", "Exchange", "ExchangeItem", 0.10),
        ("FileDownloaded", "SharePoint", "SharePointFileOperation", 0.08),
        ("FileUploaded", "OneDrive", "SharePointFileOperation", 0.07),
        ("UserLoggedIn", "AzureActiveDirectory", "AzureActiveDirectoryStsLogon", 0.06),
        ("MailboxLogin", "Exchange", "ExchangeItem", 0.05),
        ("FileSyncDownloadedFull", "OneDrive", "SharePointFileOperation", 0.04),
        ("Update", "Exchange", "ExchangeItem", 0.03),
        ("New-InboxRule", "Exchange", "ExchangeAdmin", 0.02),
        ("FileDeleted", "SharePoint", "SharePointFileOperation", 0.01),
    ]
    files = ["Q3 Forecast.xlsx", "Board Pack.pptx", "Client Agreement.docx",
             "Timesheet.xlsx", "Runbook.docx", "Pricing Model.xlsx",
             "Incident Report.docx", "Roadmap.pptx", "Payroll Summary.xlsx"]

    for day, n in spread_over_days(ctx, count):
        for _ in range(n):
            user = ctx.rng.choice(org.humans)
            op, workload, record_type, _ = ctx.weighted(ops)
            ts = work_time(ctx, day, user)
            fname = ctx.rng.choice(files)

            row = ctx.platform("OfficeActivity", ts)
            row.update({
                "OfficeWorkload": workload,
                "Operation": op,
                "RecordType": record_type,
                "OfficeObjectId": f"https://harbourline.sharepoint.com/sites/"
                                  f"{user.department.lower()}/Shared Documents/{fname}",
                "UserId": user.upn,
                "UserKey": user.object_id,
                "UserType": "Regular",
                "ClientIP": ctx.rng.choice(org.network.egress_ips),
                "UserAgent": user.user_agent,
                "ResultStatus": "Succeeded",
                "OrganizationId": org.tenant_id,
                "OrganizationName": org.domain,
                "Site_Url": f"https://harbourline.sharepoint.com/sites/{user.department.lower()}/",
                "SourceFileName": fname if "File" in op else "",
                "SourceFileExtension": fname.rsplit(".", 1)[-1] if "File" in op else "",
                "MailboxOwnerUPN": user.upn if workload == "Exchange" else "",
                "ClientInfoString": "Client=OWA;Action=ViaProxy" if workload == "Exchange" else "",
                "Parameters": [],
            })
            yield row
