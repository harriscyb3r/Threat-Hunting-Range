"""Reveal the actual planted attack events for a hunt debrief.

The score's answer key says *what* technique was planted and *how many* events;
this returns the events themselves — the specific log rows the attacker
generated — each marked whether the analyst pinned it (found) or not (missed).
That is what turns "you surfaced 0 of 10" into a concrete "here are the ten
4769 requests you should have caught, on this host, at these times".

The rows live in Kusto, not in ground truth (which only holds the labels), so
this queries the campaign database. It unions the tables the planted techniques
touch and normalises them to one shape with `column_ifexists` + `coalesce`, so
events from SecurityEvent, DeviceProcessEvents, DnsEvents etc. come back in one
readable list keyed on `_ItemId`.
"""
from __future__ import annotations

from kusto import KustoClient, KustoError
from scenarios import attack as catalogue

# Candidate columns to normalise each unioned table down to a common shape.
_ACCOUNT = ["Account", "AccountName", "TargetUserName", "UserPrincipalName",
            "InitiatingProcessAccountName", "SubjectUserName", "RequestAccountName"]
_HOST = ["Computer", "DeviceName", "Host"]
_DETAIL = ["ProcessCommandLine", "ServiceName", "CommandLine", "RemoteUrl", "FolderPath",
           "FileName", "RegistryKey", "OperationName", "ActionType", "Activity"]


def _coalesce(cols: list[str]) -> str:
    inner = ", ".join(f'column_ifexists("{c}", "")' for c in cols)
    return f"coalesce({inner})"


def _tables_for(techniques: list[str]) -> list[str]:
    """Every table the planted techniques touch, de-duplicated. Falls back to a
    broad set if a technique has no declared tables."""
    tables: list[str] = []
    for tid in techniques:
        try:
            for t in catalogue.get(tid).tables:
                if t not in tables:
                    tables.append(t)
        except KeyError:
            continue
    if not tables:
        tables = ["SecurityEvent", "DeviceProcessEvents", "DnsEvents",
                  "DeviceNetworkEvents", "SigninLogs"]
    return tables


async def attack_events(
    client: KustoClient, db_name: str, *,
    attack_item_ids: set[str], found_item_ids: set[str],
    techniques: list[str], cap: int = 500,
) -> list[dict]:
    """The planted attack rows, normalised, each flagged found/missed."""
    if not attack_item_ids:
        return []
    ids = list(attack_item_ids)
    # Guard against an over-long IN list; the campaigns cap attack events well
    # under this, but be safe.
    idlist = ",".join(repr(i) for i in ids[:5000])
    tables = ", ".join(_tables_for(techniques))

    query = f"""
union withsource=_SrcTable {tables}
| where _ItemId in ({idlist})
| project
    TimeGenerated,
    Table = Type,
    Account = {_coalesce(_ACCOUNT)},
    Host = {_coalesce(_HOST)},
    Detail = {_coalesce(_DETAIL)},
    _ItemId
| order by TimeGenerated asc
| take {cap}
"""
    try:
        result = await client.query(db_name, query)
    except KustoError:
        return []

    out: list[dict] = []
    for row in result.dicts():
        iid = row.get("_ItemId", "")
        ts = row.get("TimeGenerated")
        out.append({
            "time": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
            "table": row.get("Table", ""),
            "account": row.get("Account", ""),
            "host": row.get("Host", ""),
            "detail": row.get("Detail", ""),
            "item_id": iid,
            "found": iid in found_item_ids,
        })
    return out
