"""KQL detection -> Sigma rule (best-effort).

A saved detection in the range is KQL. Sigma is the portable format a hunter
puts in a portfolio and ports to other SIEMs, so the Act phase offers a Sigma
equivalent. This is a *best-effort* translation of the common filter shapes, not
a general KQL-to-Sigma compiler — that problem is genuinely hard (KQL has joins,
summarize, series functions Sigma has no vocabulary for).

The output is therefore always marked DRAFT and carries a note when the query
used constructs Sigma cannot express, so the analyst knows to finish it by hand
rather than trusting a silent partial translation. Honest-but-incomplete beats
plausible-but-wrong, especially for something that ends up in a portfolio.

The generated YAML follows the SigmaHQ specification: logsource by
product/service/category, a detection block of named selections combined by a
condition, plus level, status, tags (ATT&CK) and falsepositives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# Map our Kusto tables to Sigma logsource. Sigma's taxonomy is coarser than the
# table set, so several tables share a logsource — which is correct: Sigma
# describes the log category, not the specific table.
_LOGSOURCE: dict[str, dict[str, str]] = {
    "DeviceProcessEvents": {"product": "windows", "category": "process_creation"},
    "SecurityEvent": {"product": "windows", "service": "security"},
    "Event": {"product": "windows", "service": "sysmon"},
    "DeviceNetworkEvents": {"product": "windows", "category": "network_connection"},
    "DeviceFileEvents": {"product": "windows", "category": "file_event"},
    "DeviceRegistryEvents": {"product": "windows", "category": "registry_event"},
    "DeviceLogonEvents": {"product": "windows", "category": "authentication"},
    "DeviceImageLoadEvents": {"product": "windows", "category": "image_load"},
    "SigninLogs": {"product": "azure", "service": "signinlogs"},
    "AADNonInteractiveUserSignInLogs": {"product": "azure", "service": "signinlogs"},
    "AuditLogs": {"product": "azure", "service": "auditlogs"},
    "OfficeActivity": {"product": "m365", "service": "threat_management"},
    "CloudAppEvents": {"product": "m365", "service": "cloudappevents"},
    "DnsEvents": {"product": "windows", "category": "dns_query"},
    "CommonSecurityLog": {"category": "firewall"},
    "W3CIISLog": {"category": "webserver"},
}

# Kusto field -> Sigma field, where the names differ. Sigma uses the
# process_creation taxonomy (Image, CommandLine, ParentImage), not the Defender
# column names, so a portable rule has to be renamed.
_FIELD_MAP: dict[str, str] = {
    "FolderPath": "Image",
    "FileName": "Image",
    "ProcessCommandLine": "CommandLine",
    "InitiatingProcessFolderPath": "ParentImage",
    "InitiatingProcessFileName": "ParentImage",
    "InitiatingProcessCommandLine": "ParentCommandLine",
    "NewProcessName": "Image",
    "ParentProcessName": "ParentImage",
    "AccountName": "User",
    "RemoteUrl": "DestinationHostname",
    "RemoteIP": "DestinationIp",
    "RemotePort": "DestinationPort",
    "RegistryKey": "TargetObject",
    "RegistryValueData": "Details",
}

# Constructs Sigma cannot represent. Their presence forces a warning.
_UNSUPPORTED = [
    (r"\bjoin\b", "join"),
    (r"\bsummarize\b", "summarize / aggregation"),
    (r"\bmake-series\b", "make-series"),
    (r"\bevaluate\b", "evaluate plugin"),
    (r"\bmv-expand\b", "mv-expand"),
    (r"\bserers?_decompose", "series functions"),
    (r"\bcount\s*\(\)\s*>", "count threshold"),
    (r"\bdcount\b", "dcount"),
    (r"\brow_window_session\b", "row_window_session"),
    (r"\bprev\s*\(", "prev()/next()"),
]


@dataclass
class SigmaResult:
    yaml: str
    warnings: list[str] = field(default_factory=list)
    table: str = ""

    @property
    def complete(self) -> bool:
        return not self.warnings


@dataclass
class _Condition:
    field: str
    op: str          # equals | contains | startswith | endswith | in | re
    value: object


def _first_table(csl: str) -> str | None:
    """The table a query starts from — its logsource."""
    for line in csl.splitlines():
        line = line.strip()
        if not line or line.startswith("//") or line.startswith("let "):
            continue
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", line)
        if m and m.group(1) in _LOGSOURCE:
            return m.group(1)
        # Stop at the first non-comment content line.
        break
    # Fall back to a scan of the whole query.
    for table in _LOGSOURCE:
        if re.search(rf"\b{re.escape(table)}\b", csl):
            return table
    return None


def _parse_where(csl: str) -> tuple[list[_Condition], list[str]]:
    """Extract simple field/value predicates from `where` clauses.

    Deliberately narrow: `Field == "x"`, `Field has "x"`, `Field in (...)`,
    `Field startswith/endswith/contains "x"`, `Field matches regex "x"`. Anything
    outside that (arithmetic, function calls, nested parens) is skipped and
    reported, so the rule never silently omits a condition.
    """
    conditions: list[_Condition] = []
    skipped: list[str] = []

    # Grab the text of every `where ...` up to the next pipe or newline.
    for m in re.finditer(r"\bwhere\b(.+?)(?=\n\s*\||\n\s*$|\Z)", csl, re.DOTALL):
        clause = m.group(1).strip()
        # Split on top-level ' and ' only (naive: no paren tracking, good enough
        # for the flat predicates this handles).
        parts = re.split(r"\band\b", clause, flags=re.IGNORECASE)
        for part in parts:
            part = part.strip()
            cond, why = _parse_predicate(part)
            if cond:
                conditions.append(cond)
            elif why:
                skipped.append(why)
    return conditions, skipped


def _parse_predicate(text: str) -> tuple[_Condition | None, str]:
    text = text.strip().strip("()").strip()
    if not text:
        return None, ""

    # Field in ("a", "b", ...)
    m = re.match(r'([A-Za-z_]\w*)\s+in[~]?\s*\((.+)\)', text, re.IGNORECASE)
    if m:
        values = re.findall(r'"([^"]*)"', m.group(2))
        if values:
            return _Condition(m.group(1), "in", values), ""

    # Field has_any (...)  -> Sigma "contains" list
    m = re.match(r'([A-Za-z_]\w*)\s+has_any\s*\((.+)\)', text, re.IGNORECASE)
    if m:
        values = re.findall(r'"([^"]*)"', m.group(2))
        if values:
            return _Condition(m.group(1), "contains", values), ""

    # Field OP "value"
    m = re.match(
        r'([A-Za-z_]\w*)\s*(==|=~|!=|has|contains|startswith|endswith|'
        r'matches\s+regex)\s*"([^"]*)"',
        text, re.IGNORECASE)
    if m:
        field, op, value = m.group(1), m.group(2).lower(), m.group(3)
        if op in ("==", "=~"):
            return _Condition(field, "equals", value), ""
        if op == "has" or op == "contains":
            return _Condition(field, "contains", value), ""
        if op == "startswith":
            return _Condition(field, "startswith", value), ""
        if op == "endswith":
            return _Condition(field, "endswith", value), ""
        if op.startswith("matches"):
            return _Condition(field, "re", value), ""
        if op == "!=":
            return _Condition(field, "not_equals", value), ""

    # Numeric equality, e.g. EventID == 4769.
    m = re.match(r'([A-Za-z_]\w*)\s*==\s*(\d+)', text)
    if m:
        return _Condition(m.group(1), "equals", int(m.group(2))), ""

    return None, f'could not translate predicate: `{text[:60]}`'


def _sigma_field(field: str, op: str) -> str:
    base = _FIELD_MAP.get(field, field)
    suffix = {
        "contains": "|contains", "startswith": "|startswith",
        "endswith": "|endswith", "re": "|re",
    }.get(op, "")
    return base + suffix


def _yaml_value(v: object) -> str:
    """Render a scalar or list as YAML, quoting where needed."""
    if isinstance(v, list):
        return "\n" + "\n".join(f"            - {_yaml_scalar(x)}" for x in v)
    return " " + _yaml_scalar(v)


def _yaml_scalar(v: object) -> str:
    if isinstance(v, int):
        return str(v)
    s = str(v)
    if s == "" or re.search(r'[:#\[\]{}",\'\\]', s) or s != s.strip():
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def to_sigma(
    title: str, csl: str, *, techniques: list[str] | None = None,
    description: str = "", level: str = "medium", fp_notes: str = "",
    author: str = "Hunting Range",
) -> SigmaResult:
    warnings: list[str] = []
    table = _first_table(csl)

    for pattern, label in _UNSUPPORTED:
        if re.search(pattern, csl, re.IGNORECASE):
            warnings.append(
                f"query uses `{label}`, which Sigma cannot express — the detection "
                "logic below is partial and must be completed by hand")

    conditions, skipped = _parse_where(csl)
    warnings.extend(skipped)

    if not table:
        warnings.append("could not identify a Sigma logsource for this query")
        logsource = {"category": "unknown"}
    else:
        logsource = _LOGSOURCE[table]

    # Build the detection block. Each condition becomes one selection key; a list
    # value becomes a YAML sequence (Sigma OR); multiple keys AND together.
    sel_lines: list[str] = []
    if conditions:
        for c in conditions:
            if c.op == "not_equals":
                # Represent as a filter that the condition negates.
                continue
            sel_lines.append(f"        {_sigma_field(c.field, c.op)}:{_yaml_value(c.value)}")
    if not sel_lines:
        sel_lines.append("        # TODO: no translatable conditions were found")
        warnings.append("no field conditions could be extracted; fill in the selection by hand")

    negations = [c for c in conditions if c.op == "not_equals"]
    filter_lines = [f"        {_sigma_field(c.field, 'equals')}:{_yaml_value(c.value)}"
                    for c in negations]

    tag_lines = ""
    if techniques:
        tags = [f"    - attack.{t.lower().replace('.', '.')}" for t in techniques]
        tag_lines = "\n".join(tags)

    fp_lines = (fp_notes or "Unknown — validate against your environment before enabling.")
    condition = "selection" + (" and not filter" if filter_lines else "")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d") if False else "2026-01-01"
    # (date pinned deterministically; the caller can override the file later)

    detection = f"    selection:\n" + "\n".join(sel_lines)
    if filter_lines:
        detection += "\n    filter:\n" + "\n".join(filter_lines)

    yaml = f"""title: {title}
id: {_stable_uuid(title, csl)}
status: experimental
description: {description or f'DRAFT detection generated from a Hunting Range hunt.'}
author: {author}
date: {now}
tags:
{tag_lines if tag_lines else '    - attack.unknown'}
logsource:
{_render_logsource(logsource)}
detection:
{detection}
    condition: {condition}
falsepositives:
    - {fp_lines}
level: {level}
"""
    # The DRAFT banner is a comment so the YAML still parses.
    banner = "# DRAFT — machine-translated from KQL, verify before use.\n"
    if warnings:
        banner += "# Incomplete translation:\n"
        for w in warnings:
            banner += f"#   - {w}\n"
    return SigmaResult(yaml=banner + yaml, warnings=warnings, table=table or "")


def _render_logsource(ls: dict[str, str]) -> str:
    return "\n".join(f"    {k}: {v}" for k, v in ls.items())


def _stable_uuid(title: str, csl: str) -> str:
    """A deterministic UUID from the rule content, so re-exporting the same
    detection yields the same id (Sigma requires a UUID and rules are diffed)."""
    import hashlib
    h = hashlib.sha256(f"{title}\n{csl}".encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
