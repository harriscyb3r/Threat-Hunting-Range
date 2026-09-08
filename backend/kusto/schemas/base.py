"""Table schema definitions.

Fidelity rule: column names and types come from the real Microsoft tables. A
query that works here should work in a Sentinel or Defender tenant unchanged —
that is the entire point of using a real Kusto engine, and it is lost the moment
a column is invented.

These are the *analyst-relevant* subset of each table plus its platform columns,
not the exhaustive column list. Sentinel's `SigninLogs` carries ~60 columns and
`DeviceProcessEvents` ~50; the ones omitted are those no hunt pivots on. Each
schema records a `docs` URL so the subset can be re-checked against upstream
when Microsoft changes a table.

Platform columns every Log Analytics table carries:
    TenantId, SourceSystem, TimeGenerated, Type, _ItemId, _ResourceId

`_ItemId` matters beyond fidelity: it is the unique row identifier, so it is
what ground truth is keyed on (PLAN.md §3). Using a real column for this means
the range needs no hidden grading column that would give the game away.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Kusto scalar types used across the schemas.
KUSTO_TYPES = {"string", "datetime", "int", "long", "real", "bool", "dynamic", "guid", "timespan"}


@dataclass(frozen=True, slots=True)
class TableSchema:
    name: str
    family: str                      # entra | defender | windows | network
    columns: tuple[tuple[str, str], ...]
    docs: str
    description: str = ""

    @property
    def column_names(self) -> tuple[str, ...]:
        return tuple(c for c, _ in self.columns)

    def type_of(self, column: str) -> str:
        for name, kusto_type in self.columns:
            if name == column:
                return kusto_type
        raise KeyError(f"{self.name} has no column {column!r}")

    def create_command(self) -> str:
        cols = ", ".join(f"{name}:{ktype}" for name, ktype in self.columns)
        return f".create table {self.name} ({cols})"

    def datatable_header(self, columns: tuple[str, ...] | None = None) -> str:
        """`datatable(...)` type list, for building ingest commands."""
        wanted = columns or self.column_names
        return ", ".join(f"{c}:{self.type_of(c)}" for c in wanted)

    def validate(self) -> list[str]:
        problems = []
        seen: set[str] = set()
        for name, ktype in self.columns:
            if ktype not in KUSTO_TYPES:
                problems.append(f"{self.name}.{name}: unknown type {ktype!r}")
            if name in seen:
                problems.append(f"{self.name}.{name}: duplicate column")
            seen.add(name)
        for required in ("TimeGenerated", "Type", "_ItemId"):
            if required not in seen:
                problems.append(f"{self.name}: missing platform column {required}")
        return problems


# Shared column groups, so the platform columns stay identical everywhere.
PLATFORM: tuple[tuple[str, str], ...] = (
    ("TenantId", "string"),
    ("SourceSystem", "string"),
    ("TimeGenerated", "datetime"),
    ("Type", "string"),
    ("_ItemId", "string"),
    ("_ResourceId", "string"),
)

# Defender XDR tables share this initiating-process block verbatim.
INITIATING_PROCESS: tuple[tuple[str, str], ...] = (
    ("InitiatingProcessAccountDomain", "string"),
    ("InitiatingProcessAccountName", "string"),
    ("InitiatingProcessAccountSid", "string"),
    ("InitiatingProcessAccountUpn", "string"),
    ("InitiatingProcessAccountObjectId", "string"),
    ("InitiatingProcessLogonId", "string"),
    ("InitiatingProcessIntegrityLevel", "string"),
    ("InitiatingProcessTokenElevation", "string"),
    ("InitiatingProcessSHA1", "string"),
    ("InitiatingProcessSHA256", "string"),
    ("InitiatingProcessMD5", "string"),
    ("InitiatingProcessFileName", "string"),
    ("InitiatingProcessFileSize", "long"),
    ("InitiatingProcessFolderPath", "string"),
    ("InitiatingProcessId", "int"),
    ("InitiatingProcessCommandLine", "string"),
    ("InitiatingProcessCreationTime", "datetime"),
    ("InitiatingProcessParentId", "int"),
    ("InitiatingProcessParentFileName", "string"),
    ("InitiatingProcessParentCreationTime", "datetime"),
)


_REGISTRY: dict[str, TableSchema] = {}


def register(schema: TableSchema) -> TableSchema:
    if schema.name in _REGISTRY:
        raise ValueError(f"table {schema.name} already registered")
    _REGISTRY[schema.name] = schema
    return schema


def get(name: str) -> TableSchema:
    return _REGISTRY[name]


def all_schemas() -> list[TableSchema]:
    return sorted(_REGISTRY.values(), key=lambda s: (s.family, s.name))


def by_family(family: str) -> list[TableSchema]:
    return [s for s in all_schemas() if s.family == family]


def table_names() -> list[str]:
    return sorted(_REGISTRY)
