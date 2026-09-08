"""Microsoft table schemas used by the range.

Importing this package registers every table. Import the family modules for
their side effect, then re-export the registry helpers.
"""
from __future__ import annotations

from . import defender, entra, network, windows  # noqa: F401  (registration)
from .base import (INITIATING_PROCESS, PLATFORM, TableSchema, all_schemas,
                   by_family, get, table_names)

__all__ = [
    "TableSchema", "PLATFORM", "INITIATING_PROCESS",
    "all_schemas", "by_family", "get", "table_names",
]
