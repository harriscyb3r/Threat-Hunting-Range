"""ASIM parser deployment.

Parsers live as .kql files next to this module so they can be edited as KQL —
they are read by a hunter as often as by the code. Each file holds several
`.create-or-alter function` commands separated by blank lines at column zero.

Deployment order matters: a unifying `_Im_*` parser references its source
parsers, so sources must exist first. Files are applied in `PARSER_FILES` order
and commands within a file in written order, which puts each `_Im_*` last.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("range.asim")

_DIR = Path(__file__).resolve().parent

PARSER_FILES = [
    "authentication.kql",
    "processevent.kql",
    "dns_network.kql",
]

# The unifying parsers, for discovery and for the UI's schema browser.
UNIFYING_PARSERS = {
    "_Im_Authentication": "Authentication",
    "_Im_ProcessCreate": "ProcessEvent",
    "_Im_Dns": "Dns",
    "_Im_NetworkSession": "NetworkSession",
}


def split_commands(text: str) -> list[str]:
    """Split a .kql file into individual control commands.

    A command starts with `.create-or-alter` at column zero. Comment lines
    before the first command are dropped; comments inside a command body are
    kept, because they are documentation an analyst reading the parser wants.
    """
    # Drop full-line comments that sit between commands, but keep everything
    # once a command has started.
    commands: list[str] = []
    current: list[str] = []
    for line in text.splitlines():
        if line.startswith(".create-or-alter"):
            if current:
                commands.append("\n".join(current).strip())
            current = [line]
        elif current:
            current.append(line)
    if current:
        commands.append("\n".join(current).strip())
    return [c for c in commands if c]


def parser_names(text: str) -> list[str]:
    return re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\(", text, re.MULTILINE)


async def deploy(client, db: str) -> list[str]:
    """Create every ASIM parser in `db`. Returns the function names created."""
    created: list[str] = []
    for filename in PARSER_FILES:
        text = (_DIR / filename).read_text(encoding="utf-8")
        for command in split_commands(text):
            await client.mgmt(db, command)
            match = re.search(r"\n([A-Za-z_][A-Za-z0-9_]*)\(", command)
            if match:
                created.append(match.group(1))
    logger.info("deployed %d ASIM parsers to %s", len(created), db)
    return created
