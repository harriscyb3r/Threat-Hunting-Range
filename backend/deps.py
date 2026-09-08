"""Process-wide singletons.

Kept out of main.py so routers can import them without a circular import back
through the app object.
"""
from __future__ import annotations

from config import settings
from kusto import KustoClient
from store import HuntStore, Registry

kusto = KustoClient(settings.kusto_url, timeout=settings.kusto_timeout_s)
registry = Registry(settings.db_path)
# HuntStore shares the registry's connection so a hunt and its campaign are one
# file with one writer lock.
hunts = HuntStore(registry.connection)
