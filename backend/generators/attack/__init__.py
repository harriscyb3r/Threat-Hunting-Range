"""Attack technique emitters.

Importing this package registers every emitter as a side effect.
"""
from __future__ import annotations

from . import (coverage, credential_access, discover_c2_impact,  # noqa: F401
               execution, lateral, persist_evade)
from .base import (EmitContext, Emitter, Intrusion, StepPlan, Variant,
                   all_emitters, build_intrusion, get, has,
                   implemented_techniques, register)

__all__ = [
    "EmitContext", "Emitter", "Intrusion", "StepPlan", "Variant",
    "all_emitters", "build_intrusion", "get", "has",
    "implemented_techniques", "register",
]
