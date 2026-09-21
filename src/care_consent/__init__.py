"""陪护机器人记忆同意的领域协议。"""

from .agent import (
    ConsentAgent,
    ConsentError,
    EventStore,
)
from .contracts import ContractError, EventEnvelope, load_events
from .domain import (
    POLICY,
    ActorRole,
    CareContext,
    MemoryClass,
)
from .ledger import Ledger
from .policy import (
    AccessRequest,
    Denial,
    RecordingRequest,
    judge_access,
    judge_recording,
)

# 报告子模块含命令行入口，按需惰性加载，避免 python -m 时的重复初始化。
_LAZY = {
    "incident_report": ".reports",
    "pending_deletions": ".reports",
    "resident_export": ".reports",
}

__all__ = [
    "AccessRequest",
    "ConsentAgent",
    "ConsentError",
    "ContractError",
    "Denial",
    "EventEnvelope",
    "EventStore",
    "Ledger",
    "POLICY",
    "ActorRole",
    "CareContext",
    "MemoryClass",
    "RecordingRequest",
    "incident_report",
    "judge_access",
    "judge_recording",
    "load_events",
    "pending_deletions",
    "resident_export",
]


def __getattr__(name: str):
    if name in _LAZY:
        from importlib import import_module

        return getattr(import_module(_LAZY[name], __name__), name)
    raise AttributeError(name)
