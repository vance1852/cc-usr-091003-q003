"""陪护机器人记忆同意的领域协议。"""

from .agent import ConsentAgent, Decision, DeletionTask
from .contracts import ContractError, EventEnvelope, load_events
from .model import MemoryClass, Purpose, Role, Scene
from .policy import POLICY_BOOK, PolicyError
from .reports import InvestigationReport, ResidentExport

__all__ = [
    "ConsentAgent",
    "ContractError",
    "Decision",
    "DeletionTask",
    "EventEnvelope",
    "InvestigationReport",
    "MemoryClass",
    "POLICY_BOOK",
    "PolicyError",
    "Purpose",
    "ResidentExport",
    "Role",
    "Scene",
    "load_events",
]
