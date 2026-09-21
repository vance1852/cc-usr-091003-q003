"""记忆分类、照护场景与授权策略表。

三类记忆分别绑定收集目的、可见对象与保存期限；普通照护、家属探视、
生命危险临时豁免是三种互相独立的许可依据，不能合并为同一种同意。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from enum import Enum


class MemoryClass(str, Enum):
    """机器人可形成的三类记忆。"""

    VOICE_SUMMARY = "voice-summary"
    MEDICATION_REMINDER = "medication-reminder"
    BEHAVIOR_PREFERENCE = "behavior-preference"


class CareContext(str, Enum):
    """收集或调用发生时所在的场景。"""

    ROUTINE_CARE = "routine-care"      # 普通照护
    FAMILY_VISIT = "family-visit"      # 家属探视
    EMERGENCY = "emergency"            # 生命危险处置


class ActorRole(str, Enum):
    RESIDENT = "resident"
    GUARDIAN = "guardian"
    CARE_STAFF = "care-staff"
    FAMILY = "family"
    EMERGENCY_RESPONDER = "emergency-responder"
    PRIVACY_OFFICER = "privacy-officer"


# 生命危险豁免不是同意：仅在危险持续期间有效，结束后不会自动转成长期授权。
EMERGENCY_PURPOSE = "life-protection"
EMERGENCY_DEFAULT_WINDOW = timedelta(hours=12)   # 未显式结束时的豁免上限
EMERGENCY_GRACE = timedelta(hours=24)            # 危险结束后副本清除宽限期


@dataclass(frozen=True)
class ClassRule:
    """单类记忆的默认授权边界。"""

    memory_class: MemoryClass
    allowed_purposes: frozenset[str]
    default_contexts: frozenset[CareContext]
    default_audience: frozenset[str]
    max_retention: timedelta

    def retention(self, requested: timedelta | None) -> timedelta:
        """同意只能缩短、不能超出策略上限。"""
        if requested is None:
            return self.max_retention
        return min(requested, self.max_retention)


POLICY: dict[MemoryClass, ClassRule] = {
    MemoryClass.VOICE_SUMMARY: ClassRule(
        memory_class=MemoryClass.VOICE_SUMMARY,
        # 语音摘要最敏感：只服务于照护交接与即时提醒，默认 72 小时。
        allowed_purposes=frozenset({"care-handover", "care-reminder"}),
        default_contexts=frozenset({CareContext.ROUTINE_CARE}),
        default_audience=frozenset({ActorRole.CARE_STAFF.value}),
        max_retention=timedelta(hours=72),
    ),
    MemoryClass.MEDICATION_REMINDER: ClassRule(
        memory_class=MemoryClass.MEDICATION_REMINDER,
        allowed_purposes=frozenset({"medication-safety", "care-reminder"}),
        default_contexts=frozenset({CareContext.ROUTINE_CARE}),
        default_audience=frozenset(
            {ActorRole.CARE_STAFF.value, ActorRole.RESIDENT.value}
        ),
        max_retention=timedelta(days=90),
    ),
    MemoryClass.BEHAVIOR_PREFERENCE: ClassRule(
        memory_class=MemoryClass.BEHAVIOR_PREFERENCE,
        allowed_purposes=frozenset({"personalized-care", "care-reminder"}),
        default_contexts=frozenset({CareContext.ROUTINE_CARE}),
        default_audience=frozenset({ActorRole.CARE_STAFF.value}),
        max_retention=timedelta(days=180),
    ),
}

# 紧急豁免下任意类别都可因救命目的临时收集，对象限于急救与在场照护人员。
EMERGENCY_AUDIENCE = frozenset(
    {ActorRole.EMERGENCY_RESPONDER.value, ActorRole.CARE_STAFF.value}
)


def audience_matches(token: str, requester_role: str, requester_id: str) -> bool:
    """核对可见对象令牌。

    通配令牌 "family" 表示角色级授权；具名令牌 "family:visitor-1" 只放行本人。
    """

    if token == requester_role:
        return True
    return token == f"{requester_role}:{requester_id}"
