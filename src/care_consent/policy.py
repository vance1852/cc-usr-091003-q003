"""记忆类别的策略矩阵与授权条款校验。

每个记忆类别绑定固定的收集目的、默认可见对象与保存期限上限；
授权条款只能在策略矩阵范围内收紧，不能借授权放宽目的、
扩大可见对象或延长保存期限。
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .model import (
    CORE_DEVICE,
    MemoryClass,
    Purpose,
    Role,
    Scene,
)


class PolicyError(ValueError):
    """授权条款与策略矩阵冲突。"""


# 每类记忆一条策略行：目的固定、可见对象为最大集合、保留期为硬上限、
# 可授权的场景为最大集合。紧急场景由独立豁免通道处理，不出现在
# 普通同意可勾选的场景里。
POLICY_BOOK: dict[str, dict[str, Any]] = {
    MemoryClass.VOICE_SUMMARY.value: {
        "purpose": Purpose.CARE_CONTEXT.value,
        # 语音摘要可服务于照护语境还原与照护提醒两个子目的。
        "purposes": frozenset(
            {Purpose.CARE_CONTEXT.value, "care-reminder"}
        ),
        # 上限集合：住户明示授权家属探视共享时才可以包含家属；
        # 默认授权只开放照护人员，家属不在内。
        "audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value, Role.FAMILY.value}
        ),
        "default_audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value}
        ),
        "retention_ceiling": timedelta(days=30),
        "grantable_scenes": frozenset(
            {Scene.ORDINARY_CARE.value, Scene.FAMILY_VISIT.value}
        ),
    },
    MemoryClass.MEDICATION_REMINDER.value: {
        "purpose": Purpose.MEDICATION_SAFETY.value,
        "audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value}
        ),
        "default_audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value}
        ),
        "retention_ceiling": timedelta(days=90),
        "grantable_scenes": frozenset({Scene.ORDINARY_CARE.value}),
    },
    MemoryClass.BEHAVIOR_PREFERENCE.value: {
        "purpose": Purpose.PERSONALIZATION.value,
        "audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value}
        ),
        "default_audiences": frozenset(
            {Role.CARE_STAFF.value, Role.RESIDENT.value}
        ),
        "retention_ceiling": timedelta(days=180),
        "grantable_scenes": frozenset({Scene.ORDINARY_CARE.value}),
    },
}

# 紧急豁免是独立许可种类，单独限定其目的与可见对象。
EMERGENCY_POLICY = {
    "purpose": Purpose.LIFE_SAFETY.value,
    "audiences": frozenset(
        {Role.EMERGENCY_RESPONDER.value, Role.CARE_STAFF.value}
    ),
    "retention_ceiling": timedelta(hours=24),
}

DEFAULT_RETENTION = {
    MemoryClass.VOICE_SUMMARY.value: timedelta(days=7),
    MemoryClass.MEDICATION_REMINDER.value: timedelta(days=30),
    MemoryClass.BEHAVIOR_PREFERENCE.value: timedelta(days=90),
}


def purpose_for(memory_class: str) -> str:
    return POLICY_BOOK[memory_class]["purpose"]


def retention_days_ceiling(memory_class: str) -> int:
    return POLICY_BOOK[memory_class]["retention_ceiling"] // timedelta(days=1)


def validate_grant(
    memory_class: str,
    purpose: str,
    audiences: frozenset[str] | set[str] | tuple[str, ...],
    retention: timedelta,
    scenes: frozenset[str] | set[str] | tuple[str, ...],
) -> None:
    """拒绝任何超出策略矩阵的授权条款（自始无效，不产生授权）。"""

    if memory_class not in POLICY_BOOK:
        raise PolicyError(f"未知记忆类别：{memory_class}")
    row = POLICY_BOOK[memory_class]
    allowed_purposes = row.get("purposes", frozenset({row["purpose"]}))
    if purpose not in allowed_purposes:
        raise PolicyError(
            f"{memory_class} 的收集目的只能是 {sorted(allowed_purposes)}，"
            f"不能改为 {purpose}"
        )
    audience_set = frozenset(audiences)
    if not audience_set:
        raise PolicyError("授权至少需要一个可见对象")
    extra = audience_set - row["audiences"]
    if extra:
        raise PolicyError(
            f"{memory_class} 不得向 {sorted(extra)} 开放可见性"
        )
    if retention > row["retention_ceiling"]:
        raise PolicyError(
            f"{memory_class} 保存期限 {retention} 超过上限 "
            f"{row['retention_ceiling']}"
        )
    if retention <= timedelta(0):
        raise PolicyError("保存期限必须为正")
    scene_set = frozenset(scenes)
    if not scene_set:
        raise PolicyError("授权至少需要一个所在场景")
    if Role.FAMILY.value in audience_set and Scene.FAMILY_VISIT.value not in scene_set:
        raise PolicyError("家属可见必须以家属探视场景为前提，不能并入普通照护许可")
    if Scene.EMERGENCY.value in scene_set:
        raise PolicyError("紧急豁免是独立许可，不能并入普通同意")
    bad_scenes = scene_set - row["grantable_scenes"]
    if bad_scenes:
        raise PolicyError(
            f"{memory_class} 不能在场景 {sorted(bad_scenes)} 下普通授权"
        )


def default_audiences(memory_class: str) -> frozenset[str]:
    return POLICY_BOOK[memory_class]["default_audiences"]


def core_device() -> str:
    return CORE_DEVICE
