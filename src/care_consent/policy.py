"""授权裁决引擎。

两个时间点分开判断：
- 记录裁决按事件 *发生时间* 有效的授权处理，离线机器人延迟上传同样如此；
- 调用裁决按 *调用当时* 的状态处理，撤回后新调用立即被拒绝。

紧急豁免与同意是两条依据，互不转换。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from . import domain
from .domain import (
    EMERGENCY_AUDIENCE,
    EMERGENCY_DEFAULT_WINDOW,
    EMERGENCY_GRACE,
    EMERGENCY_PURPOSE,
    POLICY,
    CareContext,
    MemoryClass,
    audience_matches,
)
from .ledger import (
    Emergency,
    Grant,
    Ledger,
    MemoryRecord,
)


class Denial(str, Enum):
    SUSPENDED = "suspended"                 # 隐私专员已暂停记忆功能
    NO_BASIS = "no-basis"                   # 发生时没有有效授权
    PURPOSE_NOT_ALLOWED = "purpose-not-allowed"
    CONTEXT_MISMATCH = "context-mismatch"   # 许可不含该场景
    AUDIENCE_DENIED = "audience-denied"     # 可见对象不含请求者
    SHARING_DECLINED = "sharing-declined"   # 住户曾明确拒绝
    REVOKED = "revoked"                     # 同意已撤回
    EXPIRED = "expired"                     # 已过保存期限
    SHREDDED = "shredded"                   # 内容已删除
    EMERGENCY_INACTIVE = "emergency-inactive"
    EMERGENCY_AUDIENCE = "emergency-audience"
    EMERGENCY_PURPOSE = "emergency-purpose"


@dataclass(frozen=True)
class RecordingRequest:
    resident_id: str
    memory_class: str
    purpose: str
    context: str
    content_id: str
    occurred_at: datetime
    received_at: datetime
    collector_id: str
    record_id: str


@dataclass(frozen=True)
class AccessRequest:
    record_id: str
    requester_role: str
    requester_id: str
    context: str
    purpose: str
    at: datetime
    copy_id: str | None = None


@dataclass(frozen=True)
class RecordingDecision:
    allowed: bool
    reason: str | None
    basis_type: str | None      # "consent" | "emergency"
    basis_id: str | None
    grant: Grant | None
    expires_at: datetime | None
    guardian_id: str | None
    granted_by: str | None


@dataclass(frozen=True)
class AccessDecision:
    allowed: bool
    reason: str | None
    basis_type: str | None
    basis_id: str | None
    record: MemoryRecord | None
    breach: bool                 # 是否构成对既有记忆的越权访问
    audience_token: str | None = None


def _class(value: str) -> MemoryClass:
    try:
        return MemoryClass(value)
    except ValueError as exc:
        raise ValueError(f"未知记忆类别：{value}") from exc


def judge_recording(
    ledger: Ledger, request: RecordingRequest
) -> RecordingDecision:
    """按 occurred_at 裁决一条现场记录能否进入记忆系统。"""

    at = request.occurred_at
    memory_class = _class(request.memory_class)
    rule = POLICY[memory_class]

    if request.purpose not in rule.allowed_purposes and (
        request.context != CareContext.EMERGENCY.value
        or request.purpose != EMERGENCY_PURPOSE
    ):
        return RecordingDecision(
            False, Denial.PURPOSE_NOT_ALLOWED.value, None, None, None, None, None, None
        )

    if request.context == CareContext.EMERGENCY.value:
        return _judge_emergency_recording(ledger, request, at)

    # 非紧急场景：暂停期间一律不得记录。
    if ledger.suspension_active(at):
        return RecordingDecision(
            False, Denial.SUSPENDED.value, None, None, None, None, None, None
        )

    grant = _matching_grant(
        ledger,
        request.resident_id,
        request.memory_class,
        request.purpose,
        request.context,
        at,
    )
    if grant is None:
        return RecordingDecision(
            False, Denial.NO_BASIS.value, None, None, None, None, None, None
        )

    # 记录环节只识别“全场拒绝”；具名拒绝在调用环节按请求者身份拦截。
    decline = ledger.decline_blocks(
        request.resident_id,
        request.memory_class,
        request.context,
        None,
        at,
    )
    if decline is not None:
        return RecordingDecision(
            False, Denial.SHARING_DECLINED.value, None, None, None, None, None, None
        )

    expires_at = at + timedelta(seconds=grant.retention_seconds)
    return RecordingDecision(
        allowed=True,
        reason=None,
        basis_type="consent",
        basis_id=grant.grant_id,
        grant=grant,
        expires_at=expires_at,
        guardian_id=grant.guardian_id,
        granted_by=grant.granted_by_id,
    )


def _judge_emergency_recording(
    ledger: Ledger, request: RecordingRequest, at: datetime
) -> RecordingDecision:
    # 紧急豁免优先于暂停令：生命危险时仍可记录救命信息。
    emergency = ledger.active_emergency(request.resident_id, at)
    if emergency is None:
        return RecordingDecision(
            False, Denial.EMERGENCY_INACTIVE.value, None, None, None, None, None, None
        )
    # 硬上限：豁免不结束也不允许沉淀为长期数据。
    hard_cap = emergency.started_at + EMERGENCY_DEFAULT_WINDOW
    return RecordingDecision(
        allowed=True,
        reason=None,
        basis_type="emergency",
        basis_id=emergency.emergency_id,
        grant=None,
        expires_at=hard_cap,
        guardian_id=None,
        granted_by=None,
    )


def judge_access(ledger: Ledger, request: AccessRequest) -> AccessDecision:
    """按调用当时的状态裁决一次记忆调用。"""

    record = ledger.records.get(request.record_id)
    if record is None:
        return AccessDecision(
            False, Denial.NO_BASIS.value, None, None, None, breach=False
        )

    if record.basis_type == "emergency":
        # 紧急依据的存活边界完全由紧急窗口规则判定，不走普通 expires_at。
        return _judge_emergency_access(ledger, request, record)

    # 同意路径：先做依据与范围检查（撤回即时生效，且优先于暂停令被记录）。
    grant = ledger.grants.get(record.basis_id)
    at = request.at
    if grant is None:
        return AccessDecision(
            False, Denial.NO_BASIS.value, "consent", record.basis_id, record, True
        )
    if not grant.active_at(at):
        reason = Denial.REVOKED if grant.revoked_at is not None else Denial.EXPIRED
        return AccessDecision(
            False,
            reason.value,
            "consent",
            grant.grant_id,
            record,
            breach=reason is Denial.REVOKED,
        )
    if ledger.suspension_active(at):
        return AccessDecision(
            False, Denial.SUSPENDED.value, "consent", record.basis_id, record, True
        )
    if request.context not in grant.contexts:
        return AccessDecision(
            False,
            Denial.CONTEXT_MISMATCH.value,
            "consent",
            grant.grant_id,
            record,
            breach=True,
        )
    if request.purpose not in POLICY[MemoryClass(record.memory_class)].allowed_purposes:
        return AccessDecision(
            False,
            Denial.PURPOSE_NOT_ALLOWED.value,
            "consent",
            grant.grant_id,
            record,
            breach=True,
        )

    token = _matching_audience_token(grant, request.requester_role, request.requester_id)
    if token is None:
        return AccessDecision(
            False,
            Denial.AUDIENCE_DENIED.value,
            "consent",
            grant.grant_id,
            record,
            breach=True,
        )
    # 拒绝按“实际请求者”核对：具名拒绝只拦本人，角色通配拒绝拦下整类对象。
    requester_token = f"{request.requester_role}:{request.requester_id}"
    decline = ledger.decline_blocks(
        record.resident_id, record.memory_class, request.context, requester_token, at
    )
    if decline is not None:
        return AccessDecision(
            False,
            Denial.SHARING_DECLINED.value,
            "consent",
            grant.grant_id,
            record,
            breach=True,
            audience_token=token,
        )

    # 依据有效但内容已到存活终点：拒绝但不计越权。
    if record.shredded_at is not None and at >= record.shredded_at:
        return AccessDecision(
            False,
            Denial.SHREDDED.value,
            "consent",
            record.basis_id,
            record,
            breach=False,
        )
    if record.expires_at is not None and at >= record.expires_at:
        return AccessDecision(
            False,
            Denial.EXPIRED.value,
            "consent",
            record.basis_id,
            record,
            breach=False,
        )
    return AccessDecision(
        True, None, "consent", grant.grant_id, record, False, audience_token=token
    )


def _judge_emergency_access(
    ledger: Ledger, request: AccessRequest, record: MemoryRecord
) -> AccessDecision:
    emergency = ledger.emergencies.get(record.basis_id)
    at = request.at
    if emergency is None:
        return AccessDecision(
            False,
            Denial.EMERGENCY_INACTIVE.value,
            "emergency",
            record.basis_id,
            record,
            breach=False,
        )
    hard_cap = emergency.started_at + EMERGENCY_DEFAULT_WINDOW
    if emergency.ended_at is None:
        # 危险仍在持续：受 12 小时硬上限约束，豁免不结束也不能长期有效。
        window_open = at < hard_cap
    else:
        # 危险结束：宽限期内仍可调取，之后必须清除。
        window_open = at < emergency.ended_at + EMERGENCY_GRACE
    if not window_open:
        return AccessDecision(
            False,
            Denial.EMERGENCY_INACTIVE.value,
            "emergency",
            record.basis_id,
            record,
            breach=False,
        )
    if request.purpose != EMERGENCY_PURPOSE:
        return AccessDecision(
            False,
            Denial.EMERGENCY_PURPOSE.value,
            "emergency",
            record.basis_id,
            record,
            breach=True,
        )
    if request.requester_role not in EMERGENCY_AUDIENCE:
        return AccessDecision(
            False,
            Denial.EMERGENCY_AUDIENCE.value,
            "emergency",
            record.basis_id,
            record,
            breach=True,
        )
    return AccessDecision(True, None, "emergency", record.basis_id, record, False)


def _matching_grant(
    ledger: Ledger,
    resident_id: str,
    memory_class: str,
    purpose: str,
    context: str,
    at: datetime,
) -> Grant | None:
    candidates = [
        grant
        for grant in ledger.grants.values()
        if grant.resident_id == resident_id
        and grant.memory_class == memory_class
        and grant.purpose == purpose
        and context in grant.contexts
        and grant.active_at(at)
    ]
    if not candidates:
        return None
    # 多个有效授权时取最新决定；授权不可叠加扩权。
    return max(candidates, key=lambda g: g.valid_from)


def _matching_audience_token(
    grant: Grant, role: str, actor_id: str
) -> str | None:
    for token in grant.audience:
        if audience_matches(token, role, actor_id):
            return token
    return None


def emergency_grace_end(emergency: Emergency) -> datetime | None:
    if emergency.ended_at is None:
        return None
    return emergency.ended_at + EMERGENCY_GRACE
