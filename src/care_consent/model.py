"""领域词汇：记忆类别、所在场景、角色、目的与裁决原因。

三类许可彼此独立：普通照护同意、家属探视共享与紧急临时豁免
绝不能合并成同一种许可，因此全部以显式字符串常量区分。
"""

from __future__ import annotations

from enum import Enum


class MemoryClass(str, Enum):
    VOICE_SUMMARY = "voice-summary"
    MEDICATION_REMINDER = "medication-reminder"
    BEHAVIOR_PREFERENCE = "behavior-preference"


class Scene(str, Enum):
    ORDINARY_CARE = "ordinary-care"
    FAMILY_VISIT = "family-visit"
    EMERGENCY = "emergency"


class Role(str, Enum):
    RESIDENT = "resident"
    GUARDIAN = "guardian"
    CARE_STAFF = "care-staff"
    FAMILY = "family"
    EMERGENCY_RESPONDER = "emergency-responder"
    PRIVACY_OFFICER = "privacy-officer"
    DEVICE = "device"
    SYSTEM = "system"


class Purpose(str, Enum):
    CARE_CONTEXT = "care-context"
    MEDICATION_SAFETY = "medication-safety"
    PERSONALIZATION = "personalization"
    FAMILY_SHARE = "family-share"
    LIFE_SAFETY = "life-safety"


class DenialReason(str, Enum):
    NO_CONSENT = "no-consent"
    CONSENT_REVOKED = "consent-revoked"
    RESIDENT_REFUSED = "resident-refused"
    AUDIENCE_MISMATCH = "audience-mismatch"
    SCENE_MISMATCH = "scene-mismatch"
    RETENTION_EXPIRED = "retention-expired"
    UNAUTHORIZED_RECORD = "unauthorized-record"
    EMERGENCY_ENDED = "emergency-ended"
    INVALID_GRANT = "invalid-grant"
    RECORD_NOT_FOUND = "record-not-found"


# 核心库中的原始副本所在设备标识。
CORE_DEVICE = "core-store"

# 紧急豁免采集的数据在豁免结束后必须删除的任务原因。
REASON_REVOKED = "consent-revoked"
REASON_UNAUTHORIZED = "unauthorized-record"
REASON_EMERGENCY_ENDED = "emergency-ended"
REASON_RETENTION_EXPIRED = "retention-expired"

DENIAL_MESSAGES = {
    DenialReason.NO_CONSENT: "事件发生时没有覆盖该记忆类别、目的与场景的有效同意",
    DenialReason.CONSENT_REVOKED: "同意已撤回，撤回时点之后的新调用一律拒绝",
    DenialReason.RESIDENT_REFUSED: "住户已明确拒绝该共享，缺席同意不能覆盖明示拒绝",
    DenialReason.AUDIENCE_MISMATCH: "访问者不在该记录授权的可见对象范围内",
    DenialReason.SCENE_MISMATCH: "调用所在场景不在该同意授权的场景范围内",
    DenialReason.RETENTION_EXPIRED: "已超过授权保存期限，过期内容不得再次可见",
    DenialReason.UNAUTHORIZED_RECORD: "记录采集时没有有效授权，属于不应存在的记录",
    DenialReason.EMERGENCY_ENDED: "紧急临时豁免已经结束，不自动转为长期同意",
    DenialReason.INVALID_GRANT: "授权条款超出该记忆类别允许的策略范围，自始无效",
    DenialReason.RECORD_NOT_FOUND: "记忆记录不存在或已被清除",
}
