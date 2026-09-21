"""生成“探视复述”事故案例 fixtures/visit-incident.json。

运行：python fixtures/build_visit_incident.py

案例覆盖：
- 住户上周已拒绝在探视场景共享语音摘要，机器人仍记录并复述；
- 隐私专员暂停记忆功能、住户撤回同意、下游副本删除回执链；
- 生命危险临时豁免的开始、结束与清除（不转为长期同意）；
- 离线记录按发生时授权裁决、落账即撤回、重复上传不延长保留期；
- 监护关系变更后旧授权决定的责任链仍可追溯。
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from care_consent.agent import ConsentAgent, EventStore
from care_consent.contracts import EventEnvelope
from care_consent.domain import ActorRole, CareContext, MemoryClass

TZ = "+08:00"


def t(hour: str, day: int = 15, month: int = 9) -> datetime:
    return datetime.fromisoformat(f"2026-{month:02d}-{day:02d}T{hour}{TZ}")


def main() -> None:
    counter = {"n": 0}

    def next_id() -> str:
        counter["n"] += 1
        return f"id-{counter['n']:04d}"

    agent = ConsentAgent(EventStore(), id_factory=next_id)
    resident = "resident-014"

    # ---- 监护关系与三类授权 ------------------------------------------
    agent.designate_guardian(
        guardian_id="guardian-old-1", resident_id=resident,
        relation="daughter", at=t("09:00", 8),
    )
    agent.grant_consent(
        resident_id=resident, memory_class=MemoryClass.VOICE_SUMMARY.value,
        purpose="care-handover", contexts=[CareContext.ROUTINE_CARE.value],
        audience=[ActorRole.CARE_STAFF.value],
        at=t("10:00", 10), granted_by_role=ActorRole.RESIDENT.value,
        granted_by_id=resident, grant_id="g-voice-routine",
    )
    agent.grant_consent(
        resident_id=resident, memory_class=MemoryClass.MEDICATION_REMINDER.value,
        purpose="medication-safety", contexts=[CareContext.ROUTINE_CARE.value],
        audience=[ActorRole.CARE_STAFF.value, ActorRole.RESIDENT.value],
        at=t("10:05", 10), granted_by_role=ActorRole.RESIDENT.value,
        granted_by_id=resident, retention=timedelta(days=30),
        grant_id="g-med-routine",
    )
    agent.grant_consent(
        resident_id=resident, memory_class=MemoryClass.BEHAVIOR_PREFERENCE.value,
        purpose="personalized-care", contexts=[CareContext.ROUTINE_CARE.value],
        audience=[ActorRole.CARE_STAFF.value],
        at=t("10:10", 10), granted_by_role=ActorRole.GUARDIAN.value,
        granted_by_id="guardian-old-1", retention=timedelta(days=90),
        grant_id="g-behav-guardian",
    )

    # ---- 老人上周明确拒绝：探视场景不共享语音摘要 --------------------
    agent.decline_sharing(
        resident_id=resident, memory_class=MemoryClass.VOICE_SUMMARY.value,
        context=CareContext.FAMILY_VISIT.value, at=t("19:00", 14),
        audience_token="family:visitor-1", decline_id="d-visit-voice",
    )

    # ---- 9/15 白天普通照护：用药提醒与行为偏好 -----------------------
    agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.MEDICATION_REMINDER.value,
        purpose="medication-safety", context=CareContext.ROUTINE_CARE.value,
        content_id="ct-med-morning", occurred_at=t("08:00", 15),
        received_at=t("08:01", 15), collector_id="nurse-2",
        device_id="robot-bedroom-014", record_id="rec-med-morning",
    )
    agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.BEHAVIOR_PREFERENCE.value,
        purpose="personalized-care", context=CareContext.ROUTINE_CARE.value,
        content_id="ct-pref-tea", occurred_at=t("09:30", 15),
        received_at=t("09:31", 15), collector_id="nurse-2",
        device_id="robot-bedroom-014", record_id="rec-pref-tea",
    )

    # ---- 9/15 晚探视：事故（旧系统越权，事件由设备日志导入） ---------
    # 记录发生在家属探视场景，却援引只覆盖普通照护的授权；住户事先已拒绝。
    breach_record = EventEnvelope(
        event_id="evt-import-0001",
        kind="memory_recorded",
        occurred_at=t("20:30", 15).isoformat(),
        received_at=t("20:31", 15).isoformat(),
        attributes={
            "record_id": "rec-visit-talk",
            "resident_id": resident,
            "memory_class": MemoryClass.VOICE_SUMMARY.value,
            "purpose": "care-handover",
            "context": CareContext.FAMILY_VISIT.value,
            "basis_type": "consent",
            "basis_id": "g-voice-routine",
            "guardian_id": None,
            "granted_by": resident,
            "content_id": "ct-visit-private-talk",
            "expires_at": (t("20:30", 15) + timedelta(hours=72)).isoformat(),
        },
    )
    agent.ledger.append(breach_record)
    # 复述设备上的两份副本：卧室陪护机（采集端本地缓存）与客厅陪护机。
    for eid, copy_id, device, source in (
        ("evt-import-0002", "copy-src-rec-visit-talk", "core-memory", True),
        ("evt-import-0003", "copy-local-rec-visit-talk", "robot-bedroom-014", False),
        ("evt-import-0004", "copy-living-rec-visit-talk", "robot-living-014", False),
    ):
        agent.ledger.append(
            EventEnvelope(
                event_id=eid,
                kind="copy_distributed",
                occurred_at=t("20:32", 15).isoformat(),
                received_at=t("20:33", 15).isoformat(),
                attributes={
                    "copy_id": copy_id,
                    "record_id": "rec-visit-talk",
                    "device_id": device,
                    "is_source": source,
                },
            )
        )
    # 家属探视时听见机器人复述：越权调用（设备日志原始记录）。
    agent.ledger.append(
        EventEnvelope(
            event_id="evt-import-0005",
            kind="access_logged",
            occurred_at=t("20:35", 15).isoformat(),
            received_at=t("20:36", 15).isoformat(),
            attributes={
                "access_id": "acc-import-replay",
                "record_id": "rec-visit-talk",
                "copy_id": "copy-living-rec-visit-talk",
                "requester_role": ActorRole.FAMILY.value,
                "requester_id": "visitor-1",
                "context": CareContext.FAMILY_VISIT.value,
                "purpose": "care-handover",
                "allowed": True,
                "reason": None,
                "basis_type": "consent",
                "basis_id": "g-voice-routine",
                "breach": True,
                "resident_id": resident,
            },
        )
    )

    # ---- 9/16 投诉后：隐私专员暂停，暂停即时生效 ---------------------
    agent.suspend_memory(
        by_id="privacy-officer-1",
        reason="家属探视时机器人复述住户拒绝共享的私密谈话",
        at=t("08:40", 16),
    )
    blocked = agent.access_memory(
        record_id="rec-visit-talk",
        requester_role=ActorRole.CARE_STAFF.value, requester_id="nurse-2",
        context=CareContext.ROUTINE_CARE.value, purpose="care-handover",
        at=t("09:30", 16), access_id="acc-blocked-by-suspension",
    )
    assert not blocked.allowed and blocked.reason == "suspended"

    # 住户撤回语音摘要与用药提醒授权 → 撕碎内容、生成可追踪删除任务。
    voice_revoke = agent.revoke_consent(
        resident_id=resident, memory_class=MemoryClass.VOICE_SUMMARY.value,
        purpose="care-handover", at=t("10:00", 16), revoked_by=resident,
        grant_id="g-voice-routine",
    )
    assert voice_revoke.task_ids
    agent.revoke_consent(
        resident_id=resident, memory_class=MemoryClass.MEDICATION_REMINDER.value,
        purpose="medication-safety", at=t("11:00", 16), revoked_by=resident,
        grant_id="g-med-routine",
    )

    # 客厅机按时回执删除；卧室机始终未回执 → 仍待删除且已逾期。
    living_task = next(
        task_id for task_id in voice_revoke.task_ids
        if agent.ledger.tasks[task_id].device_id == "robot-living-014"
    )
    agent.acknowledge_deletion(task_id=living_task, at=t("08:00", 17))

    # ---- 9/17 凌晨生命危险：豁免成立，暂停令不阻断救命记录 ------------
    agent.start_emergency(
        emergency_id="em-chestpain-1", resident_id=resident, at=t("02:00", 17)
    )
    agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.VOICE_SUMMARY.value,
        purpose="life-protection", context=CareContext.EMERGENCY.value,
        content_id="ct-emergency-note", occurred_at=t("02:10", 17),
        received_at=t("02:11", 17), collector_id="nurse-night-1",
        device_id="robot-ward-014", record_id="rec-emergency-note",
    )
    ok = agent.access_memory(
        record_id="rec-emergency-note",
        requester_role=ActorRole.EMERGENCY_RESPONDER.value,
        requester_id="emt-9", context=CareContext.EMERGENCY.value,
        purpose="life-protection", at=t("02:30", 17),
        access_id="acc-emt-allowed",
    )
    assert ok.allowed
    family_try = agent.access_memory(
        record_id="rec-emergency-note",
        requester_role=ActorRole.FAMILY.value, requester_id="visitor-1",
        context=CareContext.EMERGENCY.value, purpose="life-protection",
        at=t("02:40", 17), access_id="acc-family-emergency-denied",
    )
    assert not family_try.allowed and family_try.reason == "emergency-audience"
    agent.end_emergency(emergency_id="em-chestpain-1", at=t("03:00", 17))

    # 撤回后新调用立即拒绝（内容已撕碎 → 拒绝原因 shredded）。
    replay_try = agent.access_memory(
        record_id="rec-visit-talk",
        requester_role=ActorRole.FAMILY.value, requester_id="visitor-1",
        context=CareContext.FAMILY_VISIT.value, purpose="care-handover",
        at=t("10:00", 20), access_id="acc-post-revoke-replay",
    )
    assert not replay_try.allowed

    # 豁免宽限期过后清扫：紧急记录被清除，不自动变成长期同意。
    agent.sweep_expired(at=t("09:00", 18))

    # ---- 9/18 监护关系变更：不抹去旧决定的责任链 ---------------------
    agent.revoke_guardianship(guardian_id="guardian-old-1", at=t("12:00", 18))
    agent.designate_guardian(
        guardian_id="guardian-new-2", resident_id=resident,
        relation="son", at=t("12:30", 18),
    )

    # ---- 离线机器人延迟上传：按发生时授权裁决，落账即已撤回 -----------
    late = agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.MEDICATION_REMINDER.value,
        purpose="medication-safety", context=CareContext.ROUTINE_CARE.value,
        content_id="ct-med-offline-dose", occurred_at=t("11:30", 15),
        received_at=t("15:00", 18), collector_id="nurse-2",
        device_id="robot-portable-014", record_id="rec-med-offline",
    )
    assert late.allowed and late.task_ids  # 事实成立，但立即撕碎并下发删除任务

    # 重复上传：幂等忽略，不刷新保留期、不产生新事件或新任务。
    before = len(agent.ledger.events)
    duplicate = agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.MEDICATION_REMINDER.value,
        purpose="medication-safety", context=CareContext.ROUTINE_CARE.value,
        content_id="ct-med-offline-dose", occurred_at=t("11:30", 15),
        received_at=t("09:00", 19), collector_id="nurse-2",
        device_id="robot-portable-014",
    )
    assert duplicate.duplicate and len(agent.ledger.events) == before

    # 暂停仍未解除：普通照护记录继续被拒绝（紧急情形除外）。
    refused = agent.record_memory(
        resident_id=resident, memory_class=MemoryClass.VOICE_SUMMARY.value,
        purpose="care-handover", context=CareContext.ROUTINE_CARE.value,
        content_id="ct-while-suspended", occurred_at=t("09:00", 21),
        received_at=t("09:01", 21), collector_id="nurse-2",
        device_id="robot-bedroom-014",
    )
    assert not refused.allowed and refused.reason == "suspended"

    # ---- 落盘为场景文件 ----------------------------------------------
    payload = {
        "scenario": "family-visit-replay-incident",
        "description": (
            "住户拒绝共享的探视谈话被陪护机器人复述；隐私专员调查用导入案例"
        ),
        "events": [
            {
                "event_id": e.event_id,
                "kind": e.kind,
                "occurred_at": e.occurred_at,
                "received_at": e.received_at,
                "attributes": e.attributes,
            }
            for e in agent.ledger.events
        ],
    }
    out = ROOT / "fixtures" / "visit-incident.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"写入 {out}，共 {len(payload['events'])} 个事件")


if __name__ == "__main__":
    main()
