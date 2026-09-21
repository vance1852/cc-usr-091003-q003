"""记忆同意代理的端到端规则测试。"""

from __future__ import annotations

import itertools
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from care_consent.agent import ConsentAgent, ConsentError, EventStore
from care_consent.domain import (
    EMERGENCY_GRACE,
    ActorRole,
    CareContext,
    MemoryClass,
)
from care_consent.ledger import Ledger
from care_consent.reports import incident_report, pending_deletions, resident_export

TZ = "+08:00"


def t(hour: str, day: int = 15) -> datetime:
    return datetime.fromisoformat(f"2026-09-{day:02d}T{hour}{TZ}")


def make_agent(**kwargs) -> ConsentAgent:
    counter = itertools.count(1)
    return ConsentAgent(
        EventStore(),
        id_factory=lambda: f"n-{next(counter):04d}",
        **kwargs,
    )


def grant_routine(agent: ConsentAgent, cls: str, purpose: str, **kw) -> None:
    kwargs = dict(
        resident_id="r1",
        memory_class=cls,
        purpose=purpose,
        contexts=[CareContext.ROUTINE_CARE.value],
        audience=[ActorRole.CARE_STAFF.value],
        at=t("08:00", 1),
        granted_by_role=ActorRole.RESIDENT.value,
        granted_by_id="r1",
    )
    kwargs.update(kw)
    agent.grant_consent(**kwargs)


class PolicyTableTest(unittest.TestCase):
    def test_purposes_audiences_retention_per_class(self) -> None:
        agent = make_agent()
        # 语音摘要不接受用药安全目的。
        with self.assertRaises(ConsentError):
            grant_routine(
                agent, MemoryClass.VOICE_SUMMARY.value, "medication-safety"
            )
        grant_routine(
            agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
            retention=timedelta(days=30),
        )
        grant = agent.ledger.grants["grant-n-0001"]
        self.assertEqual(72 * 3600, grant.retention_seconds)  # 上限 72 小时

    def test_emergency_cannot_be_preauthorized(self) -> None:
        agent = make_agent()
        with self.assertRaises(ConsentError):
            agent.grant_consent(
                resident_id="r1",
                memory_class=MemoryClass.VOICE_SUMMARY.value,
                purpose="care-handover",
                contexts=[CareContext.EMERGENCY.value],
                audience=[ActorRole.EMERGENCY_RESPONDER.value],
                at=t("08:00", 1),
                granted_by_role=ActorRole.RESIDENT.value,
                granted_by_id="r1",
            )

    def test_guardian_must_be_active_at_decision_time(self) -> None:
        agent = make_agent()
        with self.assertRaises(ConsentError):
            grant_routine(
                agent, MemoryClass.BEHAVIOR_PREFERENCE.value,
                "personalized-care",
                at=t("08:00", 1),
                granted_by_role=ActorRole.GUARDIAN.value,
                granted_by_id="g1",
            )
        agent.designate_guardian(
            guardian_id="g1", resident_id="r1", relation="son", at=t("07:00", 1)
        )
        grant_routine(
            agent, MemoryClass.BEHAVIOR_PREFERENCE.value, "personalized-care",
            at=t("08:00", 1),
            granted_by_role=ActorRole.GUARDIAN.value,
            granted_by_id="g1",
        )
        with self.assertRaises(ConsentError):
            grant_routine(
                agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
                at=t("08:00", 1),
                granted_by_role=ActorRole.GUARDIAN.value,
                granted_by_id="g-other",
            )


class ContextSeparationTest(unittest.TestCase):
    def test_routine_grant_does_not_cover_visit_or_emergency(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
            audience=[ActorRole.CARE_STAFF.value, "family:visitor-1"],
        )
        visit = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.FAMILY_VISIT.value,
            content_id="c-visit",
            occurred_at=t("20:00", 2),
            received_at=t("20:01", 2),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertFalse(visit.allowed)
        self.assertEqual("no-basis", visit.reason)

        emergency = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.EMERGENCY.value,
            content_id="c-em",
            occurred_at=t("21:00", 2),
            received_at=t("21:01", 2),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertFalse(emergency.allowed)
        self.assertEqual("emergency-inactive", emergency.reason)

    def test_explicit_family_grant_allows_named_visitor_only(self) -> None:
        agent = make_agent()
        agent.grant_consent(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            contexts=[CareContext.FAMILY_VISIT.value],
            audience=["family:visitor-1"],
            at=t("08:00", 1),
            granted_by_role=ActorRole.RESIDENT.value,
            granted_by_id="r1",
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.FAMILY_VISIT.value,
            content_id="c-visit",
            occurred_at=t("19:00", 1),
            received_at=t("19:01", 1),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertTrue(rec.allowed)
        ok = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.FAMILY.value,
            requester_id="visitor-1",
            context=CareContext.FAMILY_VISIT.value,
            purpose="care-handover",
            at=t("19:05", 1),
        )
        self.assertTrue(ok.allowed)
        other = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.FAMILY.value,
            requester_id="visitor-2",
            context=CareContext.FAMILY_VISIT.value,
            purpose="care-handover",
            at=t("19:06", 1),
        )
        self.assertFalse(other.allowed)
        self.assertEqual("audience-denied", other.reason)


class DeclineTest(unittest.TestCase):
    def test_decline_blocks_recording_and_named_scope(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
            audience=["family"],
        )
        agent.grant_consent(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            contexts=[CareContext.FAMILY_VISIT.value],
            audience=["family"],
            at=t("08:05", 1),
            granted_by_role=ActorRole.RESIDENT.value,
            granted_by_id="r1",
        )
        agent.decline_sharing(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            context=CareContext.FAMILY_VISIT.value,
            audience_token="family:visitor-1",
            at=t("18:00", 1),
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.FAMILY_VISIT.value,
            content_id="c1",
            occurred_at=t("19:00", 1),
            received_at=t("19:01", 1),
            collector_id="robot-1",
            device_id="robot-1",
        )
        # 记录环节只被全场拒绝阻断；具名拒绝在调用环节拦截 visitor-1。
        self.assertTrue(rec.allowed)
        v1 = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.FAMILY.value,
            requester_id="visitor-1",
            context=CareContext.FAMILY_VISIT.value,
            purpose="care-handover",
            at=t("19:05", 1),
        )
        self.assertFalse(v1.allowed)
        self.assertEqual("sharing-declined", v1.reason)
        v2 = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.FAMILY.value,
            requester_id="visitor-2",
            context=CareContext.FAMILY_VISIT.value,
            purpose="care-handover",
            at=t("19:06", 1),
        )
        self.assertTrue(v2.allowed)

    def test_blanket_decline_blocks_recording(self) -> None:
        agent = make_agent()
        agent.grant_consent(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            contexts=[CareContext.FAMILY_VISIT.value],
            audience=["family"],
            at=t("08:00", 1),
            granted_by_role=ActorRole.RESIDENT.value,
            granted_by_id="r1",
        )
        agent.decline_sharing(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            context=CareContext.FAMILY_VISIT.value,
            at=t("18:00", 1),
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.FAMILY_VISIT.value,
            content_id="c-blanket",
            occurred_at=t("19:00", 1),
            received_at=t("19:01", 1),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertFalse(rec.allowed)
        self.assertEqual("sharing-declined", rec.reason)


class RevocationAndDeletionTest(unittest.TestCase):
    def _setup_with_copy(self) -> tuple[ConsentAgent, str, str]:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.MEDICATION_REMINDER.value, "medication-safety",
            retention=timedelta(days=30),
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            context=CareContext.ROUTINE_CARE.value,
            content_id="c-med",
            occurred_at=t("08:00", 2),
            received_at=t("08:01", 2),
            collector_id="nurse-1",
            device_id="robot-bed",
        )
        dist = agent.distribute_copy(
            record_id=rec.record_id,
            device_id="robot-living",
            requester_role=ActorRole.CARE_STAFF.value,
            requester_id="nurse-1",
            context=CareContext.ROUTINE_CARE.value,
            at=t("09:00", 2),
        )
        self.assertTrue(dist.allowed)
        return agent, rec.record_id, dist.events[0].attributes["copy_id"]

    def test_revocation_immediately_denies_and_tracks_copies(self) -> None:
        agent, record_id, living_copy = self._setup_with_copy()
        result = agent.revoke_consent(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            at=t("10:00", 2),
            revoked_by="r1",
        )
        self.assertEqual(2, len(result.task_ids))  # 采集端 + 客厅端各一项
        after = agent.access_memory(
            record_id=record_id,
            requester_role=ActorRole.CARE_STAFF.value,
            requester_id="nurse-1",
            context=CareContext.ROUTINE_CARE.value,
            purpose="medication-safety",
            at=t("10:01", 2),
        )
        self.assertFalse(after.allowed)
        self.assertIn(after.reason, ("revoked", "shredded"))
        self.assertTrue(after.decision.breach)

        pending = {task.copy_id: task for task in agent.ledger.pending_tasks()}
        self.assertIn(living_copy, pending)

    def test_acknowledgement_completes_and_is_idempotent_on_retry(self) -> None:
        agent, _, living_copy = self._setup_with_copy()
        result = agent.revoke_consent(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            at=t("10:00", 2),
            revoked_by="r1",
        )
        task_id = next(
            tid for tid in result.task_ids
            if agent.ledger.tasks[tid].copy_id == living_copy
        )
        first = agent.acknowledge_deletion(task_id=task_id, at=t("12:00", 2))
        self.assertFalse(first.duplicate)
        second = agent.acknowledge_deletion(task_id=task_id, at=t("13:00", 2))
        self.assertTrue(second.duplicate)
        self.assertEqual(
            t("12:00", 2), agent.ledger.copies[living_copy].deleted_at
        )
        self.assertEqual(1, len(agent.ledger.pending_tasks()))

    def test_distribution_after_revocation_refused(self) -> None:
        agent, record_id, _ = self._setup_with_copy()
        agent.revoke_consent(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            at=t("10:00", 2),
            revoked_by="r1",
        )
        dist = agent.distribute_copy(
            record_id=record_id,
            device_id="robot-hall",
            requester_role=ActorRole.CARE_STAFF.value,
            requester_id="nurse-1",
            context=CareContext.ROUTINE_CARE.value,
            at=t("10:30", 2),
        )
        self.assertFalse(dist.allowed)


class OfflineUploadTest(unittest.TestCase):
    def test_late_upload_judged_at_occurrence_then_shredded_at_receipt(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.MEDICATION_REMINDER.value, "medication-safety",
            retention=timedelta(days=30),
            at=t("08:00", 1),
        )
        # 发生在授权期内（9/2），9/5 才上传；9/4 已撤回。
        agent.revoke_consent(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            at=t("08:00", 4),
            revoked_by="r1",
        )
        result = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            context=CareContext.ROUTINE_CARE.value,
            content_id="late-1",
            occurred_at=t("12:00", 2),
            received_at=t("09:00", 5),
            collector_id="robot-off",
            device_id="robot-off",
        )
        self.assertTrue(result.allowed)        # 按发生时授权裁决，事实成立
        self.assertTrue(result.task_ids)       # 落账即撕碎并下发删除任务
        record = agent.ledger.records[result.record_id]
        self.assertEqual(t("12:00", 2) + timedelta(days=30), record.expires_at)
        self.assertIsNotNone(record.shredded_at)

    def test_recording_before_grant_refused_even_if_uploaded_after(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.MEDICATION_REMINDER.value, "medication-safety",
            at=t("08:00", 5),
        )
        result = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            context=CareContext.ROUTINE_CARE.value,
            content_id="early-1",
            occurred_at=t("12:00", 2),
            received_at=t("09:00", 5),
            collector_id="robot-off",
            device_id="robot-off",
        )
        self.assertFalse(result.allowed)
        self.assertEqual("no-basis", result.reason)

    def test_duplicate_upload_does_not_extend_retention(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.MEDICATION_REMINDER.value, "medication-safety",
            retention=timedelta(days=10),
            at=t("08:00", 1),
        )
        first = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            context=CareContext.ROUTINE_CARE.value,
            content_id="dup-1",
            occurred_at=t("12:00", 2),
            received_at=t("12:05", 2),
            collector_id="robot-off",
            device_id="robot-off",
        )
        events_before = len(agent.ledger.events)
        expiry_before = agent.ledger.records[first.record_id].expires_at
        second = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.MEDICATION_REMINDER.value,
            purpose="medication-safety",
            context=CareContext.ROUTINE_CARE.value,
            content_id="dup-1",
            occurred_at=t("12:00", 2),
            received_at=t("12:00", 6),
            collector_id="robot-off",
            device_id="robot-off",
        )
        self.assertTrue(second.duplicate)
        self.assertEqual(events_before, len(agent.ledger.events))
        self.assertEqual(
            expiry_before, agent.ledger.records[first.record_id].expires_at
        )


class EmergencyTest(unittest.TestCase):
    def test_emergency_window_is_separate_and_expires(self) -> None:
        agent = make_agent()
        agent.start_emergency(
            emergency_id="em1", resident_id="r1", at=t("02:00", 3)
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="life-protection",
            context=CareContext.EMERGENCY.value,
            content_id="em-c1",
            occurred_at=t("02:10", 3),
            received_at=t("02:11", 3),
            collector_id="robot-ward",
            device_id="robot-ward",
        )
        self.assertTrue(rec.allowed)
        self.assertEqual("emergency", rec.decision.basis_type)
        family = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.FAMILY.value,
            requester_id="visitor-1",
            context=CareContext.EMERGENCY.value,
            purpose="life-protection",
            at=t("02:20", 3),
        )
        self.assertFalse(family.allowed)
        self.assertEqual("emergency-audience", family.reason)

        agent.end_emergency(emergency_id="em1", at=t("03:00", 3))
        # 宽限期内急救人员仍可调取，但目的仍须是 life-protection。
        wrong_purpose = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.EMERGENCY_RESPONDER.value,
            requester_id="emt-1",
            context=CareContext.ROUTINE_CARE.value,
            purpose="care-handover",
            at=t("04:00", 3),
        )
        self.assertFalse(wrong_purpose.allowed)
        self.assertEqual("emergency-purpose", wrong_purpose.reason)

        sweep_time = t("04:00", 4)
        self.assertGreaterEqual(
            sweep_time, t("03:00", 3) + EMERGENCY_GRACE
        )
        agent.sweep_expired(at=sweep_time)
        record = agent.ledger.records[rec.record_id]
        self.assertIsNotNone(record.shredded_at)
        # 紧急依据没有产生任何同意授权。
        self.assertFalse(
            any(g.resident_id == "r1" for g in agent.ledger.grants.values())
        )

    def test_responder_access_allowed_within_grace_after_end(self) -> None:
        agent = make_agent()
        agent.start_emergency(
            emergency_id="em2", resident_id="r1", at=t("02:00", 3)
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="life-protection",
            context=CareContext.EMERGENCY.value,
            content_id="em-c2",
            occurred_at=t("02:10", 3),
            received_at=t("02:11", 3),
            collector_id="robot-ward",
            device_id="robot-ward",
        )
        agent.end_emergency(emergency_id="em2", at=t("03:00", 3))
        within = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.EMERGENCY_RESPONDER.value,
            requester_id="emt-1",
            context=CareContext.EMERGENCY.value,
            purpose="life-protection",
            at=t("20:00", 3),  # 结束后 17 小时，仍在 24 小时宽限期内
        )
        self.assertTrue(within.allowed)
        after = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.EMERGENCY_RESPONDER.value,
            requester_id="emt-1",
            context=CareContext.EMERGENCY.value,
            purpose="life-protection",
            at=t("04:00", 4),  # 超过宽限期
        )
        self.assertFalse(after.allowed)
        self.assertEqual("emergency-inactive", after.reason)

    def test_unended_emergency_hits_hard_cap(self) -> None:
        agent = make_agent()
        agent.start_emergency(
            emergency_id="em3", resident_id="r1", at=t("02:00", 3)
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="life-protection",
            context=CareContext.EMERGENCY.value,
            content_id="em-c3",
            occurred_at=t("02:10", 3),
            received_at=t("02:11", 3),
            collector_id="robot-ward",
            device_id="robot-ward",
        )
        later = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.EMERGENCY_RESPONDER.value,
            requester_id="emt-1",
            context=CareContext.EMERGENCY.value,
            purpose="life-protection",
            at=t("15:00", 3),  # 开始后 13 小时，超过 12 小时硬上限
        )
        self.assertFalse(later.allowed)
        self.assertEqual("emergency-inactive", later.reason)
        agent.sweep_expired(at=t("16:00", 3))
        self.assertIsNotNone(agent.ledger.records[rec.record_id].shredded_at)


class SuspensionTest(unittest.TestCase):
    def test_suspension_blocks_routine_but_not_emergency(self) -> None:
        agent = make_agent()
        grant_routine(
            agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
        )
        rec = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.ROUTINE_CARE.value,
            content_id="c1",
            occurred_at=t("09:00", 2),
            received_at=t("09:01", 2),
            collector_id="robot-1",
            device_id="robot-1",
        )
        agent.suspend_memory(by_id="po-1", reason="调查", at=t("10:00", 2))
        blocked_access = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.CARE_STAFF.value,
            requester_id="nurse-1",
            context=CareContext.ROUTINE_CARE.value,
            purpose="care-handover",
            at=t("10:05", 2),
        )
        self.assertFalse(blocked_access.allowed)
        self.assertEqual("suspended", blocked_access.reason)
        blocked_record = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="care-handover",
            context=CareContext.ROUTINE_CARE.value,
            content_id="c2",
            occurred_at=t("10:10", 2),
            received_at=t("10:11", 2),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertFalse(blocked_record.allowed)

        agent.start_emergency(
            emergency_id="em1", resident_id="r1", at=t("11:00", 2)
        )
        emergency_record = agent.record_memory(
            resident_id="r1",
            memory_class=MemoryClass.VOICE_SUMMARY.value,
            purpose="life-protection",
            context=CareContext.EMERGENCY.value,
            content_id="c3",
            occurred_at=t("11:05", 2),
            received_at=t("11:06", 2),
            collector_id="robot-1",
            device_id="robot-1",
        )
        self.assertTrue(emergency_record.allowed)

        agent.end_emergency(emergency_id="em1", at=t("11:30", 2))
        agent.restore_memory(at=t("12:00", 2))
        again = agent.access_memory(
            record_id=rec.record_id,
            requester_role=ActorRole.CARE_STAFF.value,
            requester_id="nurse-1",
            context=CareContext.ROUTINE_CARE.value,
            purpose="care-handover",
            at=t("12:05", 2),
        )
        self.assertTrue(again.allowed)


class GuardianshipChangeTest(unittest.TestCase):
    def test_change_leaves_old_decision_chain_intact(self) -> None:
        agent = make_agent()
        agent.designate_guardian(
            guardian_id="g-old", resident_id="r1", relation="daughter",
            at=t("08:00", 1),
        )
        grant_routine(
            agent, MemoryClass.BEHAVIOR_PREFERENCE.value, "personalized-care",
            at=t("09:00", 1),
            granted_by_role=ActorRole.GUARDIAN.value,
            granted_by_id="g-old",
            retention=timedelta(days=30),
        )
        grant_id = next(
            gid
            for gid, grant in agent.ledger.grants.items()
            if grant.granted_by_id == "g-old"
        )
        grant = agent.ledger.grants[grant_id]
        grant_event = grant.decision_event_id
        agent.revoke_guardianship(guardian_id="g-old", at=t("08:00", 10))
        agent.designate_guardian(
            guardian_id="g-new", resident_id="r1", relation="son",
            at=t("09:00", 10),
        )
        self.assertEqual("g-old", grant.granted_by_id)
        self.assertEqual(grant_event, grant.decision_event_id)
        self.assertTrue(grant.active_at(t("09:00", 11)))
        # 新监护人不能追溯为旧决定负责，但可以在关系生效后作新决定。
        with self.assertRaises(ConsentError):
            grant_routine(
                agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
                at=t("07:00", 10),
                granted_by_role=ActorRole.GUARDIAN.value,
                granted_by_id="g-new",
            )


class RestartPersistenceTest(unittest.TestCase):
    def test_restart_keeps_content_hidden_and_task_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "events.jsonl")
            counter = itertools.count(1)
            agent = ConsentAgent(store, id_factory=lambda: f"n-{next(counter):04d}")
            grant_routine(
                agent, MemoryClass.MEDICATION_REMINDER.value,
                "medication-safety", retention=timedelta(days=30),
            )
            rec = agent.record_memory(
                resident_id="r1",
                memory_class=MemoryClass.MEDICATION_REMINDER.value,
                purpose="medication-safety",
                context=CareContext.ROUTINE_CARE.value,
                content_id="c1",
                occurred_at=t("09:00", 2),
                received_at=t("09:01", 2),
                collector_id="robot-bed",
                device_id="robot-bed",
            )
            revoked = agent.revoke_consent(
                resident_id="r1",
                memory_class=MemoryClass.MEDICATION_REMINDER.value,
                purpose="medication-safety",
                at=t("10:00", 2),
                revoked_by="r1",
            )
            task_id = revoked.task_ids[0]

            # 模拟数据库重启：完全从事件重放。
            reloaded = ConsentAgent.from_store(
                store, id_factory=lambda: f"m-{next(counter):04d}"
            )
            decision = reloaded.access_memory(
                record_id=rec.record_id,
                requester_role=ActorRole.CARE_STAFF.value,
                requester_id="nurse-1",
                context=CareContext.ROUTINE_CARE.value,
                purpose="medication-safety",
                at=t("14:00", 2),
            )
            self.assertFalse(decision.allowed)
            self.assertIn(decision.reason, ("revoked", "shredded"))
            self.assertIn(task_id, {t.task_id for t in reloaded.ledger.pending_tasks()})

            # 设备重试删除回执在重启后仍然有效且幂等。
            ack = reloaded.acknowledge_deletion(task_id=task_id, at=t("15:00", 2))
            self.assertFalse(ack.duplicate)
            reloaded2 = ConsentAgent.from_store(
                store, id_factory=lambda: f"m-{next(counter):04d}"
            )
            self.assertEqual(
                0, len([t for t in reloaded2.ledger.pending_tasks()
                        if t.task_id == task_id])
            )
            again = reloaded2.acknowledge_deletion(
                task_id=task_id, at=t("16:00", 2)
            )
            self.assertTrue(again.duplicate)

    def test_expired_content_never_visible_after_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / "events.jsonl")
            counter = itertools.count(1)
            agent = ConsentAgent(store, id_factory=lambda: f"n-{next(counter):04d}")
            grant_routine(
                agent, MemoryClass.VOICE_SUMMARY.value, "care-handover",
            )
            rec = agent.record_memory(
                resident_id="r1",
                memory_class=MemoryClass.VOICE_SUMMARY.value,
                purpose="care-handover",
                context=CareContext.ROUTINE_CARE.value,
                content_id="c-exp",
                occurred_at=t("09:00", 2),
                received_at=t("09:01", 2),
                collector_id="robot-1",
                device_id="robot-1",
            )
            reloaded = ConsentAgent.from_store(store)
            decision = reloaded.access_memory(
                record_id=rec.record_id,
                requester_role=ActorRole.CARE_STAFF.value,
                requester_id="nurse-1",
                context=CareContext.ROUTINE_CARE.value,
                purpose="care-handover",
                at=t("00:00", 20),   # 远超 72 小时上限
            )
            self.assertFalse(decision.allowed)
            self.assertEqual("expired", decision.reason)


class ReportTest(unittest.TestCase):
    def test_fixture_replays_full_incident(self) -> None:
        from care_consent.contracts import load_events

        _, events = load_events(ROOT / "fixtures" / "visit-incident.json")
        ledger = Ledger.replay(events)

        report = incident_report(ledger, "rec-visit-talk", now=t("09:00", 21))
        codes = {f["code"] for f in report["why_it_must_not_be_replayed"]}
        self.assertIn("context-mismatch", codes)
        self.assertIn("sharing-declined", codes)
        self.assertIn("revoked", codes)

        copies = {c["copy_id"]: c for c in report["copies"]}
        self.assertEqual("live", copies["copy-local-rec-visit-talk"]["state"])
        self.assertEqual(
            "pending",
            copies["copy-local-rec-visit-talk"]["deletion_task"]["state"],
        )
        self.assertEqual(
            "acknowledged",
            copies["copy-living-rec-visit-talk"]["deletion_task"]["state"],
        )
        self.assertTrue(
            any(a["breach"] and a["allowed"] for a in report["accesses"])
        )
        chain_types = {link["type"] for link in report["authorization_chain"]}
        self.assertEqual({"consent_granted", "recording_fact"}, chain_types)

        pending = pending_deletions(ledger, now=t("09:00", 21))
        self.assertEqual(4, len(pending))
        self.assertTrue(all(p["overdue"] for p in pending))

        # 紧急记录与离线记录都已撕碎；监护变更不影响旧链。
        self.assertIsNotNone(
            ledger.records["rec-emergency-note"].shredded_at
        )
        self.assertIsNotNone(ledger.records["rec-med-offline"].shredded_at)
        grant = ledger.grants["g-behav-guardian"]
        self.assertEqual("guardian-old-1", grant.granted_by_id)
        self.assertIsNone(grant.revoked_at)

    def test_resident_export_pseudonymizes_other_people(self) -> None:
        from care_consent.contracts import load_events

        _, events = load_events(ROOT / "fixtures" / "visit-incident.json")
        ledger = Ledger.replay(events)
        export = resident_export(ledger, "resident-014", now=t("09:00", 21))
        raw = str(export)
        self.assertNotIn("visitor-1", raw)
        self.assertNotIn("nurse-2", raw)
        self.assertNotIn("guardian-old-1", raw)
        self.assertTrue(
            any("self" in a["requester"] or "#" in a["requester"]
                for a in export["accesses_to_my_memory"])
        )
        self.assertEqual(4, export["open_deletion_tasks"])


if __name__ == "__main__":
    unittest.main()
