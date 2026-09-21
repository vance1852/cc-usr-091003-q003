"""记忆同意代理的领域规则测试。"""

from __future__ import annotations

import json
import sys
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from care_consent import (
    ConsentAgent,
    EventEnvelope,
    InvestigationReport,
    MemoryClass,
    PolicyError,
    ResidentExport,
    Role,
    Scene,
    load_events,
)
from care_consent.inspect import build_agent, officer_summary
from care_consent.model import CORE_DEVICE, DenialReason


def env(
    event_id: str,
    kind: str,
    occurred: str,
    attributes: dict | None = None,
    *,
    received: str | None = None,
) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        kind=kind,
        occurred_at=occurred,
        received_at=received or occurred,
        attributes=attributes or {},
    )


GRANT_VOICE = env(
    "g-voice",
    "consent_granted",
    "2026-09-10T08:00:00+08:00",
    {
        "resident_id": "r1",
        "memory_class": "voice-summary",
        "audiences": ["care-staff", "r1"],
        "scenes": ["ordinary-care"],
        "retention_days": 7,
    },
)
GRANT_MED = env(
    "g-med",
    "consent_granted",
    "2026-09-10T08:00:00+08:00",
    {"resident_id": "r1", "memory_class": "medication-reminder"},
)
GRANT_PREF = env(
    "g-pref",
    "consent_granted",
    "2026-09-10T08:00:00+08:00",
    {"resident_id": "r1", "memory_class": "behavior-preference"},
)


class PurposeMatrixTest(unittest.TestCase):
    def test_each_class_has_distinct_purpose_and_retention(self) -> None:
        agent = ConsentAgent("2026-09-10T09:00:00+08:00")
        agent.load([GRANT_VOICE, GRANT_MED, GRANT_PREF])
        rec_events = [
            env(
                "rec-v", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "v"},
            ),
            env(
                "rec-m", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "medication-reminder",
                 "scene": "ordinary-care", "summary": "m"},
            ),
            env(
                "rec-p", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "behavior-preference",
                 "scene": "ordinary-care", "summary": "p"},
            ),
        ]
        agent.load(rec_events)
        v = agent.record("rec-v")
        m = agent.record("rec-m")
        p = agent.record("rec-p")
        self.assertEqual("care-context", v.purpose)
        self.assertEqual("medication-safety", m.purpose)
        self.assertEqual("personalization", p.purpose)
        self.assertEqual(timedelta(days=7), v.retention)
        self.assertEqual(timedelta(days=30), m.retention)
        self.assertEqual(timedelta(days=90), p.retention)
        self.assertTrue(all(r.authorized for r in (v, m, p)))
        self.assertEqual({"care-staff", "resident"}, set(v.audiences))

    def test_medication_grant_rejected_for_family_visit_scene(self) -> None:
        agent = ConsentAgent("2026-09-10T09:00:00+08:00")
        bad = env(
            "bad", "consent_granted", "2026-09-10T08:00:00+08:00",
            {"resident_id": "r1", "memory_class": "medication-reminder",
             "scenes": ["family-visit"]},
        )
        with self.assertRaises(Exception):
            agent.load([bad])

    def test_retention_above_ceiling_rejected(self) -> None:
        agent = ConsentAgent("2026-09-10T09:00:00+08:00")
        bad = env(
            "bad", "consent_granted", "2026-09-10T08:00:00+08:00",
            {"resident_id": "r1", "memory_class": "voice-summary",
             "retention_days": 90},
        )
        with self.assertRaises(Exception):
            agent.load([bad])

    def test_emergency_scene_cannot_be_bundled_into_grant(self) -> None:
        agent = ConsentAgent("2026-09-10T09:00:00+08:00")
        bad = env(
            "bad", "consent_granted", "2026-09-10T08:00:00+08:00",
            {"resident_id": "r1", "memory_class": "voice-summary",
             "scenes": ["ordinary-care", "emergency"]},
        )
        with self.assertRaises(PolicyError):
            agent.load([bad])

    def test_family_audience_requires_family_visit_scene(self) -> None:
        agent = ConsentAgent("2026-09-10T09:00:00+08:00")
        bad = env(
            "bad", "consent_granted", "2026-09-10T08:00:00+08:00",
            {"resident_id": "r1", "memory_class": "voice-summary",
             "audiences": ["family"], "scenes": ["ordinary-care"]},
        )
        with self.assertRaises(PolicyError):
            agent.load([bad])

    def test_default_grant_does_not_cover_family_visit_replay(self) -> None:
        agent = ConsentAgent("2026-09-18T16:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-14T20:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "私密谈话"},
            ),
        ])
        decision = agent.can_access(
            record_id="rec", actor="robot-7", audience="family",
            scene="family-visit", at="2026-09-18T15:00:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.SCENE_MISMATCH.value, decision.reason)


class RevocationTest(unittest.TestCase):
    def test_new_access_immediately_denied_after_revocation(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "x"},
            ),
            env(
                "copy", "copy_distributed", "2026-09-10T08:45:00+08:00",
                {"record_id": "rec", "device_id": "bedside-robot-07"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
        ])
        before = agent.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-10T08:59:00+08:00",
        )
        after = agent.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-10T09:01:00+08:00",
        )
        self.assertTrue(before.allowed)
        self.assertFalse(after.allowed)
        self.assertEqual(DenialReason.CONSENT_REVOKED.value, after.reason)

    def test_deletion_tasks_cover_core_and_every_downstream_copy(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care"},
            ),
            env(
                "c1", "copy_distributed", "2026-09-10T08:40:00+08:00",
                {"record_id": "rec", "device_id": "bedside-robot-07"},
            ),
            env(
                "c2", "copy_distributed", "2026-09-10T08:41:00+08:00",
                {"record_id": "rec", "device_id": "visit-console-03"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
        ])
        pending = {(t.record_id, t.device_id, t.reason) for t in agent.pending_deletions()}
        self.assertIn(("rec", CORE_DEVICE, "consent-revoked"), pending)
        self.assertIn(("rec", "bedside-robot-07", "consent-revoked"), pending)
        self.assertIn(("rec", "visit-console-03", "consent-revoked"), pending)

    def test_ack_closes_task_and_purges_content(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "私密"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "ack", "deletion_acknowledged", "2026-09-10T10:00:00+08:00",
                {"record_id": "rec", "device_id": CORE_DEVICE},
            ),
        ])
        self.assertEqual("", agent.record("rec").summary)
        self.assertIsNotNone(agent.record("rec").purged_at)
        decision = agent.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-10T10:30:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.RETENTION_EXPIRED.value, decision.reason)

    def test_repeated_ack_is_idempotent(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "ack1", "deletion_acknowledged", "2026-09-10T10:00:00+08:00",
                {"record_id": "rec", "device_id": CORE_DEVICE},
            ),
        ])
        # 模拟删除任务重试：再投递一次回执事件（新 event_id）。
        agent.apply(
            env(
                "ack2-retry", "deletion_acknowledged", "2026-09-10T10:05:00+08:00",
                {"record_id": "rec", "device_id": CORE_DEVICE},
            )
        )
        tasks = [
            t for t in agent.completed_deletions()
            if t.record_id == "rec" and t.device_id == CORE_DEVICE
        ]
        self.assertEqual(1, len(tasks))
        self.assertEqual(2, tasks[0].attempts)


class OfflineUploadTest(unittest.TestCase):
    def test_offline_record_judged_by_consent_at_occurrence(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            # 发生在 09-11（同意期内），09-19 才上传（撤回之后）。
            env(
                "offline", "memory_recorded", "2026-09-11T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "离线采集"},
                received="2026-09-19T12:30:00+08:00",
            ),
            env(
                "rev", "consent_revoked", "2026-09-18T15:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
        ])
        record = agent.record("offline")
        self.assertTrue(record.authorized)
        self.assertEqual("consent:g-voice", record.basis)
        # 撤回时记录已存在 -> 删除义务仍然产生（撤回可追溯既往副本）。
        pending = {t.device_id for t in agent.pending_deletions()}
        self.assertIn(CORE_DEVICE, pending)

    def test_record_after_revocation_is_unauthorized_even_if_uploaded_late_order(self) -> None:
        # 事件流乱序到达：先收到撤回，再收到"撤回之后发生"的记录。
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rev", "consent_revoked", "2026-09-18T15:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "late", "memory_recorded", "2026-09-19T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "撤回后采集"},
                received="2026-09-19T20:00:00+08:00",
            ),
        ])
        record = agent.record("late")
        self.assertFalse(record.authorized)
        self.assertEqual(DenialReason.CONSENT_REVOKED.value, record.unauthorized_reason)

    def test_duplicate_upload_does_not_extend_retention(self) -> None:
        agent = ConsentAgent("2026-09-25T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,  # retention 7 days
            env(
                "first", "memory_recorded", "2026-09-11T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "record_id": "dup-1", "summary": "x"},
                received="2026-09-11T09:05:00+08:00",
            ),
            env(
                "second", "memory_recorded", "2026-09-11T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "record_id": "dup-1", "summary": "x",
                 "upload_attempt": 2},
                received="2026-09-20T09:00:00+08:00",
            ),
        ])
        record = agent.record("dup-1")
        # 到期日仍按发生时间 + 7 天 = 09-18，而非第二次上传 + 7 天。
        self.assertEqual(
            record.occurred_at + timedelta(days=7),
            record.occurred_at + record.retention,
        )
        self.assertEqual(1, len(agent.all_records()))
        agent.sync_deletions()
        reasons = {t.reason for t in agent.pending_deletions()}
        self.assertIn("retention-expired", reasons)

    def test_duplicate_event_id_is_fully_idempotent(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        e = env(
            "same-id", "memory_recorded", "2026-09-11T09:00:00+08:00",
            {"resident_id": "r1", "memory_class": "voice-summary",
             "scene": "ordinary-care"},
        )
        agent.load([GRANT_VOICE, e])
        agent.apply(e)  # 重放
        self.assertEqual(1, len(agent.all_records()))


class EmergencyTest(unittest.TestCase):
    def _agent_with_emergency_record(self, *, close: bool, now: str) -> ConsentAgent:
        events = [
            GRANT_VOICE,
            env(
                "emg-open", "emergency_declared", "2026-09-17T02:00:00+08:00",
                {"resident_id": "r1"},
            ),
            env(
                "emg-rec", "memory_recorded", "2026-09-17T02:05:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "emergency", "summary": "急救口述"},
            ),
            env(
                "emg-copy", "copy_distributed", "2026-09-17T02:10:00+08:00",
                {"record_id": "emg-rec", "device_id": "responder-tablet-05"},
            ),
        ]
        if close:
            events.append(
                env(
                    "emg-clear", "emergency_cleared", "2026-09-17T03:00:00+08:00",
                    {"resident_id": "r1"},
                )
            )
        agent = ConsentAgent(now)
        agent.load(events)
        return agent

    def test_emergency_collection_allowed_without_consent(self) -> None:
        agent = ConsentAgent("2026-09-17T02:30:00+08:00")
        agent.load([
            env(
                "emg-open", "emergency_declared", "2026-09-17T02:00:00+08:00",
                {"resident_id": "r2"},
            ),
            env(
                "emg-rec", "memory_recorded", "2026-09-17T02:05:00+08:00",
                {"resident_id": "r2", "memory_class": "voice-summary",
                 "scene": "emergency"},
            ),
        ])
        self.assertTrue(agent.record("emg-rec").authorized)
        decision = agent.can_access(
            record_id="emg-rec", actor="emt", audience="emergency-responder",
            scene="emergency", at="2026-09-17T02:20:00+08:00",
        )
        self.assertTrue(decision.allowed)

    def test_family_cannot_use_emergency_exemption(self) -> None:
        agent = self._agent_with_emergency_record(
            close=False, now="2026-09-17T02:30:00+08:00"
        )
        decision = agent.can_access(
            record_id="emg-rec", actor="family-console", audience="family",
            scene="family-visit", at="2026-09-17T02:20:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.SCENE_MISMATCH.value, decision.reason)

    def test_emergency_end_creates_deletions_and_does_not_become_consent(self) -> None:
        agent = self._agent_with_emergency_record(
            close=True, now="2026-09-17T04:00:00+08:00"
        )
        pending = {(t.device_id, t.reason) for t in agent.pending_deletions()}
        self.assertIn((CORE_DEVICE, "emergency-ended"), pending)
        self.assertIn(("responder-tablet-05", "emergency-ended"), pending)
        decision = agent.can_access(
            record_id="emg-rec", actor="emt", audience="emergency-responder",
            scene="emergency", at="2026-09-17T03:30:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.EMERGENCY_ENDED.value, decision.reason)
        # 豁免期间的紧急数据不变成普通记忆：普通照护场景同样不可访问。
        decision2 = agent.can_access(
            record_id="emg-rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-17T03:30:00+08:00",
        )
        self.assertFalse(decision2.allowed)
        self.assertEqual(DenialReason.EMERGENCY_ENDED.value, decision2.reason)

    def test_emergency_data_stays_emergency_only_during_window(self) -> None:
        agent = self._agent_with_emergency_record(
            close=False, now="2026-09-17T02:30:00+08:00"
        )
        # 窗口仍在，但普通照护/家属探视不能借用紧急豁免的数据。
        decision = agent.can_access(
            record_id="emg-rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-17T02:20:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.SCENE_MISMATCH.value, decision.reason)

    def test_emergency_record_collected_after_clear_is_unauthorized(self) -> None:
        agent = ConsentAgent("2026-09-17T05:00:00+08:00")
        agent.load([
            env(
                "emg-open", "emergency_declared", "2026-09-17T02:00:00+08:00",
                {"resident_id": "r1"},
            ),
            env(
                "emg-clear", "emergency_cleared", "2026-09-17T03:00:00+08:00",
                {"resident_id": "r1"},
            ),
            env(
                "late-emg", "memory_recorded", "2026-09-17T03:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "emergency"},
            ),
        ])
        self.assertFalse(agent.record("late-emg").authorized)

    def test_resident_refusal_blocks_emergency_collection(self) -> None:
        agent = ConsentAgent("2026-09-17T03:00:00+08:00")
        agent.load([
            env(
                "refuse", "sharing_refused", "2026-09-16T00:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "emergency"},
            ),
            env(
                "emg-open", "emergency_declared", "2026-09-17T02:00:00+08:00",
                {"resident_id": "r1"},
            ),
            env(
                "emg-rec", "memory_recorded", "2026-09-17T02:05:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "emergency"},
            ),
        ])
        self.assertFalse(agent.record("emg-rec").authorized)
        self.assertEqual(
            DenialReason.RESIDENT_REFUSED.value,
            agent.record("emg-rec").unauthorized_reason,
        )


class GuardianshipTest(unittest.TestCase):
    def test_guardian_can_grant_only_while_appointment_active(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        agent.load([
            env("reg", "resident_registered", "2026-09-01T09:00:00+08:00",
                {"resident_id": "r1"}),
            env("gg", "guardianship_granted", "2026-09-01T09:05:00+08:00",
                {"resident_id": "r1", "guardian_id": "g9"}),
            env(
                "gm", "consent_granted", "2026-09-13T09:05:00+08:00",
                {"resident_id": "r1", "memory_class": "medication-reminder",
                 "granted_by": "g9", "grantor_role": "guardian"},
            ),
        ])
        chain = agent.grant_chain("r1", "medication-reminder")
        self.assertEqual("g9", chain[0].term.granted_by)

    def test_grant_after_guardianship_change_rejected(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        with self.assertRaises(Exception):
            agent.load([
                env("gg", "guardianship_granted", "2026-09-01T09:05:00+08:00",
                    {"resident_id": "r1", "guardian_id": "g9"}),
                env("gx", "guardianship_revoked", "2026-09-19T14:00:00+08:00",
                    {"resident_id": "r1", "guardian_id": "g9"}),
                env(
                    "late-g", "consent_granted", "2026-09-19T15:00:00+08:00",
                    {"resident_id": "r1", "memory_class": "medication-reminder",
                     "granted_by": "g9", "grantor_role": "guardian"},
                ),
            ])

    def test_guardianship_change_preserves_responsibility_chain(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        agent.load([
            env("gg", "guardianship_granted", "2026-09-01T09:05:00+08:00",
                {"resident_id": "r1", "guardian_id": "g9"}),
            env(
                "gm", "consent_granted", "2026-09-13T09:05:00+08:00",
                {"resident_id": "r1", "memory_class": "medication-reminder",
                 "granted_by": "g9", "grantor_role": "guardian"},
            ),
            env("gx", "guardianship_revoked", "2026-09-19T14:00:00+08:00",
                {"resident_id": "r1", "guardian_id": "g9"}),
            env("gn", "guardianship_granted", "2026-09-19T14:05:00+08:00",
                {"resident_id": "r1", "guardian_id": "g10"}),
        ])
        ships = agent.guardianship_chain("r1")
        self.assertEqual(2, len(ships))
        self.assertIsNotNone(ships[0].valid_to)
        # 旧授权仍记录由 g9 作出，责任不被新监护关系抹掉。
        chain = agent.grant_chain("r1", "medication-reminder")
        self.assertEqual("g9", chain[0].term.granted_by)


class ExpiryTest(unittest.TestCase):
    def test_expired_record_not_visible_and_gets_deletion_task(self) -> None:
        agent = ConsentAgent("2026-09-25T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-11T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "旧摘要"},
            ),
        ])
        decision = agent.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-24T00:00:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.RETENTION_EXPIRED.value, decision.reason)
        pending = {t.device_id: t.reason for t in agent.pending_deletions()}
        self.assertEqual("retention-expired", pending[CORE_DEVICE])

    def test_restart_replay_does_not_revive_purged_content(self) -> None:
        # 第一次运行：撤回 -> 删除回执。
        first = ConsentAgent("2026-09-10T12:00:00+08:00")
        events = [
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "私密"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "ack", "deletion_acknowledged", "2026-09-10T10:00:00+08:00",
                {"record_id": "rec", "device_id": CORE_DEVICE},
            ),
        ]
        first.load(events)
        # 模拟数据库重启：用同一事件流重建状态。
        restarted = ConsentAgent("2026-09-11T00:00:00+08:00")
        restarted.load(events)
        record = restarted.record("rec")
        self.assertIsNotNone(record.purged_at)
        self.assertEqual("", record.summary)
        decision = restarted.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-11T00:00:00+08:00",
        )
        self.assertFalse(decision.allowed)
        # 已完成的删除任务保持完成，不重新挂起。
        self.assertEqual(0, len(restarted.pending_deletions()))

    def test_core_purge_does_not_close_downstream_tasks(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care"},
            ),
            env(
                "copy", "copy_distributed", "2026-09-10T08:45:00+08:00",
                {"record_id": "rec", "device_id": "bedside-robot-07"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "purged", "memory_purged", "2026-09-10T10:00:00+08:00",
                {"record_id": "rec"},
            ),
        ])
        pending = {t.device_id for t in agent.pending_deletions()}
        self.assertEqual({"bedside-robot-07"}, pending)
        completed = {
            t.device_id for t in agent.completed_deletions() if t.record_id == "rec"
        }
        self.assertEqual({CORE_DEVICE}, completed)

    def test_batch_ack_with_minimal_envelope_closes_scope(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "batch-ack", "deletion_acknowledged", "2026-09-10T10:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
        ])
        self.assertEqual(0, len(agent.pending_deletions()))
        self.assertIsNotNone(agent.record("rec").purged_at)

    def test_unknown_event_type_is_retained_not_dropped(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        weird = env(
            "x1", "future_event_kind", "2026-09-10T08:00:00+08:00",
            {"resident_id": "r1", "note": "保留"},
        )
        agent.load([weird])
        self.assertEqual([weird], agent.unknown_events)


class UnauthorizedRecordingTest(unittest.TestCase):
    def test_recording_without_consent_generates_deletion_task(self) -> None:
        agent = ConsentAgent("2026-09-10T12:00:00+08:00")
        agent.load([
            env(
                "rogue", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "没有同意的录音"},
            ),
        ])
        record = agent.record("rogue")
        self.assertFalse(record.authorized)
        pending = [t for t in agent.pending_deletions() if t.record_id == "rogue"]
        self.assertEqual(1, len(pending))
        self.assertEqual("unauthorized-record", pending[0].reason)
        decision = agent.can_access(
            record_id="rogue", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-10T09:00:00+08:00",
        )
        self.assertFalse(decision.allowed)

    def test_explicit_refusal_blocks_family_sharing_despite_grant(self) -> None:
        agent = ConsentAgent("2026-09-18T16:00:00+08:00")
        agent.load([
            env(
                "g", "consent_granted", "2026-09-13T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "audiences": ["care-staff", "r1", "family"],
                 "scenes": ["ordinary-care", "family-visit"],
                 "retention_days": 7},
            ),
            env(
                "rec", "memory_recorded", "2026-09-14T20:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "family-visit", "summary": "谈话"},
            ),
            env(
                "refuse", "sharing_refused", "2026-09-14T20:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "family-visit"},
            ),
        ])
        decision = agent.can_access(
            record_id="rec", actor="robot", audience="family",
            scene="family-visit", at="2026-09-18T15:00:00+08:00",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(DenialReason.RESIDENT_REFUSED.value, decision.reason)
        # 普通照护场景不受家属探视的拒绝影响。
        ok = agent.can_access(
            record_id="rec", actor="nurse", audience="care-staff",
            scene="ordinary-care", at="2026-09-18T10:00:00+08:00",
        )
        self.assertTrue(ok.allowed)


class LateCopyTest(unittest.TestCase):
    def test_copy_distributed_after_revocation_gets_immediate_deletion(self) -> None:
        agent = ConsentAgent("2026-09-20T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "late-copy", "copy_distributed", "2026-09-19T11:00:00+08:00",
                {"record_id": "rec", "device_id": "bedside-robot-07"},
            ),
        ])
        pending = {t.device_id: t.reason for t in agent.pending_deletions()}
        self.assertIn("bedside-robot-07", pending)

    def test_new_grant_after_revocation_does_not_cancel_old_deletion(self) -> None:
        agent = ConsentAgent("2026-09-12T00:00:00+08:00")
        agent.load([
            GRANT_VOICE,
            env(
                "rec", "memory_recorded", "2026-09-10T08:30:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "old"},
            ),
            env(
                "rev", "consent_revoked", "2026-09-10T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary"},
            ),
            env(
                "g2", "consent_granted", "2026-09-11T09:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "retention_days": 7},
            ),
            env(
                "new-rec", "memory_recorded", "2026-09-11T10:00:00+08:00",
                {"resident_id": "r1", "memory_class": "voice-summary",
                 "scene": "ordinary-care", "summary": "new"},
            ),
        ])
        old_tasks = {
            t.device_id for t in agent.pending_deletions() if t.record_id == "rec"
        }
        new_tasks = {
            t.device_id for t in agent.pending_deletions() if t.record_id == "new-rec"
        }
        self.assertIn(CORE_DEVICE, old_tasks)
        self.assertEqual(set(), new_tasks)


class FixtureReportTest(unittest.TestCase):
    def test_visit_incident_finding_for_the_private_talk(self) -> None:
        scenario, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        self.assertEqual("family-visit-private-talk-incident", scenario)
        report = InvestigationReport(agent).record_findings("rec-voice-0001")

        # 为何不应被复述：在事故当时（家属探视、面向家属）回放即被阻断。
        incident = report["why_it_should_not_have_been_replayed"]
        self.assertIsNotNone(incident)
        self.assertFalse(incident["would_be_allowed"])
        self.assertEqual("family-visit", incident["scene"])
        self.assertEqual("family", incident["audience"])
        self.assertIn(incident["reason"], {
            DenialReason.RESIDENT_REFUSED.value,
            DenialReason.SCENE_MISMATCH.value,
            DenialReason.AUDIENCE_MISMATCH.value,
        })
        # 现在该记录也已因撤回/过期而不可访问。
        blocked = report["why_replay_now_is_blocked"]
        self.assertIsNotNone(blocked)

        # 哪些副本仍待删除：床边机器人与探视屏，核心库已回执。
        pending_devices = set(report["pending_copy_deletions"])
        self.assertIn("bedside-robot-07", pending_devices)
        self.assertIn("visit-console-03", pending_devices)
        task_devices = {t["device_id"] for t in report["deletion_tasks"]}
        self.assertIn(CORE_DEVICE, task_devices)
        core_task = next(
            t for t in report["deletion_tasks"] if t["device_id"] == CORE_DEVICE
        )
        self.assertEqual("completed", core_task["status"])

        # 谁在什么依据下访问过：那次家属探视复述被记录为违规。
        violations = [a for a in report["access_log"] if not a["allowed"]]
        self.assertTrue(any(a["audience"] == "family" for a in violations))
        self.assertTrue(all("compliance" in a for a in report["access_log"]))

        # 责任链保留：授权由本人作出，撤回由本人作出。
        chain = report["consent_chain"]
        self.assertTrue(any(g["revoked_by"] == "resident-014" for g in chain))
        self.assertTrue(any(g["granted_by"] == "resident-014" for g in chain))

    def test_emergency_record_deletion_completed_in_fixture(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        report = InvestigationReport(agent).record_findings("rec-emg-0001")
        self.assertEqual("purged", report["status"])
        self.assertEqual(0, len(report["pending_copy_deletions"]))
        self.assertTrue(
            all(t["status"] == "completed" for t in report["deletion_tasks"])
        )

    def test_offline_record_judged_at_occurrence_and_duplicate_collapsed(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        record = agent.record("rec-voice-0002")
        self.assertTrue(record.authorized)
        # 09-17 09:00 发生时同意仍有效（09-18 15:30 才撤回）。
        # 撤回时该记录已存在，所以删除任务仍在；重复上传只有一条记录。
        self.assertEqual(
            1,
            len([r for r in agent.all_records() if r.record_id == "rec-voice-0002"]),
        )

    def test_guardianship_change_kept_in_report(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        report = InvestigationReport(agent).record_findings("rec-voice-0001")
        guardians = report["guardianship_chain"]
        self.assertEqual(2, len(guardians))
        self.assertEqual("g9" if False else "guardian-009", guardians[0]["guardian_id"])
        self.assertIsNotNone(guardians[0]["valid_to"])
        self.assertEqual("guardian-010", guardians[1]["guardian_id"])

    def test_officer_summary_lists_pending_copy_locations(self) -> None:
        scenario, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        summary = officer_summary(scenario, agent, None)
        self.assertIn("bedside-robot-07", summary["pending_copy_locations"])
        self.assertIn("visit-console-03", summary["pending_copy_locations"])


class ResidentExportTest(unittest.TestCase):
    def test_export_redacts_other_residents(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        export = ResidentExport(agent).export("resident-014")
        private = next(
            r for r in export["your_memory_records"] if r["record_id"] == "rec-voice-0001"
        )
        self.assertTrue(private["contains_other_peoples_information"])
        self.assertEqual("【涉及他人，已遮蔽】", private["content"])
        self.assertNotIn("resident-022", json.dumps(export, ensure_ascii=False))

    def test_export_contains_own_records_and_consent_history(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        export = ResidentExport(agent).export("resident-014")
        ids = {r["record_id"] for r in export["your_memory_records"]}
        self.assertIn("rec-voice-0001", ids)
        self.assertIn("rec-med-0001", ids)
        self.assertIn("rec-emg-0001", ids)
        voice_chain = export["your_consent_decisions"]["voice-summary"]
        self.assertTrue(any(g["active"] is False for g in voice_chain))

    def test_export_for_other_resident_exposes_nothing_about_resident_014(self) -> None:
        _, agent = build_agent(ROOT / "fixtures" / "visit_incident.json")
        export = ResidentExport(agent).export("resident-022")
        blob = json.dumps(export, ensure_ascii=False)
        self.assertNotIn("rec-voice-0001", blob)
        self.assertNotIn("rec-emg-0001", blob)
        self.assertNotIn("resident-014", blob)


if __name__ == "__main__":
    unittest.main()
