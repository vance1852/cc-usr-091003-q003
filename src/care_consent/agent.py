"""记忆同意代理：机器人应用的统一入口。

每次记录、调用、分发、撤回与遗忘都落为不可变事件；代理不隐式读取
系统时钟，所有时间点由调用方显式提供。
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from . import domain
from .contracts import EventEnvelope
from .domain import POLICY, CareContext, MemoryClass
from .ledger import Ledger
from .policy import (
    AccessDecision,
    AccessRequest,
    RecordingDecision,
    RecordingRequest,
    judge_access,
    judge_recording,
)

DELETION_SLA_DEFAULT = timedelta(hours=24)


def _iso(at: datetime) -> str:
    if at.tzinfo is None:
        raise ValueError("时间必须包含时区")
    return at.isoformat()


class ConsentError(ValueError):
    """代理调用不满足前置条件。"""


@dataclass
class ActionResult:
    allowed: bool
    events: list[EventEnvelope]
    reason: str | None = None
    record_id: str | None = None
    task_ids: tuple[str, ...] = ()
    duplicate: bool = False
    decision: RecordingDecision | AccessDecision | None = None


class EventStore:
    """JSONL 事件存储；整库写入用临时文件加原子替换。"""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None

    def append(self, events: list[EventEnvelope]) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(self._raw(event), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def load(self) -> list[EventEnvelope]:
        if self.path is None or not self.path.exists():
            return []
        events: list[EventEnvelope] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(
                    EventEnvelope.from_dict(json.loads(line))
                )
        return events

    def replace_all(self, events: list[EventEnvelope]) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps(self._raw(event), ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)

    @staticmethod
    def _raw(event: EventEnvelope) -> dict[str, Any]:
        return {
            "event_id": event.event_id,
            "kind": event.kind,
            "occurred_at": event.occurred_at,
            "received_at": event.received_at,
            "attributes": event.attributes,
        }


class ConsentAgent:
    """机器人侧的记忆同意代理。"""

    def __init__(
        self,
        store: EventStore | None = None,
        *,
        deletion_sla: timedelta = DELETION_SLA_DEFAULT,
        id_factory: Callable[[], str] | None = None,
        ledger: Ledger | None = None,
    ):
        self.store = store or EventStore()
        self.deletion_sla = deletion_sla
        self._next_id = id_factory or (lambda: uuid.uuid4().hex)
        if ledger is not None:
            self.ledger = ledger
        else:
            self.ledger = Ledger.replay(self.store.load())

    # ---- 事件落账 ----------------------------------------------------

    def _emit(
        self,
        kind: str,
        at: datetime,
        attributes: dict[str, Any],
        *,
        event_id: str | None = None,
        received_at: datetime | None = None,
    ) -> EventEnvelope:
        event = EventEnvelope(
            event_id=event_id or f"evt-{self._next_id()}",
            kind=kind,
            occurred_at=_iso(at),
            received_at=_iso(received_at or at),
            attributes=attributes,
        )
        if self.ledger.append(event):
            self.store.append([event])
        return event

    # ---- 监护关系 ----------------------------------------------------

    def designate_guardian(
        self,
        *,
        guardian_id: str,
        resident_id: str,
        relation: str,
        at: datetime,
        event_id: str | None = None,
    ) -> EventEnvelope:
        return self._emit(
            "guardian_designated",
            at,
            {
                "guardian_id": guardian_id,
                "resident_id": resident_id,
                "relation": relation,
            },
            event_id=event_id,
        )

    def revoke_guardianship(
        self, *, guardian_id: str, at: datetime, event_id: str | None = None
    ) -> EventEnvelope:
        if guardian_id not in self.ledger.guardians:
            raise ConsentError(f"未知监护关系：{guardian_id}")
        return self._emit(
            "guardian_revoked",
            at,
            {"guardian_id": guardian_id},
            event_id=event_id,
        )

    # ---- 授权与拒绝 --------------------------------------------------

    def grant_consent(
        self,
        *,
        resident_id: str,
        memory_class: str,
        purpose: str,
        contexts: list[str] | str,
        audience: list[str] | str,
        at: datetime,
        granted_by_role: str,
        granted_by_id: str,
        retention: timedelta | None = None,
        grant_id: str | None = None,
        event_id: str | None = None,
    ) -> EventEnvelope:
        mem = MemoryClass(memory_class)
        rule = POLICY[mem]
        contexts = [contexts] if isinstance(contexts, str) else list(contexts)
        audience = [audience] if isinstance(audience, str) else list(audience)
        for ctx in contexts:
            if CareContext(ctx) is CareContext.EMERGENCY:
                # 生命危险豁免由法定情形触发，不能被“同意”预先打包。
                raise ConsentError("紧急豁免不能作为同意授予")
        if purpose not in rule.allowed_purposes:
            raise ConsentError(
                f"{memory_class} 不允许目的 {purpose}；"
                f"允许：{sorted(rule.allowed_purposes)}"
            )
        if not audience:
            raise ConsentError("至少指定一个可见对象")
        if granted_by_role == domain.ActorRole.GUARDIAN.value:
            guardianship = self.ledger.guardians.get(granted_by_id)
            if guardianship is None or not guardianship.active_at(at):
                raise ConsentError("授权时不存在有效的监护关系")
            if guardianship.resident_id != resident_id:
                raise ConsentError("监护人只能为被监护住户授权")
        elif granted_by_role != domain.ActorRole.RESIDENT.value:
            raise ConsentError("只能由住户本人或监护人授权")

        retention = rule.retention(retention)
        grant_id = grant_id or f"grant-{self._next_id()}"
        return self._emit(
            "consent_granted",
            at,
            {
                "grant_id": grant_id,
                "resident_id": resident_id,
                "subject_id": resident_id,
                "subject_type": "resident",
                "granted_by_role": granted_by_role,
                "granted_by_id": granted_by_id,
                "guardian_id": (
                    granted_by_id
                    if granted_by_role == domain.ActorRole.GUARDIAN.value
                    else None
                ),
                "memory_class": memory_class,
                "purpose": purpose,
                "contexts": contexts,
                "audience": audience,
                "retention_seconds": int(retention.total_seconds()),
                "valid_from": _iso(at),
            },
            event_id=event_id,
        )

    def decline_sharing(
        self,
        *,
        resident_id: str,
        memory_class: str,
        context: str,
        at: datetime,
        audience_token: str | None = None,
        decline_id: str | None = None,
        event_id: str | None = None,
    ) -> EventEnvelope:
        MemoryClass(memory_class)
        CareContext(context)
        return self._emit(
            "sharing_declined",
            at,
            {
                "decline_id": decline_id or f"decline-{self._next_id()}",
                "resident_id": resident_id,
                "memory_class": memory_class,
                "context": context,
                "audience_token": audience_token,
            },
            event_id=event_id,
        )

    def revoke_consent(
        self,
        *,
        resident_id: str,
        memory_class: str,
        purpose: str,
        at: datetime,
        revoked_by: str,
        grant_id: str | None = None,
        subject_id: str | None = None,
        event_id: str | None = None,
    ) -> ActionResult:
        MemoryClass(memory_class)
        attrs = {
            "resident_id": resident_id,
            "memory_class": memory_class,
            "purpose": purpose,
            "revoked_by": revoked_by,
        }
        if grant_id:
            attrs["grant_id"] = grant_id
        if subject_id:
            attrs["subject_id"] = subject_id
        revoke_event = self._emit(
            "consent_revoked", at, attrs, event_id=event_id
        )
        affected = self._records_covered_by(
            resident_id, memory_class, purpose, grant_id
        )
        task_ids: list[str] = []
        for record in affected:
            tasks = self._shred(record, at, reason="revocation",
                                trigger_event_id=revoke_event.event_id)
            task_ids.extend(tasks)
        return ActionResult(
            allowed=True,
            events=[revoke_event],
            record_id=None,
            task_ids=tuple(task_ids),
        )

    # ---- 暂停 / 恢复 -------------------------------------------------

    def suspend_memory(
        self, *, by_id: str, reason: str, at: datetime, event_id: str | None = None
    ) -> EventEnvelope:
        return self._emit(
            "memory_suspended",
            at,
            {"by_id": by_id, "reason": reason},
            event_id=event_id,
        )

    def restore_memory(self, *, at: datetime, event_id: str | None = None) -> EventEnvelope:
        return self._emit("memory_restored", at, {}, event_id=event_id)

    # ---- 紧急豁免 ----------------------------------------------------

    def start_emergency(
        self,
        *,
        emergency_id: str,
        at: datetime,
        resident_id: str | None = None,
        event_id: str | None = None,
    ) -> EventEnvelope:
        return self._emit(
            "emergency_started",
            at,
            {"emergency_id": emergency_id, "resident_id": resident_id},
            event_id=event_id,
        )

    def end_emergency(
        self, *, emergency_id: str, at: datetime, event_id: str | None = None
    ) -> EventEnvelope:
        if emergency_id not in self.ledger.emergencies:
            raise ConsentError(f"未知紧急事件：{emergency_id}")
        return self._emit(
            "emergency_ended",
            at,
            {"emergency_id": emergency_id},
            event_id=event_id,
        )

    # ---- 记录（含离线上传） ------------------------------------------

    def record_memory(
        self,
        *,
        resident_id: str,
        memory_class: str,
        purpose: str,
        context: str,
        content_id: str,
        occurred_at: datetime,
        received_at: datetime,
        collector_id: str,
        device_id: str,
        record_id: str | None = None,
        event_id: str | None = None,
    ) -> ActionResult:
        if received_at < occurred_at:
            raise ConsentError("接收时间不能早于发生时间")

        duplicate = self._find_content(resident_id, content_id)
        if duplicate is not None:
            # 重复上传：不新建事实、不刷新 expires_at、不产生新副本。
            return ActionResult(
                allowed=True,
                events=[],
                record_id=duplicate.record_id,
                duplicate=True,
            )

        record_id = record_id or f"rec-{self._next_id()}"
        request = RecordingRequest(
            resident_id=resident_id,
            memory_class=memory_class,
            purpose=purpose,
            context=context,
            content_id=content_id,
            occurred_at=occurred_at,
            received_at=received_at,
            collector_id=collector_id,
            record_id=record_id,
        )
        decision = judge_recording(self.ledger, request)
        if not decision.allowed:
            refused = self._emit(
                "recording_refused",
                occurred_at,
                {
                    "resident_id": resident_id,
                    "memory_class": memory_class,
                    "purpose": purpose,
                    "context": context,
                    "content_id": content_id,
                    "collector_id": collector_id,
                    "reason": decision.reason,
                },
                event_id=event_id,
                received_at=received_at,
            )
            result = ActionResult(False, [refused], decision.reason, record_id)
            return result

        attrs = {
            "record_id": record_id,
            "resident_id": resident_id,
            "memory_class": memory_class,
            "purpose": purpose,
            "context": context,
            "basis_type": decision.basis_type,
            "basis_id": decision.basis_id,
            "guardian_id": decision.guardian_id,
            "granted_by": decision.granted_by,
            "content_id": content_id,
            "expires_at": _iso(decision.expires_at) if decision.expires_at else None,
        }
        recorded = self._emit(
            "memory_recorded",
            occurred_at,
            attrs,
            event_id=event_id,
            received_at=received_at,
        )
        source_copy = self._emit(
            "copy_distributed",
            occurred_at,
            {
                "copy_id": f"copy-src-{record_id}",
                "record_id": record_id,
                "device_id": "core-memory",
                "is_source": True,
            },
            received_at=received_at,
        )
        # 采集机器人本地缓存是第一份下游副本，撤回时同样要删除。
        local_copy = self._emit(
            "copy_distributed",
            occurred_at,
            {
                "copy_id": f"copy-local-{record_id}",
                "record_id": record_id,
                "device_id": device_id,
                "is_source": False,
            },
            received_at=received_at,
        )
        events = [recorded, source_copy, local_copy]
        task_ids: list[str] = []
        # 延迟上传的内容落账时撤回/过期已经生效：立即撕碎并建删除任务。
        record = self.ledger.records[record_id]
        if self._should_forget_now(record, received_at):
            task_ids = self._shred(
                record,
                received_at,
                reason="revocation"
                if self._is_revoked(record, received_at)
                else "expiry",
                trigger_event_id=recorded.event_id,
            )
        return ActionResult(
            allowed=True,
            events=events,
            record_id=record_id,
            task_ids=tuple(task_ids),
            decision=decision,
        )

    # ---- 调用 --------------------------------------------------------

    def access_memory(
        self,
        *,
        record_id: str,
        requester_role: str,
        requester_id: str,
        context: str,
        purpose: str,
        at: datetime,
        copy_id: str | None = None,
        access_id: str | None = None,
        event_id: str | None = None,
    ) -> ActionResult:
        request = AccessRequest(
            record_id=record_id,
            requester_role=requester_role,
            requester_id=requester_id,
            context=context,
            purpose=purpose,
            at=at,
            copy_id=copy_id,
        )
        decision = judge_access(self.ledger, request)
        record = self.ledger.records.get(record_id)
        logged = self._emit(
            "access_logged",
            at,
            {
                "access_id": access_id or f"acc-{self._next_id()}",
                "record_id": record_id,
                "copy_id": copy_id,
                "requester_role": requester_role,
                "requester_id": requester_id,
                "context": context,
                "purpose": purpose,
                "allowed": decision.allowed,
                "reason": decision.reason,
                "basis_type": decision.basis_type,
                "basis_id": decision.basis_id,
                "breach": decision.breach,
                "resident_id": record.resident_id if record else None,
            },
            event_id=event_id,
        )
        result = ActionResult(
            allowed=decision.allowed,
            events=[logged],
            reason=decision.reason,
            record_id=record_id,
            decision=decision,
        )
        return result

    # ---- 下游副本 ----------------------------------------------------

    def distribute_copy(
        self,
        *,
        record_id: str,
        device_id: str,
        requester_role: str,
        requester_id: str,
        context: str,
        at: datetime,
        copy_id: str | None = None,
        event_id: str | None = None,
    ) -> ActionResult:
        record = self.ledger.records.get(record_id)
        if record is None:
            raise ConsentError(f"未知记忆：{record_id}")
        decision = judge_access(
            self.ledger,
            AccessRequest(
                record_id=record_id,
                requester_role=requester_role,
                requester_id=requester_id,
                context=context,
                purpose=record.purpose,
                at=at,
            ),
        )
        if not decision.allowed:
            refused = self._emit(
                "authorization_refused",
                at,
                {
                    "record_id": record_id,
                    "device_id": device_id,
                    "requester_role": requester_role,
                    "requester_id": requester_id,
                    "context": context,
                    "reason": decision.reason,
                },
                event_id=event_id,
            )
            return ActionResult(False, [refused], decision.reason, record_id)

        existing = next(
            (
                copy
                for copy in self.ledger.copies_of(record_id)
                if copy.device_id == device_id and copy.deleted_at is None
            ),
            None,
        )
        if existing is not None:
            return ActionResult(
                allowed=True, events=[], record_id=record_id, duplicate=True
            )
        event = self._emit(
            "copy_distributed",
            at,
            {
                "copy_id": copy_id or f"copy-{self._next_id()}",
                "record_id": record_id,
                "device_id": device_id,
                "is_source": False,
            },
            event_id=event_id,
        )
        return ActionResult(True, [event], None, record_id)

    def acknowledge_deletion(
        self,
        *,
        task_id: str,
        at: datetime,
        event_id: str | None = None,
    ) -> ActionResult:
        task = self.ledger.tasks.get(task_id)
        if task is None:
            raise ConsentError(f"未知删除任务：{task_id}")
        if task.acknowledged_at is not None:
            # 设备重试：回执幂等，不产生重复事件。
            return ActionResult(
                allowed=True, events=[], record_id=task.record_id, duplicate=True
            )
        event = self._emit(
            "deletion_acknowledged",
            at,
            {"task_id": task_id, "copy_id": task.copy_id},
            event_id=event_id,
        )
        return ActionResult(True, [event], None, task.record_id)

    # ---- 到期清扫 ----------------------------------------------------

    def sweep_expired(self, *, at: datetime) -> list[str]:
        """使所有到期/豁免结束的内容立即不可见并补建删除任务。幂等。"""
        task_ids: list[str] = []
        for record in list(self.ledger.records.values()):
            if record.shredded_at is not None:
                continue
            if not self._should_forget_now(record, at):
                continue
            reason = "emergency-end" if record.basis_type == "emergency" else "expiry"
            task_ids.extend(
                self._shred(record, at, reason=reason, trigger_event_id=None)
            )
        return task_ids

    # ---- 内部辅助 ----------------------------------------------------

    def _records_covered_by(
        self,
        resident_id: str,
        memory_class: str,
        purpose: str,
        grant_id: str | None,
    ):
        ids: set[str] | None = None
        if grant_id is not None:
            ids = {grant_id}
        else:
            ids = {
                grant.grant_id
                for grant in self.ledger.grants.values()
                if grant.resident_id == resident_id
                and grant.memory_class == memory_class
                and grant.purpose == purpose
            }
        return [
            record
            for record in self.ledger.records.values()
            if record.resident_id == resident_id
            and record.memory_class == memory_class
            and record.purpose == purpose
            and record.basis_id in ids
            and record.shredded_at is None
        ]

    def _find_content(self, resident_id: str, content_id: str):
        return next(
            (
                record
                for record in self.ledger.records.values()
                if record.resident_id == resident_id
                and record.content_id == content_id
            ),
            None,
        )

    def _is_revoked(self, record, at: datetime) -> bool:
        if record.basis_type != "consent":
            return False
        grant = self.ledger.grants.get(record.basis_id)
        return grant is not None and grant.revoked_at is not None and at >= grant.revoked_at

    def _should_forget_now(self, record, at: datetime) -> bool:
        if record.expires_at is not None and at >= record.expires_at:
            return True
        if self._is_revoked(record, at):
            return True
        if record.basis_type == "emergency":
            from .domain import EMERGENCY_DEFAULT_WINDOW, EMERGENCY_GRACE

            emergency = self.ledger.emergencies.get(record.basis_id)
            if emergency is not None:
                if emergency.ended_at is not None:
                    if at >= emergency.ended_at + EMERGENCY_GRACE:
                        return True
                elif at >= emergency.started_at + EMERGENCY_DEFAULT_WINDOW:
                    return True
        return False

    def _shred(self, record, at: datetime, *, reason: str, trigger_event_id: str | None) -> list[str]:
        """撕碎内容本体并为仍在设备上的副本建立可追踪删除任务。"""
        task_ids: list[str] = []
        events: list[EventEnvelope] = []
        live_copies = [c for c in self.ledger.copies_of(record.record_id) if c.deleted_at is None]
        copy_ids = [c.copy_id for c in live_copies if c.is_source]
        if record.shredded_at is None:
            events.append(
                EventEnvelope(
                    event_id=f"evt-{self._next_id()}",
                    kind="content_shredded",
                    occurred_at=_iso(at),
                    received_at=_iso(at),
                    attributes={
                        "record_id": record.record_id,
                        "reason": reason,
                        "trigger_event_id": trigger_event_id,
                        "copy_ids": copy_ids,
                    },
                )
            )
        for copy in live_copies:
            if copy.is_source:
                continue
            existing_task = next(
                (
                    task
                    for task in self.ledger.tasks.values()
                    if task.copy_id == copy.copy_id and task.acknowledged_at is None
                ),
                None,
            )
            if existing_task is not None:
                continue
            task_id = f"task-{self._next_id()}"
            events.append(
                EventEnvelope(
                    event_id=f"evt-{self._next_id()}",
                    kind="deletion_task_created",
                    occurred_at=_iso(at),
                    received_at=_iso(at),
                    attributes={
                        "task_id": task_id,
                        "copy_id": copy.copy_id,
                        "record_id": record.record_id,
                        "device_id": copy.device_id,
                        "reason": reason,
                        "due_at": _iso(at + self.deletion_sla),
                    },
                )
            )
            task_ids.append(task_id)
        for event in events:
            self.ledger.append(event)
        self.store.append(events)
        return task_ids

    # ---- 重启 --------------------------------------------------------

    @classmethod
    def from_store(cls, store: EventStore, **kwargs: Any) -> "ConsentAgent":
        return cls(store=store, ledger=Ledger.replay(store.load()), **kwargs)
