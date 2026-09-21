"""事件溯源账本：所有授权状态都由不可变事件重放得到。

事件只增不改；内容本体与元数据分离，删除时撕碎内容、保留责任元数据，
因此数据库重启或删除任务重试都不会让过期内容重新可见。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .contracts import EventEnvelope


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Grant:
    grant_id: str
    resident_id: str
    subject_id: str
    subject_type: str
    granted_by_role: str
    granted_by_id: str
    guardian_id: str | None
    memory_class: str
    purpose: str
    contexts: tuple[str, ...]
    audience: tuple[str, ...]
    retention_seconds: int
    valid_from: datetime
    valid_to: datetime | None
    decision_event_id: str
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revoke_event_id: str | None = None

    def active_at(self, at: datetime) -> bool:
        if at < self.valid_from:
            return False
        if self.valid_to is not None and at >= self.valid_to:
            return False
        if self.revoked_at is not None and at >= self.revoked_at:
            return False
        return True


@dataclass
class Guardianship:
    guardian_id: str
    resident_id: str
    relation: str
    valid_from: datetime
    valid_to: datetime | None = None

    def active_at(self, at: datetime) -> bool:
        return at >= self.valid_from and (
            self.valid_to is None or at < self.valid_to
        )


@dataclass
class Emergency:
    emergency_id: str
    resident_id: str | None
    started_at: datetime
    ended_at: datetime | None = None

    def active_at(self, at: datetime) -> bool:
        if at < self.started_at:
            return False
        return self.ended_at is None or at < self.ended_at


@dataclass
class MemoryRecord:
    record_id: str
    event_id: str
    resident_id: str
    memory_class: str
    purpose: str
    context: str
    occurred_at: datetime
    received_at: datetime
    basis_type: str            # "consent" | "emergency"
    basis_id: str
    guardian_id: str | None
    granted_by: str | None
    content_id: str
    expires_at: datetime | None
    shredded_at: datetime | None = None
    shred_event_id: str | None = None


@dataclass
class Copy:
    copy_id: str
    record_id: str
    device_id: str
    created_at: datetime
    is_source: bool = False
    deleted_at: datetime | None = None
    delete_event_id: str | None = None


@dataclass
class DeletionTask:
    task_id: str
    copy_id: str
    record_id: str
    device_id: str
    reason: str                # revocation | expiry | emergency-end
    created_at: datetime
    due_at: datetime
    acknowledged_at: datetime | None = None
    ack_event_id: str | None = None


@dataclass
class AccessEntry:
    access_id: str
    at: datetime
    record_id: str
    copy_id: str | None
    requester_role: str
    requester_id: str
    context: str
    purpose: str
    allowed: bool
    reason: str
    basis_type: str | None
    basis_id: str | None
    breach: bool = False


@dataclass
class SharingDecline:
    """住户对某类记忆在某场景下向某对象共享的明确拒绝。"""

    decline_id: str
    resident_id: str
    memory_class: str
    context: str
    audience_token: str | None
    at: datetime


@dataclass
class Suspension:
    suspended_at: datetime
    restored_at: datetime | None = None
    by_id: str | None = None
    reason: str | None = None


@dataclass
class Ledger:
    events: list[EventEnvelope] = field(default_factory=list)
    by_event_id: dict[str, EventEnvelope] = field(default_factory=dict)
    grants: dict[str, Grant] = field(default_factory=dict)
    guardians: dict[str, Guardianship] = field(default_factory=dict)
    emergencies: dict[str, Emergency] = field(default_factory=dict)
    records: dict[str, MemoryRecord] = field(default_factory=dict)
    copies: dict[str, Copy] = field(default_factory=dict)
    tasks: dict[str, DeletionTask] = field(default_factory=dict)
    accesses: list[AccessEntry] = field(default_factory=list)
    refusals: list[dict[str, Any]] = field(default_factory=list)
    declines: dict[str, SharingDecline] = field(default_factory=dict)
    suspensions: list[Suspension] = field(default_factory=list)
    reuploads: dict[str, int] = field(default_factory=dict)
    # 仅满足信封契约、缺少领域属性的事件（如早期协议样例）：原样保留但不投影。
    skipped: list[tuple[str, str]] = field(default_factory=list)

    # ---- 追加与重放 --------------------------------------------------

    def append(self, event: EventEnvelope) -> bool:
        """追加事件；重复 event_id 视为重传，直接幂等忽略。"""
        if event.event_id in self.by_event_id:
            return False
        self.events.append(event)
        self.by_event_id[event.event_id] = event
        try:
            self._apply(event)
        except KeyError as exc:
            self.skipped.append((event.event_id, str(exc)))
        return True

    @classmethod
    def replay(cls, events: list[EventEnvelope]) -> "Ledger":
        ledger = cls()
        for event in events:
            ledger.append(event)
        return ledger

    # ---- 事件应用 ----------------------------------------------------

    def _apply(self, event: EventEnvelope) -> None:
        at = parse_ts(event.occurred_at)
        a = event.attributes
        kind = event.kind
        if kind == "guardian_designated":
            self.guardians[a["guardian_id"]] = Guardianship(
                guardian_id=a["guardian_id"],
                resident_id=a["resident_id"],
                relation=a.get("relation", ""),
                valid_from=at,
            )
        elif kind == "guardian_revoked":
            self.guardians[a["guardian_id"]].valid_to = at
        elif kind == "consent_granted":
            valid_to = a.get("valid_to")
            self.grants[a["grant_id"]] = Grant(
                grant_id=a["grant_id"],
                resident_id=a["resident_id"],
                subject_id=a.get("subject_id", a["resident_id"]),
                subject_type=a.get("subject_type", "resident"),
                granted_by_role=a["granted_by_role"],
                granted_by_id=a["granted_by_id"],
                guardian_id=a.get("guardian_id"),
                memory_class=a["memory_class"],
                purpose=a["purpose"],
                contexts=tuple(a["contexts"]),
                audience=tuple(a["audience"]),
                retention_seconds=int(a["retention_seconds"]),
                valid_from=parse_ts(a["valid_from"]),
                valid_to=parse_ts(valid_to) if valid_to else None,
                decision_event_id=event.event_id,
            )
        elif kind == "consent_revoked":
            targets = self._revocation_targets(a)
            for grant in targets:
                grant.revoked_at = at
                grant.revoked_by = a.get("revoked_by")
                grant.revoke_event_id = event.event_id
        elif kind == "emergency_started":
            self.emergencies[a["emergency_id"]] = Emergency(
                emergency_id=a["emergency_id"],
                resident_id=a.get("resident_id"),
                started_at=at,
            )
        elif kind == "emergency_ended":
            emergency = self.emergencies[a["emergency_id"]]
            emergency.ended_at = at
        elif kind == "memory_recorded":
            # 同一现场事实（content_id）只落一份；重复上传不覆盖、不延长保留期。
            existing = next(
                (
                    r
                    for r in self.records.values()
                    if r.resident_id == a["resident_id"]
                    and r.content_id == a["content_id"]
                ),
                None,
            )
            if existing is not None:
                self.reuploads[existing.record_id] = (
                    self.reuploads.get(existing.record_id, 0) + 1
                )
                return
            expires = a.get("expires_at")
            self.records[a["record_id"]] = MemoryRecord(
                record_id=a["record_id"],
                event_id=event.event_id,
                resident_id=a["resident_id"],
                memory_class=a["memory_class"],
                purpose=a["purpose"],
                context=a["context"],
                occurred_at=at,
                received_at=parse_ts(event.received_at),
                basis_type=a["basis_type"],
                basis_id=a["basis_id"],
                guardian_id=a.get("guardian_id"),
                granted_by=a.get("granted_by"),
                content_id=a["content_id"],
                expires_at=parse_ts(expires) if expires else None,
            )
        elif kind == "copy_distributed":
            self.copies[a["copy_id"]] = Copy(
                copy_id=a["copy_id"],
                record_id=a["record_id"],
                device_id=a["device_id"],
                created_at=at,
                is_source=bool(a.get("is_source", False)),
            )
        elif kind == "deletion_task_created":
            self.tasks[a["task_id"]] = DeletionTask(
                task_id=a["task_id"],
                copy_id=a["copy_id"],
                record_id=a["record_id"],
                device_id=a["device_id"],
                reason=a["reason"],
                created_at=at,
                due_at=parse_ts(a["due_at"]),
            )
        elif kind == "deletion_acknowledged":
            task = self.tasks[a["task_id"]]
            task.acknowledged_at = at
            task.ack_event_id = event.event_id
            copy = self.copies[a["copy_id"]]
            copy.deleted_at = at
            copy.delete_event_id = event.event_id
        elif kind == "content_shredded":
            record = self.records[a["record_id"]]
            record.shredded_at = at
            record.shred_event_id = event.event_id
            # 中心侧内容撕碎即视为源副本同步删除（仍有删除回执链可追踪）。
            for copy in self.copies_of(record.record_id):
                if copy.is_source and copy.deleted_at is None:
                    copy.deleted_at = at
                    copy.delete_event_id = event.event_id
        elif kind == "access_logged":
            self.accesses.append(
                AccessEntry(
                    access_id=a["access_id"],
                    at=at,
                    record_id=a["record_id"],
                    copy_id=a.get("copy_id"),
                    requester_role=a["requester_role"],
                    requester_id=a["requester_id"],
                    context=a["context"],
                    purpose=a["purpose"],
                    allowed=bool(a["allowed"]),
                    reason=a["reason"],
                    basis_type=a.get("basis_type"),
                    basis_id=a.get("basis_id"),
                    breach=bool(a.get("breach", False)),
                )
            )
        elif kind in ("recording_refused", "authorization_refused"):
            self.refusals.append({"kind": kind, "at": at, **a})
        elif kind == "sharing_declined":
            self.declines[a["decline_id"]] = SharingDecline(
                decline_id=a["decline_id"],
                resident_id=a["resident_id"],
                memory_class=a["memory_class"],
                context=a["context"],
                audience_token=a.get("audience_token"),
                at=at,
            )
        elif kind == "memory_suspended":
            self.suspensions.append(
                Suspension(
                    suspended_at=at,
                    by_id=a.get("by_id"),
                    reason=a.get("reason"),
                )
            )
        elif kind == "memory_restored":
            for suspension in reversed(self.suspensions):
                if suspension.restored_at is None:
                    suspension.restored_at = at
                    break
        # 未识别事件原样保留在 events 中，不静默丢弃。

    def _revocation_targets(self, a: dict[str, Any]) -> list[Grant]:
        if a.get("grant_id"):
            grant = self.grants.get(a["grant_id"])
            return [grant] if grant and grant.revoked_at is None else []
        return [
            grant
            for grant in self.grants.values()
            if grant.resident_id == a["resident_id"]
            and grant.memory_class == a["memory_class"]
            and grant.purpose == a["purpose"]
            and grant.revoked_at is None
            and (a.get("subject_id") in (None, grant.subject_id))
        ]

    # ---- 查询 --------------------------------------------------------

    def active_emergency(
        self, resident_id: str, at: datetime
    ) -> Emergency | None:
        for emergency in self.emergencies.values():
            if not emergency.active_at(at):
                continue
            if emergency.resident_id is None or emergency.resident_id == resident_id:
                return emergency
        return None

    def copies_of(self, record_id: str) -> list[Copy]:
        return [c for c in self.copies.values() if c.record_id == record_id]

    def pending_tasks(self, at: datetime | None = None) -> list[DeletionTask]:
        tasks = [t for t in self.tasks.values() if t.acknowledged_at is None]
        if at is not None:
            tasks.sort(key=lambda t: t.due_at)
        return tasks

    def records_for_resident(self, resident_id: str) -> list[MemoryRecord]:
        return [r for r in self.records.values() if r.resident_id == resident_id]

    def suspension_active(self, at: datetime) -> bool:
        """隐私专员暂停期间，除紧急豁免外不得记录或调用。"""
        active = False
        for suspension in self.suspensions:
            if at < suspension.suspended_at:
                continue
            if suspension.restored_at is None or at < suspension.restored_at:
                active = True
        return active

    def decline_blocks(
        self,
        resident_id: str,
        memory_class: str,
        context: str,
        audience_token: str | None,
        at: datetime,
    ) -> SharingDecline | None:
        """查找仍然有效的明确拒绝。

        audience_token 语义：
        - "*"：调查视角，匹配该类记忆/场景下任意拒绝；
        - None：只匹配不针对特定对象的全场拒绝（记录环节使用）；
        - 具名令牌：匹配全场拒绝、同角色通配拒绝或同一具名对象的拒绝。
        拒绝之后若存在更新的针对性授权决定，则不再阻断。
        """
        blocking: SharingDecline | None = None
        for decline in self.declines.values():
            if decline.resident_id != resident_id:
                continue
            if decline.memory_class != memory_class:
                continue
            if decline.context not in (context, "*"):
                continue
            if not _decline_matches(decline.audience_token, audience_token):
                continue
            # 拒绝之后若存在更新的针对性授权决定，则不再阻断。
            later_grant = any(
                g.resident_id == resident_id
                and g.memory_class == memory_class
                and g.valid_from > decline.at
                and context in g.contexts
                for g in self.grants.values()
            )
            if not later_grant and (blocking is None or decline.at > blocking.at):
                blocking = decline
        return blocking


def _decline_matches(
    declined_token: str | None, query_token: str | None
) -> bool:
    if query_token == "*":
        return True
    if declined_token is None:
        # 全场拒绝阻断一切；查询 None（记录环节）也只被全场拒绝阻断。
        return True
    if query_token is None:
        return False
    if declined_token == query_token:
        return True
    if ":" not in declined_token and query_token.startswith(declined_token + ":"):
        return True
    return False
