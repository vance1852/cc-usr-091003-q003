"""记忆同意代理：以事件溯源方式重建授权状态并裁决每次记录、调用与遗忘。

关键规则：

* 离线补传按 ``occurred_at``（事件发生时间）裁决，而非接收时间；
  因此回放必须按发生时间排序，``received_at`` 只保留在审计链上。
* 重复上传（同一 ``event_id`` 或同一记录幂等键）只折叠为一个事实，
  不会重新计算保留期限，也不会让已撤回的同意复活。
* 撤回之后新调用立即拒绝；已分发到下游设备的副本生成可追踪删除任务。
* 紧急临时豁免有明确开启/结束，结束时其数据转为删除任务，
  不会自动变成长期同意。
* 监护关系变更只影响之后的授权资格，旧决定（由谁授权、谁撤销）
  的责任链原样保留。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

from .contracts import EventEnvelope
from .model import (
    CORE_DEVICE,
    DenialReason,
    Purpose,
    REASON_EMERGENCY_ENDED,
    REASON_REVOKED,
    REASON_RETENTION_EXPIRED,
    REASON_UNAUTHORIZED,
    Role,
    Scene,
)
from .policy import (
    DEFAULT_RETENTION,
    EMERGENCY_POLICY,
    PolicyError,
    default_audiences,
    purpose_for,
    validate_grant,
)


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _iso(value: datetime) -> str:
    return value.isoformat()


def _dt(value: str | datetime) -> datetime:
    return value if isinstance(value, datetime) else _parse(value)


class ConsentAgentError(ValueError):
    """裁决输入不合法（区别于合法的拒绝）。"""


@dataclass(frozen=True)
class Decision:
    """一次记录或调用请求的裁决结果。"""

    allowed: bool
    at: str
    actor: str
    audience: str
    scene: str
    memory_class: str
    purpose: str
    record_id: str | None = None
    basis: str | None = None
    reason: str | None = None
    message: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "at": self.at,
            "actor": self.actor,
            "audience": self.audience,
            "scene": self.scene,
            "memory_class": self.memory_class,
            "purpose": self.purpose,
            "record_id": self.record_id,
            "basis": self.basis,
            "reason": self.reason,
            "message": self.message,
        }


@dataclass(frozen=True)
class GrantTerm:
    """一份授权条款的授权范围快照。"""

    memory_class: str
    purpose: str
    audiences: frozenset[str]
    scenes: frozenset[str]
    retention: timedelta
    granted_by: str
    granted_at: datetime
    grant_event_id: str


@dataclass
class _Access:
    at: datetime
    actor: str
    audience: str
    scene: str
    purpose: str
    allowed: bool
    basis: str | None
    reason: str | None
    decision_event_id: str | None


@dataclass
class _Record:
    record_id: str
    event_id: str
    memory_class: str
    resident_id: str
    scene: str
    occurred_at: datetime
    received_at: datetime
    purpose: str
    audiences: frozenset[str]
    retention: timedelta
    basis: str
    authorized: bool
    unauthorized_reason: str | None
    summary: str
    other_residents: tuple[str, ...]
    copies: dict[str, tuple[str, datetime]] = field(default_factory=dict)
    accesses: list[_Access] = field(default_factory=list)
    # 硬删除后只保留墓碑，任何重载/重试都不能让内容复活。
    purged_at: datetime | None = None


@dataclass
class _GrantState:
    term: GrantTerm
    revoked_at: datetime | None = None
    revoke_event_id: str | None = None
    revoked_by: str | None = None


@dataclass
class _EmergencyWindow:
    opened_at: datetime
    closed_at: datetime | None
    open_event_id: str
    close_event_id: str | None
    declared_by: str


@dataclass
class _Guardianship:
    guardian_id: str
    resident_id: str
    valid_from: datetime
    valid_to: datetime | None
    event_id: str
    relation: str


@dataclass
class DeletionTask:
    task_id: str
    resident_id: str
    record_id: str
    device_id: str
    created_at: datetime
    reason: str
    status: str
    idempotency_key: str
    completed_at: datetime | None = None
    record_event_id: str | None = None
    attempts: int = 0

    @property
    def pending(self) -> bool:
        return self.status == "pending"

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "resident_id": self.resident_id,
            "record_id": self.record_id,
            "device_id": self.device_id,
            "created_at": _iso(self.created_at),
            "reason": self.reason,
            "status": self.status,
            "idempotency_key": self.idempotency_key,
            "completed_at": _iso(self.completed_at) if self.completed_at else None,
            "record_event_id": self.record_event_id,
            "attempts": self.attempts,
        }


class ConsentAgent:
    """按事件流重建授权状态并作出裁决的记忆同意代理。

    ``now`` 必须由调用方显式提供（例如调查场景的截止时间），
    领域逻辑不隐式读取系统时钟。
    """

    def __init__(self, now: str | datetime) -> None:
        self.now = _dt(now)
        self.residents: set[str] = set()
        # (resident_id, memory_class) -> 按授权发生时间排序的条款列表
        self._grants: dict[tuple[str, str], list[_GrantState]] = {}
        self._refusals: dict[tuple[str, str, str | None], datetime] = {}
        self._guardianships: dict[str, list[_Guardianship]] = {}
        self._emergencies: dict[str, list[_EmergencyWindow]] = {}
        self._records: dict[str, _Record] = {}
        self._event_ids: set[str] = set()
        # 记录幂等键 -> record_id，吸收离线机器人的重复上传。
        self._record_keys: dict[tuple[str, str, str], str] = {}
        self._deletions: dict[str, DeletionTask] = {}
        self._deletion_keys: set[str] = set()
        self._counter = 0

    @staticmethod
    def _canonical_audience(value: str, resident_id: str) -> str:
        """把"住户本人"的各种写法归一为 resident 角色。

        受众是角色而非身份：授权条款里写住户 ID 等同于把住户本人
        列为可见对象；其他住户 ID 不构成合法受众。
        """

        if value == resident_id:
            return Role.RESIDENT.value
        return value

    # ------------------------------------------------------------------
    # 事件装载
    # ------------------------------------------------------------------

    def load(self, events: Iterable[EventEnvelope]) -> None:
        # 时点回放：截止时点之后才发生的事件"尚未发生"，不参与状态重建。
        # 注意按 occurred_at 而非 received_at 过滤——离线设备稍后上传的
        # 记录只要事发于截止之前，仍按事发时的授权裁决。
        ordered = sorted(
            (e for e in events if _parse(e.occurred_at) <= self.now),
            key=lambda e: (_parse(e.occurred_at), _parse(e.received_at), e.event_id),
        )
        for event in ordered:
            self.apply(event)
        # 全部事件（含迟到的补传、分发与撤回）归位后，统一派生删除义务；
        # 数据库重启后重放事件流也走同一入口，过期内容不会重新可见。
        self._derive_deletion_obligations()

    def _derive_deletion_obligations(self) -> None:
        """对照当前时间点重放每条记录的删除义务，幂等且可反复执行。

        覆盖四种触发：未授权采集、撤回、过期、紧急豁免结束。
        对核心库与每一个已分发副本分别生成可追踪任务；
        已完成的任务不会因重放而复活。
        """

        for record in self._records.values():
            locations = (CORE_DEVICE, *record.copies.keys())
            for device_id in locations:
                present_at = (
                    record.occurred_at
                    if device_id == CORE_DEVICE
                    else record.copies[device_id][1]
                )
                # 时点回放：截止时点之后才出现的副本尚未存在。
                if present_at > self.now:
                    continue
                trigger = self._deletion_trigger(record, present_at)
                if trigger is None:
                    continue
                reason, at = trigger
                self._create_deletion(
                    record=record,
                    device_id=device_id,
                    at=at,
                    reason=reason,
                    trigger_event_id=None,
                )

    def _deletion_trigger(
        self, record: _Record, present_at: datetime
    ) -> tuple[str, datetime] | None:
        """返回该位置最早发生的删除义务（原因, 应删除时点）。"""

        triggers: list[tuple[datetime, str]] = []
        if not record.authorized:
            triggers.append((present_at, REASON_UNAUTHORIZED))
        expires = record.occurred_at + record.retention
        # 只要截止到 now 已过期，该位置的副本就负债；
        # 副本若在过期之后才到达，由下面的兜底逻辑在到达时点建任务。
        if record.authorized and expires <= self.now:
            triggers.append((expires, REASON_RETENTION_EXPIRED))
        if record.basis.startswith("emergency-exemption"):
            window = next(
                (
                    w
                    for w in self._emergencies.get(record.resident_id, [])
                    if w.open_event_id == record.basis.split(":", 1)[1]
                ),
                None,
            )
            if window is not None and window.closed_at is not None:
                triggers.append((window.closed_at, REASON_EMERGENCY_ENDED))
        if record.basis.startswith("consent:"):
            basis_event = record.basis.split(":", 1)[1]
            for state in self._grants.get(
                (record.resident_id, record.memory_class), []
            ):
                # 只撤回"该记录所依据的那份授权"；撤回只对撤回时点
                # 已经存在的副本生效，之后新授权下的记录不受牵连。
                if (
                    state.term.grant_event_id == basis_event
                    and state.revoked_at is not None
                    and state.revoked_at >= record.occurred_at
                ):
                    triggers.append((state.revoked_at, REASON_REVOKED))
        effective = [
            (at, reason) for at, reason in triggers if at >= present_at
        ]
        if not effective:
            # 义务时点早于副本出现时点（撤回后才分发的迟到副本）：
            # 副本一到达即负债。
            if triggers:
                earliest_reason = min(triggers, key=lambda t: t[0])[1]
                return earliest_reason, present_at
            return None
        at, reason = min(effective, key=lambda t: t[0])
        return reason, at if at >= present_at else present_at

    def apply(self, event: EventEnvelope) -> None:
        if event.event_id in self._event_ids:
            # 同一事件的重复上传：完全幂等，不改变任何状态。
            return
        self._event_ids.add(event.event_id)
        kind = event.kind
        handler = {
            "resident_registered": self._do_resident_registered,
            "guardianship_granted": self._do_guardianship_granted,
            "guardianship_revoked": self._do_guardianship_revoked,
            "consent_granted": self._do_consent_granted,
            "consent_revoked": self._do_consent_revoked,
            "sharing_refused": self._do_sharing_refused,
            "emergency_declared": self._do_emergency_declared,
            "emergency_cleared": self._do_emergency_cleared,
            "memory_recorded": self._do_memory_recorded,
            "copy_distributed": self._do_copy_distributed,
            "memory_accessed": self._do_memory_accessed,
            "memory_purged": self._do_memory_purged,
            "deletion_requested": self._do_deletion_requested,
            "deletion_acknowledged": self._do_deletion_acknowledged,
        }.get(kind)
        if handler is None:
            # 未知事件类型不静默丢弃：登记为未处理事件，接入方可见。
            self._handle_unknown(event)
            return
        handler(event)

    def _handle_unknown(self, event: EventEnvelope) -> None:
        if not hasattr(self, "unknown_events"):
            self.unknown_events: list[EventEnvelope] = []
        self.unknown_events.append(event)

    # ------------------------------------------------------------------
    # 主体与监护
    # ------------------------------------------------------------------

    def _do_resident_registered(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, "resident_id", event)
        self.residents.add(a["resident_id"])

    def _do_guardianship_granted(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "guardian_id"), event)
        occurred = _parse(event.occurred_at)
        self._guardianships.setdefault(a["resident_id"], []).append(
            _Guardianship(
                guardian_id=a["guardian_id"],
                resident_id=a["resident_id"],
                valid_from=occurred,
                valid_to=None,
                event_id=event.event_id,
                relation=str(a.get("relation", "guardian")),
            )
        )

    def _do_guardianship_revoked(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "guardian_id"), event)
        occurred = _parse(event.occurred_at)
        for ship in self._guardianships.get(a["resident_id"], []):
            if ship.guardian_id == a["guardian_id"] and ship.valid_to is None:
                ship.valid_to = occurred
                return
        # 变更未知监护关系也保留为事件事实，但无法闭合旧关系。
        raise ConsentAgentError(
            f"事件 {event.event_id} 试图终止不存在的监护关系"
        )

    def _guardian_active(self, resident_id: str, guardian_id: str, at: datetime) -> bool:
        for ship in self._guardianships.get(resident_id, []):
            if ship.guardian_id != guardian_id:
                continue
            if ship.valid_from <= at and (ship.valid_to is None or at < ship.valid_to):
                return True
        return False

    # ------------------------------------------------------------------
    # 同意与拒绝
    # ------------------------------------------------------------------

    def _do_consent_granted(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "memory_class"), event)
        resident_id = a["resident_id"]
        memory_class = a["memory_class"]
        occurred = _parse(event.occurred_at)

        granted_by = a.get("granted_by", resident_id)
        grantor_role = a.get("grantor_role", Role.RESIDENT.value)
        if grantor_role == Role.GUARDIAN.value and granted_by != resident_id:
            if not self._guardian_active(resident_id, granted_by, occurred):
                raise ConsentAgentError(
                    f"事件 {event.event_id}：{granted_by} 在该时点不是"
                    f" {resident_id} 的在任监护人，不能代为授权"
                )

        purpose = a.get("purpose") or purpose_for(memory_class)
        raw_audiences = a.get("audiences")
        audience_set = (
            frozenset(self._canonical_audience(x, resident_id) for x in raw_audiences)
            if raw_audiences
            else default_audiences(memory_class)
        )
        scenes = a.get("scenes")
        # 默认只授权普通照护；家属探视共享必须显式列出，不被默认包含。
        scene_set = (
            frozenset(scenes) if scenes else frozenset({Scene.ORDINARY_CARE.value})
        )
        if "retention_days" in a:
            retention = timedelta(days=float(a["retention_days"]))
        else:
            retention = DEFAULT_RETENTION[memory_class]

        try:
            validate_grant(memory_class, purpose, audience_set, retention, scene_set)
        except PolicyError as exc:
            # 自始无效的授权不产生授权状态；错误原样传播以拒绝装载。
            raise PolicyError(f"事件 {event.event_id} 的授权条款无效：{exc}") from exc

        term = GrantTerm(
            memory_class=memory_class,
            purpose=purpose,
            audiences=audience_set,
            scenes=scene_set,
            retention=retention,
            granted_by=granted_by,
            granted_at=occurred,
            grant_event_id=event.event_id,
        )
        self._grants.setdefault((resident_id, memory_class), []).append(
            _GrantState(term=term)
        )

    def _do_consent_revoked(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "memory_class"), event)
        occurred = _parse(event.occurred_at)
        revoked_by = a.get("revoked_by", a["resident_id"])
        chain = self._grants.get((a["resident_id"], a["memory_class"]), [])
        open_grants = [g for g in chain if g.revoked_at is None]
        if not open_grants:
            raise ConsentAgentError(
                f"事件 {event.event_id} 撤回了不存在或已撤回的同意"
            )
        for state in open_grants:
            state.revoked_at = occurred
            state.revoke_event_id = event.event_id
            state.revoked_by = revoked_by
        # 撤回即时生效：为现存记录安排删除（核心库 + 全部下游副本）。
        for record in self._records.values():
            if record.resident_id != a["resident_id"]:
                continue
            if record.memory_class != a["memory_class"]:
                continue
            if record.purged_at is not None:
                continue
            # 紧急豁免记录不属于同意体系，其删除由豁免结束通道处理。
            if not record.basis.startswith("consent:"):
                continue
            if record.occurred_at > occurred:
                continue
            for device in (CORE_DEVICE, *record.copies.keys()):
                self._create_deletion(
                    record=record,
                    device_id=device,
                    at=occurred,
                    reason=REASON_REVOKED,
                    trigger_event_id=event.event_id,
                )

    def _do_sharing_refused(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "memory_class", "scene"), event)
        occurred = _parse(event.occurred_at)
        key = (a["resident_id"], a["memory_class"], a["scene"])
        # 后到的拒绝覆盖更早的拒绝时间；拒绝没有"到期"概念，
        # 只能由住户新的明示授权事件解除。
        self._refusals[key] = occurred

    # ------------------------------------------------------------------
    # 紧急豁免
    # ------------------------------------------------------------------

    def _do_emergency_declared(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, "resident_id", event)
        occurred = _parse(event.occurred_at)
        windows = self._emergencies.setdefault(a["resident_id"], [])
        if windows and windows[-1].closed_at is None:
            raise ConsentAgentError(
                f"事件 {event.event_id}：{a['resident_id']} 已有未关闭的紧急窗口"
            )
        windows.append(
            _EmergencyWindow(
                opened_at=occurred,
                closed_at=None,
                open_event_id=event.event_id,
                close_event_id=None,
                declared_by=a.get("declared_by", Role.CARE_STAFF.value),
            )
        )

    def _do_emergency_cleared(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, "resident_id", event)
        occurred = _parse(event.occurred_at)
        windows = self._emergencies.get(a["resident_id"], [])
        open_windows = [w for w in windows if w.closed_at is None]
        if not open_windows:
            raise ConsentAgentError(
                f"事件 {event.event_id}：没有开启中的紧急窗口可以结束"
            )
        window = open_windows[-1]
        window.closed_at = occurred
        window.close_event_id = event.event_id
        # 豁免结束不转为长期同意：窗口期内依豁免采集的记录立即删除。
        for record in self._records.values():
            if record.resident_id != a["resident_id"]:
                continue
            if not record.basis.startswith("emergency-exemption"):
                continue
            if record.purged_at is not None:
                continue
            for device in (CORE_DEVICE, *record.copies.keys()):
                self._create_deletion(
                    record=record,
                    device_id=device,
                    at=occurred,
                    reason=REASON_EMERGENCY_ENDED,
                    trigger_event_id=event.event_id,
                )

    def _emergency_open(self, resident_id: str, at: datetime) -> _EmergencyWindow | None:
        for window in self._emergencies.get(resident_id, []):
            if window.opened_at <= at and (
                window.closed_at is None or at < window.closed_at
            ):
                return window
        return None

    # ------------------------------------------------------------------
    # 记录、分发与访问
    # ------------------------------------------------------------------

    def _do_memory_recorded(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("resident_id", "memory_class"), event)
        occurred = _parse(event.occurred_at)
        received = _parse(event.received_at)
        resident_id = a["resident_id"]
        memory_class = a["memory_class"]
        # 未标注场景的记录按最窄的"普通照护"处理：绝不会被默认解释为
        # 家属探视共享或紧急豁免。
        scene = a.get("scene", Scene.ORDINARY_CARE.value)

        idem_key = (
            resident_id,
            memory_class,
            str(a.get("record_id", event.event_id)),
        )
        if idem_key in self._record_keys:
            # 离线机器人重复上传：折叠，不刷新保留期限、不复活任何授权。
            return

        term = self._active_grant(resident_id, memory_class, occurred)
        window = (
            self._emergency_open(resident_id, occurred)
            if scene == Scene.EMERGENCY.value
            else None
        )

        authorized = False
        basis: str | None = None
        reason: str | None = None
        purpose = a.get("purpose") or purpose_for(memory_class)
        audiences: frozenset[str] = frozenset()
        retention = DEFAULT_RETENTION[memory_class]

        refused_scene = self._refusals.get((resident_id, memory_class, scene))
        refused_any = self._refusals.get((resident_id, memory_class, None))
        refused = (
            (refused_scene is not None and refused_scene <= occurred)
            or (refused_any is not None and refused_any <= occurred)
        )

        if term is not None and scene in term.term.scenes:
            if refused:
                reason = DenialReason.RESIDENT_REFUSED.value
            else:
                authorized = True
                basis = f"consent:{term.term.grant_event_id}"
                purpose = term.term.purpose
                audiences = term.term.audiences
                retention = term.term.retention
        elif window is not None and scene == Scene.EMERGENCY.value:
            if refused:
                reason = DenialReason.RESIDENT_REFUSED.value
            else:
                authorized = True
                basis = f"emergency-exemption:{window.open_event_id}"
                purpose = EMERGENCY_POLICY["purpose"]
                audiences = EMERGENCY_POLICY["audiences"]
                retention = EMERGENCY_POLICY["retention_ceiling"]
        elif refused:
            reason = DenialReason.RESIDENT_REFUSED.value
        elif term is not None:
            reason = DenialReason.SCENE_MISMATCH.value
        elif self._ever_held_grant(resident_id, memory_class, occurred):
            # 有过授权但在事发时点已失效（撤回/到期不适用，授权本身无到期）。
            reason = DenialReason.CONSENT_REVOKED.value
        else:
            reason = DenialReason.NO_CONSENT.value

        record_id = str(a.get("record_id", event.event_id))
        other = tuple(a.get("other_residents", ()))
        record = _Record(
            record_id=record_id,
            event_id=event.event_id,
            memory_class=memory_class,
            resident_id=resident_id,
            scene=scene,
            occurred_at=occurred,
            received_at=received,
            purpose=purpose,
            audiences=audiences,
            retention=retention,
            basis=basis or "none",
            authorized=authorized,
            unauthorized_reason=None if authorized else reason,
            summary=str(a.get("summary", "")),
            other_residents=other,
        )
        self._records[record_id] = record
        self._record_keys[idem_key] = record_id

        if not authorized:
            # 未经授权的记录不得存在：立即形成删除任务（追踪事故副本）。
            self._create_deletion(
                record=record,
                device_id=CORE_DEVICE,
                at=occurred,
                reason=REASON_UNAUTHORIZED,
                trigger_event_id=event.event_id,
            )
        # 过期是"时间到点"义务而非事件，由 sync_deletions() 在装载后
        # 或定时维护时统一派生；重复上传不刷新保留期限。

    def _do_copy_distributed(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("record_id", "device_id"), event)
        occurred = _parse(event.occurred_at)
        record = self._records.get(a["record_id"])
        if record is None:
            raise ConsentAgentError(
                f"事件 {event.event_id} 分发了不存在的记录 {a['record_id']}"
            )
        if a["device_id"] in record.copies:
            return
        record.copies[a["device_id"]] = (event.event_id, occurred)
        # 副本到达时若已有删除义务（撤回/过期/豁免结束/清除），立即挂任务。
        trigger = self._deletion_trigger(record, occurred)
        if trigger is not None:
            reason, at = trigger
            self._create_deletion(
                record=record,
                device_id=a["device_id"],
                at=at,
                reason=reason,
                trigger_event_id=None,
            )

    def _do_memory_accessed(self, event: EventEnvelope) -> None:
        """把现场已经发生的访问事件登记进审计链（含违规复述）。"""

        a = event.attributes
        self._require(a, ("record_id", "actor", "audience", "scene", "at"), event)
        record = self._records.get(a["record_id"])
        if record is None:
            raise ConsentAgentError(
                f"事件 {event.event_id} 访问了不存在的记录 {a['record_id']}"
            )
        at = _parse(a["at"])
        record.accesses.append(
            _Access(
                at=at,
                actor=a["actor"],
                audience=a["audience"],
                scene=a["scene"],
                purpose=a.get("purpose", record.purpose),
                allowed=bool(a.get("allowed_decision", False)),
                basis=a.get("basis"),
                reason=a.get("reason"),
                decision_event_id=event.event_id,
            )
        )

    def _do_memory_purged(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, "record_id", event)
        record = self._records.get(a["record_id"])
        if record is None:
            return
        record.purged_at = _parse(event.occurred_at)
        record.summary = ""
        # 核心库清除只闭合核心库任务；下游设备的删除义务独立追踪，
        # 不能因核心库已删而被勾销。
        for task in self._deletions.values():
            if (
                task.record_id == record.record_id
                and task.device_id == CORE_DEVICE
                and task.status == "pending"
            ):
                task.status = "completed"
                task.completed_at = record.purged_at

    def _do_deletion_requested(self, event: EventEnvelope) -> None:
        a = event.attributes
        self._require(a, ("record_id", "device_id", "reason"), event)
        record = self._records.get(a["record_id"])
        if record is None:
            raise ConsentAgentError(
                f"事件 {event.event_id} 针对不存在的记录"
            )
        self._create_deletion(
            record=record,
            device_id=a["device_id"],
            at=_parse(event.occurred_at),
            reason=a["reason"],
            trigger_event_id=event.event_id,
        )

    def _do_deletion_acknowledged(self, event: EventEnvelope) -> None:
        a = event.attributes
        occurred = _parse(event.occurred_at)
        if a.get("record_id") and a.get("device_id"):
            self._ack_one(a["record_id"], a["device_id"], occurred)
            return
        # 最小信封形式：只给住户 + 记忆类别时，闭合该范围内
        # 当时所有待办删除任务（如核心库对撤回批次的整体回执）。
        self._require(a, ("resident_id", "memory_class"), event)
        matched = [
            t
            for t in self._deletions.values()
            if t.resident_id == a["resident_id"]
            and self._record(t.record_id) is not None
            and self._record(t.record_id).memory_class == a["memory_class"]
            and t.status == "pending"
        ]
        if not matched:
            raise ConsentAgentError(
                f"事件 {event.event_id} 回执了不存在的删除任务"
            )
        purged_core = False
        for task in matched:
            task.attempts += 1
            task.status = "completed"
            task.completed_at = occurred
            if task.device_id == CORE_DEVICE:
                purged_core = True
        if purged_core:
            for task in matched:
                if task.device_id != CORE_DEVICE:
                    continue
                record = self._records.get(task.record_id)
                if record is not None and record.purged_at is None:
                    record.purged_at = occurred
                    record.summary = ""

    def _ack_one(self, record_id: str, device_id: str, occurred: datetime) -> None:
        key = f"{record_id}@{device_id}"
        task = self._deletions.get(key)
        if task is None:
            raise ConsentAgentError("回执了不存在的删除任务：" + key)
        # 重试与重复回执只增加尝试计数，不新建任务、不改变删除事实。
        task.attempts += 1
        if task.status != "completed":
            task.status = "completed"
            task.completed_at = occurred
        record = self._records.get(record_id)
        if device_id == CORE_DEVICE and record is not None and record.purged_at is None:
            record.purged_at = occurred
            record.summary = ""

    def _record(self, record_id: str) -> _Record | None:
        return self._records.get(record_id)

    # ------------------------------------------------------------------
    # 在线裁决 API
    # ------------------------------------------------------------------

    def can_record(
        self,
        *,
        resident_id: str,
        memory_class: str,
        scene: str,
        at: str | datetime | None = None,
    ) -> Decision:
        """裁决"现在能否采集"，不产生记录。"""

        moment = _dt(at) if at is not None else self.now
        term = self._active_grant(resident_id, memory_class, moment)
        window = self._emergency_open(resident_id, moment)
        if term is not None and scene in term.term.scenes:
            if self._is_refused(resident_id, memory_class, scene, moment):
                return self._deny(
                    moment, Role.SYSTEM.value, scene, memory_class,
                    purpose_for(memory_class), DenialReason.RESIDENT_REFUSED,
                )
            return Decision(
                allowed=True, at=_iso(moment), actor=Role.SYSTEM.value,
                audience=",".join(sorted(term.term.audiences)), scene=scene,
                memory_class=memory_class, purpose=term.term.purpose,
                basis=f"consent:{term.term.grant_event_id}",
            )
        if window is not None and scene == Scene.EMERGENCY.value:
            if self._is_refused(resident_id, memory_class, scene, moment):
                return self._deny(
                    moment, Role.SYSTEM.value, scene, memory_class,
                    EMERGENCY_POLICY["purpose"], DenialReason.RESIDENT_REFUSED,
                )
            return Decision(
                allowed=True, at=_iso(moment), actor=Role.SYSTEM.value,
                audience=",".join(sorted(EMERGENCY_POLICY["audiences"])),
                scene=scene, memory_class=memory_class,
                purpose=EMERGENCY_POLICY["purpose"],
                basis=f"emergency-exemption:{window.open_event_id}",
            )
        if term is None:
            reason = DenialReason.NO_CONSENT
        else:
            reason = DenialReason.SCENE_MISMATCH
        return self._deny(
            moment, Role.SYSTEM.value, scene, memory_class,
            purpose_for(memory_class), reason,
        )

    def can_access(
        self,
        *,
        record_id: str,
        actor: str,
        audience: str,
        scene: str,
        at: str | datetime | None = None,
    ) -> Decision:
        """裁决"现在能否调用/复述一条已有记忆"。

        撤回之后的新调用立即拒绝；过期、已清除、紧急豁免已结束、
        场景或可见对象不匹配都会拒绝。
        """

        moment = _dt(at) if at is not None else self.now
        record = self._records.get(record_id)
        purpose = (
            record.purpose
            if record is not None
            else Purpose.CARE_CONTEXT.value
        )
        if record is None:
            return self._deny(
                moment, actor, scene, "", purpose,
                DenialReason.RECORD_NOT_FOUND, record_id=record_id, audience=audience,
            )
        mc = record.memory_class

        if record.purged_at is not None and moment >= record.purged_at:
            return self._deny(
                moment, actor, scene, mc, purpose,
                DenialReason.RETENTION_EXPIRED, record_id=record_id, audience=audience,
            )
        if not record.authorized:
            reason = DenialReason(record.unauthorized_reason) if (
                record.unauthorized_reason
                and record.unauthorized_reason in {r.value for r in DenialReason}
            ) else DenialReason.UNAUTHORIZED_RECORD
            return self._deny(
                moment, actor, scene, mc, purpose,
                reason, record_id=record_id, audience=audience,
            )
        if record.basis.startswith("emergency-exemption"):
            window = self._emergency_open(record.resident_id, moment)
            # 豁免结束（或调用时点根本没有开放窗口）不变成长期同意；
            # 窗口虽在但调用场景不是紧急处置，同样不允许——
            # 紧急许可不能与普通照护或家属探视混用。
            if window is None:
                return self._deny(
                    moment, actor, scene, mc, purpose,
                    DenialReason.EMERGENCY_ENDED, record_id=record_id, audience=audience,
                )
            if scene != Scene.EMERGENCY.value:
                return self._deny(
                    moment, actor, scene, mc, purpose,
                    DenialReason.SCENE_MISMATCH, record_id=record_id, audience=audience,
                )
            allowed_audience = EMERGENCY_POLICY["audiences"]
            basis = f"emergency-exemption:{window.open_event_id}"
        else:
            term = self._active_grant(record.resident_id, mc, moment)
            if term is None:
                return self._deny(
                    moment, actor, scene, mc, purpose,
                    DenialReason.CONSENT_REVOKED, record_id=record_id, audience=audience,
                )
            if self._is_refused(record.resident_id, mc, scene, moment):
                return self._deny(
                    moment, actor, scene, mc, purpose,
                    DenialReason.RESIDENT_REFUSED, record_id=record_id, audience=audience,
                )
            if scene not in term.term.scenes:
                return self._deny(
                    moment, actor, scene, mc, purpose,
                    DenialReason.SCENE_MISMATCH, record_id=record_id, audience=audience,
                )
            allowed_audience = term.term.audiences
            basis = f"consent:{term.term.grant_event_id}"

        if record.occurred_at + record.retention <= moment:
            return self._deny(
                moment, actor, scene, mc, purpose,
                DenialReason.RETENTION_EXPIRED, record_id=record_id, audience=audience,
            )
        if audience not in allowed_audience:
            return self._deny(
                moment, actor, scene, mc, purpose,
                DenialReason.AUDIENCE_MISMATCH, record_id=record_id, audience=audience,
            )
        return Decision(
            allowed=True, at=_iso(moment), actor=actor, audience=audience,
            scene=scene, memory_class=mc, purpose=purpose,
            record_id=record_id, basis=basis,
        )

    def grant_consent(self, **attributes: Any) -> GrantTerm:
        """供在线服务使用的显式授权入口（同样经过策略矩阵校验）。"""

        resident_id = attributes["resident_id"]
        memory_class = attributes["memory_class"]
        at = _dt(attributes.get("at", self.now))
        purpose = attributes.get("purpose", purpose_for(memory_class))
        audiences = attributes.get("audiences", default_audiences(memory_class))
        scenes = attributes.get(
            "scenes", frozenset({Scene.ORDINARY_CARE.value})
        )
        retention = attributes.get("retention", DEFAULT_RETENTION[memory_class])
        audience_values = frozenset(
            self._canonical_audience(x, resident_id) for x in audiences
        )
        validate_grant(memory_class, purpose, audience_values, retention, frozenset(scenes))
        granted_by = attributes.get("granted_by", resident_id)
        self._counter += 1
        term = GrantTerm(
            memory_class=memory_class,
            purpose=purpose,
            audiences=audience_values,
            scenes=frozenset(scenes),
            retention=retention,
            granted_by=granted_by,
            granted_at=at,
            grant_event_id=f"api-grant-{self._counter}",
        )
        self._grants.setdefault((resident_id, memory_class), []).append(
            _GrantState(term=term)
        )
        return term

    # ------------------------------------------------------------------
    # 删除任务
    # ------------------------------------------------------------------

    def _create_deletion(
        self,
        *,
        record: _Record,
        device_id: str,
        at: datetime,
        reason: str,
        trigger_event_id: str | None,
    ) -> DeletionTask:
        # 同一记录在同一设备上的删除义务只有一个；重试/重启/重复触发
        # 都折叠到同一任务。多个原因并存时保留最早发生的那个。
        key = f"{record.record_id}@{device_id}"
        existing = self._deletions.get(key)
        if existing is not None:
            if at < existing.created_at:
                existing.created_at = at
                existing.reason = reason
            return existing
        self._counter += 1
        task = DeletionTask(
            task_id=f"del-{self._counter:04d}",
            resident_id=record.resident_id,
            record_id=record.record_id,
            device_id=device_id,
            created_at=at,
            reason=reason,
            status="pending",
            idempotency_key=key,
            record_event_id=record.event_id,
        )
        self._deletions[key] = task
        self._deletion_keys.add(key)
        return task

    def sync_deletions(self) -> None:
        """定时维护入口：对照当前时间补齐过期/迟到副本的删除义务。

        幂等，可在数据库重启、删除任务重试或任何时刻安全调用。
        """

        self._derive_deletion_obligations()

    def pending_deletions(self) -> list[DeletionTask]:
        return sorted(
            (t for t in self._deletions.values() if t.pending),
            key=lambda t: (t.created_at, t.task_id),
        )

    def completed_deletions(self) -> list[DeletionTask]:
        return sorted(
            (t for t in self._deletions.values() if not t.pending),
            key=lambda t: (t.created_at, t.task_id),
        )

    # ------------------------------------------------------------------
    # 查询视图
    # ------------------------------------------------------------------

    def records_for(self, resident_id: str) -> list[_Record]:
        return [r for r in self._records.values() if r.resident_id == resident_id]

    def all_records(self) -> list[_Record]:
        return sorted(self._records.values(), key=lambda r: r.occurred_at)

    def grant_chain(self, resident_id: str, memory_class: str) -> list[_GrantState]:
        return list(self._grants.get((resident_id, memory_class), []))

    def guardianship_chain(self, resident_id: str) -> list[_Guardianship]:
        return list(self._guardianships.get(resident_id, []))

    def emergency_windows(self, resident_id: str) -> list[_EmergencyWindow]:
        return list(self._emergencies.get(resident_id, []))

    def record(self, record_id: str) -> _Record | None:
        return self._records.get(record_id)

    def live_records(self, at: str | datetime | None = None) -> list[_Record]:
        moment = _dt(at) if at is not None else self.now
        return [r for r in self._records.values() if self._record_live(r, moment)]

    # ------------------------------------------------------------------
    # 内部规则
    # ------------------------------------------------------------------

    def _record_live(self, record: _Record, at: datetime) -> bool:
        if record.purged_at is not None:
            return False
        if not record.authorized:
            return False
        if record.occurred_at + record.retention <= at:
            return False
        if record.basis.startswith("emergency-exemption") and self._emergency_open(
            record.resident_id, at
        ) is None:
            return False
        term = self._active_grant(record.resident_id, record.memory_class, at)
        if term is None:
            return False
        return not self._is_refused(
            record.resident_id, record.memory_class, record.scene, at
        )

    def _active_grant(
        self, resident_id: str, memory_class: str, at: datetime
    ) -> _GrantState | None:
        """返回 at 时点有效的最新授权条款；撤回后的新调用拿不到任何条款。"""

        chain = self._grants.get((resident_id, memory_class), [])
        active = [
            state
            for state in chain
            if state.term.granted_at <= at
            and (state.revoked_at is None or at < state.revoked_at)
        ]
        if not active:
            return None
        return max(active, key=lambda s: s.term.granted_at)

    def _ever_held_grant(
        self, resident_id: str, memory_class: str, at: datetime
    ) -> bool:
        """at 时点之前（含）是否曾存在过授权——用于区分"从未同意"与"已撤回"。"""

        return any(
            state.term.granted_at <= at
            for state in self._grants.get((resident_id, memory_class), [])
        )

    def _is_refused(
        self,
        resident_id: str,
        memory_class: str,
        scene: str,
        at: datetime,
    ) -> bool:
        specific = self._refusals.get((resident_id, memory_class, scene))
        wildcard = self._refusals.get((resident_id, memory_class, None))
        marks = [t for t in (specific, wildcard) if t is not None and t <= at]
        return bool(marks)

    def _deny(
        self,
        at: datetime,
        actor: str,
        scene: str,
        memory_class: str,
        purpose: str,
        reason: DenialReason,
        record_id: str | None = None,
        audience: str = "",
    ) -> Decision:
        from .model import DENIAL_MESSAGES

        return Decision(
            allowed=False,
            at=_iso(at),
            actor=actor,
            audience=audience,
            scene=scene,
            memory_class=memory_class,
            purpose=purpose,
            record_id=record_id,
            reason=reason.value,
            message=DENIAL_MESSAGES[reason],
        )

    @staticmethod
    def _require(
        attributes: dict[str, Any],
        fields: str | tuple[str, ...],
        event: EventEnvelope,
    ) -> None:
        if isinstance(fields, str):
            fields = (fields,)
        missing = [f for f in fields if attributes.get(f) in (None, "")]
        if missing:
            raise ConsentAgentError(
                f"事件 {event.event_id}（{event.kind}）缺少属性：" + "、".join(missing)
            )
