"""面向隐私专员与住户的两份只读报告。

* 隐私专员：某条（或某住户的）记录为何被采集/为何不应被复述、
  哪些副本仍待删除、谁在什么依据下访问过。
* 住户：只含本人信息的个人记录；涉及其他住户的字段被遮蔽，
  不暴露任何其他人的身份与内容。
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .agent import (
    ConsentAgent,
    DeletionTask,
    _Access,
    _GrantState,
    _Guardianship,
    _Record,
)
from .model import CORE_DEVICE


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _grant_basis(state: _GrantState) -> str:
    return f"consent:{state.term.grant_event_id}"


def _grant_entry(state: _GrantState) -> dict[str, Any]:
    term = state.term
    return {
        "grant_event_id": term.grant_event_id,
        "granted_by": term.granted_by,
        "granted_at": _iso(term.granted_at),
        "purpose": term.purpose,
        "audiences": sorted(term.audiences),
        "scenes": sorted(term.scenes),
        "retention_days": term.retention.total_seconds() / 86400,
        "revoked_at": _iso(state.revoked_at),
        "revoked_by": state.revoked_by,
        "revoke_event_id": state.revoke_event_id,
        "active": state.revoked_at is None,
    }


def _guardianship_entry(ship: _Guardianship) -> dict[str, Any]:
    return {
        "guardian_id": ship.guardian_id,
        "relation": ship.relation,
        "valid_from": _iso(ship.valid_from),
        "valid_to": _iso(ship.valid_to),
        "granted_by_event": ship.event_id,
    }


def _access_entry(access: _Access) -> dict[str, Any]:
    return {
        "at": _iso(access.at),
        "actor": access.actor,
        "audience": access.audience,
        "scene": access.scene,
        "purpose": access.purpose,
        "allowed": access.allowed,
        "basis": access.basis,
        "reason": access.reason,
        "audit_event_id": access.decision_event_id,
    }


def _deletion_entry(task: DeletionTask) -> dict[str, Any]:
    data = task.as_dict()
    data["location"] = "核心库" if task.device_id == CORE_DEVICE else "下游设备"
    return data


class InvestigationReport:
    """隐私专员调查报告。"""

    def __init__(self, agent: ConsentAgent) -> None:
        self._agent = agent

    def record_findings(self, record_id: str) -> dict[str, Any]:
        agent = self._agent
        record = agent.record(record_id)
        if record is None:
            return {
                "record_id": record_id,
                "generated_at": _iso(agent.now),
                "status": "not-found",
            }

        grant_chain = agent.grant_chain(record.resident_id, record.memory_class)
        emergencies = agent.emergency_windows(record.resident_id)
        related_deletions = sorted(
            (
                t
                for t in list(agent.pending_deletions()) + list(
                    agent.completed_deletions()
                )
                if t.record_id == record_id
            ),
            key=lambda t: (t.created_at, t.task_id),
        )

        why_collected: dict[str, Any]
        if record.authorized:
            why_collected = {
                "authorized": True,
                "basis": record.basis,
                "purpose": record.purpose,
                "audiences_at_collection": sorted(record.audiences),
                "scene": record.scene,
                "retention_days": record.retention.total_seconds() / 86400,
                "occurred_at": _iso(record.occurred_at),
                "received_at": _iso(record.received_at),
                "rule": "按事件发生时（非上传时）有效的授权裁决",
            }
        else:
            why_collected = {
                "authorized": False,
                "basis": record.basis,
                "reason": record.unauthorized_reason,
                "scene": record.scene,
                "occurred_at": _iso(record.occurred_at),
                "received_at": _iso(record.received_at),
            }

        # 该记录在"现在"被复述会不会被允许，以及逐次访问的合规判定。
        replay = agent.can_access(
            record_id=record_id,
            actor="privacy-officer-review",
            audience=_review_audience(record),
            scene=record.scene,
            at=agent.now,
        )
        # 在事故访问的同一时点、同一场景与受众下回放裁决，
        # 直接回答"那段谈话当时为何不应被复述"。
        incident_replay = self._replay_incident_context(record)
        accesses = [_access_entry(a) for a in record.accesses]
        for entry, access in zip(accesses, record.accesses):
            entry["compliance"] = self._classify_access(record, access)

        return {
            "record_id": record_id,
            "generated_at": _iso(agent.now),
            "resident_id": record.resident_id,
            "memory_class": record.memory_class,
            "status": "purged" if record.purged_at is not None else (
                "expired" if record.occurred_at + record.retention <= agent.now
                else "live"
            ),
            "collection": why_collected,
            "why_replay_now_is_blocked": None
            if replay.allowed
            else {"reason": replay.reason, "message": replay.message},
            "why_it_should_not_have_been_replayed": incident_replay,
            "copies": [
                {
                    "device_id": device_id,
                    "distributed_by_event": event_id,
                    "distributed_at": _iso(distributed_at),
                }
                for device_id, (event_id, distributed_at) in sorted(
                    record.copies.items()
                )
            ],
            "deletion_tasks": [_deletion_entry(t) for t in related_deletions],
            "pending_copy_deletions": [
                t.device_id for t in related_deletions if t.pending
            ],
            "access_log": accesses,
            "consent_chain": [_grant_entry(g) for g in grant_chain],
            "guardianship_chain": [
                _guardianship_entry(s)
                for s in agent.guardianship_chain(record.resident_id)
            ],
            "emergency_windows": [
                {
                    "opened_at": _iso(w.opened_at),
                    "closed_at": _iso(w.closed_at),
                    "opened_by_event": w.open_event_id,
                    "closed_by_event": w.close_event_id,
                    "declared_by": w.declared_by,
                }
                for w in emergencies
            ],
            "other_residents_in_content": list(record.other_residents),
            "summary_present": bool(record.summary),
        }

    def resident_overview(self, resident_id: str) -> dict[str, Any]:
        """住户维度的全局视图：授权、记录、待删副本、违规访问。"""

        agent = self._agent
        records = agent.records_for(resident_id)
        pending = [
            t for t in agent.pending_deletions() if t.resident_id == resident_id
        ]
        violations: list[dict[str, Any]] = []
        for record in records:
            for access in record.accesses:
                if not access.allowed:
                    violations.append(
                        {
                            "record_id": record.record_id,
                            "memory_class": record.memory_class,
                            **_access_entry(access),
                        }
                    )
                elif self._classify_access(record, access) != "allowed":
                    violations.append(
                        {
                            "record_id": record.record_id,
                            "memory_class": record.memory_class,
                            **_access_entry(access),
                            "compliance": self._classify_access(record, access),
                        }
                    )
        return {
            "resident_id": resident_id,
            "generated_at": _iso(agent.now),
            "consent_chains": {
                memory_class: [
                    _grant_entry(g)
                    for g in agent.grant_chain(resident_id, memory_class)
                ]
                for memory_class in sorted({r.memory_class for r in records})
            },
            "records": [
                {
                    "record_id": r.record_id,
                    "memory_class": r.memory_class,
                    "scene": r.scene,
                    "authorized": r.authorized,
                    "basis": r.basis,
                    "occurred_at": _iso(r.occurred_at),
                    "expires_at": _iso(r.occurred_at + r.retention),
                    "purged_at": _iso(r.purged_at),
                    "copies": sorted(r.copies.keys()),
                }
                for r in sorted(records, key=lambda r: r.occurred_at)
            ],
            "pending_deletions": [_deletion_entry(t) for t in pending],
            "access_violations": violations,
        }

    def _replay_incident_context(self, record: _Record) -> dict[str, Any] | None:
        """在事故复述的时点/场景/受众下重放裁决，给出阻断依据。"""

        incident = next(
            (a for a in record.accesses if not a.allowed),
            None,
        )
        if incident is None:
            incident = next(iter(record.accesses), None)
        if incident is None:
            return None
        decision = self._agent.can_access(
            record_id=record.record_id,
            actor=incident.actor,
            audience=incident.audience,
            scene=incident.scene,
            at=incident.at,
        )
        return {
            "at": _iso(incident.at),
            "actor": incident.actor,
            "audience": incident.audience,
            "scene": incident.scene,
            "would_be_allowed": decision.allowed,
            "reason": decision.reason,
            "message": decision.message,
            "basis_attempted": incident.basis,
            "audit_event_id": incident.decision_event_id,
        }

    def _classify_access(self, record: _Record, access: _Access) -> str:
        """对照记录授权范围复核每一次历史访问。"""

        if access.at < record.occurred_at:
            return "impossible-ordering"
        if record.purged_at is not None and access.at >= record.purged_at:
            return "access-after-purge"
        if record.occurred_at + record.retention <= access.at:
            return "access-after-expiry"
        if record.basis == "emergency-exemption":
            window = next(
                (
                    w
                    for w in self._agent.emergency_windows(record.resident_id)
                    if w.opened_at <= access.at
                    and (w.closed_at is None or access.at < w.closed_at)
                ),
                None,
            )
            if window is None:
                return "access-after-emergency-ended"
            allowed_audience = {"emergency-responder", "care-staff"}
        else:
            term = self._agent.grant_chain(
                record.resident_id, record.memory_class
            )
            active = [
                s
                for s in term
                if s.term.granted_at <= access.at
                and (s.revoked_at is None or access.at < s.revoked_at)
            ]
            if not active:
                return "access-after-revocation"
            latest = max(active, key=lambda s: s.term.granted_at)
            if self._agent._is_refused(
                record.resident_id, record.memory_class, access.scene, access.at
            ):
                return "resident-refused"
            if access.scene not in latest.term.scenes:
                return "scene-mismatch"
            allowed_audience = set(latest.term.audiences)
        if access.audience not in allowed_audience:
            return "audience-mismatch"
        return "allowed"


def _review_audience(record: _Record) -> str:
    # 专员复核用占位受众；主要让 reason 落在真正阻断原因上。
    if record.audiences:
        return sorted(record.audiences)[0]
    return "privacy-officer"


class ResidentExport:
    """住户本人的个人记录导出：遮蔽任何涉及他人的信息。"""

    REDACTED = "【涉及他人，已遮蔽】"

    def __init__(self, agent: ConsentAgent) -> None:
        self._agent = agent

    def export(self, resident_id: str) -> dict[str, Any]:
        agent = self._agent
        records = agent.records_for(resident_id)
        items: list[dict[str, Any]] = []
        for record in sorted(records, key=lambda r: r.occurred_at):
            involves_others = bool(record.other_residents)
            item = {
                "record_id": record.record_id,
                "memory_class": record.memory_class,
                "scene": record.scene,
                "occurred_at": _iso(record.occurred_at),
                "purpose": record.purpose,
                "retention_days": record.retention.total_seconds() / 86400,
                "expires_at": _iso(record.occurred_at + record.retention),
                "authorized": record.authorized,
                "basis": record.basis,
                "content": self.REDACTED if involves_others else record.summary,
                "contains_other_peoples_information": involves_others,
                "copies_held_on_devices": [
                    self._redact_device(device) for device in sorted(record.copies)
                ],
                "deletion_status": self._deletion_status(record),
            }
            # 访问日志只回显与本人有关的动作；访问者身份若是其他住户则遮蔽。
            item["accesses"] = [
                self._redact_access(access) for access in record.accesses
            ]
            items.append(item)

        chains: dict[str, Any] = {}
        for memory_class in {r.memory_class for r in records} | {
            key[1]
            for key in agent._grants
            if key[0] == resident_id
        }:
            chains[memory_class] = [
                _grant_entry(g)
                for g in agent.grant_chain(resident_id, memory_class)
            ]

        return {
            "resident_id": resident_id,
            "generated_at": _iso(agent.now),
            "your_consent_decisions": chains,
            "your_memory_records": items,
            "notice": (
                "本导出仅包含您本人的记录；凡内容涉及其他住户，"
                "相关身份与内容已遮蔽，不影响您主张删除或查阅自己的信息。"
            ),
        }

    def _deletion_status(self, record: _Record) -> dict[str, Any]:
        tasks = [
            t
            for t in list(self._agent.pending_deletions())
            + list(self._agent.completed_deletions())
            if t.record_id == record.record_id
        ]
        return {
            "pending_devices": [self._redact_device(t.device_id) for t in tasks if t.pending],
            "completed": sum(1 for t in tasks if not t.pending),
            "purged_from_core": record.purged_at is not None,
        }

    def _redact_access(self, access: _Access) -> dict[str, Any]:
        entry = _access_entry(access)
        # actor/audience 若是住户标识（形如 resident-xxx 且非本人），遮蔽。
        for field_name in ("actor", "audience"):
            value = entry[field_name]
            if isinstance(value, str) and value.startswith("resident-"):
                entry[field_name] = self.REDACTED
        return entry

    def _redact_device(self, device_id: str) -> str:
        # 设备编号本身可帮助住户追踪副本，不暴露他人身份，保留。
        return device_id
