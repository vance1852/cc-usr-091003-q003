"""面向隐私专员与住户的两类报告。

- 隐私专员事故报告：还原一段记忆为何不应被复述、哪些副本仍待删除、
  谁在什么依据下访问过它，保留完整责任链。
- 住户个人记录：只含本人数据，其他自然人的身份一律假名化。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .contracts import load_events
from .domain import CareContext
from .ledger import Ledger, parse_ts


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str
    at: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "detail": self.detail, "at": self.at}


def _grant_chain(ledger: Ledger, record) -> list[dict[str, Any]]:
    """还原一条记录的授权责任链（决定事件不可被后发事件抹去）。"""
    chain: list[dict[str, Any]] = []
    if record.basis_type == "consent":
        grant = ledger.grants.get(record.basis_id)
        if grant is not None:
            chain.append(
                {
                    "type": "consent_granted",
                    "event_id": grant.decision_event_id,
                    "at": grant.valid_from.isoformat(),
                    "grant_id": grant.grant_id,
                    "memory_class": grant.memory_class,
                    "purpose": grant.purpose,
                    "contexts": list(grant.contexts),
                    "audience": list(grant.audience),
                    "retention_hours": round(grant.retention_seconds / 3600, 2),
                    "decided_by": f"{grant.granted_by_role}:{grant.granted_by_id}",
                    "guardian_id": grant.guardian_id,
                    "status": (
                        "revoked"
                        if grant.revoked_at is not None
                        else "active"
                        if grant.valid_to is None
                        else "expired"
                    ),
                    "revoked_at": grant.revoked_at.isoformat()
                    if grant.revoked_at
                    else None,
                    "revoke_event_id": grant.revoke_event_id,
                }
            )
    elif record.basis_type == "emergency":
        emergency = ledger.emergencies.get(record.basis_id)
        if emergency is not None:
            chain.append(
                {
                    "type": "emergency_window",
                    "emergency_id": emergency.emergency_id,
                    "started_at": emergency.started_at.isoformat(),
                    "ended_at": emergency.ended_at.isoformat()
                    if emergency.ended_at
                    else None,
                    "note": "生命危险临时豁免，不是同意，结束后不转为长期授权",
                }
            )
    chain.append(
        {
            "type": "recording_fact",
            "event_id": record.event_id,
            "occurred_at": record.occurred_at.isoformat(),
            "received_at": record.received_at.isoformat(),
            "context": record.context,
            "purpose": record.purpose,
            "content_id": record.content_id,
            "expires_at": record.expires_at.isoformat() if record.expires_at else None,
            "shredded_at": record.shredded_at.isoformat()
            if record.shredded_at
            else None,
            "late_upload_seconds": int(
                (record.received_at - record.occurred_at).total_seconds()
            ),
        }
    )
    return chain


def evaluate_record(
    ledger: Ledger, record, *, now: datetime
) -> list[Finding]:
    """给出该记录此刻与历史上不可被复述的全部理由。"""
    findings: list[Finding] = []

    if record.basis_type == "consent":
        grant = ledger.grants.get(record.basis_id)
        if grant is None:
            findings.append(Finding("no-basis", "记录引用的授权不存在"))
        else:
            if record.context not in grant.contexts:
                findings.append(
                    Finding(
                        "context-mismatch",
                        f"授权仅覆盖场景 {sorted(grant.contexts)}，"
                        f"记录发生在 {record.context}，自始超出授权范围",
                        record.occurred_at.isoformat(),
                    )
                )
            decline = ledger.decline_blocks(
                record.resident_id,
                record.memory_class,
                record.context,
                "*",
                record.occurred_at,
            )
            if decline is not None:
                findings.append(
                    Finding(
                        "sharing-declined",
                        f"住户已于 {decline.at.isoformat()} 明确拒绝在"
                        f"{decline.context} 场景共享该类记忆，拒绝优先于宽泛授权",
                        decline.at.isoformat(),
                    )
                )
            if grant.revoked_at is not None:
                findings.append(
                    Finding(
                        "revoked",
                        f"同意已于 {grant.revoked_at.isoformat()} 撤回，"
                        "撤回后新调用必须立即拒绝",
                        grant.revoked_at.isoformat(),
                    )
                )
    else:
        emergency = ledger.emergencies.get(record.basis_id)
        if emergency is not None and emergency.ended_at is not None:
            findings.append(
                Finding(
                    "emergency-ended",
                    "记录依据是生命危险临时豁免；危险结束且宽限期过后必须清除，"
                    "不自动转为长期同意",
                    emergency.ended_at.isoformat(),
                )
            )

    if record.expires_at is not None and now >= record.expires_at:
        findings.append(
            Finding(
                "expired",
                f"已过保存期限 {record.expires_at.isoformat()}，过期内容不得再可见",
                record.expires_at.isoformat(),
            )
        )
    if record.shredded_at is not None:
        findings.append(
            Finding(
                "shredded",
                f"内容本体已于 {record.shredded_at.isoformat()} 撕碎，"
                "仅保留责任元数据",
                record.shredded_at.isoformat(),
            )
        )
    return findings


def copy_status(ledger: Ledger, record, *, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for copy in ledger.copies_of(record.record_id):
        task = next(
            (
                task
                for task in ledger.tasks.values()
                if task.copy_id == copy.copy_id
            ),
            None,
        )
        rows.append(
            {
                "copy_id": copy.copy_id,
                "device_id": copy.device_id,
                "is_source": copy.is_source,
                "created_at": copy.created_at.isoformat(),
                "state": "deleted" if copy.deleted_at is not None else "live",
                "deleted_at": copy.deleted_at.isoformat() if copy.deleted_at else None,
                "deletion_task": (
                    {
                        "task_id": task.task_id,
                        "reason": task.reason,
                        "created_at": task.created_at.isoformat(),
                        "due_at": task.due_at.isoformat(),
                        "overdue": now >= task.due_at,
                        "state": (
                            "acknowledged"
                            if task.acknowledged_at is not None
                            else "pending"
                        ),
                        "acknowledged_at": task.acknowledged_at.isoformat()
                        if task.acknowledged_at
                        else None,
                    }
                    if task is not None
                    else None
                ),
            }
        )
    return rows


def incident_report(
    ledger: Ledger, record_id: str, *, now: datetime
) -> dict[str, Any]:
    record = ledger.records.get(record_id)
    if record is None:
        raise KeyError(f"未知记录：{record_id}")

    accesses = [
        {
            "access_id": entry.access_id,
            "at": entry.at.isoformat(),
            "requester": f"{entry.requester_role}:{entry.requester_id}",
            "context": entry.context,
            "purpose": entry.purpose,
            "allowed": entry.allowed,
            "denial_reason": entry.reason,
            "basis": (
                f"{entry.basis_type}:{entry.basis_id}"
                if entry.basis_type
                else None
            ),
            "breach": entry.breach,
        }
        for entry in ledger.accesses
        if entry.record_id == record_id
    ]
    breaches = [a for a in accesses if a["breach"]]

    return {
        "record_id": record.record_id,
        "resident_id": record.resident_id,
        "memory_class": record.memory_class,
        "content_id": record.content_id,
        "generated_at": now.isoformat(),
        "why_it_must_not_be_replayed": [
            f.as_dict() for f in evaluate_record(ledger, record, now=now)
        ],
        "historical_breaches": breaches,
        "authorization_chain": _grant_chain(ledger, record),
        "copies": copy_status(ledger, record, now=now),
        "pending_deletion": [
            row["deletion_task"]
            for row in copy_status(ledger, record, now=now)
            if row["deletion_task"]
            and row["deletion_task"]["state"] == "pending"
        ],
        "accesses": accesses,
    }


def pending_deletions(ledger: Ledger, *, now: datetime) -> list[dict[str, Any]]:
    rows = []
    for task in ledger.pending_tasks():
        record = ledger.records.get(task.record_id)
        rows.append(
            {
                "task_id": task.task_id,
                "copy_id": task.copy_id,
                "record_id": task.record_id,
                "resident_id": record.resident_id if record else None,
                "device_id": task.device_id,
                "reason": task.reason,
                "created_at": task.created_at.isoformat(),
                "due_at": task.due_at.isoformat(),
                "overdue": now >= task.due_at,
            }
        )
    return rows


class _Pseudonymizer:
    """把其他自然人的稳定标识替换为角色加短码（跨次导出稳定）。"""

    def __init__(self, self_id: str) -> None:
        self.self_id = self_id
        self._map: dict[str, str] = {}

    def actor(self, role: str, actor_id: str) -> str:
        if actor_id == self.self_id:
            return "self（本人）"
        key = f"{role}:{actor_id}"
        if key not in self._map:
            digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]
            self._map[key] = f"{role}#{digest}"
        return self._map[key]


def resident_export(
    ledger: Ledger, resident_id: str, *, now: datetime
) -> dict[str, Any]:
    """生成不暴露其他自然人身份的住户个人记录。"""
    pseudo = _Pseudonymizer(resident_id)

    my_records = []
    for record in ledger.records_for_resident(resident_id):
        if record.basis_type == "emergency":
            # 紧急记录的存活状态以紧急窗口（含宽限期）为准。
            from .policy import AccessRequest, judge_access

            probe = judge_access(
                ledger,
                AccessRequest(
                    record_id=record.record_id,
                    requester_role="emergency-responder",
                    requester_id="export-probe",
                    context="emergency",
                    purpose="life-protection",
                    at=now,
                ),
            )
            if record.shredded_at is not None:
                state = "shredded"
            elif probe.allowed:
                state = "live"
            else:
                state = "window-closed"
        elif record.shredded_at is not None:
            state = "shredded"
        elif record.expires_at is not None and now >= record.expires_at:
            state = "expired"
        else:
            state = "live"
        my_records.append(
            {
                "record_id": record.record_id,
                "memory_class": record.memory_class,
                "purpose": record.purpose,
                "context": record.context,
                "occurred_at": record.occurred_at.isoformat(),
                "received_at": record.received_at.isoformat(),
                "basis_type": record.basis_type,
                "basis_id": record.basis_id,
                "guardian_id": (
                    pseudo.actor("guardian", record.guardian_id)
                    if record.guardian_id
                    else None
                ),
                "expires_at": record.expires_at.isoformat()
                if record.expires_at
                else None,
                "state": state,
                "copies": [
                    {
                        "device_id": copy.device_id,
                        "state": "deleted" if copy.deleted_at else "live",
                    }
                    for copy in ledger.copies_of(record.record_id)
                ],
            }
        )

    my_decisions = []
    for grant in ledger.grants.values():
        if grant.resident_id != resident_id:
            continue
        my_decisions.append(
            {
                "decision": "granted",
                "event_id": grant.decision_event_id,
                "at": grant.valid_from.isoformat(),
                "memory_class": grant.memory_class,
                "purpose": grant.purpose,
                "contexts": list(grant.contexts),
                "retention_hours": round(grant.retention_seconds / 3600, 2),
                "made_by": "self"
                if grant.granted_by_role == "resident"
                else pseudo.actor("guardian", grant.guardian_id),
                "status": "revoked" if grant.revoked_at is not None else "active",
                "revoked_at": grant.revoked_at.isoformat()
                if grant.revoked_at
                else None,
            }
        )
    for decline in ledger.declines.values():
        if decline.resident_id != resident_id:
            continue
        my_decisions.append(
            {
                "decision": "declined",
                "at": decline.at.isoformat(),
                "memory_class": decline.memory_class,
                "context": decline.context,
            }
        )

    record_ids = {r.record_id for r in ledger.records_for_resident(resident_id)}
    my_accesses = []
    for entry in ledger.accesses:
        if entry.record_id not in record_ids:
            continue
        my_accesses.append(
            {
                "at": entry.at.isoformat(),
                "requester": pseudo.actor(entry.requester_role, entry.requester_id),
                "context": entry.context,
                "purpose": entry.purpose,
                "allowed": entry.allowed,
                "denial_reason": entry.reason,
            }
        )

    return {
        "resident_id": resident_id,
        "generated_at": now.isoformat(),
        "records": sorted(my_records, key=lambda r: r["occurred_at"]),
        "decisions": sorted(my_decisions, key=lambda d: d["at"]),
        "accesses_to_my_memory": sorted(my_accesses, key=lambda a: a["at"]),
        "open_deletion_tasks": sum(
            1
            for t in ledger.pending_tasks()
            if (r := ledger.records.get(t.record_id)) is not None
            and r.resident_id == resident_id
        ),
    }


def _render_incident(report: dict[str, Any], pending: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append(f"事故记录：{report['record_id']}（住户 {report['resident_id']}，"
                 f"{report['memory_class']}）")
    lines.append("")
    lines.append("一、为何不应被复述：")
    for finding in report["why_it_must_not_be_replayed"]:
        lines.append(f"  - [{finding['code']}] {finding['detail']}")
    lines.append("")
    lines.append("二、历史越权复述：")
    if not report["historical_breaches"]:
        lines.append("  无")
    for breach in report["historical_breaches"]:
        if breach["allowed"]:
            lines.append(
                f"  - {breach['at']} {breach['requester']} 在{breach['context']}场景"
                f"以{breach['purpose']}为由调用 → 旧系统放行了复述（"
                f"依据 {breach['basis']}，但该依据不覆盖此场景），"
                "按现规则必须拒绝"
            )
        else:
            lines.append(
                f"  - {breach['at']} {breach['requester']} 在{breach['context']}场景"
                f"以{breach['purpose']}为由调用 → 已拒绝（{breach['denial_reason']}）"
            )
    lines.append("")
    lines.append("三、副本与删除任务：")
    for copy in report["copies"]:
        task = copy["deletion_task"]
        if task is None:
            lines.append(
                f"  - {copy['copy_id']} @ {copy['device_id']}：{copy['state']}（无删除任务）"
            )
        else:
            flag = "，已逾期" if task["overdue"] and task["state"] == "pending" else ""
            lines.append(
                f"  - {copy['copy_id']} @ {copy['device_id']}：{copy['state']}；"
                f"删除任务 {task['task_id']}（{task['reason']}）{task['state']}"
                f"，期限 {task['due_at']}{flag}"
            )
    lines.append("")
    lines.append("四、谁在什么依据下访问过：")
    for access in report["accesses"]:
        verdict = "允许" if access["allowed"] else f"拒绝（{access['denial_reason']}）"
        lines.append(
            f"  - {access['at']} {access['requester']}：{verdict}，"
            f"依据 {access['basis'] or '无'}"
        )
    lines.append("")
    lines.append("五、授权责任链：")
    for link in report["authorization_chain"]:
        lines.append(f"  - {json.dumps(link, ensure_ascii=False)}")
    lines.append("")
    lines.append(f"全系统待删除任务：{len(pending)} 项")
    for task in pending:
        overdue = "（已逾期）" if task["overdue"] else ""
        lines.append(
            f"  - {task['task_id']} → {task['device_id']} / {task['copy_id']}，"
            f"原因 {task['reason']}，期限 {task['due_at']}{overdue}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="记忆同意事故报告")
    parser.add_argument("fixture", type=Path, help="场景事件文件")
    parser.add_argument("--record", help="要调查的记录标识")
    parser.add_argument("--resident", help="生成住户个人记录")
    parser.add_argument("--now", help="报告时间（默认取文件中最后事件时间）")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    _, events = load_events(args.fixture)
    ledger = Ledger.replay(events)
    now = parse_ts(args.now) if args.now else max(
        (parse_ts(e.occurred_at) for e in events), default=datetime.max
    )

    if args.resident:
        payload: Any = resident_export(ledger, args.resident, now=now)
    else:
        record_id = args.record
        if record_id is None:
            record_id = next(
                (
                    rid
                    for rid, record in ledger.records.items()
                    if record.context == CareContext.FAMILY_VISIT.value
                ),
                next(iter(ledger.records), None),
            )
        if record_id is None:
            raise SystemExit("案例中没有任何记忆记录")
        payload = incident_report(ledger, record_id, now=now)
        payload["all_pending_deletions"] = pending_deletions(ledger, now=now)

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    else:
        if args.resident:
            print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        else:
            pending = payload["all_pending_deletions"]
            print(_render_incident(payload, pending))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
