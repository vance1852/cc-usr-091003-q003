"""命令行入口：导入案例事件，输出隐私专员调查结论与住户导出。

用法::

    python -m care_consent.inspect fixtures/incident.json \
        [--record RECORD_ID] [--resident RESIDENT_ID] [--as-of ISO8601]

不隐式读取系统时钟：``--as-of`` 缺省取案例中最后一个事件的发生时间。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .agent import ConsentAgent
from .contracts import load_events
from .reports import InvestigationReport, ResidentExport


def build_agent(path: str | Path, as_of: str | None = None) -> tuple[str, ConsentAgent]:
    scenario, events = load_events(path)
    if as_of is None:
        as_of = max(events, key=lambda e: e.occurred_at).occurred_at
    agent = ConsentAgent(as_of)
    agent.load(events)
    return scenario, agent


def officer_summary(scenario: str, agent: ConsentAgent, record_id: str | None) -> dict[str, Any]:
    report = InvestigationReport(agent)
    if record_id is not None:
        return {
            "scenario": scenario,
            "as_of": agent.now.isoformat(),
            "finding": report.record_findings(record_id),
        }
    pending = agent.pending_deletions()
    unauthorized = [r for r in agent.all_records() if not r.authorized]
    return {
        "scenario": scenario,
        "as_of": agent.now.isoformat(),
        "records_loaded": len(agent.all_records()),
        "unauthorized_records": [
            {
                "record_id": r.record_id,
                "memory_class": r.memory_class,
                "scene": r.scene,
                "reason": r.unauthorized_reason,
                "occurred_at": r.occurred_at.isoformat(),
            }
            for r in unauthorized
        ],
        "pending_deletions": [t.as_dict() for t in pending],
        "pending_copy_locations": sorted(
            {t.device_id for t in pending if t.device_id != "core-store"}
        ),
        "residents": sorted(agent.residents),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="记忆同意案例调查")
    parser.add_argument("case_file", help="事件案例 JSON 路径")
    parser.add_argument("--record", help="针对单条记录输出完整调查结论")
    parser.add_argument("--resident", help="输出该住户的脱敏个人记录")
    parser.add_argument("--as-of", help="裁决截止时间（默认最后一个事件的发生时间）")
    args = parser.parse_args(argv)

    scenario, agent = build_agent(args.case_file, args.as_of)
    if args.resident:
        payload: Any = ResidentExport(agent).export(args.resident)
    else:
        payload = officer_summary(scenario, agent, args.record)
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
