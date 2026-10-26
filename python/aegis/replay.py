"""Reconstruct a workflow from its session log and optionally re-run tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .session import explain_call


Executor = Callable[[str, dict], str]


@dataclass
class ReplayStep:
    call_id: str
    agent_id: str
    tool: str
    recorded_output: str | None
    reexecuted_output: str | None
    matched: bool | None


@dataclass
class ReplayReport:
    steps: list[ReplayStep] = field(default_factory=list)
    samples: list[dict] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        executed = [step for step in self.steps if step.matched is not None]
        return bool(executed) and all(step.matched for step in executed)

    def explain(self, records: list[dict], call_id: str) -> dict:
        return explain_call(records, call_id)


def replay(records: list[dict], executor: Executor | None = None) -> ReplayReport:
    pending: dict[str, dict] = {}
    report = ReplayReport()
    for record in records:
        event = record["event"]
        kind = event.get("kind")
        if kind == "sample":
            report.samples.append(
                {
                    "agent_id": event.get("agent_id"),
                    "seed": event.get("seed"),
                    "detail": event.get("detail"),
                }
            )
            continue
        if kind == "tool_call":
            pending[event["call_id"]] = event
            continue
        if kind != "tool_output":
            continue
        call = pending.get(event.get("call_id", ""))
        if call is None:
            continue
        reexecuted = None
        matched = None
        if executor is not None:
            reexecuted = executor(call.get("tool", ""), call.get("arguments") or {})
            matched = reexecuted == event.get("output")
        report.steps.append(
            ReplayStep(
                call_id=event.get("call_id", ""),
                agent_id=call.get("agent_id", ""),
                tool=call.get("tool", ""),
                recorded_output=event.get("output"),
                reexecuted_output=reexecuted,
                matched=matched,
            )
        )
    return report
