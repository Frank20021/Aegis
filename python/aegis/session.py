"""Append-only session log with a hash chain.

Records are the unit of replay, debugging, and audit. A session that runs for
48 hours is the same file with a larger timestamp span.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass
class TraceEvent:
    ts: str
    session_id: str
    agent_id: str
    kind: str
    seed: int | None = None
    tool: str | None = None
    call_id: str | None = None
    arguments: dict | None = None
    output: str | None = None
    fuel_used: int | None = None
    detail: dict | None = None

    def to_dict(self) -> dict:
        raw = asdict(self)
        return {key: value for key, value in raw.items() if value is not None}


@dataclass
class SessionAnalysis:
    session_id: str
    span: timedelta
    started: datetime | None
    ended: datetime | None
    tool_sequence: list[tuple[str, str, str]] = field(default_factory=list)
    agents: list[str] = field(default_factory=list)
    call_count: int = 0
    chain_ok: bool = False


class SessionLog:
    def __init__(self, path: Path, session_id: str):
        self.path = Path(path)
        self.session_id = session_id
        self.prev = "0" * 64
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size:
            existing = read_records(self.path)
            if existing:
                self.prev = existing[-1]["hash"]

    def append(self, event: TraceEvent) -> str:
        body = event.to_dict()
        body["session_id"] = self.session_id
        digest = hashlib.sha256((self.prev + canonical(body)).encode()).hexdigest()
        record = {"prev": self.prev, "hash": digest, "event": body}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        self.prev = digest
        return digest

    def records(self) -> list[dict]:
        return read_records(self.path)


def read_records(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def verify_chain(records: list[dict]) -> bool:
    prev = "0" * 64
    for record in records:
        digest = hashlib.sha256((prev + canonical(record["event"])).encode()).hexdigest()
        if record.get("prev") != prev or record.get("hash") != digest:
            return False
        prev = digest
    return True


def analyze(records: list[dict]) -> SessionAnalysis:
    events = [record["event"] for record in records]
    stamps = []
    for event in events:
        stamps.append(datetime.fromisoformat(event["ts"]))
    started = min(stamps) if stamps else None
    ended = max(stamps) if stamps else None
    span = (ended - started) if started and ended else timedelta(0)
    sequence = []
    agents: list[str] = []
    for event in events:
        agent_id = event.get("agent_id", "")
        if agent_id and agent_id not in agents:
            agents.append(agent_id)
        if event.get("kind") == "tool_call":
            sequence.append((agent_id, event.get("tool", ""), event.get("call_id", "")))
    session_id = events[0]["session_id"] if events else ""
    return SessionAnalysis(
        session_id=session_id,
        span=span,
        started=started,
        ended=ended,
        tool_sequence=sequence,
        agents=agents,
        call_count=len(sequence),
        chain_ok=verify_chain(records),
    )


def explain_call(records: list[dict], call_id: str) -> dict:
    events = [record["event"] for record in records]
    call_index = next(
        index
        for index, event in enumerate(events)
        if event.get("kind") == "tool_call" and event.get("call_id") == call_id
    )
    call = events[call_index]
    output = next(
        (
            event
            for event in events[call_index:]
            if event.get("kind") == "tool_output" and event.get("call_id") == call_id
        ),
        None,
    )
    seed = None
    for event in reversed(events[: call_index + 1]):
        if event.get("kind") == "sample" and event.get("agent_id") == call.get("agent_id"):
            seed = event.get("seed")
            break
    return {
        "agent_id": call.get("agent_id"),
        "tool": call.get("tool"),
        "arguments": call.get("arguments"),
        "output": None if output is None else output.get("output"),
        "seed": seed,
        "call_id": call_id,
    }
