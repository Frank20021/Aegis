"""Tiered agent context.

Hot context is the resident window that counts against the inference budget.
When another agent needs that room, the least-recently-used window is summarized
into a Letta core-memory block and the full text is appended to cold storage.
The hot token count never grows past the budget, so admitting past the tested
capacity demotes a resident instead of allocating another full context.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path

from .letta_adapter import MemoryStore


def full_context(agent_id: str, tokens: int, chars_per_token: int = 4) -> str:
    unit = f"[{agent_id}] "
    need = tokens * chars_per_token
    copies = (need // len(unit)) + 1
    return (unit * copies)[:need]


@dataclass
class AgentState:
    agent_id: str
    tier: str
    hot: str
    hot_tokens: int
    warm_summary: str
    cold_records: int
    last_access: int


class TieredMemory:
    def __init__(
        self,
        *,
        slots: int,
        context_tokens: int,
        cold_dir: Path,
        store: MemoryStore | None = None,
        chars_per_token: int = 4,
    ):
        if slots < 1:
            raise ValueError("slots must be positive")
        if context_tokens < 1:
            raise ValueError("context_tokens must be positive")
        self.slots = slots
        self.context_tokens = context_tokens
        self.hot_budget = slots * context_tokens
        self.cold_dir = Path(cold_dir)
        self.cold_dir.mkdir(parents=True, exist_ok=True)
        self.store = store
        self.chars_per_token = chars_per_token
        self.agents: dict[str, AgentState] = {}
        self.evictions = 0
        self._clock = 0

    @property
    def hot_tokens(self) -> int:
        return sum(agent.hot_tokens for agent in self.agents.values())

    @property
    def resident_ids(self) -> list[str]:
        return [agent.agent_id for agent in self.agents.values() if agent.tier == "hot"]

    def hot_text(self, agent_id: str) -> str:
        agent = self.agents[agent_id]
        agent.last_access = self._tick()
        return agent.hot

    def admit(self, agent_id: str, context: str | None = None) -> str:
        if agent_id in self.agents:
            raise ValueError(f"agent {agent_id} is already admitted")
        if context is None:
            context = full_context(agent_id, self.context_tokens, self.chars_per_token)
        tokens = max(1, math.ceil(len(context) / self.chars_per_token))
        if tokens > self.context_tokens:
            raise ValueError("context exceeds the per-agent window")
        while self.hot_tokens + tokens > self.hot_budget:
            self._demote_lru()
        self.agents[agent_id] = AgentState(
            agent_id=agent_id,
            tier="hot",
            hot=context,
            hot_tokens=tokens,
            warm_summary="",
            cold_records=0,
            last_access=self._tick(),
        )
        return "hot"

    def _demote_lru(self) -> None:
        residents = [agent for agent in self.agents.values() if agent.tier == "hot"]
        if not residents:
            raise MemoryError("hot budget is full and no resident agent can be demoted")
        victim = min(residents, key=lambda agent: agent.last_access)
        summary = victim.hot[:240]
        self._archive(victim, victim.hot)
        if self.store is not None:
            self.store.update_block(victim.agent_id, "summary", summary)
            self.store.archival_insert(victim.agent_id, victim.hot)
        victim.warm_summary = summary
        victim.hot = ""
        victim.hot_tokens = 0
        victim.tier = "warm"
        self.evictions += 1

    def _archive(self, agent: AgentState, text: str) -> None:
        path = self.cold_dir / f"{agent.agent_id}.jsonl"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"text": text}) + "\n")
        agent.cold_records += 1

    def cold_text(self, agent_id: str) -> str:
        path = self.cold_dir / f"{agent_id}.jsonl"
        if not path.exists():
            return ""
        chunks = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                chunks.append(json.loads(line)["text"])
        return "\n".join(chunks)

    def _tick(self) -> int:
        self._clock += 1
        return self._clock
