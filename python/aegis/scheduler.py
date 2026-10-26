"""Agent workers.

`local` runs agents in-process. `ray` places each agent in its own Ray Core
actor so concurrent workflows share one driver and many address spaces.
"""

from __future__ import annotations

import logging


class AgentWorker:
    def __init__(self, agent_id: str, context: str):
        self.agent_id = agent_id
        self.context = context
        self.observations: list[tuple[str, str]] = []

    def observe(self, tool: str, output: str) -> int:
        self.observations.append((tool, output))
        return len(self.observations)

    def release_hot(self) -> None:
        self.context = ""


class AgentRuntime:
    def __init__(self, backend: str = "local"):
        if backend not in {"local", "ray"}:
            raise ValueError(f"unknown backend {backend}")
        self.backend = backend
        self._actors: dict = {}
        self._ray = None
        self._actor_cls = None
        if backend == "ray":
            import ray

            if not ray.is_initialized():
                ray.init(
                    ignore_reinit_error=True,
                    include_dashboard=False,
                    logging_level=logging.ERROR,
                    num_cpus=1,
                )
            self._ray = ray
            self._actor_cls = ray.remote(AgentWorker)

    def spawn(self, agent_id: str, context: str) -> None:
        if self._ray is not None:
            self._actors[agent_id] = self._actor_cls.remote(agent_id, context)
        else:
            self._actors[agent_id] = AgentWorker(agent_id, context)

    def observe(self, agent_id: str, tool: str, output: str) -> int:
        actor = self._actors[agent_id]
        if self._ray is not None:
            return self._ray.get(actor.observe.remote(tool, output))
        return actor.observe(tool, output)

    def release_hot(self, agent_id: str) -> None:
        actor = self._actors[agent_id]
        if self._ray is not None:
            self._ray.get(actor.release_hot.remote())
        else:
            actor.release_hot()

    def shutdown(self) -> None:
        if self._ray is not None and self._ray.is_initialized():
            self._ray.shutdown()
            self._ray = None
