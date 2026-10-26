"""One step of a traced multi-agent workflow."""

from __future__ import annotations

from .inference import LocalDeterministicLM
from .memory import TieredMemory
from .runtime import SandboxProcess
from .scheduler import AgentRuntime
from .trace import Tracer


class Workflow:
    def __init__(
        self,
        memory: TieredMemory,
        agents: AgentRuntime,
        tracer: Tracer,
        sandbox: SandboxProcess | None = None,
        lm: LocalDeterministicLM | None = None,
    ):
        self.memory = memory
        self.agents = agents
        self.tracer = tracer
        self.sandbox = sandbox
        self.lm = lm or LocalDeterministicLM()

    def run_tool(self, agent_id: str, tool: str, arguments: dict, *, seed: int) -> str:
        prompt = self.memory.hot_text(agent_id)
        completion = self.lm.complete(model="local", prompt=prompt, seed=seed, max_tokens=16)
        self.tracer.sample(
            agent_id,
            completion.seed,
            model=completion.model,
            prompt_sha256=completion.prompt_sha256,
        )
        call_id = self.tracer.tool_call(agent_id, tool, arguments)
        output, fuel_used = self.execute(tool, arguments)
        self.tracer.tool_output(agent_id, call_id, output, tool=tool, fuel_used=fuel_used)
        self.agents.observe(agent_id, tool, output)
        return output

    def execute(self, tool: str, arguments: dict) -> tuple[str, int | None]:
        if tool == "echo":
            text = str(arguments.get("text", ""))
            if self.sandbox is not None:
                result = self.sandbox.invoke("echo", text.encode())
                return result["output"].decode(), result.get("fuel_consumed")
            return text, None
        if tool == "add":
            return str(int(arguments["a"]) + int(arguments["b"])), None
        raise KeyError(tool)
