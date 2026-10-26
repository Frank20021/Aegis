"""Execution trace: sampling seeds, tool calls, and tool outputs.

The tracer writes the session log directly. When DSPy is installed,
`dspy_callback` adapts DSPy's module and tool hooks onto the same records.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .session import SessionLog, TraceEvent, utc_now


class Tracer:
    def __init__(self, session: SessionLog):
        self.session = session
        self._sequence = 0
        self._tools: dict[str, str] = {}

    def sample(
        self,
        agent_id: str,
        seed: int,
        *,
        model: str,
        prompt_sha256: str,
        ts: str | None = None,
    ) -> None:
        self.session.append(
            TraceEvent(
                ts=ts or utc_now(),
                session_id=self.session.session_id,
                agent_id=agent_id,
                kind="sample",
                seed=seed,
                detail={"model": model, "prompt_sha256": prompt_sha256},
            )
        )

    def tool_call(
        self,
        agent_id: str,
        tool: str,
        arguments: dict,
        *,
        call_id: str | None = None,
        ts: str | None = None,
    ) -> str:
        if call_id is None:
            self._sequence += 1
            call_id = f"call-{self._sequence}"
        self._tools[call_id] = tool
        self.session.append(
            TraceEvent(
                ts=ts or utc_now(),
                session_id=self.session.session_id,
                agent_id=agent_id,
                kind="tool_call",
                tool=tool,
                call_id=call_id,
                arguments=arguments,
            )
        )
        return call_id

    def tool_output(
        self,
        agent_id: str,
        call_id: str,
        output: str,
        *,
        tool: str | None = None,
        fuel_used: int | None = None,
        ts: str | None = None,
    ) -> None:
        self.session.append(
            TraceEvent(
                ts=ts or utc_now(),
                session_id=self.session.session_id,
                agent_id=agent_id,
                kind="tool_output",
                tool=tool or self._tools.get(call_id),
                call_id=call_id,
                output=output,
                fuel_used=fuel_used,
            )
        )


def dspy_callback(tracer: Tracer, agent_id: str):
    """Return a DSPy `BaseCallback` that records LM seeds and tool I/O.

    Returns None when DSPy is not installed. The callback is what a DSPy
    program passes to `dspy.configure(callbacks=[...])`.
    """

    base_cls = _dspy_base_callback()
    if base_cls is None:
        return None

    class AuditCallback(base_cls):  # type: ignore[misc, valid-type]
        def on_lm_start(self, call_id, instance, inputs):  # noqa: ANN001
            kwargs = getattr(instance, "kwargs", None) or {}
            seed = kwargs.get("seed", 0)
            prompt = ""
            if isinstance(inputs, dict):
                prompt = str(inputs.get("prompt") or inputs.get("messages") or "")
            digest = hashlib.sha256(prompt.encode()).hexdigest()
            model = str(getattr(instance, "model", "dspy"))
            tracer.sample(agent_id, int(seed) if seed is not None else 0, model=model, prompt_sha256=digest)

        def on_tool_start(self, call_id, instance, inputs):  # noqa: ANN001
            name = getattr(instance, "name", None) or instance.__class__.__name__
            arguments = inputs if isinstance(inputs, dict) else {"input": inputs}
            tracer.tool_call(agent_id, str(name), arguments, call_id=str(call_id))

        def on_tool_end(self, call_id, outputs, exception):  # noqa: ANN001
            text = "" if exception is not None else _stringify(outputs)
            tracer.tool_output(agent_id, str(call_id), text)

    return AuditCallback()


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    return str(value)


def _dspy_base_callback():
    try:
        import dspy
    except ImportError:
        return None
    utils = getattr(dspy, "utils", None)
    if utils is None:
        return None
    for module_name in ("callback", "callbacks"):
        module = getattr(utils, module_name, None)
        if module is None:
            continue
        base = getattr(module, "BaseCallback", None)
        if base is not None:
            return base
    return None
