import pytest

from aegis.scheduler import AgentRuntime


def test_local_runtime_runs_sixty_four_agents():
    runtime = AgentRuntime("local")
    for index in range(64):
        runtime.spawn(f"agent-{index}", "context")
    assert runtime.observe("agent-0", "echo", "ok") == 1
    assert runtime.observe("agent-63", "echo", "ok") == 1
    runtime.release_hot("agent-0")
    assert runtime._actors["agent-0"].context == ""


def test_ray_backend_is_optional():
    pytest.importorskip("ray")
    runtime = AgentRuntime("ray")
    try:
        runtime.spawn("agent-ray", "context")
        assert runtime.observe("agent-ray", "echo", "pong") == 1
    finally:
        runtime.shutdown()
