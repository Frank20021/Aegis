from aegis.__main__ import run_demo


def test_control_plane_demo(tmp_path):
    summary = run_demo(None, tmp_path / "demo")
    assert summary["slots"] == 64
    assert summary["evictions_after_full_load"] == 0
    assert summary["evictions_after_overflow"] == 1
    assert summary["hot_tokens_after_full_load"] == summary["hot_tokens_after_overflow"]
    assert summary["echo"] == "ping"
    assert summary["add"] == "5"
    assert summary["chain_ok"]
    assert summary["replay_ok"]
    assert summary["summary_block"]
    assert len(summary["agents"]) == 65
    assert sum(agent["tier"] == "warm" for agent in summary["agents"]) == 1
