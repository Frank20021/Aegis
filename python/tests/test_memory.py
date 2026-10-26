from aegis.inference import ModelBudget
from aegis.letta_adapter import LocalLettaStore
from aegis.memory import TieredMemory


def test_sixty_four_full_contexts_fit_and_the_next_one_demotes(tmp_path):
    context_tokens = 4096
    budget = ModelBudget(max_model_len=8192, kv_token_budget=64 * context_tokens, max_num_seqs=64)
    slots = budget.resident_slots(context_tokens)
    assert slots == 64

    store = LocalLettaStore(tmp_path / "letta")
    memory = TieredMemory(
        slots=slots,
        context_tokens=context_tokens,
        cold_dir=tmp_path / "cold",
        store=store,
    )
    for index in range(64):
        assert memory.admit(f"agent-{index}") == "hot"
    assert memory.evictions == 0
    assert memory.hot_tokens == 64 * context_tokens
    assert len(memory.resident_ids) == 64

    memory.admit("agent-64")
    assert memory.evictions == 1
    assert memory.hot_tokens == 64 * context_tokens
    assert len(memory.resident_ids) == 64

    warm = [agent for agent in memory.agents.values() if agent.tier == "warm"]
    assert len(warm) == 1
    demoted = warm[0]
    assert demoted.hot == ""
    assert demoted.hot_tokens == 0
    archived = memory.cold_text(demoted.agent_id)
    assert len(archived) == context_tokens * memory.chars_per_token
    assert store.get_block(demoted.agent_id, "summary") == archived[:240]


def test_context_over_the_window_is_rejected(tmp_path):
    memory = TieredMemory(slots=1, context_tokens=8, cold_dir=tmp_path)
    try:
        memory.admit("too-big", context="x" * 100)
    except ValueError as exc:
        assert "window" in str(exc)
    else:
        raise AssertionError("expected the oversize context to be rejected")
