"""`python -m aegis demo` and `python -m aegis replay`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .inference import LocalDeterministicLM, ModelBudget
from .letta_adapter import LettaAppClient, LocalLettaStore
from .memory import TieredMemory
from .replay import replay
from .runtime import SandboxProcess
from .scheduler import AgentRuntime
from .session import SessionLog, analyze, read_records, verify_chain
from .trace import Tracer
from .ui import serve_ui
from .workflow import Workflow


def run_demo(runtime_bin: Path | None, root: Path, *, bench: bool = False) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    session = SessionLog(root / "session.jsonl", "demo")
    budget = ModelBudget(max_model_len=8192, kv_token_budget=64 * 4096, max_num_seqs=64)
    slots = budget.resident_slots(4096)
    store = LocalLettaStore(root / "letta")
    memory = TieredMemory(
        slots=slots,
        context_tokens=4096,
        cold_dir=root / "cold",
        store=store,
    )
    agents = AgentRuntime("local")
    tracer = Tracer(session)
    sandbox = SandboxProcess(runtime_bin) if runtime_bin else None
    try:
        for index in range(slots):
            agent_id = f"agent-{index:02d}"
            memory.admit(agent_id)
            agents.spawn(agent_id, memory.hot_text(agent_id))
        admitted_evictions = memory.evictions
        admitted_hot = memory.hot_tokens
        workflow = Workflow(memory, agents, tracer, sandbox=sandbox, lm=LocalDeterministicLM())
        echoed = workflow.run_tool("agent-00", "echo", {"text": "ping"}, seed=7)
        added = workflow.run_tool("agent-01", "add", {"a": 2, "b": 3}, seed=11)
        memory.admit("agent-overflow")
        agents.spawn("agent-overflow", memory.hot_text("agent-overflow"))
        records = session.records()

        def executor(tool: str, arguments: dict) -> str:
            return workflow.execute(tool, arguments)[0]

        report = replay(records, executor)
        analysis = analyze(records)
        bench_stats = None
        if bench and sandbox is not None:
            bench_stats = sandbox.request({"op": "bench-isolation", "iterations": 300, "warmup": 40})
        summary = {
            "slots": slots,
            "evictions_after_full_load": admitted_evictions,
            "hot_tokens_after_full_load": admitted_hot,
            "evictions_after_overflow": memory.evictions,
            "hot_tokens_after_overflow": memory.hot_tokens,
            "echo": echoed,
            "add": added,
            "chain_ok": verify_chain(records),
            "replay_ok": report.ok,
            "span_seconds": analysis.span.total_seconds(),
            "bench": bench_stats,
            "demoted": next(
                (agent.agent_id for agent in memory.agents.values() if agent.tier == "warm"),
                None,
            ),
            "agents": [
                {
                    "id": agent.agent_id,
                    "tier": agent.tier,
                    "hot_tokens": agent.hot_tokens,
                    "cold_records": agent.cold_records,
                }
                for agent in sorted(
                    memory.agents.values(),
                    key=lambda agent: (agent.agent_id == "agent-overflow", agent.agent_id),
                )
            ],
        }
        if summary["demoted"] is not None:
            summary["summary_block"] = store.get_block(summary["demoted"], "summary")
        else:
            summary["summary_block"] = None
    finally:
        if sandbox is not None:
            sandbox.close()
    _print_summary(summary)
    return summary


def letta_check(url: str) -> int:
    client = LettaAppClient(url)
    value = "resident context moved to a Letta summary block"
    client.update_block("aegis-check", "summary", value)
    readback = client.get_block("aegis-check", "summary")
    client.archival_insert("aegis-check", "full context")
    agent_id = client.agent_ids["aegis-check"]
    print(f"letta={url} agent={agent_id} summary_ok={readback == value}")
    return 0 if readback == value else 1


def replay_file(path: Path) -> int:
    records = read_records(path)
    analysis = analyze(records)
    print(f"session={analysis.session_id} calls={analysis.call_count} span={analysis.span} chain_ok={analysis.chain_ok}")
    for agent_id, tool, call_id in analysis.tool_sequence:
        print(f"  {agent_id} {tool} {call_id}")
    return 0 if analysis.chain_ok else 1


def _print_summary(summary: dict) -> None:
    print(
        f"admitted {summary['slots']} full-context agents, "
        f"evictions={summary['evictions_after_full_load']}, "
        f"hot_tokens={summary['hot_tokens_after_full_load']}"
    )
    print(
        f"one past capacity demoted a resident, "
        f"evictions={summary['evictions_after_overflow']}, "
        f"hot_tokens={summary['hot_tokens_after_overflow']}"
    )
    print(f"echo -> {summary['echo']}")
    print(f"add -> {summary['add']}")
    print(f"audit_chain={summary['chain_ok']} replay={summary['replay_ok']}")
    if summary["bench"] is not None:
        stats = summary["bench"]
        print(
            f"isolation mean_us={stats.get('mean_us'):.2f} "
            f"p50_us={stats.get('p50_us'):.2f} "
            f"within_target={stats.get('within_target')}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis")
    sub = parser.add_subparsers(dest="cmd", required=True)
    demo = sub.add_parser("demo", help="admit 64 agents, run traced tools, replay them")
    demo.add_argument("--runtime", type=Path)
    demo.add_argument("--bench", action="store_true")
    demo.add_argument("--out", type=Path, default=Path("sessions/demo"))
    replay_cmd = sub.add_parser("replay", help="print a recorded session")
    replay_cmd.add_argument("trace", type=Path)
    letta_cmd = sub.add_parser("letta", help="write one memory block to a local Letta App Server")
    letta_cmd.add_argument("--url", default="ws://127.0.0.1:4500/ws")
    ui_cmd = sub.add_parser("ui", help="open a local page that runs the demo and shows it")
    ui_cmd.add_argument("--runtime", type=Path)
    ui_cmd.add_argument("--host", default="127.0.0.1")
    ui_cmd.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.cmd == "demo":
        summary = run_demo(args.runtime, args.out, bench=args.bench)
        return 0 if summary["chain_ok"] and summary["replay_ok"] else 1
    if args.cmd == "letta":
        return letta_check(args.url)
    if args.cmd == "ui":
        serve_ui(args.runtime, args.host, args.port)
        return 0
    return replay_file(args.trace)


if __name__ == "__main__":
    sys.exit(main())
