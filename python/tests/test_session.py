from datetime import datetime, timedelta, timezone

from aegis.replay import replay
from aegis.session import SessionLog, TraceEvent, analyze, explain_call, utc_now, verify_chain
from aegis.trace import Tracer


def test_hash_chain_detects_tampering(tmp_path):
    log = SessionLog(tmp_path / "session.jsonl", "audit")
    log.append(
        TraceEvent(
            ts=utc_now(),
            session_id="audit",
            agent_id="a",
            kind="tool_call",
            tool="echo",
            call_id="c1",
            arguments={"text": "hi"},
        )
    )
    records = log.records()
    assert verify_chain(records)
    records[0]["event"]["tool"] = "exfiltrate"
    assert not verify_chain(records)


def test_forty_eight_hour_session_replays_in_order(tmp_path):
    log = SessionLog(tmp_path / "long.jsonl", "long")
    tracer = Tracer(log)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    tracer.sample("agent-a", 7, model="local", prompt_sha256="abc", ts=start.isoformat())
    first = tracer.tool_call("agent-a", "echo", {"text": "one"}, ts=start.isoformat())
    tracer.tool_output("agent-a", first, "one", ts=(start + timedelta(hours=1)).isoformat())
    second = tracer.tool_call(
        "agent-a",
        "echo",
        {"text": "two"},
        ts=(start + timedelta(hours=47)).isoformat(),
    )
    tracer.tool_output("agent-a", second, "two", ts=(start + timedelta(hours=48)).isoformat())

    records = log.records()
    analysis = analyze(records)
    assert analysis.span == timedelta(hours=48)
    assert analysis.chain_ok
    assert analysis.tool_sequence == [("agent-a", "echo", "call-1"), ("agent-a", "echo", "call-2")]

    report = replay(records, lambda tool, arguments: arguments["text"])
    assert report.ok
    assert [step.recorded_output for step in report.steps] == ["one", "two"]
    assert report.samples[0]["seed"] == 7

    explained = explain_call(records, "call-2")
    assert explained["tool"] == "echo"
    assert explained["arguments"] == {"text": "two"}
    assert explained["output"] == "two"
    assert explained["seed"] == 7


def test_replay_reports_a_mismatch(tmp_path):
    log = SessionLog(tmp_path / "bad.jsonl", "bad")
    tracer = Tracer(log)
    call_id = tracer.tool_call("agent-a", "echo", {"text": "one"})
    tracer.tool_output("agent-a", call_id, "one")
    report = replay(log.records(), lambda tool, arguments: "different")
    assert not report.ok
    assert report.steps[0].matched is False
