"""Local page for one Aegis demo run."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .session import read_records

PAGE = (Path(__file__).with_name("ui.html")).read_text(encoding="utf-8")


def build_view(summary: dict, records: list[dict]) -> dict:
    tools: dict[str, str] = {}
    events = []
    for record in records:
        event = record["event"]
        if event.get("kind") == "tool_call" and event.get("tool"):
            tools[event["agent_id"]] = event["tool"]
        events.append(
            {
                "kind": event.get("kind"),
                "agent_id": event.get("agent_id"),
                "tool": event.get("tool"),
                "seed": event.get("seed"),
                "output": event.get("output"),
                "arguments": event.get("arguments"),
                "call_id": event.get("call_id"),
                "hash": str(record.get("hash", ""))[:12],
            }
        )
    agents = []
    for agent in summary.get("agents", []):
        agents.append({**agent, "tool": tools.get(agent["id"])})
    return {
        "slots": summary["slots"],
        "evictions_after_full_load": summary["evictions_after_full_load"],
        "evictions_after_overflow": summary["evictions_after_overflow"],
        "hot_tokens": summary["hot_tokens_after_overflow"],
        "echo": summary["echo"],
        "add": summary["add"],
        "chain_ok": summary["chain_ok"],
        "replay_ok": summary["replay_ok"],
        "demoted": summary["demoted"],
        "summary_block": summary.get("summary_block"),
        "span_seconds": summary.get("span_seconds"),
        "bench": summary.get("bench"),
        "agents": agents,
        "events": events,
    }


def run_view(runtime_bin: Path | None, root: Path) -> dict:
    from .__main__ import run_demo

    root.mkdir(parents=True, exist_ok=True)
    session = root / "session.jsonl"
    if session.exists():
        session.unlink()
    summary = run_demo(runtime_bin, root, bench=runtime_bin is not None)
    return build_view(summary, read_records(session))


class _UiState:
    def __init__(self, runtime_bin: Path | None, root: Path):
        self.runtime_bin = runtime_bin
        self.root = root
        self.lock = threading.Lock()


def make_handler(state: _UiState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] in ("/", "/index.html"):
                body = PAGE.encode()
                self._send(200, "text/html; charset=utf-8", body)
                return
            self._send(404, "text/plain; charset=utf-8", b"not found")

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != "/api/run":
                self._send(404, "text/plain; charset=utf-8", b"not found")
                return
            try:
                with state.lock:
                    payload = run_view(state.runtime_bin, state.root)
            except Exception as exc:
                body = json.dumps({"error": str(exc)}).encode()
                self._send(500, "application/json", body)
                return
            self._send(200, "application/json", json.dumps(payload).encode())

        def log_message(self, fmt: str, *args) -> None:
            return

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def serve_ui(runtime_bin: Path | None, host: str = "127.0.0.1", port: int = 8765) -> None:
    repo = Path(__file__).resolve().parents[2]
    if runtime_bin is None:
        candidate = repo / "target" / "release" / "aegis"
        runtime_bin = candidate if candidate.is_file() else None
    state = _UiState(runtime_bin, repo / "sessions" / "ui")
    server = ThreadingHTTPServer((host, port), make_handler(state))
    print(f"Aegis UI at http://{host}:{port}", flush=True)
    server.serve_forever()
