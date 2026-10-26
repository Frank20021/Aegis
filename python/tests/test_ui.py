import json
import threading
from http.server import ThreadingHTTPServer

from aegis.session import read_records
from aegis.ui import build_view, make_handler, run_view
from aegis.__main__ import run_demo


class _Server:
    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.httpd.server_address
        self.url = f"http://{host}:{port}"

    def close(self):
        self.httpd.shutdown()
        self.thread.join(timeout=5)


def test_view_names_the_demoted_agent(tmp_path):
    summary = run_demo(None, tmp_path / "demo")
    view = build_view(summary, read_records(tmp_path / "demo" / "session.jsonl"))
    assert view["demoted"]
    assert view["echo"] == "ping"
    assert any(event["kind"] == "tool_output" and event["output"] == "5" for event in view["events"])
    demoted = next(agent for agent in view["agents"] if agent["id"] == view["demoted"])
    assert demoted["tier"] == "warm"
    assert demoted["hot_tokens"] == 0


def test_ui_page_runs_the_demo(tmp_path):
    state = type("State", (), {"runtime_bin": None, "root": tmp_path / "ui", "lock": threading.Lock()})()
    server = _Server(make_handler(state))
    try:
        import urllib.request

        page = urllib.request.urlopen(server.url, timeout=5)
        assert b"Run the demo" in page.read()
        request = urllib.request.Request(server.url + "/api/run", method="POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read())
        assert payload["slots"] == 64
        assert payload["replay_ok"] is True
        assert len(payload["agents"]) == 65
    finally:
        server.close()


def test_run_view_replaces_an_older_session(tmp_path):
    root = tmp_path / "ui"
    first = run_view(None, root)
    second = run_view(None, root)
    assert len(first["events"]) == len(second["events"]) == 6
