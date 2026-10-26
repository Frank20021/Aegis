import json
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from aegis.inference import VllmClient
from aegis.letta_adapter import LettaAppClient, LettaClient


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


def test_vllm_client_reads_model_len_and_completions():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"data": [{"id": "demo", "max_model_len": 8192}]}).encode()
            self._send(body)

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            body = json.dumps({"choices": [{"text": f"seed={request['seed']}"}]}).encode()
            self._send(body)

        def _send(self, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = _Server(Handler)
    try:
        client = VllmClient(server.url)
        budget = client.budget(kv_token_budget=64 * 4096, max_num_seqs=64)
        assert budget.max_model_len == 8192
        assert budget.resident_slots(4096) == 64
        completion = client.complete(model="demo", prompt="hello", seed=7, max_tokens=8)
        assert completion.text == "seed=7"
        assert completion.seed == 7
    finally:
        server.close()


def test_letta_client_updates_blocks_and_archival():
    state = {"blocks": [], "archival": []}

    class Handler(BaseHTTPRequestHandler):
        def do_PATCH(self):
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            label = self.path.rstrip("/").split("/")[-1]
            state["blocks"] = [block for block in state["blocks"] if block["label"] != label]
            state["blocks"].append({"label": label, "value": request["value"]})
            self._send(b"{}")

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            state["archival"].append(request["text"])
            self._send(b"{}")

        def do_GET(self):
            body = json.dumps({"blocks": state["blocks"]}).encode()
            self._send(body)

        def _send(self, body: bytes):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = _Server(Handler)
    try:
        client = LettaClient(server.url)
        client.update_block("agent-1", "summary", "short")
        client.archival_insert("agent-1", "full context")
        assert client.get_block("agent-1", "summary") == "short"
        assert state["archival"] == ["full context"]
    finally:
        server.close()


def test_letta_app_server_round_trip():
    try:
        with urllib.request.urlopen("http://127.0.0.1:4500/readyz", timeout=1) as response:
            ready = response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        ready = False
    if not ready:
        pytest.skip("Letta App Server is not listening on 127.0.0.1:4500")
    client = LettaAppClient()
    client.update_block("aegis-test", "summary", "short")
    client.archival_insert("aegis-test", "full context")
    assert client.get_block("aegis-test", "summary") == "short"
    assert client.agent_ids["aegis-test"].startswith("agent-local-")
