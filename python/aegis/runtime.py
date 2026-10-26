"""Subprocess client for the `aegis worker` JSON protocol."""

from __future__ import annotations

import base64
import json
import subprocess
import threading
from pathlib import Path


class SandboxProcess:
    def __init__(self, binary: Path):
        self.binary = Path(binary)
        self.proc = subprocess.Popen(
            [str(self.binary), "worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.stderr_lines: list[str] = []
        self._lock = threading.Lock()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def request(self, payload: dict) -> dict:
        if self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("worker is closed")
        with self._lock:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
            line = self.proc.stdout.readline()
        if not line:
            detail = "".join(self.stderr_lines[-20:])
            raise RuntimeError(f"worker exited before responding: {detail}")
        return json.loads(line)

    def invoke(
        self,
        name: str,
        data: bytes,
        *,
        ring: bool = False,
        fuel: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict:
        payload: dict = {
            "op": "invoke",
            "name": name,
            "input_b64": base64.b64encode(data).decode(),
            "ring": ring,
        }
        if fuel is not None:
            payload["fuel"] = fuel
        if timeout_ms is not None:
            payload["timeout_ms"] = timeout_ms
        response = self.request(payload)
        if not response.get("ok"):
            raise RuntimeError(response.get("error") or str(response))
        response["output"] = base64.b64decode(response.get("output_b64") or "")
        return response

    def open_ring(self, path: Path, capacity: int, payload: int) -> dict:
        response = self.request(
            {
                "op": "ring-open",
                "path": str(path),
                "capacity": capacity,
                "payload": payload,
            }
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error") or str(response))
        return response

    def close(self) -> None:
        if self.proc.stdin is not None:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def _drain_stderr(self) -> None:
        if self.proc.stderr is None:
            return
        for line in self.proc.stderr:
            self.stderr_lines.append(line)
