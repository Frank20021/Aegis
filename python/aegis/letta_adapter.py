"""Letta-shaped memory blocks.

`LocalLettaStore` keeps core-memory blocks in process and appends archival
memory to disk. `LettaClient` speaks the retired HTTP API:

- PATCH `/v1/agents/{id}/core-memory/blocks/{label}`
- POST  `/v1/agents/{id}/archival-memory`
- GET   `/v1/agents/{id}/core-memory`

`LettaAppClient` speaks the current App Server at `ws://127.0.0.1:4500/ws`.
That server stores memory as MemFS files. A core block is `{label}.md` and
each archival insert is a new root file named `archival-{id}.md`.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import struct
import urllib.request
import uuid
from pathlib import Path
from typing import Protocol
from urllib.parse import urlparse


class MemoryStore(Protocol):
    def update_block(self, agent_id: str, label: str, value: str) -> None: ...

    def get_block(self, agent_id: str, label: str) -> str | None: ...

    def archival_insert(self, agent_id: str, text: str) -> None: ...


class LocalLettaStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.blocks: dict[tuple[str, str], str] = {}

    def update_block(self, agent_id: str, label: str, value: str) -> None:
        self.blocks[(agent_id, label)] = value

    def get_block(self, agent_id: str, label: str) -> str | None:
        return self.blocks.get((agent_id, label))

    def archival_insert(self, agent_id: str, text: str) -> None:
        path = self.root / "archival" / f"{agent_id}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"text": text}) + "\n")


class LettaClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def update_block(self, agent_id: str, label: str, value: str) -> None:
        self._request(
            "PATCH",
            f"/v1/agents/{agent_id}/core-memory/blocks/{label}",
            {"value": value},
        )

    def get_block(self, agent_id: str, label: str) -> str | None:
        payload = self._request("GET", f"/v1/agents/{agent_id}/core-memory")
        for block in payload.get("blocks", []):
            if block.get("label") == label:
                return block.get("value")
        return None

    def archival_insert(self, agent_id: str, text: str) -> None:
        self._request("POST", f"/v1/agents/{agent_id}/archival-memory", {"text": text})

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read()
        if not raw:
            return {}
        return json.loads(raw.decode())


def _memory_document(name: str, description: str, body: str) -> str:
    return f"---\nname: {name}\ndescription: {description}\n---\n{body}"


def _memory_body(content: str) -> str:
    if content.startswith("---\n"):
        end = content.find("\n---\n", 4)
        if end >= 0:
            return content[end + 5 :].strip("\n")
    return content.strip("\n")


class _WebSocket:
    """Small client for one App Server request. Loopback only, text frames."""

    def __init__(self, url: str, timeout: float):
        parsed = urlparse(url)
        if parsed.scheme != "ws" or not parsed.hostname or not parsed.port:
            raise ValueError(f"expected a ws://host:port URL, got {url}")
        self.sock = socket.create_connection((parsed.hostname, parsed.port), timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = parsed.path or "/"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode())
        self._buffer = b""
        header = self._read_until(b"\r\n\r\n")
        status = header.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raise ConnectionError(status.decode(errors="replace"))

    def close(self) -> None:
        try:
            self._send_frame(0x8, b"")
        except OSError:
            pass
        self.sock.close()

    def send_text(self, text: str) -> None:
        self._send_frame(0x1, text.encode())

    def recv_text(self) -> str:
        chunks: list[bytes] = []
        while True:
            opcode, payload = self._recv_frame()
            if opcode == 0x8:
                raise ConnectionError("Letta closed the socket")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode in (0x0, 0x1):
                chunks.append(payload)
                if self._last_fin:
                    return b"".join(chunks).decode()
                continue
            raise ConnectionError(f"unexpected websocket opcode {opcode}")

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        header = bytearray([0x80 | opcode])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _recv_frame(self) -> tuple[int, bytes]:
        first, second = self._read_exact(2)
        self._last_fin = bool(first & 0x80)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8))[0]
        if second & 0x80:
            mask = self._read_exact(4)
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(self._read_exact(length)))
        else:
            payload = self._read_exact(length)
        return opcode, payload

    def _read_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            chunk = self.sock.recv(max(4096, size - len(self._buffer)))
            if not chunk:
                raise ConnectionError("Letta closed the socket")
            self._buffer += chunk
        data = self._buffer[:size]
        self._buffer = self._buffer[size:]
        return data

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self._buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("Letta closed the socket")
            self._buffer += chunk
        end = self._buffer.index(marker) + len(marker)
        data = self._buffer[:end]
        self._buffer = self._buffer[end:]
        return data


class LettaAppClient:
    """Memory store backed by a running Letta App Server."""

    def __init__(self, url: str = "ws://127.0.0.1:4500/ws", timeout: float = 30.0):
        self.url = url
        self.timeout = timeout
        self.agent_ids: dict[str, str] = {}
        self._seq = 0

    def update_block(self, agent_id: str, label: str, value: str) -> None:
        self._write(
            agent_id,
            f"{label}.md",
            _memory_document(label, "Aegis core memory block", value),
            f"update {label}",
        )

    def get_block(self, agent_id: str, label: str) -> str | None:
        message = self._rpc(
            {
                "type": "read_memory_file",
                "agent_id": self._letta_id(agent_id),
                "path": f"{label}.md",
            }
        )
        if not message.get("success"):
            return None
        content = message.get("content")
        if not isinstance(content, str):
            return None
        return _memory_body(content)

    def archival_insert(self, agent_id: str, text: str) -> None:
        name = uuid.uuid4().hex
        self._write(
            agent_id,
            f"archival-{name}.md",
            _memory_document("archival", "Aegis archival passage", text),
            "archival insert",
        )

    def _write(self, agent_id: str, path: str, content: str, commit_message: str) -> None:
        message = self._rpc(
            {
                "type": "write_memory_file",
                "agent_id": self._letta_id(agent_id),
                "path": path,
                "content": content,
                "commit_message": commit_message,
            }
        )
        if not message.get("success"):
            raise RuntimeError(message.get("error") or f"write_memory_file failed for {path}")

    def _letta_id(self, agent_id: str) -> str:
        if agent_id.startswith("agent-local-"):
            return agent_id
        cached = self.agent_ids.get(agent_id)
        if cached:
            return cached
        message = self._rpc({"type": "create_agent", "personality": "blank", "pin_global": True})
        if not message.get("success") or not message.get("agent_id"):
            raise RuntimeError(message.get("error") or "create_agent failed")
        self.agent_ids[agent_id] = message["agent_id"]
        return message["agent_id"]

    def _rpc(self, payload: dict) -> dict:
        self._seq += 1
        request_id = f"aegis-{self._seq}"
        socket_client = _WebSocket(self.url, self.timeout)
        try:
            socket_client.send_text(json.dumps({**payload, "request_id": request_id}))
            while True:
                message = json.loads(socket_client.recv_text())
                if message.get("request_id") == request_id:
                    return message
        finally:
            socket_client.close()
