import json
import subprocess
from pathlib import Path

import pytest

from aegis.runtime import SandboxProcess
from aegis.shm import MAGIC, Ring, WRITE_SEQ_OFFSET


ROOT = Path(__file__).resolve().parents[2]


def aegis_binary() -> Path | None:
    for candidate in (ROOT / "target" / "release" / "aegis", ROOT / "target" / "debug" / "aegis"):
        if candidate.exists():
            return candidate
    return None


@pytest.fixture
def binary():
    found = aegis_binary()
    if found is None:
        pytest.skip("aegis binary is not built")
    return found


def test_worker_echo_and_shared_memory_ring(binary, tmp_path):
    sandbox = SandboxProcess(binary)
    try:
        echoed = sandbox.invoke("echo", b"hello aegis")
        assert echoed["output"] == b"hello aegis"
        assert echoed["exit_code"] == 0

        ring_path = tmp_path / "tools.ring"
        sandbox.open_ring(ring_path, 128, 4096)
        published = sandbox.invoke("echo", b"from-ring", ring=True)
        ring = Ring.open(ring_path)
        try:
            assert ring.pop() == b"from-ring"
            assert published["ring_seq"] == 1
        finally:
            ring.close()

        secure = sandbox.request({"op": "secure"})
        if secure.get("ok"):
            assert secure["seccomp"] == "installed"
        else:
            assert "Linux" in secure["error"] or "linux" in secure["error"].lower()
    finally:
        sandbox.close()


def test_shm_spec_matches_python(binary):
    completed = subprocess.run([str(binary), "shm-spec"], check=True, capture_output=True, text=True)
    spec = json.loads(completed.stdout)
    assert spec["magic"] == MAGIC
    assert spec["write_seq_offset"] == WRITE_SEQ_OFFSET
