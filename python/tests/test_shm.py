from aegis.shm import HEADER_SIZE, MAGIC, SLOT_PAYLOAD_OFFSET, WRITE_SEQ_OFFSET, Ring


def test_python_ring_round_trip(tmp_path):
    path = tmp_path / "local.ring"
    writer = Ring.create(path, 8, 64)
    reader = Ring.open(path)
    try:
        for index in range(10):
            payload = f"msg-{index}".encode()
            writer.push(payload)
            assert reader.pop() == payload
        assert reader.pop() is None
    finally:
        writer.close()
        reader.close()


def test_layout_constants_match_the_rust_spec():
    assert MAGIC == 0x31474541
    assert HEADER_SIZE == 128
    assert WRITE_SEQ_OFFSET == 24
    assert SLOT_PAYLOAD_OFFSET == 16
