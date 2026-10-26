"""Python view of the Aegis shared-memory ring.

The byte layout matches `aegis-shm`. A Rust worker is the producer; this
module is the consumer used by the control plane. The same class can also
drive an in-process ring for tests.
"""

from __future__ import annotations

import mmap
import struct
import zlib
from pathlib import Path

MAGIC = 0x31474541
VERSION = 1
HEADER_SIZE = 128
WRITE_SEQ_OFFSET = 24
READ_SEQ_OFFSET = 32
SLOT_LEN_OFFSET = 8
SLOT_CRC_OFFSET = 12
SLOT_PAYLOAD_OFFSET = 16

_HEADER = struct.Struct("<IIIIII")
_U64 = struct.Struct("<Q")
_LEN_CRC = struct.Struct("<II")


def stride_for(payload_cap: int) -> int:
    raw = SLOT_PAYLOAD_OFFSET + payload_cap
    return (raw + 63) & ~63


class RingError(Exception):
    pass


class Ring:
    def __init__(self, path: Path, mapping: mmap.mmap, handle, capacity: int, stride: int, payload_cap: int):
        self.path = Path(path)
        self._map = mapping
        self._handle = handle
        self.capacity = capacity
        self.stride = stride
        self.payload_cap = payload_cap

    @classmethod
    def create(cls, path: Path, capacity: int, payload_cap: int) -> Ring:
        if capacity <= 0 or capacity & (capacity - 1) != 0:
            raise RingError("capacity must be a power of two")
        if payload_cap <= 0:
            raise RingError("payload capacity must be positive")
        stride = stride_for(payload_cap)
        total = HEADER_SIZE + capacity * stride
        path = Path(path)
        handle = path.open("w+b")
        handle.truncate(total)
        mapping = mmap.mmap(handle.fileno(), total)
        _HEADER.pack_into(mapping, 0, 0, VERSION, capacity, stride, payload_cap, 0)
        _U64.pack_into(mapping, WRITE_SEQ_OFFSET, 0)
        _U64.pack_into(mapping, READ_SEQ_OFFSET, 0)
        _HEADER.pack_into(mapping, 0, MAGIC, VERSION, capacity, stride, payload_cap, 0)
        return cls(path, mapping, handle, capacity, stride, payload_cap)

    @classmethod
    def open(cls, path: Path) -> Ring:
        path = Path(path)
        handle = path.open("r+b")
        mapping = mmap.mmap(handle.fileno(), 0)
        magic, version, capacity, stride, payload_cap, _pad = _HEADER.unpack_from(mapping, 0)
        if magic != MAGIC or version != VERSION:
            raise RingError(f"bad ring header magic={magic:#x} version={version}")
        if stride != stride_for(payload_cap):
            raise RingError("stride does not match the payload capacity")
        return cls(path, mapping, handle, capacity, stride, payload_cap)

    def push(self, payload: bytes) -> int:
        if len(payload) > self.payload_cap:
            raise RingError(f"payload of {len(payload)} bytes exceeds {self.payload_cap}")
        write_seq = self._load_u64(WRITE_SEQ_OFFSET)
        read_seq = self._load_u64(READ_SEQ_OFFSET)
        if ((write_seq - read_seq) & ((1 << 64) - 1)) >= self.capacity:
            raise RingError("ring is full")
        message = write_seq + 1
        slot = self._slot(write_seq)
        self._store_u64(slot, message * 2 - 1)
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        _LEN_CRC.pack_into(self._map, slot + SLOT_LEN_OFFSET, len(payload), crc)
        self._map[slot + SLOT_PAYLOAD_OFFSET : slot + SLOT_PAYLOAD_OFFSET + len(payload)] = payload
        self._store_u64(slot, message * 2)
        self._store_u64(WRITE_SEQ_OFFSET, message)
        return message

    def pop(self) -> bytes | None:
        write_seq = self._load_u64(WRITE_SEQ_OFFSET)
        read_seq = self._load_u64(READ_SEQ_OFFSET)
        if read_seq == write_seq:
            return None
        message = read_seq + 1
        slot = self._slot(read_seq)
        expected = message * 2
        for _ in range(64):
            first = self._load_u64(slot)
            if first != expected:
                continue
            length, crc = _LEN_CRC.unpack_from(self._map, slot + SLOT_LEN_OFFSET)
            if length > self.payload_cap:
                raise RingError("ring checksum mismatch")
            start = slot + SLOT_PAYLOAD_OFFSET
            payload = bytes(self._map[start : start + length])
            second = self._load_u64(slot)
            if first == second and (zlib.crc32(payload) & 0xFFFFFFFF) == crc:
                self._store_u64(READ_SEQ_OFFSET, message)
                return payload
        raise RingError("ring checksum mismatch")

    def close(self) -> None:
        self._map.close()
        self._handle.close()

    def _slot(self, sequence: int) -> int:
        index = sequence & (self.capacity - 1)
        return HEADER_SIZE + index * self.stride

    def _load_u64(self, offset: int) -> int:
        first = _U64.unpack_from(self._map, offset)[0]
        second = _U64.unpack_from(self._map, offset)[0]
        if first == second:
            return first
        return _U64.unpack_from(self._map, offset)[0]

    def _store_u64(self, offset: int, value: int) -> None:
        _U64.pack_into(self._map, offset, value & ((1 << 64) - 1))
