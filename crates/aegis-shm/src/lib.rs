//! File-backed shared-memory ring buffer.
//!
//! One producer and one consumer. The producer publishes a slot, then advances
//! `write_seq` with a release store. The consumer acquire-loads `write_seq`
//! before reading the slot, so the payload writes are visible. A per-slot
//! sequence and a CRC let a reader in another language detect a torn slot.
//!
//! # Layout (little-endian)
//!
//! Header, 128 bytes:
//! - `0`: magic `u32` (`AEG1` = `0x3147_4541`)
//! - `4`: version `u32`
//! - `8`: capacity `u32` (power of two, slot count)
//! - `12`: stride `u32`
//! - `16`: payload capacity `u32`
//! - `20`: reserved `u32`
//! - `24`: write sequence `u64`
//! - `32`: read sequence `u64`
//!
//! Each slot:
//! - `0`: sequence `u64` (odd while the producer is writing, `2 * msg` when stable)
//! - `8`: length `u32`
//! - `12`: CRC-32 (ISO-HDLC / zlib) of the payload `u32`
//! - `16`: payload bytes

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{fence, AtomicU64, Ordering};

use memmap2::MmapMut;
use thiserror::Error;

pub const MAGIC: u32 = 0x3147_4541;
pub const VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 128;
pub const WRITE_SEQ_OFFSET: usize = 24;
pub const READ_SEQ_OFFSET: usize = 32;
pub const SLOT_SEQ_OFFSET: usize = 0;
pub const SLOT_LEN_OFFSET: usize = 8;
pub const SLOT_CRC_OFFSET: usize = 12;
pub const SLOT_PAYLOAD_OFFSET: usize = 16;

const MAX_PAYLOAD: u32 = 1024 * 1024;
const MAX_CAPACITY: u32 = 1 << 20;

#[derive(Debug, Error)]
pub enum ShmError {
    #[error("ring is full")]
    Full,
    #[error("payload of {len} bytes exceeds the slot capacity {cap}")]
    TooLarge { len: usize, cap: usize },
    #[error("ring checksum mismatch")]
    Corrupt,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub struct Ring {
    _map: MmapMut,
    base: *mut u8,
    path: PathBuf,
    capacity: u32,
    stride: u32,
    payload_cap: u32,
}

// The map stays alive for the life of the ring. Producer and consumer share
// the mapping and only touch slots under the SPSC sequence protocol.
unsafe impl Send for Ring {}
unsafe impl Sync for Ring {}

impl Ring {
    pub fn create(
        path: impl AsRef<Path>,
        capacity: u32,
        payload_cap: u32,
    ) -> Result<Self, ShmError> {
        validate(capacity, payload_cap)?;
        let stride = stride_for(payload_cap);
        let total = total_size(capacity, stride)?;
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        file.set_len(total as u64)?;
        let map = unsafe { MmapMut::map_mut(&file)? };
        let ring = Self::from_map(map, path, capacity, stride, payload_cap)?;
        ring.write_header()?;
        Ok(ring)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, ShmError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let map = unsafe { MmapMut::map_mut(&file)? };
        if map.len() < HEADER_SIZE {
            return Err(ShmError::Invalid(
                "ring file is smaller than the header".into(),
            ));
        }
        let base = map.as_ptr() as *mut u8;
        let magic = unsafe { ptr::read_unaligned(base.cast::<u32>()) };
        if magic != MAGIC {
            return Err(ShmError::Invalid(format!("bad magic {magic:#x}")));
        }
        let version = unsafe { ptr::read_unaligned(base.add(4).cast::<u32>()) };
        if version != VERSION {
            return Err(ShmError::Invalid(format!("unsupported version {version}")));
        }
        let capacity = unsafe { ptr::read_unaligned(base.add(8).cast::<u32>()) };
        let stride = unsafe { ptr::read_unaligned(base.add(12).cast::<u32>()) };
        let payload_cap = unsafe { ptr::read_unaligned(base.add(16).cast::<u32>()) };
        validate(capacity, payload_cap)?;
        if stride != stride_for(payload_cap) {
            return Err(ShmError::Invalid(
                "stride does not match payload capacity".into(),
            ));
        }
        let total = total_size(capacity, stride)?;
        if map.len() < total {
            return Err(ShmError::Invalid("ring file is truncated".into()));
        }
        Self::from_map(map, path, capacity, stride, payload_cap)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn payload_cap(&self) -> u32 {
        self.payload_cap
    }

    pub fn push(&self, payload: &[u8]) -> Result<u64, ShmError> {
        if payload.len() > self.payload_cap as usize {
            return Err(ShmError::TooLarge {
                len: payload.len(),
                cap: self.payload_cap as usize,
            });
        }
        let write_seq = self.write_seq();
        let read_seq = self.read_seq();
        let w = write_seq.load(Ordering::Relaxed);
        let r = read_seq.load(Ordering::Acquire);
        if w.wrapping_sub(r) >= u64::from(self.capacity) {
            return Err(ShmError::Full);
        }
        let n = w + 1;
        let index = (w as usize) & (self.capacity as usize - 1);
        let slot = self.slot(index);
        let seq = self.slot_seq(slot);
        seq.store(n * 2 - 1, Ordering::SeqCst);
        let crc = crc32fast::hash(payload);
        unsafe {
            ptr::write_unaligned(
                slot.add(SLOT_LEN_OFFSET).cast::<u32>(),
                payload.len() as u32,
            );
            ptr::write_unaligned(slot.add(SLOT_CRC_OFFSET).cast::<u32>(), crc);
            ptr::copy_nonoverlapping(
                payload.as_ptr(),
                slot.add(SLOT_PAYLOAD_OFFSET),
                payload.len(),
            );
        }
        fence(Ordering::SeqCst);
        seq.store(n * 2, Ordering::SeqCst);
        write_seq.store(n, Ordering::Release);
        Ok(n)
    }

    pub fn pop(&self) -> Result<Option<Vec<u8>>, ShmError> {
        let write_seq = self.write_seq();
        let read_seq = self.read_seq();
        let r = read_seq.load(Ordering::Relaxed);
        let w = write_seq.load(Ordering::Acquire);
        if r == w {
            return Ok(None);
        }
        let n = r + 1;
        let index = (r as usize) & (self.capacity as usize - 1);
        let slot = self.slot(index);
        let expected = n * 2;
        let mut payload = vec![0u8; self.payload_cap as usize];
        let mut stable_len = 0usize;
        let mut saw_stable = false;
        for _ in 0..1024 {
            let s1 = self.slot_seq(slot).load(Ordering::SeqCst);
            if s1 != expected {
                std::hint::spin_loop();
                continue;
            }
            let len =
                unsafe { ptr::read_unaligned(slot.add(SLOT_LEN_OFFSET).cast::<u32>()) } as usize;
            let crc = unsafe { ptr::read_unaligned(slot.add(SLOT_CRC_OFFSET).cast::<u32>()) };
            if len > self.payload_cap as usize {
                return Err(ShmError::Corrupt);
            }
            unsafe {
                ptr::copy_nonoverlapping(slot.add(SLOT_PAYLOAD_OFFSET), payload.as_mut_ptr(), len);
            }
            fence(Ordering::SeqCst);
            let s2 = self.slot_seq(slot).load(Ordering::SeqCst);
            if s1 == s2 && crc32fast::hash(&payload[..len]) == crc {
                stable_len = len;
                saw_stable = true;
                break;
            }
        }
        if !saw_stable {
            return Err(ShmError::Corrupt);
        }
        payload.truncate(stable_len);
        read_seq.store(n, Ordering::Release);
        Ok(Some(payload))
    }

    fn write_header(&self) -> Result<(), ShmError> {
        unsafe {
            ptr::write_unaligned(self.base.cast::<u32>(), 0);
            ptr::write_unaligned(self.base.add(4).cast::<u32>(), VERSION);
            ptr::write_unaligned(self.base.add(8).cast::<u32>(), self.capacity);
            ptr::write_unaligned(self.base.add(12).cast::<u32>(), self.stride);
            ptr::write_unaligned(self.base.add(16).cast::<u32>(), self.payload_cap);
            ptr::write_unaligned(self.base.add(20).cast::<u32>(), 0);
        }
        self.write_seq().store(0, Ordering::Relaxed);
        self.read_seq().store(0, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        unsafe { ptr::write_unaligned(self.base.cast::<u32>(), MAGIC) };
        fence(Ordering::SeqCst);
        Ok(())
    }

    fn from_map(
        map: MmapMut,
        path: PathBuf,
        capacity: u32,
        stride: u32,
        payload_cap: u32,
    ) -> Result<Self, ShmError> {
        let base = map.as_ptr() as *mut u8;
        if base.align_offset(8) != 0 {
            return Err(ShmError::Invalid("mapping is not 8-byte aligned".into()));
        }
        Ok(Self {
            _map: map,
            base,
            path,
            capacity,
            stride,
            payload_cap,
        })
    }

    fn write_seq(&self) -> &AtomicU64 {
        unsafe { &*self.base.add(WRITE_SEQ_OFFSET).cast::<AtomicU64>() }
    }

    fn read_seq(&self) -> &AtomicU64 {
        unsafe { &*self.base.add(READ_SEQ_OFFSET).cast::<AtomicU64>() }
    }

    fn slot(&self, index: usize) -> *mut u8 {
        let offset = HEADER_SIZE + index * self.stride as usize;
        unsafe { self.base.add(offset) }
    }

    fn slot_seq(&self, slot: *mut u8) -> &AtomicU64 {
        unsafe { &*slot.add(SLOT_SEQ_OFFSET).cast::<AtomicU64>() }
    }
}

pub fn stride_for(payload_cap: u32) -> u32 {
    let raw = SLOT_PAYLOAD_OFFSET as u32 + payload_cap;
    raw.saturating_add(63) & !63
}

fn total_size(capacity: u32, stride: u32) -> Result<usize, ShmError> {
    let slots = (capacity as usize)
        .checked_mul(stride as usize)
        .ok_or_else(|| ShmError::Invalid("ring size overflow".into()))?;
    HEADER_SIZE
        .checked_add(slots)
        .ok_or_else(|| ShmError::Invalid("ring size overflow".into()))
}

fn validate(capacity: u32, payload_cap: u32) -> Result<(), ShmError> {
    if capacity == 0 || !capacity.is_power_of_two() || capacity > MAX_CAPACITY {
        return Err(ShmError::Invalid(
            "capacity must be a non-zero power of two up to 2^20".into(),
        ));
    }
    if payload_cap == 0 || payload_cap > MAX_PAYLOAD {
        return Err(ShmError::Invalid(
            "payload capacity must be between 1 and 1 MiB".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Instant;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aegis-shm-{name}-{}.ring", std::process::id()))
    }

    #[test]
    fn round_trip_preserves_bytes_and_order() {
        let path = temp_path("round");
        let _ = std::fs::remove_file(&path);
        let ring = Ring::create(&path, 8, 64).unwrap();
        let opened = Ring::open(&path).unwrap();
        for i in 0..20u32 {
            let msg = format!("tool-result-{i}");
            ring.push(msg.as_bytes()).unwrap();
            let got = opened.pop().unwrap().unwrap();
            assert_eq!(got, msg.as_bytes());
        }
        assert!(opened.pop().unwrap().is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn full_ring_rejects_the_next_push() {
        let path = temp_path("full");
        let _ = std::fs::remove_file(&path);
        let ring = Ring::create(&path, 4, 32).unwrap();
        for i in 0..4u8 {
            ring.push(&[i]).unwrap();
        }
        assert!(matches!(ring.push(&[9]), Err(ShmError::Full)));
        assert_eq!(ring.pop().unwrap().unwrap(), vec![0]);
        ring.push(&[9]).unwrap();
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let path = temp_path("big");
        let _ = std::fs::remove_file(&path);
        let ring = Ring::create(&path, 2, 8).unwrap();
        assert!(matches!(ring.push(&[0; 9]), Err(ShmError::TooLarge { .. })));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn two_threads_move_every_message() {
        let path = temp_path("spsc");
        let _ = std::fs::remove_file(&path);
        let count: u64 = 20_000;
        let payload = 128usize;
        let ring = Ring::create(&path, 1024, payload as u32).unwrap();
        let reader = Ring::open(&path).unwrap();
        let start = Barrier::new(2);
        let start_p = Arc::new(start);
        let start_c = Arc::clone(&start_p);
        let producer = thread::spawn(move || {
            start_p.wait();
            for i in 0..count {
                let mut msg = vec![0u8; payload];
                msg[..8].copy_from_slice(&i.to_le_bytes());
                while let Err(ShmError::Full) = ring.push(&msg) {
                    std::hint::spin_loop();
                }
            }
        });
        let consumer = thread::spawn(move || {
            start_c.wait();
            let began = Instant::now();
            for i in 0..count {
                loop {
                    match reader.pop().unwrap() {
                        Some(got) => {
                            let mut expected = [0u8; 8];
                            expected.copy_from_slice(&i.to_le_bytes());
                            assert_eq!(&got[..8], &expected);
                            break;
                        }
                        None => std::hint::spin_loop(),
                    }
                }
            }
            began.elapsed()
        });
        producer.join().unwrap();
        let elapsed = consumer.join().unwrap();
        let rate = count as f64 / elapsed.as_secs_f64();
        assert!(
            rate > 2_100.0,
            "shared-memory throughput {rate:.0} msg/s, expected above 2100"
        );
        let _ = std::fs::remove_file(&path);
    }
}
