use std::path::PathBuf;
use std::thread;
use std::time::Instant;

use aegis_sandbox::Sandbox;
use aegis_shm::{Ring, ShmError};
use anyhow::{bail, Result};

pub enum BenchRequest {
    Isolation {
        iterations: u32,
        warmup: u32,
    },
    Throughput {
        count: u64,
        payload: usize,
    },
    All {
        iterations: u32,
        warmup: u32,
        count: u64,
        payload: usize,
    },
}

pub fn run(request: BenchRequest) -> Result<()> {
    match request {
        BenchRequest::Isolation { iterations, warmup } => isolation(iterations, warmup),
        BenchRequest::Throughput { count, payload } => throughput(count, payload),
        BenchRequest::All {
            iterations,
            warmup,
            count,
            payload,
        } => {
            isolation(iterations, warmup)?;
            throughput(count, payload)
        }
    }
}

fn isolation(iterations: u32, warmup: u32) -> Result<()> {
    let sandbox = Sandbox::new()?;
    report(
        "isolation-nop",
        &sandbox.measure("nop", b"", iterations, warmup)?,
    );
    report(
        "isolation-echo",
        &sandbox.measure("echo", b"ping", iterations, warmup)?,
    );
    Ok(())
}

fn report(label: &str, stats: &aegis_sandbox::LatencyStats) {
    let mean_us = stats.mean_micros();
    println!("{label} iterations={}", stats.iterations);
    println!(
        "mean_us={mean_us:.2} p50_us={:.2} p99_us={:.2} min_us={:.2} max_us={:.2}",
        stats.p50_micros(),
        stats.p99_micros(),
        stats.min.as_secs_f64() * 1_000_000.0,
        stats.max.as_secs_f64() * 1_000_000.0
    );
    println!(
        "target_us=380 within_target={}",
        if mean_us < 380.0 { "true" } else { "false" }
    );
}

fn throughput(count: u64, payload: usize) -> Result<()> {
    if payload < 8 {
        bail!("payload must be at least 8 bytes");
    }
    let path: PathBuf =
        std::env::temp_dir().join(format!("aegis-bench-{}.ring", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let ring = Ring::create(&path, 8192, payload as u32)?;
    let reader = Ring::open(&path)?;
    let started = Instant::now();
    let producer = thread::spawn(move || -> Result<()> {
        for index in 0..count {
            let mut message = vec![0u8; payload];
            message[..8].copy_from_slice(&index.to_le_bytes());
            while let Err(err) = ring.push(&message) {
                if matches!(err, ShmError::Full) {
                    std::hint::spin_loop();
                    continue;
                }
                return Err(err.into());
            }
        }
        Ok(())
    });
    let consumer = thread::spawn(move || -> Result<()> {
        let mut seen = 0u64;
        while seen < count {
            match reader.pop()? {
                Some(got) => {
                    let mut expected = [0u8; 8];
                    expected.copy_from_slice(&seen.to_le_bytes());
                    if got.len() != payload || got[..8] != expected {
                        bail!("ring payload mismatch at message {seen}");
                    }
                    seen += 1;
                }
                None => std::hint::spin_loop(),
            }
        }
        Ok(())
    });
    producer.join().expect("producer thread")?;
    consumer.join().expect("consumer thread")?;
    let elapsed = started.elapsed();
    let rate = count as f64 / elapsed.as_secs_f64();
    println!(
        "throughput messages={count} payload={payload} seconds={:.4}",
        elapsed.as_secs_f64()
    );
    println!("msgs_per_sec={rate:.0}");
    println!(
        "target_msgs_per_sec=2100 within_target={}",
        if rate > 2100.0 { "true" } else { "false" }
    );
    let _ = std::fs::remove_file(&path);
    Ok(())
}
