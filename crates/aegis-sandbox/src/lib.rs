//! Wasmtime-backed tool sandbox.
//!
//! Each invocation gets a fresh store, so guest memory cannot leak into the
//! next call. Modules only import `aegis.input_len`, `aegis.read_input`, and
//! `aegis.write_output`. There is no WASI filesystem, socket, or environment
//! access. Fuel and epoch deadlines bound guest computation.

mod host;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder, Trap};

const MAX_COPY: usize = 1024 * 1024;

pub(crate) struct GuestState {
    limits: StoreLimits,
    input: Vec<u8>,
    output: Vec<u8>,
    max_output: usize,
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_memory_bytes: usize,
    pub max_output_bytes: usize,
    pub fuel: Option<u64>,
    pub timeout: Option<Duration>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 16 * 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            fuel: None,
            timeout: Some(Duration::from_secs(5)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvokeResult {
    pub exit_code: i32,
    pub output: Vec<u8>,
    pub fuel_consumed: Option<u64>,
    pub elapsed: Duration,
}

#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub iterations: u32,
    pub mean: Duration,
    pub p50: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
}

impl LatencyStats {
    pub fn mean_micros(&self) -> f64 {
        self.mean.as_secs_f64() * 1_000_000.0
    }

    pub fn p50_micros(&self) -> f64 {
        self.p50.as_secs_f64() * 1_000_000.0
    }

    pub fn p99_micros(&self) -> f64 {
        self.p99.as_secs_f64() * 1_000_000.0
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("unknown module `{0}`")]
    UnknownModule(String),
    #[error("invalid module name `{0}`")]
    BadName(String),
    #[error("module `{name}` does not export `{export}`")]
    MissingExport { name: String, export: String },
    #[error("out of fuel")]
    OutOfFuel,
    #[error("execution interrupted after {0:?}")]
    Interrupted(Duration),
    #[error("guest trap: {0}")]
    Trap(String),
    #[error("{0}")]
    Engine(String),
}

struct SandboxEngine {
    engine: Engine,
    linker: Linker<GuestState>,
    modules: RwLock<HashMap<String, Module>>,
    stop: Arc<AtomicBool>,
    watchdog: Mutex<Option<JoinHandle<()>>>,
    fueled: bool,
}

impl SandboxEngine {
    fn new(fueled: bool) -> Result<Self, SandboxError> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.consume_fuel(fueled);
        config.max_wasm_stack(512 * 1024);
        let engine = Engine::new(&config).map_err(|err| SandboxError::Engine(err.to_string()))?;
        let linker = host::link(&engine).map_err(|err| SandboxError::Engine(err.to_string()))?;
        let stop = Arc::new(AtomicBool::new(false));
        let watchdog = spawn_watchdog(engine.clone(), Arc::clone(&stop));
        Ok(Self {
            engine,
            linker,
            modules: RwLock::new(HashMap::new()),
            stop,
            watchdog: Mutex::new(Some(watchdog)),
            fueled,
        })
    }

    fn load(&self, name: &str, bytes: &[u8]) -> Result<(), SandboxError> {
        let module = Module::new(&self.engine, bytes)
            .map_err(|err| SandboxError::Engine(err.to_string()))?;
        self.modules
            .write()
            .unwrap()
            .insert(name.to_string(), module);
        Ok(())
    }

    fn invoke(
        &self,
        name: &str,
        input: &[u8],
        limits: &Limits,
    ) -> Result<InvokeResult, SandboxError> {
        let started = Instant::now();
        let module = self
            .modules
            .read()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| SandboxError::UnknownModule(name.to_string()))?;
        let state = GuestState {
            limits: StoreLimitsBuilder::new()
                .memory_size(limits.max_memory_bytes)
                .instances(8)
                .memories(4)
                .tables(8)
                .table_elements(1024)
                .trap_on_grow_failure(true)
                .build(),
            input: input.to_vec(),
            output: Vec::new(),
            max_output: limits.max_output_bytes,
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        let budget = limits.fuel;
        if let Some(fuel) = budget {
            store
                .set_fuel(fuel)
                .map_err(|err| SandboxError::Engine(err.to_string()))?;
        }
        let ticks = match limits.timeout {
            Some(timeout) => timeout.as_millis().max(1) as u64,
            None => u64::MAX / 4,
        };
        store.set_epoch_deadline(ticks);

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(|err| SandboxError::Engine(err.to_string()))?;
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "run")
            .map_err(|_| SandboxError::MissingExport {
                name: name.to_string(),
                export: "run".to_string(),
            })?;

        let call = func.call(&mut store, ());
        let elapsed = started.elapsed();
        let fuel_consumed = if self.fueled {
            let remaining = store.get_fuel().unwrap_or(0);
            Some(budget.unwrap_or(0).saturating_sub(remaining))
        } else {
            None
        };
        match call {
            Ok(exit_code) => Ok(InvokeResult {
                exit_code,
                output: store.data().output.clone(),
                fuel_consumed,
                elapsed,
            }),
            Err(err) => Err(classify(err, elapsed)),
        }
    }
}

impl Drop for SandboxEngine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.watchdog.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

fn spawn_watchdog(engine: Engine, stop: Arc<AtomicBool>) -> JoinHandle<()> {
    thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            thread::park_timeout(Duration::from_millis(1));
            if stop.load(Ordering::Relaxed) {
                break;
            }
            engine.increment_epoch();
        }
    })
}

fn classify(err: wasmtime::Error, elapsed: Duration) -> SandboxError {
    // Alternate formatting walks the source chain, which is where a host
    // function's `bail!` message shows up.
    let rendered = format!("{err:#}");
    match err.downcast_ref::<Trap>() {
        Some(trap) if *trap == Trap::OutOfFuel => SandboxError::OutOfFuel,
        Some(trap) if *trap == Trap::Interrupt => SandboxError::Interrupted(elapsed),
        Some(_) | None => SandboxError::Trap(rendered),
    }
}

/// Compiled tool modules and the engines that run them.
pub struct Sandbox {
    plain: SandboxEngine,
    fueled: Mutex<Option<SandboxEngine>>,
    sources: RwLock<HashMap<String, Vec<u8>>>,
}

impl Sandbox {
    pub fn new() -> Result<Self, SandboxError> {
        let plain = SandboxEngine::new(false)?;
        let sandbox = Self {
            plain,
            fueled: Mutex::new(None),
            sources: RwLock::new(HashMap::new()),
        };
        sandbox.load("nop", include_str!("../../../examples/nop.wat").as_bytes())?;
        sandbox.load(
            "echo",
            include_str!("../../../examples/echo.wat").as_bytes(),
        )?;
        Ok(sandbox)
    }

    pub fn load(&self, name: &str, bytes: &[u8]) -> Result<(), SandboxError> {
        validate_name(name)?;
        self.plain.load(name, bytes)?;
        self.sources
            .write()
            .unwrap()
            .insert(name.to_string(), bytes.to_vec());
        if let Some(engine) = self.fueled.lock().unwrap().as_ref() {
            engine.load(name, bytes)?;
        }
        Ok(())
    }

    pub fn invoke(
        &self,
        name: &str,
        input: &[u8],
        limits: Limits,
    ) -> Result<InvokeResult, SandboxError> {
        if limits.fuel.is_some() {
            self.invoke_fueled(name, input, &limits)
        } else {
            self.plain.invoke(name, input, &limits)
        }
    }

    pub fn measure_isolation(
        &self,
        iterations: u32,
        warmup: u32,
    ) -> Result<LatencyStats, SandboxError> {
        self.measure("nop", b"", iterations, warmup)
    }

    /// Time full invocations: module lookup, a fresh store, instantiation, and the call.
    pub fn measure(
        &self,
        module: &str,
        input: &[u8],
        iterations: u32,
        warmup: u32,
    ) -> Result<LatencyStats, SandboxError> {
        let limits = Limits {
            timeout: Some(Duration::from_secs(2)),
            fuel: None,
            ..Limits::default()
        };
        for _ in 0..warmup {
            let result = self.invoke(module, input, limits.clone())?;
            std::hint::black_box(result.exit_code);
        }
        let mut samples = Vec::with_capacity(iterations as usize);
        for _ in 0..iterations {
            let result = self.invoke(module, input, limits.clone())?;
            std::hint::black_box(result.exit_code);
            samples.push(result.elapsed.as_nanos());
        }
        if samples.is_empty() {
            return Err(SandboxError::Engine("isolation sample set is empty".into()));
        }
        samples.sort_unstable();
        let total: u128 = samples.iter().sum();
        let mean = Duration::from_nanos((total / samples.len() as u128) as u64);
        Ok(LatencyStats {
            iterations,
            mean,
            p50: percentile(&samples, 0.50),
            p99: percentile(&samples, 0.99),
            min: Duration::from_nanos(samples[0] as u64),
            max: Duration::from_nanos(*samples.last().unwrap() as u64),
        })
    }

    fn invoke_fueled(
        &self,
        name: &str,
        input: &[u8],
        limits: &Limits,
    ) -> Result<InvokeResult, SandboxError> {
        let mut slot = self.fueled.lock().unwrap();
        if slot.is_none() {
            let engine = SandboxEngine::new(true)?;
            let sources = self.sources.read().unwrap().clone();
            for (module_name, bytes) in &sources {
                engine.load(module_name, bytes)?;
            }
            *slot = Some(engine);
        }
        slot.as_ref().unwrap().invoke(name, input, limits)
    }
}

fn percentile(sorted: &[u128], p: f64) -> Duration {
    let rank = ((sorted.len() as f64) * p).ceil() as usize;
    let index = rank.saturating_sub(1).min(sorted.len() - 1);
    Duration::from_nanos(sorted[index] as u64)
}

fn validate_name(name: &str) -> Result<(), SandboxError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-');
    if ok {
        Ok(())
    } else {
        Err(SandboxError::BadName(name.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn echo_round_trip() {
        let sandbox = Sandbox::new().unwrap();
        let result = sandbox
            .invoke("echo", b"hello aegis", Limits::default())
            .unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.output, b"hello aegis");
    }

    #[test]
    fn fresh_store_does_not_keep_previous_output() {
        let sandbox = Sandbox::new().unwrap();
        sandbox.invoke("echo", b"one", Limits::default()).unwrap();
        let result = sandbox.invoke("echo", b"two", Limits::default()).unwrap();
        assert_eq!(result.output, b"two");
    }

    #[test]
    fn output_limit_traps() {
        let sandbox = Sandbox::new().unwrap();
        let wat = r#"
            (module
              (import "aegis" "write_output" (func $w (param i32 i32)))
              (memory (export "memory") 1)
              (func (export "run") (result i32)
                (call $w (i32.const 0) (i32.const 64))
                i32.const 0))
        "#;
        sandbox.load("chatty", wat.as_bytes()).unwrap();
        let err = sandbox
            .invoke(
                "chatty",
                b"",
                Limits {
                    max_output_bytes: 16,
                    ..Limits::default()
                },
            )
            .unwrap_err();
        assert!(
            err.to_string().contains("output"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn memory_grow_past_the_cap_fails() {
        let sandbox = Sandbox::new().unwrap();
        sandbox
            .load(
                "grow",
                include_str!("../../../examples/grow.wat").as_bytes(),
            )
            .unwrap();
        let outcome = sandbox.invoke(
            "grow",
            b"",
            Limits {
                max_memory_bytes: 64 * 1024,
                ..Limits::default()
            },
        );
        match outcome {
            Err(err) => assert!(!err.to_string().is_empty(), "{err}"),
            Ok(result) => assert_eq!(result.exit_code, -1, "memory.grow must be refused"),
        }
    }

    #[test]
    fn fuel_stops_a_busy_loop() {
        let sandbox = Sandbox::new().unwrap();
        sandbox
            .load(
                "loop",
                include_str!("../../../examples/loop.wat").as_bytes(),
            )
            .unwrap();
        let err = sandbox
            .invoke(
                "loop",
                b"",
                Limits {
                    fuel: Some(20_000),
                    timeout: Some(Duration::from_secs(2)),
                    ..Limits::default()
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::OutOfFuel | SandboxError::Interrupted(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn epoch_interrupts_a_loop_without_fuel() {
        let sandbox = Sandbox::new().unwrap();
        sandbox
            .load(
                "loop",
                include_str!("../../../examples/loop.wat").as_bytes(),
            )
            .unwrap();
        let err = sandbox
            .invoke(
                "loop",
                b"",
                Limits {
                    fuel: None,
                    timeout: Some(Duration::from_millis(200)),
                    ..Limits::default()
                },
            )
            .unwrap_err();
        assert!(
            matches!(err, SandboxError::Interrupted(_)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn fib_completes_with_enough_fuel() {
        let sandbox = Sandbox::new().unwrap();
        sandbox
            .load("fib", include_str!("../../../examples/fib.wat").as_bytes())
            .unwrap();
        let result = sandbox
            .invoke(
                "fib",
                b"",
                Limits {
                    fuel: Some(50_000_000),
                    ..Limits::default()
                },
            )
            .unwrap();
        // fib(12) = 144
        assert_eq!(result.exit_code, 144);
        assert!(result.fuel_consumed.unwrap() > 0);
    }

    #[test]
    fn concurrent_invocations_stay_isolated() {
        let sandbox = Arc::new(Sandbox::new().unwrap());
        let mut handles = Vec::new();
        for index in 0..8 {
            let sandbox = Arc::clone(&sandbox);
            handles.push(thread::spawn(move || {
                let input = format!("t{index}");
                let result = sandbox
                    .invoke("echo", input.as_bytes(), Limits::default())
                    .unwrap();
                assert_eq!(result.output, input.as_bytes());
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
    }

    #[test]
    fn isolation_path_stays_under_a_generous_bound() {
        let sandbox = Sandbox::new().unwrap();
        let stats = sandbox.measure_isolation(40, 10).unwrap();
        assert!(
            stats.p50.as_millis() < 100,
            "p50 isolation {} ms",
            stats.p50.as_millis()
        );
    }
}
