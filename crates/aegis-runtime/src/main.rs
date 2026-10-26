mod bench;
mod worker;

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use aegis_sandbox::{Limits, Sandbox};
use aegis_seccomp::{self, Arch};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "aegis", version, about = "Sandboxed multi-agent runtime")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run one tool module and print its output.
    Invoke {
        #[arg(long, default_value = "echo")]
        name: String,
        #[arg(long)]
        input: Option<String>,
        #[arg(long)]
        wat_file: Option<PathBuf>,
        #[arg(long)]
        fuel: Option<u64>,
        #[arg(long, default_value_t = 5000)]
        timeout_ms: u64,
    },
    /// Measure store-isolation latency and shared-memory throughput.
    Bench {
        #[command(subcommand)]
        which: BenchCmd,
    },
    /// Serve newline-delimited JSON requests on stdin.
    Worker,
    /// Show or install the seccomp-BPF profile.
    Seccomp {
        #[command(subcommand)]
        action: SeccompCmd,
    },
    /// Print the shared-memory ring layout constants.
    ShmSpec,
}

#[derive(Subcommand)]
enum BenchCmd {
    Isolation {
        #[arg(long, default_value_t = 2000)]
        iterations: u32,
        #[arg(long, default_value_t = 200)]
        warmup: u32,
    },
    Throughput {
        #[arg(long, default_value_t = 200_000)]
        count: u64,
        #[arg(long, default_value_t = 256)]
        payload: usize,
    },
    All {
        #[arg(long, default_value_t = 2000)]
        iterations: u32,
        #[arg(long, default_value_t = 200)]
        warmup: u32,
        #[arg(long, default_value_t = 200_000)]
        count: u64,
    },
}

#[derive(Subcommand)]
enum SeccompCmd {
    /// Print the allowlist and the kill list for this machine's architecture.
    Profile,
    /// Apply the filter in a child process and check that `socket` is blocked.
    SelfTest,
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Command::Invoke {
            name,
            input,
            wat_file,
            fuel,
            timeout_ms,
        } => invoke(name, input, wat_file, fuel, timeout_ms),
        Command::Bench { which } => bench::run(which_to_request(which)),
        Command::Worker => worker::serve(),
        Command::Seccomp { action } => seccomp_cmd(action),
        Command::ShmSpec => {
            println!("{}", worker::shm_spec_json());
            Ok(())
        }
    }
}

fn which_to_request(which: BenchCmd) -> bench::BenchRequest {
    match which {
        BenchCmd::Isolation { iterations, warmup } => {
            bench::BenchRequest::Isolation { iterations, warmup }
        }
        BenchCmd::Throughput { count, payload } => {
            bench::BenchRequest::Throughput { count, payload }
        }
        BenchCmd::All {
            iterations,
            warmup,
            count,
        } => bench::BenchRequest::All {
            iterations,
            warmup,
            count,
            payload: 256,
        },
    }
}

fn invoke(
    name: String,
    input: Option<String>,
    wat_file: Option<PathBuf>,
    fuel: Option<u64>,
    timeout_ms: u64,
) -> Result<()> {
    let sandbox = Sandbox::new()?;
    if let Some(path) = wat_file {
        let wat = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        sandbox.load(&name, &wat)?;
    }
    let timeout = if timeout_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(timeout_ms))
    };
    let result = sandbox.invoke(
        &name,
        input.unwrap_or_default().as_bytes(),
        Limits {
            fuel,
            timeout,
            ..Limits::default()
        },
    )?;
    println!(
        "exit={} elapsed_us={} fuel={:?} output={}",
        result.exit_code,
        result.elapsed.as_micros(),
        result.fuel_consumed,
        String::from_utf8_lossy(&result.output)
    );
    Ok(())
}

fn seccomp_cmd(action: SeccompCmd) -> Result<()> {
    match action {
        SeccompCmd::Profile => {
            let arch = Arch::native().context("no seccomp architecture for this process")?;
            println!("{}", aegis_seccomp::profile_json(arch)?);
            Ok(())
        }
        SeccompCmd::SelfTest => worker::seccomp_self_test(),
    }
}
