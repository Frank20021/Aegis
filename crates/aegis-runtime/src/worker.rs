use std::io::{self, BufRead, Write};
use std::time::Duration;

use aegis_sandbox::{Limits, Sandbox, SandboxError};
use aegis_shm::{self, Ring};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

pub fn shm_spec_json() -> String {
    json!({
        "magic": aegis_shm::MAGIC,
        "version": aegis_shm::VERSION,
        "header_size": aegis_shm::HEADER_SIZE,
        "write_seq_offset": aegis_shm::WRITE_SEQ_OFFSET,
        "read_seq_offset": aegis_shm::READ_SEQ_OFFSET,
        "slot_seq_offset": aegis_shm::SLOT_SEQ_OFFSET,
        "slot_len_offset": aegis_shm::SLOT_LEN_OFFSET,
        "slot_crc_offset": aegis_shm::SLOT_CRC_OFFSET,
        "slot_payload_offset": aegis_shm::SLOT_PAYLOAD_OFFSET,
    })
    .to_string()
}

pub fn serve() -> Result<()> {
    let sandbox = Sandbox::new()?;
    let stdin = io::stdin();
    let mut lines = stdin.lock();
    let mut line = String::new();
    let mut ring: Option<Ring> = None;
    let mut secured = false;
    loop {
        line.clear();
        let read = lines.read_line(&mut line)?;
        if read == 0 {
            break;
        }
        if line.trim().is_empty() {
            continue;
        }
        let response = handle_line(&sandbox, &mut ring, &mut secured, line.trim());
        let mut stdout = io::stdout().lock();
        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}

fn handle_line(
    sandbox: &Sandbox,
    ring: &mut Option<Ring>,
    secured: &mut bool,
    line: &str,
) -> String {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(err) => {
            return json!({"ok": false, "error": format!("invalid json: {err}")}).to_string()
        }
    };
    let id = value.get("id").cloned().unwrap_or(Value::Null);
    match dispatch(sandbox, ring, secured, &value) {
        Ok(mut body) => {
            body["id"] = id;
            body["ok"] = Value::Bool(true);
            body.to_string()
        }
        Err(err) => json!({
            "id": id,
            "ok": false,
            "kind": err.kind,
            "error": err.message,
        })
        .to_string(),
    }
}

struct WorkerError {
    kind: &'static str,
    message: String,
}

fn dispatch(
    sandbox: &Sandbox,
    ring: &mut Option<Ring>,
    secured: &mut bool,
    value: &Value,
) -> Result<Value, WorkerError> {
    let op = value
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| worker_err("bad_request", "missing op"))?;
    match op {
        "load" => {
            if *secured {
                return Err(worker_err(
                    "secured",
                    "modules must be loaded before the seccomp filter is installed",
                ));
            }
            let name = required_str(value, "name")?;
            let wat = required_str(value, "wat")?;
            if wat.len() > 256 * 1024 {
                return Err(worker_err("bad_request", "module text exceeds 256 KiB"));
            }
            sandbox.load(name, wat.as_bytes()).map_err(sandbox_err)?;
            Ok(json!({"name": name}))
        }
        "invoke" => {
            let name = required_str(value, "name")?;
            let input = decode_input(value)?;
            let fuel = value.get("fuel").and_then(Value::as_u64);
            let timeout = match value.get("timeout_ms") {
                Some(Value::Number(number)) if number.as_u64() == Some(0) => None,
                Some(Value::Number(number)) => {
                    Some(Duration::from_millis(number.as_u64().unwrap_or(5_000)))
                }
                _ => Some(Duration::from_millis(5_000)),
            };
            let max_output = value
                .get("max_output")
                .and_then(Value::as_u64)
                .unwrap_or(1024 * 1024) as usize;
            let result = sandbox
                .invoke(
                    name,
                    &input,
                    Limits {
                        fuel,
                        timeout,
                        max_output_bytes: max_output,
                        ..Limits::default()
                    },
                )
                .map_err(sandbox_err)?;
            let mut body = json!({
                "name": name,
                "exit_code": result.exit_code,
                "elapsed_us": result.elapsed.as_micros() as u64,
                "fuel_consumed": result.fuel_consumed,
                "output_b64": STANDARD.encode(&result.output),
            });
            if value.get("ring").and_then(Value::as_bool).unwrap_or(false) {
                let attached = ring.as_ref().ok_or_else(|| {
                    worker_err("bad_request", "no shared-memory ring is attached")
                })?;
                let seq = attached.push(&result.output).map_err(|err| WorkerError {
                    kind: "ring",
                    message: err.to_string(),
                })?;
                body["ring_seq"] = json!(seq);
            }
            Ok(body)
        }
        "ring-open" => {
            if *secured {
                return Err(worker_err(
                    "secured",
                    "open the ring before installing the seccomp filter",
                ));
            }
            let path = required_str(value, "path")?;
            let capacity = required_u32(value, "capacity")?;
            let payload = required_u32(value, "payload")?;
            *ring = Some(
                Ring::create(path, capacity, payload).map_err(|err| WorkerError {
                    kind: "ring",
                    message: err.to_string(),
                })?,
            );
            Ok(json!({"path": path, "capacity": capacity, "payload": payload}))
        }
        "secure" => match aegis_seccomp::install_native() {
            Ok(()) => {
                *secured = true;
                Ok(json!({"seccomp": "installed"}))
            }
            Err(err) => Err(WorkerError {
                kind: "unsupported",
                message: err.to_string(),
            }),
        },
        "bench-isolation" => {
            let iterations = value
                .get("iterations")
                .and_then(Value::as_u64)
                .unwrap_or(200) as u32;
            let warmup = value.get("warmup").and_then(Value::as_u64).unwrap_or(20) as u32;
            let stats = sandbox
                .measure_isolation(iterations, warmup)
                .map_err(sandbox_err)?;
            Ok(json!({
                "iterations": stats.iterations,
                "mean_us": stats.mean_micros(),
                "p50_us": stats.p50_micros(),
                "p99_us": stats.p99_micros(),
                "target_us": 380.0,
                "within_target": stats.mean_micros() < 380.0,
            }))
        }
        "shm-spec" => Ok(serde_json::from_str(&shm_spec_json()).unwrap()),
        other => Err(worker_err("bad_request", format!("unknown op {other}"))),
    }
}

fn decode_input(value: &Value) -> Result<Vec<u8>, WorkerError> {
    if let Some(text) = value.get("input").and_then(Value::as_str) {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(encoded) = value.get("input_b64").and_then(Value::as_str) {
        return STANDARD
            .decode(encoded)
            .map_err(|err| worker_err("bad_request", err.to_string()));
    }
    Ok(Vec::new())
}

fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, WorkerError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| worker_err("bad_request", format!("missing {key}")))
}

fn required_u32(value: &Value, key: &str) -> Result<u32, WorkerError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| worker_err("bad_request", format!("missing {key}")))
}

fn sandbox_err(err: SandboxError) -> WorkerError {
    let kind = match &err {
        SandboxError::OutOfFuel => "out_of_fuel",
        SandboxError::Interrupted(_) => "interrupted",
        SandboxError::UnknownModule(_) => "unknown_module",
        SandboxError::BadName(_) => "bad_request",
        SandboxError::MissingExport { .. } => "missing_export",
        SandboxError::Trap(_) | SandboxError::Engine(_) => "trap",
    };
    WorkerError {
        kind,
        message: err.to_string(),
    }
}

fn worker_err(kind: &'static str, message: impl Into<String>) -> WorkerError {
    WorkerError {
        kind,
        message: message.into(),
    }
}

pub fn seccomp_self_test() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        println!("seccomp self-test skipped: seccomp-bpf is a Linux kernel feature");
        println!("status=skipped");
        Ok(())
    }
    #[cfg(target_os = "linux")]
    {
        linux_seccomp_self_test()
    }
}

#[cfg(target_os = "linux")]
fn linux_seccomp_self_test() -> Result<()> {
    let mut fds = [0i32; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc != 0 {
        anyhow::bail!("pipe: {}", std::io::Error::last_os_error());
    }
    let read_fd = fds[0];
    let write_fd = fds[1];
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        anyhow::bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { libc::close(read_fd) };
        child_seccomp(write_fd);
    }
    unsafe { libc::close(write_fd) };
    let mut status = 0i32;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited < 0 {
        anyhow::bail!("waitpid: {}", std::io::Error::last_os_error());
    }
    let mut buf = [0u8; 512];
    let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
    unsafe { libc::close(read_fd) };
    let output = if n > 0 {
        String::from_utf8_lossy(&buf[..n as usize]).to_string()
    } else {
        String::new()
    };
    let signaled = unsafe { libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS };
    let exited_ok = unsafe { libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 };
    let socket_blocked = signaled || (exited_ok && output.contains("eperm"));
    println!("child_output={}", output.trim());
    println!("socket_blocked={socket_blocked}");
    if output.contains("ok") && socket_blocked && !output.contains("socket\n") {
        println!("status=pass");
        Ok(())
    } else {
        anyhow::bail!("seccomp self-test failed: {output:?} status={status}");
    }
}

#[cfg(target_os = "linux")]
fn child_seccomp(write_fd: i32) -> ! {
    let write_all = |bytes: &[u8]| unsafe {
        libc::write(write_fd, bytes.as_ptr().cast(), bytes.len());
    };
    let sandbox = match Sandbox::new() {
        Ok(sandbox) => sandbox,
        Err(err) => {
            write_all(format!("engine-fail {err}\n").as_bytes());
            unsafe { libc::_exit(5) }
        }
    };
    if let Err(err) = aegis_seccomp::install_native() {
        write_all(format!("install-fail {err}\n").as_bytes());
        unsafe { libc::_exit(4) }
    }
    match sandbox.invoke(
        "nop",
        b"",
        Limits {
            timeout: Some(Duration::from_secs(2)),
            fuel: None,
            ..Limits::default()
        },
    ) {
        Ok(_) => write_all(b"ok\n"),
        Err(err) => {
            write_all(format!("invoke-fail {err}\n").as_bytes());
            unsafe { libc::_exit(3) }
        }
    }
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if sock >= 0 {
        write_all(b"socket\n");
        unsafe { libc::_exit(2) }
    }
    write_all(b"eperm\n");
    unsafe { libc::_exit(0) }
}
