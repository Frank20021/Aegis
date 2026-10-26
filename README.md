# Aegis

Aegis runs tools for multi-agent workflows inside a Wasmtime sandbox. Each call gets a fresh store, a memory cap, and either a fuel budget or an epoch deadline. On Linux the worker installs a seccomp-BPF filter after modules are compiled, so a native escape is limited to a short syscall allowlist. Tool outputs can be handed off through a shared-memory ring. A Python control plane admits agent contexts against a vLLM-shaped token budget, mirrors warm state into Letta memory blocks, can place agents in Ray Core actors, and writes a hash-chained trace that replay and audit can read back.

## Layout

| Path | Role |
| --- | --- |
| `crates/aegis-sandbox` | Wasmtime engine, per-invoke store, fuel, epoch deadlines, memory cap |
| `crates/aegis-seccomp` | Default-deny BPF profile, checked by an in-process interpreter |
| `crates/aegis-shm` | Single-producer single-consumer shared-memory ring |
| `crates/aegis-runtime` | `aegis` CLI: `invoke`, `bench`, `worker`, `seccomp` |
| `python/aegis` | Memory tiers, Ray or local scheduling, vLLM and Letta clients, DSPy callback, trace, replay |

## Tool ABI

A tool exports `run() -> i32`. Tools that read input or write output also export a memory named `memory` and import:

- `aegis.input_len() -> i32`
- `aegis.read_input(ptr, len) -> i32`
- `aegis.write_output(ptr, len)`

There is no WASI. Guests do not get files, sockets, clocks, or the process environment through this ABI. `examples/echo.wat` is the reference module. `nop` and `echo` are built into the worker.

## Build

Rust stable and Python 3.10+ are required. The tests use Python 3.12.

```sh
make test
make bench
make demo
```

`make bench` and `make demo` build the release binary. Release is the configuration the latency numbers refer to; debug builds spend much longer in store setup.

The worker speaks newline-delimited JSON on stdin and stdout:

```json
{"op":"invoke","name":"echo","input":"hello"}
{"op":"ring-open","path":"/tmp/aegis.ring","capacity":1024,"payload":4096}
{"op":"invoke","name":"echo","input":"hello","ring":true}
{"op":"load","name":"custom","wat":"(module ...)"}
{"op":"secure"}
{"op":"bench-isolation","iterations":300,"warmup":40}
```

`secure` installs the seccomp filter. On macOS it returns an error and leaves the worker unrestricted, because seccomp-BPF is a Linux kernel feature. Load modules and open the ring before `secure`; both need system calls the filter denies.

## seccomp

The profile is default-deny. Runtime calls used by a compiled Wasmtime instance stay allowed: mapping memory, futexes, clocks, signals, and stdio. Calls that create a socket, a new executable image, or a trace relationship kill the process (`execve`, `execveat`, `socket`, `connect`, `ptrace`, `bpf`, `clone`, `clone3`, `openat`, and the rest of `DENY_KILL` in `crates/aegis-seccomp`). Any other syscall fails with `EPERM`.

`aegis seccomp profile` prints the numbers for this machine. `aegis seccomp self-test` forks, compiles a nop module, installs the filter, runs it, then calls `socket`. The child should be killed with `SIGSYS`, or see `EPERM` if the deny action is changed. Tests on every platform run the same BPF program in an interpreter and check that `read` is allowed, `socket` kills, and a wrong architecture kills.

## Memory and scheduling

`ModelBudget` combines three limits:

- `max_model_len`, the longest context one agent may hold. `VllmClient` reads this from `GET /v1/models` when a vLLM server is up.
- `kv_token_budget`, how many tokens can stay resident at once.
- `max_num_seqs`, vLLM's concurrent-sequence cap.

The tested configuration is `max_model_len=8192`, `kv_token_budget=64*4096`, `max_num_seqs=64`. That admits 64 agents with a 4096-token window and zero evictions. Admitting a 65th agent writes the least-recently-used full context to a cold JSONL file, stores a 240-character extract in a Letta `summary` block, and keeps the hot token count on the budget.

`LettaClient` talks to a Letta server (`PATCH /v1/agents/{id}/core-memory/blocks/{label}`, `POST /v1/agents/{id}/archival-memory`). `LocalLettaStore` implements the same methods on disk for machines without a server. `LocalDeterministicLM` stands in for `VllmClient.complete` when no GPU is attached; both record the sampling seed.

`AgentRuntime("local")` runs agents in-process. `AgentRuntime("ray")` puts each agent in a Ray Core actor. Ray and DSPy are optional (`pip install -e 'python[agents]'` from a checkout, or install `ray` and `dspy`). `dspy_callback` adapts DSPy's `BaseCallback` so LM seeds and tool calls land in the same session log.

## Trace, replay, audit

A session file is a JSONL hash chain. Each record stores the previous digest and `sha256(prev + canonical_json(event))`. Events are `sample` (seed, model, prompt hash), `tool_call` (name, arguments), and `tool_output` (bytes the tool returned, fuel used when the call was metered).

`replay` walks that chain. With an executor it runs each tool again and compares the output to the recorded one. `explain_call` returns the tool, the arguments, the recorded output, and the sampling seed that preceded the call. `analyze` reports the timestamp span and the tool sequence. A log whose first and last events are 48 hours apart is read by the same code as a short run; the suite builds that span and checks the sequence comes back in order. Tampering with a record breaks `verify_chain`.

## Benchmarks

`aegis bench isolation` times a warm engine doing a full invocation: module lookup, a fresh store, instantiation, and the call. `isolation-nop` is an empty module. `isolation-echo` copies a short input through the host ABI. The target for the mean is under 380 µs.

`aegis bench throughput` pushes 256-byte messages from one thread to another through the ring. The target is more than 2,100 messages per second.

Both commands print `within_target=true` or `false` from the measurement. They do not hard-code a result.

On this machine (Apple Silicon, macOS, `cargo build --release`) the release bench reported:

| Measurement | Result |
| --- | --- |
| `isolation-nop` mean / p50 / p99 | 1.24 µs / 1.21 µs / 1.50 µs |
| `isolation-echo` mean / p50 / p99 | 8.52 µs / 7.92 µs / 18.96 µs |
| Ring throughput, 200,000 messages of 256 bytes | about 5.58 million messages/second |

Debug builds are slower. Re-run `make bench` after a release build to record the numbers for the machine in front of you.

## What is trusted

The control plane and the worker process are trusted. Guest Wasm is not. The sandbox boundary is a fresh Wasmtime store plus the host ABI above. seccomp is a second boundary on Linux, applied to the worker after compilation so Cranelift can still emit code. The ring is a transport for tool results, not an isolation boundary between agents.
