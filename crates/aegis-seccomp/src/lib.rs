//! Default-deny seccomp-BPF profile for a Wasmtime worker.
//!
//! The filter is built on every platform and checked by an in-process BPF
//! interpreter. Installing it (`prctl` / `seccomp`) is Linux-only. The worker
//! compiles modules first, then installs the filter, so a later native escape
//! from a guest is limited to the allowlist below.
//!
//! Denied calls that grant a new address space, a socket, or a trace relationship
//! kill the process. Anything else that is not on the allowlist fails with
//! `EPERM`.

use std::fmt::Write as _;

use thiserror::Error;

pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EPERM: u32 = 1;

const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARCH: u32 = 4;

/// Names the worker may use after the filter is installed.
pub const ALLOW: &[&str] = &[
    "read",
    "write",
    "close",
    "fstat",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "mremap",
    "madvise",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "ioctl",
    "fcntl",
    "dup",
    "dup3",
    "pipe2",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "sched_yield",
    "nanosleep",
    "clock_gettime",
    "clock_nanosleep",
    "futex",
    "getpid",
    "gettid",
    "getrandom",
    "membarrier",
    "rseq",
    "restart_syscall",
    "exit",
    "exit_group",
    "tgkill",
    "prlimit64",
    "statx",
];

/// Calls that stay unavailable even if a future allowlist edit gets sloppy.
/// These kill the process instead of returning an error.
pub const DENY_KILL: &[&str] = &[
    "execve",
    "execveat",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "mount",
    "umount2",
    "bpf",
    "perf_event_open",
    "kexec_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "unshare",
    "setns",
    "clone",
    "clone3",
    "personality",
    "openat",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn audit_arch(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    pub fn native() -> Option<Self> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(Arch::X86_64)
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(Arch::Aarch64)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            None
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[derive(Debug, Clone)]
pub struct Filter {
    pub arch: Arch,
    pub instructions: Vec<SockFilter>,
}

#[derive(Debug, Error)]
pub enum SeccompError {
    #[error("unknown syscall {name} on {arch:?}")]
    UnknownSyscall { arch: Arch, name: &'static str },
    #[error("seccomp-bpf filters can be installed on Linux only")]
    UnsupportedOs,
    #[error("filter has no native architecture on this process")]
    UnsupportedArch,
    #[error("failed to install seccomp filter: {0}")]
    Install(String),
}

pub fn compile(arch: Arch) -> Result<Filter, SeccompError> {
    let deny: Vec<u32> = DENY_KILL
        .iter()
        .map(|name| lookup(arch, name))
        .collect::<Result<_, _>>()?;
    let allow: Vec<u32> = ALLOW
        .iter()
        .map(|name| lookup(arch, name))
        .collect::<Result<_, _>>()?;

    let mut program = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH),
        // Match: skip the kill. Mismatch: execute it.
        jump(BPF_JMP | BPF_JEQ | BPF_K, arch.audit_arch(), 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR),
    ];

    let first_compare = program.len();
    for _ in deny.iter().chain(allow.iter()) {
        program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 0));
    }
    let errno_idx = program.len();
    program.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
    let kill_idx = program.len();
    program.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    let allow_idx = program.len();
    program.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    for (i, number) in deny.iter().chain(allow.iter()).enumerate() {
        let insn = first_compare + i;
        let target = if i < deny.len() { kill_idx } else { allow_idx };
        let jt = u8::try_from(target - (insn + 1)).expect("seccomp jump offset fits in u8");
        program[insn] = jump(BPF_JMP | BPF_JEQ | BPF_K, *number, jt, 0);
    }
    // errno_idx is reached by falling through the last compare (jf = 0).
    let _ = errno_idx;

    Ok(Filter {
        arch,
        instructions: program,
    })
}

/// Evaluate the filter the way the kernel would for `nr` at `arch`.
pub fn eval(filter: &Filter, nr: u32, arch: u32) -> u32 {
    let mut acc = 0u32;
    let mut pc = 0usize;
    while pc < filter.instructions.len() {
        let insn = &filter.instructions[pc];
        if insn.code == BPF_LD | BPF_W | BPF_ABS {
            acc = match insn.k {
                SECCOMP_DATA_NR => nr,
                SECCOMP_DATA_ARCH => arch,
                _ => 0,
            };
            pc += 1;
        } else if insn.code == BPF_JMP | BPF_JEQ | BPF_K {
            if acc == insn.k {
                pc = pc + 1 + insn.jt as usize;
            } else {
                pc = pc + 1 + insn.jf as usize;
            }
        } else if insn.code == BPF_RET | BPF_K {
            return insn.k;
        } else {
            panic!("unexpected bpf opcode {:#x}", insn.code);
        }
    }
    panic!("seccomp program fell off the end");
}

pub fn decision_name(action: u32) -> &'static str {
    match action & 0xffff_0000 {
        SECCOMP_RET_ALLOW => "allow",
        SECCOMP_RET_KILL_PROCESS => "kill",
        SECCOMP_RET_ERRNO => "errno",
        _ => "other",
    }
}

pub fn profile_json(arch: Arch) -> Result<String, SeccompError> {
    let mut allow = String::new();
    let mut deny = String::new();
    for name in ALLOW {
        let _ = write!(
            &mut allow,
            "{{\"name\":\"{name}\",\"nr\":{}}},",
            lookup(arch, name)?
        );
    }
    allow.pop();
    for name in DENY_KILL {
        let _ = write!(
            &mut deny,
            "{{\"name\":\"{name}\",\"nr\":{}}},",
            lookup(arch, name)?
        );
    }
    deny.pop();
    Ok(format!(
        "{{\"arch\":\"{arch:?}\",\"audit_arch\":{},\"default\":\"errno-eperm\",\"allow\":[{allow}],\"deny_kill\":[{deny}]}}",
        arch.audit_arch()
    ))
}

/// Install the native-architecture filter on this thread group.
///
/// On Linux this sets `NO_NEW_PRIVS` and applies the filter with `TSYNC`.
/// On other kernels it returns [`SeccompError::UnsupportedOs`] without changing
/// the process.
pub fn install_native() -> Result<(), SeccompError> {
    let arch = Arch::native().ok_or(SeccompError::UnsupportedArch)?;
    let filter = compile(arch)?;
    install(&filter)
}

pub fn install(filter: &Filter) -> Result<(), SeccompError> {
    #[cfg(target_os = "linux")]
    {
        install_linux(filter)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = filter;
        Err(SeccompError::UnsupportedOs)
    }
}

#[cfg(target_os = "linux")]
fn install_linux(filter: &Filter) -> Result<(), SeccompError> {
    let mut raw: Vec<libc::sock_filter> = filter
        .instructions
        .iter()
        .map(|insn| libc::sock_filter {
            code: insn.code,
            jt: insn.jt,
            jf: insn.jf,
            k: insn.k,
        })
        .collect();
    let prog = libc::sock_fprog {
        len: raw.len() as libc::c_ushort,
        filter: raw.as_mut_ptr(),
    };
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(SeccompError::Install(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let rc = libc::syscall(
            libc::SYS_seccomp,
            1, // SECCOMP_SET_MODE_FILTER
            1, // SECCOMP_FILTER_FLAG_TSYNC
            &prog as *const libc::sock_fprog,
        );
        if rc != 0 {
            return Err(SeccompError::Install(
                std::io::Error::last_os_error().to_string(),
            ));
        }
    }
    Ok(())
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

fn lookup(arch: Arch, name: &'static str) -> Result<u32, SeccompError> {
    let table: &[(&str, u32)] = match arch {
        Arch::X86_64 => X86_64,
        Arch::Aarch64 => AARCH64,
    };
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
        .ok_or(SeccompError::UnknownSyscall { arch, name })
}

// Numbers from Linux 6.12: arch/x86/entry/syscalls/syscall_64.tbl
// and include/uapi/asm-generic/unistd.h for aarch64.
const X86_64: &[(&str, u32)] = &[
    ("read", 0),
    ("write", 1),
    ("close", 3),
    ("fstat", 5),
    ("lseek", 8),
    ("mmap", 9),
    ("mprotect", 10),
    ("munmap", 11),
    ("brk", 12),
    ("rt_sigaction", 13),
    ("rt_sigprocmask", 14),
    ("rt_sigreturn", 15),
    ("ioctl", 16),
    ("pread64", 17),
    ("pwrite64", 18),
    ("readv", 19),
    ("writev", 20),
    ("sched_yield", 24),
    ("mremap", 25),
    ("madvise", 28),
    ("dup", 32),
    ("nanosleep", 35),
    ("getpid", 39),
    ("socket", 41),
    ("connect", 42),
    ("accept", 43),
    ("bind", 49),
    ("listen", 50),
    ("clone", 56),
    ("execve", 59),
    ("exit", 60),
    ("fcntl", 72),
    ("ptrace", 101),
    ("sigaltstack", 131),
    ("personality", 135),
    ("mount", 165),
    ("umount2", 166),
    ("reboot", 169),
    ("init_module", 175),
    ("delete_module", 176),
    ("gettid", 186),
    ("futex", 202),
    ("restart_syscall", 219),
    ("clock_gettime", 228),
    ("clock_nanosleep", 230),
    ("exit_group", 231),
    ("tgkill", 234),
    ("kexec_load", 246),
    ("openat", 257),
    ("unshare", 272),
    ("accept4", 288),
    ("dup3", 292),
    ("pipe2", 293),
    ("perf_event_open", 298),
    ("prlimit64", 302),
    ("setns", 308),
    ("process_vm_readv", 310),
    ("process_vm_writev", 311),
    ("finit_module", 313),
    ("getrandom", 318),
    ("bpf", 321),
    ("execveat", 322),
    ("membarrier", 324),
    ("statx", 332),
    ("rseq", 334),
    ("clone3", 435),
];

const AARCH64: &[(&str, u32)] = &[
    ("dup", 23),
    ("dup3", 24),
    ("fcntl", 25),
    ("ioctl", 29),
    ("umount2", 39),
    ("mount", 40),
    ("openat", 56),
    ("close", 57),
    ("pipe2", 59),
    ("lseek", 62),
    ("read", 63),
    ("write", 64),
    ("readv", 65),
    ("writev", 66),
    ("pread64", 67),
    ("pwrite64", 68),
    ("fstat", 80),
    ("personality", 92),
    ("exit", 93),
    ("exit_group", 94),
    ("unshare", 97),
    ("futex", 98),
    ("nanosleep", 101),
    ("kexec_load", 104),
    ("init_module", 105),
    ("delete_module", 106),
    ("clock_gettime", 113),
    ("clock_nanosleep", 115),
    ("ptrace", 117),
    ("sched_yield", 124),
    ("restart_syscall", 128),
    ("tgkill", 131),
    ("sigaltstack", 132),
    ("rt_sigaction", 134),
    ("rt_sigprocmask", 135),
    ("rt_sigreturn", 139),
    ("reboot", 142),
    ("getpid", 172),
    ("gettid", 178),
    ("socket", 198),
    ("bind", 200),
    ("listen", 201),
    ("accept", 202),
    ("connect", 203),
    ("brk", 214),
    ("munmap", 215),
    ("mremap", 216),
    ("clone", 220),
    ("execve", 221),
    ("mmap", 222),
    ("mprotect", 226),
    ("madvise", 233),
    ("perf_event_open", 241),
    ("accept4", 242),
    ("prlimit64", 261),
    ("setns", 268),
    ("process_vm_readv", 270),
    ("process_vm_writev", 271),
    ("finit_module", 273),
    ("getrandom", 278),
    ("bpf", 280),
    ("execveat", 281),
    ("membarrier", 283),
    ("statx", 291),
    ("rseq", 293),
    ("clone3", 435),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_allows_runtime_calls_and_kills_escape_calls() {
        for arch in [Arch::X86_64, Arch::Aarch64] {
            let filter = compile(arch).unwrap();
            assert!(filter.instructions.len() < 256);
            let allow_names: std::collections::HashSet<_> = ALLOW.iter().copied().collect();
            let deny_names: std::collections::HashSet<_> = DENY_KILL.iter().copied().collect();
            assert!(allow_names.is_disjoint(&deny_names));

            for name in ALLOW {
                let nr = lookup(arch, name).unwrap();
                assert_eq!(
                    decision_name(eval(&filter, nr, arch.audit_arch())),
                    "allow",
                    "{name} on {arch:?}"
                );
            }
            for name in DENY_KILL {
                let nr = lookup(arch, name).unwrap();
                assert_eq!(
                    decision_name(eval(&filter, nr, arch.audit_arch())),
                    "kill",
                    "{name} on {arch:?}"
                );
            }
            assert_eq!(
                decision_name(eval(&filter, 0x0fff_0000, arch.audit_arch())),
                "errno"
            );
            assert_eq!(
                decision_name(eval(&filter, lookup(arch, "read").unwrap(), 0)),
                "kill"
            );
        }
    }

    #[test]
    fn install_is_unavailable_off_linux() {
        // Never install a filter in-process here: on Linux that would constrain
        // the rest of the test binary. The forked self-test covers installation.
        if !cfg!(target_os = "linux") {
            assert!(matches!(install_native(), Err(SeccompError::UnsupportedOs)));
        }
    }
}
