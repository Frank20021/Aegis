use wasmtime::{bail, format_err, Caller, Extern, Linker, Memory};

use crate::GuestState;

pub fn link(engine: &wasmtime::Engine) -> wasmtime::Result<Linker<GuestState>> {
    let mut linker = Linker::new(engine);
    linker.func_wrap("aegis", "input_len", input_len)?;
    linker.func_wrap("aegis", "read_input", read_input)?;
    linker.func_wrap("aegis", "write_output", write_output)?;
    Ok(linker)
}

fn input_len(caller: Caller<'_, GuestState>) -> i32 {
    caller.data().input.len().min(i32::MAX as usize) as i32
}

fn read_input(mut caller: Caller<'_, GuestState>, ptr: i32, len: i32) -> wasmtime::Result<i32> {
    if ptr < 0 || len < 0 {
        bail!("negative pointer or length");
    }
    let ptr = ptr as usize;
    let len = len as usize;
    if len > crate::MAX_COPY {
        bail!("read length exceeds 1 MiB");
    }
    let n = len.min(caller.data().input.len());
    let buf = caller.data().input[..n].to_vec();
    let memory = guest_memory(&mut caller)?;
    memory
        .write(&mut caller, ptr, &buf)
        .map_err(|err| format_err!("{err}"))?;
    Ok(n as i32)
}

fn write_output(mut caller: Caller<'_, GuestState>, ptr: i32, len: i32) -> wasmtime::Result<()> {
    if ptr < 0 || len < 0 {
        bail!("negative pointer or length");
    }
    let ptr = ptr as usize;
    let len = len as usize;
    let max_output = caller.data().max_output;
    let current = caller.data().output.len();
    if len > max_output || current.saturating_add(len) > max_output {
        bail!("output limit exceeded");
    }
    let memory = guest_memory(&mut caller)?;
    let mut buf = vec![0u8; len];
    memory
        .read(&caller, ptr, &mut buf)
        .map_err(|err| format_err!("{err}"))?;
    caller.data_mut().output.extend_from_slice(&buf);
    Ok(())
}

fn guest_memory(caller: &mut Caller<'_, GuestState>) -> wasmtime::Result<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(memory)) => Ok(memory),
        _ => bail!("module must export a memory named \"memory\""),
    }
}
