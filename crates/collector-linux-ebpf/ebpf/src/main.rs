#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    cty::{c_long, c_void},
    helpers::{bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::{HashMap, PerCpuArray, PerfEventByteArray},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use linux_ebpf_shared::{
    ADDR_FAMILY_INET, ADDR_FAMILY_INET6, CAP_SUMMARY_NET_ADMIN, CAP_SUMMARY_SETGID,
    CAP_SUMMARY_SETUID, CAP_SUMMARY_SYS_ADMIN, CAP_SUMMARY_SYS_MODULE, CAP_SUMMARY_SYS_PTRACE,
    CAP_SUMMARY_SYS_RAWIO, COMM_LEN, EVENT_KIND_NET_CONNECT, EVENT_KIND_PRIVILEGE_CHANGE,
    EVENT_KIND_PROCESS_EXIT, EVENT_KIND_PROCESS_START, FILE_OP_CREATE, FILE_OP_OBSERVED,
    FILE_OP_WRITE, ID_NO_CHANGE, IP_LEN, PATH_LEN, PRIV_OP_CAPSET, PRIV_OP_EXEC_COMMIT,
    PRIV_OP_SETEGID, PRIV_OP_SETEUID, PRIV_OP_SETGID, PRIV_OP_SETREGID, PRIV_OP_SETRESGID,
    PRIV_OP_SETRESUID, PRIV_OP_SETREUID, PRIV_OP_SETUID, TrailRawEvent,
};

#[allow(dead_code)]
const O_WRONLY: u32 = 1;
#[allow(dead_code)]
const O_RDWR: u32 = 2;
#[allow(dead_code)]
const O_CREAT: u32 = 0o100;
#[allow(dead_code)]
const O_TRUNC: u32 = 0o1000;
#[allow(dead_code)]
const O_APPEND: u32 = 0o2000;
const EINPROGRESS: i32 = 115;
const TRACEPOINT_SYSCALL_ARGS_OFFSET: usize = 16;
const TRACEPOINT_SYSCALL_RETVAL_OFFSET: usize = 16;

#[repr(C)]
struct ExecPending {
    path: [u8; PATH_LEN],
    uid: u32,
    gid: u32,
}

#[repr(C)]
struct ConnectPending {
    fd: u32,
    family: u16,
    port_be: u16,
    uid: u32,
    gid: u32,
    ip: [u8; IP_LEN],
}

#[repr(C)]
struct PrivPending {
    op: u8,
    reserved: [u8; 3],
    uid: u32,
    gid: u32,
    target_uid: u32,
    target_gid: u32,
}

#[allow(dead_code)]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[repr(C)]
struct SockAddrIn6 {
    sin6_family: u16,
    sin6_port: u16,
    sin6_flowinfo: u32,
    sin6_addr: [u8; 16],
    sin6_scope_id: u32,
}

#[map(name = "EVENTS")]
static EVENTS: PerfEventByteArray = PerfEventByteArray::new(0);

#[map(name = "EVENT_SCRATCH")]
static EVENT_SCRATCH: PerCpuArray<TrailRawEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "PENDING_EXEC")]
static PENDING_EXEC: HashMap<u32, ExecPending> = HashMap::with_max_entries(16_384, 0);

#[map(name = "PENDING_CONNECT")]
static PENDING_CONNECT: HashMap<u32, ConnectPending> = HashMap::with_max_entries(16_384, 0);

#[map(name = "PENDING_PRIV")]
static PENDING_PRIV: HashMap<u32, PrivPending> = HashMap::with_max_entries(16_384, 0);

#[kprobe]
pub fn enter_execve(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_execve(ctx, 0) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_execveat(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_execve(ctx, 1) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match unsafe { try_sched_process_exec(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_sched_process_exit(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn enter_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_connect(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[tracepoint]
pub fn exit_connect(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_connect(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_openat(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe]
pub fn enter_openat2(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe]
pub fn enter_renameat(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe]
pub fn enter_renameat2(ctx: ProbeContext) -> u32 {
    let _ = ctx;
    0
}

#[kprobe]
pub fn enter_setuid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setuid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setuid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_seteuid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_seteuid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_seteuid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setreuid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setreuid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setreuid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setresuid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setresuid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setresuid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setgid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setgid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setgid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setegid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setegid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setegid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setregid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setregid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setregid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_setresgid(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_setresgid(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_setresgid(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kprobe]
pub fn enter_capset(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_capset(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

#[kretprobe]
pub fn exit_capset(ctx: RetProbeContext) -> u32 {
    match unsafe { try_exit_privilege(ctx) } {
        Ok(value) => value,
        Err(_) => 0,
    }
}

unsafe fn try_enter_execve(ctx: ProbeContext, path_arg_index: usize) -> Result<u32, c_long> {
    let path_ptr: *const u8 = ctx.arg(path_arg_index).ok_or(1_i64)?;
    let mut pending = ExecPending {
        path: [0; PATH_LEN],
        uid: ctx.uid(),
        gid: ctx.gid(),
    };
    let _ = unsafe { bpf_probe_read_user_str_bytes(path_ptr, &mut pending.path) }?;
    let pid = ctx.tgid();
    let _ = PENDING_EXEC.insert(&pid, &pending, 0);
    Ok(0)
}

unsafe fn try_sched_process_exec(ctx: TracePointContext) -> Result<u32, c_long> {
    let pid = ctx.tgid();
    let event = unsafe { reserve_event(&ctx, EVENT_KIND_PROCESS_START) }?;
    unsafe {
        (*event).op = PRIV_OP_EXEC_COMMIT;
        (*event).aux_uid = ID_NO_CHANGE;
        (*event).aux_gid = ID_NO_CHANGE;
    }
    if let Some(value) = unsafe { PENDING_EXEC.get(&pid) } {
        unsafe {
            (*event).primary = value.path;
            (*event).aux_uid = value.uid;
            (*event).aux_gid = value.gid;
        }
        let _ = PENDING_EXEC.remove(&pid);
    }
    unsafe { emit_event(&ctx, event) };
    Ok(0)
}

unsafe fn try_sched_process_exit(ctx: TracePointContext) -> Result<u32, c_long> {
    let event = unsafe { reserve_event(&ctx, EVENT_KIND_PROCESS_EXIT) }?;
    unsafe { emit_event(&ctx, event) };
    Ok(0)
}

unsafe fn try_enter_connect(ctx: TracePointContext) -> Result<u32, c_long> {
    let fd = unsafe { read_sys_enter_arg(&ctx, 0) }? as i32;
    let sockaddr_ptr = unsafe { read_sys_enter_arg(&ctx, 1) }? as *const c_void;
    let family = unsafe { bpf_probe_read_user(sockaddr_ptr as *const u16) }?;
    let mut pending = ConnectPending {
        fd: fd as u32,
        family,
        port_be: 0,
        uid: ctx.uid(),
        gid: ctx.gid(),
        ip: [0; IP_LEN],
    };

    match family {
        ADDR_FAMILY_INET => {
            let addr = unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn) }?;
            pending.port_be = addr.sin_port;
            copy_prefix(&mut pending.ip, &addr.sin_addr);
        }
        ADDR_FAMILY_INET6 => {
            let addr = unsafe { bpf_probe_read_user(sockaddr_ptr as *const SockAddrIn6) }?;
            pending.port_be = addr.sin6_port;
            pending.ip = addr.sin6_addr;
        }
        _ => return Ok(0),
    }

    let tid = ctx.pid();
    let _ = PENDING_CONNECT.insert(&tid, &pending, 0);
    Ok(0)
}

unsafe fn try_exit_connect(ctx: TracePointContext) -> Result<u32, c_long> {
    let tid = ctx.pid();
    let retval = unsafe { read_sys_exit_retval(&ctx) }? as i32;
    let Some(pending) = (unsafe { PENDING_CONNECT.get(&tid) }) else {
        return Ok(0);
    };

    if retval == 0 || retval == -EINPROGRESS {
        let event = unsafe { reserve_event(&ctx, EVENT_KIND_NET_CONNECT) }?;
        unsafe {
            (*event).uid = pending.uid;
            (*event).gid = pending.gid;
            (*event).flags = pending.fd;
            (*event).result = retval;
            (*event).family = pending.family;
            (*event).port_be = pending.port_be;
            (*event).ip = pending.ip;
            emit_event(&ctx, event);
        }
    }

    let _ = PENDING_CONNECT.remove(&tid);
    Ok(0)
}

unsafe fn read_sys_enter_arg(ctx: &TracePointContext, index: usize) -> Result<u64, c_long> {
    unsafe {
        ctx.read_at::<u64>(TRACEPOINT_SYSCALL_ARGS_OFFSET + index * core::mem::size_of::<u64>())
    }
}

unsafe fn read_sys_exit_retval(ctx: &TracePointContext) -> Result<i64, c_long> {
    unsafe { ctx.read_at::<i64>(TRACEPOINT_SYSCALL_RETVAL_OFFSET) }
}

#[allow(dead_code)]
unsafe fn try_enter_openat(ctx: ProbeContext) -> Result<u32, c_long> {
    let _ = ctx;
    Ok(0)
}

#[allow(dead_code)]
unsafe fn try_enter_openat2(ctx: ProbeContext) -> Result<u32, c_long> {
    let _ = ctx;
    Ok(0)
}

#[allow(dead_code)]
unsafe fn emit_file_open(ctx: &ProbeContext, path_ptr: *const u8, flags: u32) -> Result<u32, c_long> {
    let _ = (ctx, path_ptr, flags);
    Ok(0)
}

#[allow(dead_code)]
unsafe fn try_enter_renameat(ctx: ProbeContext) -> Result<u32, c_long> {
    let _ = ctx;
    Ok(0)
}

unsafe fn try_enter_setuid(ctx: ProbeContext) -> Result<u32, c_long> {
    let uid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETUID, uid, ID_NO_CHANGE) }
}

unsafe fn try_enter_seteuid(ctx: ProbeContext) -> Result<u32, c_long> {
    let uid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETEUID, uid, ID_NO_CHANGE) }
}

unsafe fn try_enter_setreuid(ctx: ProbeContext) -> Result<u32, c_long> {
    let ruid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    let euid = ctx.arg::<u32>(1).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETREUID, preferred_id(euid, ruid, ID_NO_CHANGE), ID_NO_CHANGE) }
}

unsafe fn try_enter_setresuid(ctx: ProbeContext) -> Result<u32, c_long> {
    let ruid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    let euid = ctx.arg::<u32>(1).ok_or(1_i64)?;
    let suid = ctx.arg::<u32>(2).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETRESUID, preferred_id(euid, ruid, suid), ID_NO_CHANGE) }
}

unsafe fn try_enter_setgid(ctx: ProbeContext) -> Result<u32, c_long> {
    let gid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETGID, ID_NO_CHANGE, gid) }
}

unsafe fn try_enter_setegid(ctx: ProbeContext) -> Result<u32, c_long> {
    let gid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETEGID, ID_NO_CHANGE, gid) }
}

unsafe fn try_enter_setregid(ctx: ProbeContext) -> Result<u32, c_long> {
    let rgid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    let egid = ctx.arg::<u32>(1).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETREGID, ID_NO_CHANGE, preferred_id(egid, rgid, ID_NO_CHANGE)) }
}

unsafe fn try_enter_setresgid(ctx: ProbeContext) -> Result<u32, c_long> {
    let rgid = ctx.arg::<u32>(0).ok_or(1_i64)?;
    let egid = ctx.arg::<u32>(1).ok_or(1_i64)?;
    let sgid = ctx.arg::<u32>(2).ok_or(1_i64)?;
    unsafe { store_priv_pending(&ctx, PRIV_OP_SETRESGID, ID_NO_CHANGE, preferred_id(egid, rgid, sgid)) }
}

unsafe fn try_enter_capset(ctx: ProbeContext) -> Result<u32, c_long> {
    let header_ptr: *const CapUserHeader = ctx.arg(0).ok_or(1_i64)?;
    let data_ptr: *const CapUserData = ctx.arg(1).ok_or(1_i64)?;
    let header = unsafe { bpf_probe_read_user(header_ptr) }?;
    let first = unsafe { bpf_probe_read_user(data_ptr) }?;
    let second = unsafe { bpf_probe_read_user(data_ptr.add(1)) }.unwrap_or(CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    });
    let summary = summarize_capabilities(first, second);
    let target_pid = if header.pid <= 0 {
        ctx.tgid()
    } else {
        header.pid as u32
    };
    unsafe { store_priv_pending(&ctx, PRIV_OP_CAPSET, target_pid, summary) }
}

unsafe fn store_priv_pending(
    ctx: &ProbeContext,
    op: u8,
    target_uid: u32,
    target_gid: u32,
) -> Result<u32, c_long> {
    let tid = ctx.pid();
    let pending = PrivPending {
        op,
        reserved: [0; 3],
        uid: ctx.uid(),
        gid: ctx.gid(),
        target_uid,
        target_gid,
    };
    let _ = PENDING_PRIV.insert(&tid, &pending, 0);
    Ok(0)
}

unsafe fn try_exit_privilege(ctx: RetProbeContext) -> Result<u32, c_long> {
    let tid = ctx.pid();
    let retval = ctx.ret::<i32>().ok_or(1_i64)?;
    let Some(pending) = (unsafe { PENDING_PRIV.get(&tid) }) else {
        return Ok(0);
    };
    if retval == 0 {
        let event = unsafe { reserve_event(&ctx, EVENT_KIND_PRIVILEGE_CHANGE) }?;
        unsafe {
            (*event).op = pending.op;
            (*event).uid = pending.uid;
            (*event).gid = pending.gid;
            if pending.op == PRIV_OP_CAPSET {
                (*event).flags = pending.target_uid;
                (*event).aux_uid = pending.target_gid;
            } else {
                (*event).aux_uid = pending.target_uid;
                (*event).aux_gid = pending.target_gid;
            }
            (*event).result = retval;
            write_priv_name(&mut (*event).primary, pending.op);
            emit_event(&ctx, event);
        }
    }
    let _ = PENDING_PRIV.remove(&tid);
    Ok(0)
}

unsafe fn reserve_event<C: EbpfContext>(ctx: &C, kind: u8) -> Result<*mut TrailRawEvent, c_long> {
    let ptr = EVENT_SCRATCH.get_ptr_mut(0).ok_or(1_i64)?;
    unsafe {
        core::ptr::write_bytes(ptr, 0, 1);
        (*ptr).kind = kind;
        (*ptr).pid = ctx.tgid();
        (*ptr).tid = ctx.pid();
        (*ptr).uid = ctx.uid();
        (*ptr).gid = ctx.gid();
        (*ptr).ts_ns = aya_ebpf::helpers::r#gen::bpf_ktime_get_ns();
        (*ptr).comm = ctx.command().unwrap_or([0; COMM_LEN]);
    }
    Ok(ptr)
}

unsafe fn emit_event<C: EbpfContext>(ctx: &C, event: *const TrailRawEvent) {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            event.cast::<u8>(),
            core::mem::size_of::<TrailRawEvent>(),
        )
    };
    EVENTS.output(ctx, bytes, 0);
}

#[allow(dead_code)]
fn classify_open_flags(flags: u32) -> u8 {
    if flags & O_CREAT != 0 {
        FILE_OP_CREATE
    } else if flags & (O_WRONLY | O_RDWR | O_TRUNC | O_APPEND) != 0 {
        FILE_OP_WRITE
    } else {
        FILE_OP_OBSERVED
    }
}

#[allow(dead_code)]
fn output<C: EbpfContext>(ctx: &C, event: &TrailRawEvent) {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (event as *const TrailRawEvent).cast::<u8>(),
            core::mem::size_of::<TrailRawEvent>(),
        )
    };
    EVENTS.output(ctx, bytes, 0);
}

fn preferred_id(primary: u32, secondary: u32, tertiary: u32) -> u32 {
    if primary != ID_NO_CHANGE {
        primary
    } else if secondary != ID_NO_CHANGE {
        secondary
    } else {
        tertiary
    }
}

fn write_priv_name(target: &mut [u8; PATH_LEN], op: u8) {
    let name: &[u8] = match op {
        PRIV_OP_SETUID => b"setuid",
        PRIV_OP_SETEUID => b"seteuid",
        PRIV_OP_SETREUID => b"setreuid",
        PRIV_OP_SETRESUID => b"setresuid",
        PRIV_OP_SETGID => b"setgid",
        PRIV_OP_SETEGID => b"setegid",
        PRIV_OP_SETREGID => b"setregid",
        PRIV_OP_SETRESGID => b"setresgid",
        PRIV_OP_CAPSET => b"capset",
        _ => b"privilege_change",
    };
    let mut index = 0;
    while index < name.len() && index < PATH_LEN {
        target[index] = name[index];
        index += 1;
    }
}

fn summarize_capabilities(first: CapUserData, second: CapUserData) -> u32 {
    let effective = ((second.effective as u64) << 32) | u64::from(first.effective);
    let permitted = ((second.permitted as u64) << 32) | u64::from(first.permitted);
    let combined = effective | permitted;
    let mut summary = 0_u32;
    for (bit, flag) in [
        (21_u32, CAP_SUMMARY_SYS_ADMIN),
        (12_u32, CAP_SUMMARY_NET_ADMIN),
        (19_u32, CAP_SUMMARY_SYS_PTRACE),
        (16_u32, CAP_SUMMARY_SYS_MODULE),
        (17_u32, CAP_SUMMARY_SYS_RAWIO),
        (7_u32, CAP_SUMMARY_SETUID),
        (6_u32, CAP_SUMMARY_SETGID),
    ] {
        if combined & (1_u64 << bit) != 0 {
            summary |= flag;
        }
    }
    summary
}

fn copy_prefix<const N: usize>(target: &mut [u8; IP_LEN], source: &[u8; N]) {
    let len = if N > IP_LEN { IP_LEN } else { N };
    let mut index = 0;
    while index < len {
        target[index] = source[index];
        index += 1;
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
