#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user, bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::RingBuf,
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use core::{mem, ptr};

const SCHEMA_VERSION: u16 = 1;

const KIND_PROCESS_EXEC: u8 = 1;
const KIND_PROCESS_EXIT: u8 = 2;
const KIND_NETWORK_CONNECT: u8 = 3;
const KIND_FILE_ACCESS: u8 = 4;
const KIND_PRIVILEGE_CHANGE: u8 = 5;

const WIRE_COMM_LEN: usize = 16;
const WIRE_PATH_LEN: usize = 256;
const WIRE_ARG_SAMPLE_LEN: usize = 256;
const WIRE_ACCESS_LEN: usize = 16;
const WIRE_ADDR_LEN: usize = 46;
const WIRE_PROTOCOL_LEN: usize = 8;
const WIRE_CGROUP_LEN: usize = 32;
const WIRE_CONTAINER_LEN: usize = 64;

const SCHED_PROCESS_EXEC_FILENAME_LOC_OFFSET: usize = 8;
const OPENAT_FILENAME_PTR_OFFSET: usize = 24;
const OPENAT_FLAGS_OFFSET: usize = 32;
const CONNECT_SOCKADDR_PTR_OFFSET: usize = 24;
const AF_INET: u16 = 2;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;
const O_TRUNC: u64 = 0x200;

#[repr(C, align(8))]
pub struct WireEventRecord {
    pub schema_version: u16,
    pub kind: u8,
    pub flags: u8,
    pub _pad0: u32,
    pub pid: i64,
    pub ppid: i64,
    pub uid: i64,
    pub gid: i64,
    pub src_port: u16,
    pub dest_port: u16,
    pub _pad1: u32,
    pub comm: [u8; WIRE_COMM_LEN],
    pub binary: [u8; WIRE_PATH_LEN],
    pub argument_sample: [u8; WIRE_ARG_SAMPLE_LEN],
    pub filename: [u8; WIRE_PATH_LEN],
    pub access_type: [u8; WIRE_ACCESS_LEN],
    pub src_ip: [u8; WIRE_ADDR_LEN],
    pub dest_ip: [u8; WIRE_ADDR_LEN],
    pub protocol: [u8; WIRE_PROTOCOL_LEN],
    pub cgroup_id: [u8; WIRE_CGROUP_LEN],
    pub container_id: [u8; WIRE_CONTAINER_LEN],
}

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn tracepoint_sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sched_process_exec(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sched_process_exec(_ctx: TracePointContext) -> Result<(), i64> {
    emit_exec_event(_ctx)
}

#[tracepoint]
pub fn tracepoint_sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sched_process_exit(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sched_process_exit(_ctx: TracePointContext) -> Result<(), i64> {
    emit_event(KIND_PROCESS_EXIT)
}

#[kprobe]
pub fn kprobe_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    match try_kprobe_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_kprobe_tcp_v4_connect(_ctx: ProbeContext) -> Result<(), i64> {
    emit_network_event(b"tcp")
}

#[kprobe]
pub fn kprobe_tcp_v6_connect(ctx: ProbeContext) -> u32 {
    match try_kprobe_tcp_v6_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_kprobe_tcp_v6_connect(_ctx: ProbeContext) -> Result<(), i64> {
    emit_network_event(b"tcp6")
}

#[tracepoint]
pub fn tracepoint_sys_enter_connect(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sys_enter_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sys_enter_connect(_ctx: TracePointContext) -> Result<(), i64> {
    emit_connect_event(_ctx)
}

#[tracepoint]
pub fn tracepoint_sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sys_enter_openat(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sys_enter_openat(_ctx: TracePointContext) -> Result<(), i64> {
    emit_file_event(_ctx)
}

#[tracepoint]
pub fn tracepoint_sys_enter_setuid(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sys_enter_setuid(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sys_enter_setuid(_ctx: TracePointContext) -> Result<(), i64> {
    emit_event(KIND_PRIVILEGE_CHANGE)
}

#[tracepoint]
pub fn tracepoint_sys_enter_setgid(ctx: TracePointContext) -> u32 {
    match try_tracepoint_sys_enter_setgid(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_tracepoint_sys_enter_setgid(_ctx: TracePointContext) -> Result<(), i64> {
    emit_event(KIND_PRIVILEGE_CHANGE)
}

fn emit_event(kind: u8) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<WireEventRecord>(0) else {
        return Err(1);
    };
    unsafe {
        init_event(entry.as_mut_ptr(), kind);
    }
    entry.submit(0);
    Ok(())
}

fn emit_exec_event(ctx: TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<WireEventRecord>(0) else {
        return Err(1);
    };
    unsafe {
        let event = entry.as_mut_ptr();
        init_event(event, KIND_PROCESS_EXEC);
        copy_exec_filename(&ctx, &mut (*event).binary);
    }
    entry.submit(0);
    Ok(())
}

fn emit_network_event(protocol: &[u8]) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<WireEventRecord>(0) else {
        return Err(1);
    };
    unsafe {
        let event = entry.as_mut_ptr();
        init_event(event, KIND_NETWORK_CONNECT);
        set_str(&mut (*event).protocol, protocol);
    }
    entry.submit(0);
    Ok(())
}

fn emit_connect_event(ctx: TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<WireEventRecord>(0) else {
        return Err(1);
    };
    let supported = unsafe {
        let event = entry.as_mut_ptr();
        init_event(event, KIND_NETWORK_CONNECT);
        copy_sockaddr_peer(&ctx, event)
    };
    if supported {
        entry.submit(0);
    } else {
        entry.discard(0);
    }
    Ok(())
}

fn emit_file_event(ctx: TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<WireEventRecord>(0) else {
        return Err(1);
    };
    unsafe {
        let event = entry.as_mut_ptr();
        init_event(event, KIND_FILE_ACCESS);
        copy_openat_filename(&ctx, &mut (*event).filename);
        let flags = ctx.read_at::<u64>(OPENAT_FLAGS_OFFSET).unwrap_or(0);
        set_str(&mut (*event).access_type, openat_access_type(flags));
    }
    entry.submit(0);
    Ok(())
}

unsafe fn init_event(event: *mut WireEventRecord, kind: u8) {
    ptr::write_bytes(event as *mut u8, 0, mem::size_of::<WireEventRecord>());
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    (*event).schema_version = SCHEMA_VERSION;
    (*event).kind = kind;
    (*event).pid = (pid_tgid >> 32) as i64;
    (*event).uid = (uid_gid & 0xffff_ffff) as i64;
    (*event).gid = (uid_gid >> 32) as i64;
    if let Ok(comm) = bpf_get_current_comm() {
        (*event).comm = comm;
    }
}

unsafe fn copy_exec_filename<const N: usize>(ctx: &TracePointContext, destination: &mut [u8; N]) {
    let data_loc = ctx
        .read_at::<u32>(SCHED_PROCESS_EXEC_FILENAME_LOC_OFFSET)
        .unwrap_or(0);
    let offset = (data_loc & 0xffff) as usize;
    if offset == 0 {
        return;
    }
    let src = (ctx.as_ptr() as *const u8).add(offset);
    let _ = bpf_probe_read_kernel_str_bytes(src, destination);
}

unsafe fn copy_openat_filename<const N: usize>(ctx: &TracePointContext, destination: &mut [u8; N]) {
    let filename_ptr = ctx.read_at::<u64>(OPENAT_FILENAME_PTR_OFFSET).unwrap_or(0);
    if filename_ptr == 0 {
        return;
    }
    let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, destination);
}

unsafe fn copy_sockaddr_peer(ctx: &TracePointContext, event: *mut WireEventRecord) -> bool {
    let sockaddr_ptr = ctx.read_at::<u64>(CONNECT_SOCKADDR_PTR_OFFSET).unwrap_or(0);
    if sockaddr_ptr == 0 {
        return false;
    }
    let family = bpf_probe_read_user::<u16>(sockaddr_ptr as *const u16).unwrap_or(0);
    if family != AF_INET {
        return false;
    }
    let port_network = bpf_probe_read_user::<u16>((sockaddr_ptr + 2) as *const u16).unwrap_or(0);
    let octets =
        bpf_probe_read_user::<[u8; 4]>((sockaddr_ptr + 4) as *const [u8; 4]).unwrap_or([0; 4]);
    if port_network == 0 || octets == [0; 4] {
        return false;
    }
    set_str(&mut (*event).protocol, b"tcp4");
    (*event).dest_port = swap_u16(port_network);
    write_ipv4_addr(&mut (*event).dest_ip, octets);
    true
}

fn openat_access_type(flags: u64) -> &'static [u8] {
    if flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) != 0 {
        b"write"
    } else {
        b"read"
    }
}

fn swap_u16(value: u16) -> u16 {
    (value >> 8) | (value << 8)
}

fn write_ipv4_addr<const N: usize>(destination: &mut [u8; N], octets: [u8; 4]) {
    let mut index = 0;
    index = write_u8_decimal(destination, index, octets[0]);
    index = write_byte(destination, index, b'.');
    index = write_u8_decimal(destination, index, octets[1]);
    index = write_byte(destination, index, b'.');
    index = write_u8_decimal(destination, index, octets[2]);
    index = write_byte(destination, index, b'.');
    let _ = write_u8_decimal(destination, index, octets[3]);
}

fn write_u8_decimal<const N: usize>(
    destination: &mut [u8; N],
    mut index: usize,
    value: u8,
) -> usize {
    if value >= 100 {
        index = write_byte(destination, index, b'0' + (value / 100));
        index = write_byte(destination, index, b'0' + ((value / 10) % 10));
        write_byte(destination, index, b'0' + (value % 10))
    } else if value >= 10 {
        index = write_byte(destination, index, b'0' + (value / 10));
        write_byte(destination, index, b'0' + (value % 10))
    } else {
        write_byte(destination, index, b'0' + value)
    }
}

fn write_byte<const N: usize>(destination: &mut [u8; N], index: usize, value: u8) -> usize {
    if index < N.saturating_sub(1) {
        destination[index] = value;
        index + 1
    } else {
        index
    }
}

fn set_str<const N: usize>(destination: &mut [u8; N], value: &[u8]) {
    let mut index = 0;
    while index < N && index < value.len() {
        destination[index] = value[index];
        index += 1;
    }
}

const _: () = {
    let _ = mem::size_of::<WireEventRecord>();
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
