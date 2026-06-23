use chrono::Utc;
use duckdb::{params, Connection};
use ebpf_sensor_common::{event_from_json_line, event_to_ndjson, EbpfEvent, SCHEMA_VERSION};
use serde::Serialize;
use serde_json::json;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, String>;

const WIRE_KIND_PROCESS_EXEC: u8 = 1;
const WIRE_KIND_PROCESS_EXIT: u8 = 2;
const WIRE_KIND_NETWORK_CONNECT: u8 = 3;
const WIRE_KIND_FILE_ACCESS: u8 = 4;
const WIRE_KIND_PRIVILEGE_CHANGE: u8 = 5;

const WIRE_HEADER_LEN: usize = 48;
const WIRE_COMM_LEN: usize = 16;
const WIRE_PATH_LEN: usize = 256;
const WIRE_ARG_SAMPLE_LEN: usize = 256;
const WIRE_ACCESS_LEN: usize = 16;
const WIRE_ADDR_LEN: usize = 46;
const WIRE_PROTOCOL_LEN: usize = 8;
const WIRE_CGROUP_LEN: usize = 32;
const WIRE_CONTAINER_LEN: usize = 64;
const WIRE_TRAILER_PAD_LEN: usize = 4;

pub const WIRE_EVENT_RECORD_SIZE: usize = WIRE_HEADER_LEN
    + WIRE_COMM_LEN
    + WIRE_PATH_LEN
    + WIRE_ARG_SAMPLE_LEN
    + WIRE_PATH_LEN
    + WIRE_ACCESS_LEN
    + WIRE_ADDR_LEN
    + WIRE_ADDR_LEN
    + WIRE_PROTOCOL_LEN
    + WIRE_CGROUP_LEN
    + WIRE_CONTAINER_LEN
    + WIRE_TRAILER_PAD_LEN;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Config {
    pub host: String,
    pub watched_prefixes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            host: hostname(),
            watched_prefixes: vec![
                "/tmp".to_string(),
                "/var/tmp".to_string(),
                "/dev/shm".to_string(),
                "/etc".to_string(),
                "/root/.ssh".to_string(),
                "/home".to_string(),
                "/var/www".to_string(),
                "/usr/local/bin".to_string(),
                "/bin".to_string(),
                "/usr/bin".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapturePlan {
    pub mode: String,
    pub schema_version: u16,
    pub host: String,
    pub watched_prefixes: Vec<String>,
    pub behavior_families: Vec<String>,
    pub readiness: Readiness,
    pub probes: Vec<ProbeSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Readiness {
    pub btf: bool,
    pub tracefs: bool,
    pub ringbuf_hint: bool,
    pub unprivileged_bpf_disabled: Option<String>,
    pub privilege_note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeSpec {
    pub event_type: String,
    pub program: String,
    pub attach_kind: String,
    pub attach_point: String,
    pub purpose: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelEventKind {
    ProcessExec,
    ProcessExit,
    NetworkConnect,
    FileAccess,
    PrivilegeChange,
}

impl KernelEventKind {
    fn event_type(self) -> &'static str {
        match self {
            KernelEventKind::ProcessExec => "process_exec",
            KernelEventKind::ProcessExit => "process_exit",
            KernelEventKind::NetworkConnect => "network_connect",
            KernelEventKind::FileAccess => "file_access",
            KernelEventKind::PrivilegeChange => "privilege_change",
        }
    }

    fn wire_kind(self) -> u8 {
        match self {
            KernelEventKind::ProcessExec => WIRE_KIND_PROCESS_EXEC,
            KernelEventKind::ProcessExit => WIRE_KIND_PROCESS_EXIT,
            KernelEventKind::NetworkConnect => WIRE_KIND_NETWORK_CONNECT,
            KernelEventKind::FileAccess => WIRE_KIND_FILE_ACCESS,
            KernelEventKind::PrivilegeChange => WIRE_KIND_PRIVILEGE_CHANGE,
        }
    }

    fn from_wire_kind(value: u8) -> Option<Self> {
        match value {
            WIRE_KIND_PROCESS_EXEC => Some(KernelEventKind::ProcessExec),
            WIRE_KIND_PROCESS_EXIT => Some(KernelEventKind::ProcessExit),
            WIRE_KIND_NETWORK_CONNECT => Some(KernelEventKind::NetworkConnect),
            WIRE_KIND_FILE_ACCESS => Some(KernelEventKind::FileAccess),
            WIRE_KIND_PRIVILEGE_CHANGE => Some(KernelEventKind::PrivilegeChange),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelEvent {
    pub kind: KernelEventKind,
    pub timestamp: String,
    pub pid: Option<i64>,
    pub ppid: Option<i64>,
    pub uid: Option<i64>,
    pub gid: Option<i64>,
    pub comm: Option<String>,
    pub binary: Option<String>,
    pub arguments: Vec<String>,
    pub filename: Option<String>,
    pub access_type: Option<String>,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<String>,
    pub dest_port: Option<u16>,
    pub protocol: Option<String>,
    pub cgroup_id: Option<String>,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireEventRecord {
    schema_version: u16,
    kind: u8,
    flags: u8,
    pid: i64,
    ppid: i64,
    uid: i64,
    gid: i64,
    src_port: u16,
    dest_port: u16,
    comm: [u8; WIRE_COMM_LEN],
    binary: [u8; WIRE_PATH_LEN],
    argument_sample: [u8; WIRE_ARG_SAMPLE_LEN],
    filename: [u8; WIRE_PATH_LEN],
    access_type: [u8; WIRE_ACCESS_LEN],
    src_ip: [u8; WIRE_ADDR_LEN],
    dest_ip: [u8; WIRE_ADDR_LEN],
    protocol: [u8; WIRE_PROTOCOL_LEN],
    cgroup_id: [u8; WIRE_CGROUP_LEN],
    container_id: [u8; WIRE_CONTAINER_LEN],
}

impl WireEventRecord {
    pub fn new(kind: KernelEventKind) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            kind: kind.wire_kind(),
            flags: 0,
            pid: 0,
            ppid: 0,
            uid: -1,
            gid: -1,
            src_port: 0,
            dest_port: 0,
            comm: [0; WIRE_COMM_LEN],
            binary: [0; WIRE_PATH_LEN],
            argument_sample: [0; WIRE_ARG_SAMPLE_LEN],
            filename: [0; WIRE_PATH_LEN],
            access_type: [0; WIRE_ACCESS_LEN],
            src_ip: [0; WIRE_ADDR_LEN],
            dest_ip: [0; WIRE_ADDR_LEN],
            protocol: [0; WIRE_PROTOCOL_LEN],
            cgroup_id: [0; WIRE_CGROUP_LEN],
            container_id: [0; WIRE_CONTAINER_LEN],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != WIRE_EVENT_RECORD_SIZE {
            return Err(format!(
                "wire event record has {} byte(s), expected {WIRE_EVENT_RECORD_SIZE}",
                bytes.len()
            ));
        }
        let schema_version = u16::from_le_bytes([bytes[0], bytes[1]]);
        if schema_version != SCHEMA_VERSION {
            return Err(format!(
                "wire event schema_version={schema_version}, expected {SCHEMA_VERSION}"
            ));
        }
        let mut record = Self::new(KernelEventKind::ProcessExec);
        record.schema_version = schema_version;
        record.kind = bytes[2];
        record.flags = bytes[3];
        record.pid = read_i64(bytes, 8);
        record.ppid = read_i64(bytes, 16);
        record.uid = read_i64(bytes, 24);
        record.gid = read_i64(bytes, 32);
        record.src_port = u16::from_le_bytes([bytes[40], bytes[41]]);
        record.dest_port = u16::from_le_bytes([bytes[42], bytes[43]]);

        let mut offset = WIRE_HEADER_LEN;
        read_fixed(bytes, &mut offset, &mut record.comm);
        read_fixed(bytes, &mut offset, &mut record.binary);
        read_fixed(bytes, &mut offset, &mut record.argument_sample);
        read_fixed(bytes, &mut offset, &mut record.filename);
        read_fixed(bytes, &mut offset, &mut record.access_type);
        read_fixed(bytes, &mut offset, &mut record.src_ip);
        read_fixed(bytes, &mut offset, &mut record.dest_ip);
        read_fixed(bytes, &mut offset, &mut record.protocol);
        read_fixed(bytes, &mut offset, &mut record.cgroup_id);
        read_fixed(bytes, &mut offset, &mut record.container_id);
        Ok(record)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; WIRE_EVENT_RECORD_SIZE];
        bytes[0..2].copy_from_slice(&self.schema_version.to_le_bytes());
        bytes[2] = self.kind;
        bytes[3] = self.flags;
        bytes[8..16].copy_from_slice(&self.pid.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.ppid.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.uid.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.gid.to_le_bytes());
        bytes[40..42].copy_from_slice(&self.src_port.to_le_bytes());
        bytes[42..44].copy_from_slice(&self.dest_port.to_le_bytes());

        let mut offset = WIRE_HEADER_LEN;
        write_fixed(&mut bytes, &mut offset, &self.comm);
        write_fixed(&mut bytes, &mut offset, &self.binary);
        write_fixed(&mut bytes, &mut offset, &self.argument_sample);
        write_fixed(&mut bytes, &mut offset, &self.filename);
        write_fixed(&mut bytes, &mut offset, &self.access_type);
        write_fixed(&mut bytes, &mut offset, &self.src_ip);
        write_fixed(&mut bytes, &mut offset, &self.dest_ip);
        write_fixed(&mut bytes, &mut offset, &self.protocol);
        write_fixed(&mut bytes, &mut offset, &self.cgroup_id);
        write_fixed(&mut bytes, &mut offset, &self.container_id);
        bytes
    }

    pub fn with_pid(mut self, value: i64) -> Self {
        self.pid = value;
        self
    }

    pub fn with_ppid(mut self, value: i64) -> Self {
        self.ppid = value;
        self
    }

    pub fn with_uid(mut self, value: i64) -> Self {
        self.uid = value;
        self
    }

    pub fn with_gid(mut self, value: i64) -> Self {
        self.gid = value;
        self
    }

    pub fn with_comm(mut self, value: &str) -> Self {
        copy_string(value, &mut self.comm);
        self
    }

    pub fn with_binary(mut self, value: &str) -> Self {
        copy_string(value, &mut self.binary);
        self
    }

    pub fn with_argument_sample(mut self, value: &str) -> Self {
        copy_string(value, &mut self.argument_sample);
        self
    }

    pub fn with_filename(mut self, value: &str) -> Self {
        copy_string(value, &mut self.filename);
        self
    }

    pub fn with_access_type(mut self, value: &str) -> Self {
        copy_string(value, &mut self.access_type);
        self
    }

    pub fn with_src_ip(mut self, value: &str) -> Self {
        copy_string(value, &mut self.src_ip);
        self
    }

    pub fn with_src_port(mut self, value: u16) -> Self {
        self.src_port = value;
        self
    }

    pub fn with_dest_ip(mut self, value: &str) -> Self {
        copy_string(value, &mut self.dest_ip);
        self
    }

    pub fn with_dest_port(mut self, value: u16) -> Self {
        self.dest_port = value;
        self
    }

    pub fn with_protocol(mut self, value: &str) -> Self {
        copy_string(value, &mut self.protocol);
        self
    }

    pub fn with_cgroup_id(mut self, value: &str) -> Self {
        copy_string(value, &mut self.cgroup_id);
        self
    }

    pub fn with_container_id(mut self, value: &str) -> Self {
        copy_string(value, &mut self.container_id);
        self
    }
}

pub fn run(args: Vec<String>) -> Result<()> {
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    run_with_io(args, &mut stdout, &mut stderr)
}

pub fn run_with_io<W: Write, E: Write>(
    args: Vec<String>,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<()> {
    let Some(command) = args.first().map(String::as_str) else {
        return usage(stdout);
    };
    match command {
        "check" => check(&args[1..], stdout),
        "capture" => capture(&args[1..], stdout, stderr),
        "import" => import(&args[1..], stdout, stderr),
        "run" => run_replay(&args[1..], stdout, stderr),
        "-h" | "--help" | "help" => usage(stdout),
        other => Err(format!("unknown command: {other}")),
    }
}

pub fn capture_plan(config: &Config) -> CapturePlan {
    CapturePlan {
        mode: "dry_run".to_string(),
        schema_version: SCHEMA_VERSION,
        host: config.host.clone(),
        watched_prefixes: config.watched_prefixes.clone(),
        behavior_families: vec![
            "signature_ioc".to_string(),
            "anomaly_baseline".to_string(),
            "stateful_correlation".to_string(),
        ],
        readiness: detect_readiness(),
        probes: vec![
            ProbeSpec {
                event_type: "process_exec".to_string(),
                program: "tracepoint_sched_process_exec".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "sched/sched_process_exec".to_string(),
                purpose: "process lineage, binary, and argument sampling".to_string(),
            },
            ProbeSpec {
                event_type: "process_exit".to_string(),
                program: "tracepoint_sched_process_exit".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "sched/sched_process_exit".to_string(),
                purpose: "lifecycle accounting for process fanout and dwell-time windows"
                    .to_string(),
            },
            ProbeSpec {
                event_type: "network_connect".to_string(),
                program: "tracepoint_sys_enter_connect".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "syscalls/sys_enter_connect".to_string(),
                purpose: "outbound connection peer address and port extraction".to_string(),
            },
            ProbeSpec {
                event_type: "file_access".to_string(),
                program: "tracepoint_sys_enter_openat".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "syscalls/sys_enter_openat".to_string(),
                purpose: "watched-path reads and writes for persistence or credential access"
                    .to_string(),
            },
            ProbeSpec {
                event_type: "privilege_change".to_string(),
                program: "tracepoint_sys_enter_setuid".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "syscalls/sys_enter_setuid".to_string(),
                purpose: "identity transition and privilege-change detection".to_string(),
            },
            ProbeSpec {
                event_type: "privilege_change".to_string(),
                program: "tracepoint_sys_enter_setgid".to_string(),
                attach_kind: "tracepoint".to_string(),
                attach_point: "syscalls/sys_enter_setgid".to_string(),
                purpose: "group identity transition detection".to_string(),
            },
        ],
    }
}

pub fn normalize_kernel_event(event: KernelEvent, config: &Config) -> Option<EbpfEvent> {
    if event.kind == KernelEventKind::FileAccess
        && !is_watched_path(event.filename.as_deref(), &config.watched_prefixes)
    {
        return None;
    }

    let severity_hint = severity_for_kernel_event(&event);
    Some(
        EbpfEvent {
            schema_version: SCHEMA_VERSION,
            timestamp: if event.timestamp.is_empty() {
                now_rfc3339()
            } else {
                event.timestamp.clone()
            },
            host: Some(config.host.clone()),
            event_type: event.kind.event_type().to_string(),
            pid: event.pid,
            ppid: event.ppid,
            uid: event.uid,
            gid: event.gid,
            comm: event.comm.clone(),
            binary: event.binary.clone(),
            arguments_sample: event.arguments.clone(),
            argv_truncated: false,
            cgroup_id: event.cgroup_id.clone(),
            container_id: event.container_id.clone(),
            src_ip: event.src_ip.clone(),
            src_port: event.src_port,
            dest_ip: event.dest_ip.clone(),
            dest_port: event.dest_port,
            protocol: event.protocol.clone(),
            filename: event.filename.clone(),
            access_type: event.access_type.clone(),
            severity_hint,
            raw: json!({
                "sensor": "honeypot-ebpf",
                "source": "kernel_event",
                "kind": event.kind.event_type(),
            }),
        }
        .normalized(Some(&config.host)),
    )
}

pub fn decode_wire_event(
    record: WireEventRecord,
    observed_at: &str,
    config: &Config,
) -> Option<EbpfEvent> {
    let kind = KernelEventKind::from_wire_kind(record.kind)?;
    normalize_kernel_event(
        KernelEvent {
            kind,
            timestamp: observed_at.to_string(),
            pid: nonzero_i64(record.pid),
            ppid: nonzero_i64(record.ppid),
            uid: nonnegative_i64(record.uid),
            gid: nonnegative_i64(record.gid),
            comm: fixed_string(&record.comm),
            binary: fixed_string(&record.binary),
            arguments: fixed_string(&record.argument_sample).into_iter().collect(),
            filename: fixed_string(&record.filename),
            access_type: fixed_string(&record.access_type),
            src_ip: fixed_string(&record.src_ip),
            src_port: nonzero_u16(record.src_port),
            dest_ip: fixed_string(&record.dest_ip),
            dest_port: nonzero_u16(record.dest_port),
            protocol: fixed_string(&record.protocol),
            cgroup_id: fixed_string(&record.cgroup_id),
            container_id: fixed_string(&record.container_id),
        },
        config,
    )
}

/// Extract a container id from the contents of `/proc/<pid>/cgroup`.
/// Recognizes Docker/CRI-O/containerd/libpod cgroup layouts (v1 and v2).
pub fn container_id_from_cgroup(contents: &str) -> Option<String> {
    for line in contents.lines() {
        // cgroup v1 lines are "hierarchy:controllers:path"; v2 is "0::path".
        let path = line.rsplit(':').next().unwrap_or(line);
        for segment in path.split('/') {
            if let Some(id) = container_id_from_segment(segment) {
                return Some(id);
            }
        }
    }
    None
}

fn container_id_from_segment(segment: &str) -> Option<String> {
    // systemd cgroup v2 names look like "docker-<id>.scope" / "crio-<id>.scope".
    let mut candidate = segment.strip_suffix(".scope").unwrap_or(segment);
    for prefix in ["docker-", "crio-", "containerd-", "libpod-"] {
        if let Some(rest) = candidate.strip_prefix(prefix) {
            candidate = rest;
            break;
        }
    }
    // Container ids embedded in cgroup paths are the full hex id (Docker: 64).
    if candidate.len() >= 32 && candidate.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(candidate.to_string())
    } else {
        None
    }
}

pub fn enrich_process_context_from_procfs(mut event: EbpfEvent, proc_root: &Path) -> EbpfEvent {
    let Some(pid) = event.pid else {
        return event;
    };
    if event.binary.is_none() {
        if let Ok(path) = fs::read_link(proc_root.join(pid.to_string()).join("exe")) {
            event.binary = Some(path.display().to_string());
        }
    }
    if event.container_id.is_none() {
        if let Ok(contents) = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")) {
            event.container_id = container_id_from_cgroup(&contents);
        }
    }
    if !event.arguments_sample.is_empty() {
        return event.normalized(None);
    }
    let cmdline_path = proc_root.join(pid.to_string()).join("cmdline");
    let Ok(bytes) = fs::read(cmdline_path) else {
        return event.normalized(None);
    };
    let mut args = Vec::new();
    for part in bytes.split(|byte| *byte == 0) {
        if part.is_empty() {
            continue;
        }
        args.push(String::from_utf8_lossy(part).to_string());
        if args.len() >= 8 {
            event.argv_truncated = true;
            break;
        }
    }
    if args.is_empty() {
        return event.normalized(None);
    }
    if event.binary.is_none() {
        event.binary = args.first().cloned();
    }
    event.arguments_sample = args;
    event.normalized(None)
}

fn usage<W: Write>(stdout: &mut W) -> Result<()> {
    writeln!(
        stdout,
        "Usage:\n  honeypot-ebpf check [--config PATH]\n  honeypot-ebpf capture [--config PATH] --dry-run\n  honeypot-ebpf capture [--config PATH] --probe-object PATH [--duration-seconds N] [--output PATH] [--db PATH]\n  honeypot-ebpf import PATH [--db PATH]\n  honeypot-ebpf run --input PATH [--config PATH] [--output PATH] [--db PATH]\n\nThe MVP userspace tool validates host eBPF readiness, plans live probes, imports normalized eBPF NDJSON, and replays NDJSON through the same redaction/storage path."
    )
    .map_err(|err| err.to_string())
}

fn check<W: Write>(args: &[String], stdout: &mut W) -> Result<()> {
    let config = read_config(option_value(args, "--config").unwrap_or("config/ebpf-sensor.toml"))?;
    let readiness = detect_readiness();
    writeln!(stdout, "schema_version={SCHEMA_VERSION}").map_err(|err| err.to_string())?;
    writeln!(stdout, "host={}", config.host).map_err(|err| err.to_string())?;
    writeln!(
        stdout,
        "watched_prefixes={}",
        config.watched_prefixes.join(",")
    )
    .map_err(|err| err.to_string())?;
    writeln!(stdout, "btf={}", readiness.btf).map_err(|err| err.to_string())?;
    writeln!(stdout, "tracefs={}", readiness.tracefs).map_err(|err| err.to_string())?;
    writeln!(stdout, "ringbuf_hint={}", readiness.ringbuf_hint).map_err(|err| err.to_string())?;
    if let Some(value) = readiness.unprivileged_bpf_disabled {
        writeln!(stdout, "unprivileged_bpf_disabled={value}").map_err(|err| err.to_string())?;
    }
    writeln!(stdout, "capability_note={}", readiness.privilege_note)
        .map_err(|err| err.to_string())?;
    Ok(())
}

fn capture<W: Write, E: Write>(args: &[String], stdout: &mut W, stderr: &mut E) -> Result<()> {
    let config = read_config(option_value(args, "--config").unwrap_or("config/ebpf-sensor.toml"))?;
    let mut plan = capture_plan(&config);
    if args.iter().any(|arg| arg == "--dry-run") {
        plan.mode = "dry_run".to_string();
        serde_json::to_writer_pretty(&mut *stdout, &plan).map_err(|err| err.to_string())?;
        writeln!(stdout).map_err(|err| err.to_string())?;
        return Ok(());
    }

    let Some(probe_object) = option_value(args, "--probe-object") else {
        return Err(
            "capture requires --probe-object PATH unless --dry-run is supplied".to_string(),
        );
    };
    if !Path::new(probe_object).exists() {
        return Err(format!("probe object not found: {probe_object}"));
    }
    let duration_seconds = option_value(args, "--duration-seconds")
        .map(parse_positive_u64)
        .transpose()?
        .unwrap_or(60);
    capture_live(
        probe_object,
        &config,
        duration_seconds,
        option_value(args, "--output"),
        option_value(args, "--db"),
        stdout,
        stderr,
    )
}

#[cfg(all(feature = "live-ebpf", target_os = "linux"))]
fn capture_live<W: Write, E: Write>(
    probe_object: &str,
    config: &Config,
    duration_seconds: u64,
    output_path: Option<&str>,
    db_path: Option<&str>,
    stdout: &mut W,
    stderr: &mut E,
) -> Result<()> {
    use aya::maps::ring_buf::RingBuf;
    use aya::programs::{KProbe, TracePoint};
    use aya::Ebpf;
    use std::convert::{TryFrom, TryInto};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut bpf = Ebpf::load_file(probe_object)
        .map_err(|err| {
            format!(
                "failed to load eBPF object {probe_object}: {err}; live capture usually requires root or CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE"
            )
        })?;
    let plan = capture_plan(config);
    let mut attached = 0usize;

    for probe in &plan.probes {
        let Some(program) = bpf.program_mut(&probe.program) else {
            writeln!(
                stderr,
                "warning=probe_object_missing_program program={}",
                probe.program
            )
            .map_err(|err| err.to_string())?;
            continue;
        };
        match probe.attach_kind.as_str() {
            "tracepoint" => {
                let tracepoint: &mut TracePoint = program
                    .try_into()
                    .map_err(|err| format!("{} is not a tracepoint: {err}", probe.program))?;
                tracepoint
                    .load()
                    .map_err(|err| format!("failed to load {}: {err}", probe.program))?;
                let Some((category, name)) = probe.attach_point.split_once('/') else {
                    return Err(format!(
                        "{} has invalid tracepoint attach point {}",
                        probe.program, probe.attach_point
                    ));
                };
                tracepoint
                    .attach(category, name)
                    .map_err(|err| format!("failed to attach {}: {err}", probe.program))?;
                attached += 1;
            }
            "kprobe" => {
                let kprobe: &mut KProbe = program
                    .try_into()
                    .map_err(|err| format!("{} is not a kprobe: {err}", probe.program))?;
                kprobe
                    .load()
                    .map_err(|err| format!("failed to load {}: {err}", probe.program))?;
                kprobe
                    .attach(&probe.attach_point, 0)
                    .map_err(|err| format!("failed to attach {}: {err}", probe.program))?;
                attached += 1;
            }
            other => return Err(format!("unsupported probe attach kind: {other}")),
        }
    }

    if attached == 0 {
        return Err("probe object did not contain any expected MVP programs".to_string());
    }

    let map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| "probe object does not expose EVENTS ring buffer".to_string())?;
    let mut events_map = RingBuf::try_from(map).map_err(|err| err.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(duration_seconds);
    let mut events = Vec::new();
    writeln!(
        stderr,
        "attached_probes={attached} duration_seconds={duration_seconds}"
    )
    .map_err(|err| err.to_string())?;

    while Instant::now() < deadline {
        let mut drained = false;
        while let Some(item) = events_map.next() {
            drained = true;
            let record = WireEventRecord::from_bytes(&item)
                .map_err(|err| format!("failed to decode eBPF ring event: {err}"))?;
            if let Some(event) = decode_wire_event(record, &now_rfc3339(), config) {
                events.push(enrich_process_context_from_procfs(
                    event,
                    Path::new("/proc"),
                ));
            }
        }
        if !drained {
            thread::sleep(Duration::from_millis(100));
        }
    }

    if let Some(path) = output_path {
        write_events(path, &events)?;
    } else {
        for event in &events {
            write!(
                stdout,
                "{}",
                event_to_ndjson(event).map_err(|err| err.to_string())?
            )
            .map_err(|err| err.to_string())?;
        }
    }
    if let Some(db) = db_path {
        let inserted = insert_events(db, &events)?;
        writeln!(stderr, "Stored {inserted} eBPF event(s) in {db}")
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

#[cfg(not(all(feature = "live-ebpf", target_os = "linux")))]
fn capture_live<W: Write, E: Write>(
    _probe_object: &str,
    _config: &Config,
    _duration_seconds: u64,
    _output_path: Option<&str>,
    _db_path: Option<&str>,
    _stdout: &mut W,
    _stderr: &mut E,
) -> Result<()> {
    Err(
        "live capture loader is not enabled in this build; rebuild on Linux with `cargo build -p ebpf-sensor --features live-ebpf`, or use --dry-run/replay with run --input"
            .to_string(),
    )
}

fn import<W: Write, E: Write>(args: &[String], stdout: &mut W, stderr: &mut E) -> Result<()> {
    let Some(input) = args.first() else {
        return Err("import requires an input NDJSON path".to_string());
    };
    let db_path = option_value(args, "--db");
    let config = Config::default();
    let events = read_events(input, &config)?;
    if let Some(db) = db_path {
        let inserted = insert_events(db, &events)?;
        writeln!(stderr, "Stored {inserted} eBPF event(s) in {db}")
            .map_err(|err| err.to_string())?;
    } else {
        for event in &events {
            write!(
                stdout,
                "{}",
                event_to_ndjson(event).map_err(|err| err.to_string())?
            )
            .map_err(|err| err.to_string())?;
        }
    }
    Ok(())
}

fn run_replay<W: Write, E: Write>(args: &[String], stdout: &mut W, stderr: &mut E) -> Result<()> {
    let input = option_value(args, "--input")
        .ok_or_else(|| "run currently requires --input PATH for MVP replay mode".to_string())?;
    let config = read_config(option_value(args, "--config").unwrap_or("config/ebpf-sensor.toml"))?;
    let events = read_events(input, &config)?;
    if let Some(output) = option_value(args, "--output") {
        write_events(output, &events)?;
    } else {
        for event in &events {
            write!(
                stdout,
                "{}",
                event_to_ndjson(event).map_err(|err| err.to_string())?
            )
            .map_err(|err| err.to_string())?;
        }
    }
    if let Some(db) = option_value(args, "--db") {
        let inserted = insert_events(db, &events)?;
        writeln!(stderr, "Stored {inserted} eBPF event(s) in {db}")
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn read_events(path: &str, config: &Config) -> Result<Vec<EbpfEvent>> {
    let file = File::open(path).map_err(|err| format!("{path}: {err}"))?;
    let mut events = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|err| format!("{path}: {err}"))?;
        let Some(event) =
            event_from_json_line(&line).map_err(|err| format!("{path}:{}: {err}", index + 1))?
        else {
            continue;
        };
        events.push(event.normalized(Some(&config.host)));
    }
    Ok(events)
}

fn write_events(path: &str, events: &[EbpfEvent]) -> Result<()> {
    let output = PathBuf::from(path);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&output)
        .map_err(|err| format!("{}: {err}", output.display()))?;
    for event in events {
        file.write_all(
            event_to_ndjson(event)
                .map_err(|err| err.to_string())?
                .as_bytes(),
        )
        .map_err(|err| format!("{}: {err}", output.display()))?;
    }
    Ok(())
}

fn insert_events(db_path: &str, events: &[EbpfEvent]) -> Result<usize> {
    if let Some(parent) = Path::new(db_path).parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    let conn = Connection::open(db_path).map_err(|err| err.to_string())?;
    init_db(&conn)?;
    let mut stmt = conn
        .prepare(
            "INSERT OR REPLACE INTO ebpf_events VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
        )
        .map_err(|err| err.to_string())?;
    for event in events {
        let id = event_id(event);
        stmt.execute(params![
            id,
            i64::from(event.schema_version),
            event.timestamp,
            event.host,
            event.event_type,
            event.pid,
            event.ppid,
            event.uid,
            event.gid,
            event.comm,
            event.binary,
            serde_json::to_string(&event.arguments_sample).map_err(|err| err.to_string())?,
            event.argv_truncated,
            event.cgroup_id,
            event.container_id,
            event.src_ip,
            event.src_port.map(i64::from),
            event.dest_ip,
            event.dest_port.map(i64::from),
            event.protocol,
            event.filename,
            event.access_type,
            event.severity_hint,
            serde_json::to_string(&event.raw).map_err(|err| err.to_string())?,
        ])
        .map_err(|err| err.to_string())?;
    }
    Ok(events.len())
}

fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS ebpf_events (
            id TEXT PRIMARY KEY,
            schema_version BIGINT,
            timestamp TEXT,
            host TEXT,
            event_type TEXT,
            pid BIGINT,
            ppid BIGINT,
            uid BIGINT,
            gid BIGINT,
            comm TEXT,
            "binary" TEXT,
            arguments_sample TEXT,
            argv_truncated BOOLEAN,
            cgroup_id TEXT,
            container_id TEXT,
            src_ip TEXT,
            src_port BIGINT,
            dest_ip TEXT,
            dest_port BIGINT,
            protocol TEXT,
            filename TEXT,
            access_type TEXT,
            severity_hint TEXT,
            raw TEXT
        );
        ALTER TABLE ebpf_events ADD COLUMN IF NOT EXISTS raw TEXT;
        "#,
    )
    .map_err(|err| err.to_string())
}

fn event_id(event: &EbpfEvent) -> String {
    let raw = format!(
        "{}|{}|{}|{}|{}|{}",
        event.timestamp,
        event.host.as_deref().unwrap_or(""),
        event.event_type,
        event.pid.unwrap_or_default(),
        event.filename.as_deref().unwrap_or(""),
        event.dest_ip.as_deref().unwrap_or("")
    );
    stable_hash(raw.as_bytes())
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    format!("{hash:016x}")
}

fn read_config(path: &str) -> Result<Config> {
    let mut config = Config::default();
    let Ok(text) = fs::read_to_string(path) else {
        return Ok(config);
    };
    for line in text.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() || trimmed.starts_with('[') {
            continue;
        }
        let Some((key, raw_value)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = raw_value.trim();
        if key == "host" {
            config.host = unquote(value).unwrap_or_else(|| config.host.clone());
        }
        if key == "watched_prefixes" {
            let prefixes = parse_string_list(value);
            if !prefixes.is_empty() {
                config.watched_prefixes = prefixes;
            }
        }
    }
    Ok(config)
}

fn parse_string_list(value: &str) -> Vec<String> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Vec::new();
    }
    value[1..value.len() - 1]
        .split(',')
        .filter_map(|item| unquote(item.trim()))
        .collect()
}

fn unquote(value: &str) -> Option<String> {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        Some(value[1..value.len() - 1].to_string())
    } else if !value.is_empty() {
        Some(value.to_string())
    } else {
        None
    }
}

fn option_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].as_str())
}

fn parse_positive_u64(value: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|err| format!("{value} is not a positive integer: {err}"))?;
    if parsed == 0 {
        Err("duration must be greater than zero".to_string())
    } else {
        Ok(parsed)
    }
}

fn detect_readiness() -> Readiness {
    Readiness {
        btf: Path::new("/sys/kernel/btf/vmlinux").exists(),
        tracefs: Path::new("/sys/kernel/tracing/events").exists()
            || Path::new("/sys/kernel/debug/tracing/events").exists(),
        ringbuf_hint: Path::new("/sys/kernel/btf/vmlinux").exists(),
        unprivileged_bpf_disabled: fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
        privilege_note:
            "live loading usually requires root or CAP_BPF/CAP_PERFMON/CAP_SYS_RESOURCE".to_string(),
    }
}

fn is_watched_path(filename: Option<&str>, watched_prefixes: &[String]) -> bool {
    let Some(filename) = filename else {
        return false;
    };
    watched_prefixes
        .iter()
        .any(|prefix| filename == prefix || filename.starts_with(&format!("{prefix}/")))
}

fn severity_for_kernel_event(event: &KernelEvent) -> Option<String> {
    match event.kind {
        KernelEventKind::PrivilegeChange => Some("high".to_string()),
        KernelEventKind::FileAccess => file_severity(event),
        KernelEventKind::ProcessExec => process_severity(event),
        KernelEventKind::NetworkConnect => network_severity(event),
        KernelEventKind::ProcessExit => None,
    }
}

fn file_severity(event: &KernelEvent) -> Option<String> {
    let access = event.access_type.as_deref().unwrap_or_default();
    let filename = event.filename.as_deref().unwrap_or_default();
    if matches!(access, "write" | "truncate" | "delete" | "rename")
        && (filename.starts_with("/etc/")
            || filename.starts_with("/root/.ssh/")
            || filename.ends_with("/authorized_keys"))
    {
        Some("high".to_string())
    } else if access == "write" || access == "truncate" {
        Some("medium".to_string())
    } else {
        None
    }
}

fn process_severity(event: &KernelEvent) -> Option<String> {
    let binary = event.binary.as_deref().unwrap_or_default();
    let basename = binary.rsplit('/').next().unwrap_or(binary);
    let args = event.arguments.join(" ").to_ascii_lowercase();
    if matches!(
        basename,
        "curl" | "wget" | "nc" | "ncat" | "socat" | "python" | "python3"
    ) || args.contains("http://")
        || args.contains("https://")
    {
        Some("medium".to_string())
    } else if matches!(basename, "sh" | "bash" | "dash" | "zsh") {
        Some("low".to_string())
    } else {
        None
    }
}

fn network_severity(event: &KernelEvent) -> Option<String> {
    if matches!(event.dest_port, Some(4444 | 1337 | 31337 | 5555)) {
        return Some("high".to_string());
    }
    if event.dest_ip.as_deref().is_some_and(is_public_ip_hint) {
        return Some("medium".to_string());
    }
    None
}

fn is_public_ip_hint(value: &str) -> bool {
    !(value.starts_with("10.")
        || value.starts_with("172.16.")
        || value.starts_with("172.17.")
        || value.starts_with("172.18.")
        || value.starts_with("172.19.")
        || value.starts_with("172.20.")
        || value.starts_with("172.21.")
        || value.starts_with("172.22.")
        || value.starts_with("172.23.")
        || value.starts_with("172.24.")
        || value.starts_with("172.25.")
        || value.starts_with("172.26.")
        || value.starts_with("172.27.")
        || value.starts_with("172.28.")
        || value.starts_with("172.29.")
        || value.starts_with("172.30.")
        || value.starts_with("172.31.")
        || value.starts_with("192.168.")
        || value.starts_with("127.")
        || value == "::1")
}

fn read_i64(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn read_fixed<const N: usize>(bytes: &[u8], offset: &mut usize, destination: &mut [u8; N]) {
    destination.copy_from_slice(&bytes[*offset..*offset + N]);
    *offset += N;
}

fn write_fixed<const N: usize>(bytes: &mut [u8], offset: &mut usize, source: &[u8; N]) {
    bytes[*offset..*offset + N].copy_from_slice(source);
    *offset += N;
}

fn copy_string<const N: usize>(value: &str, destination: &mut [u8; N]) {
    destination.fill(0);
    if N == 0 {
        return;
    }
    let bytes = value.as_bytes();
    let limit = bytes.len().min(N.saturating_sub(1));
    destination[..limit].copy_from_slice(&bytes[..limit]);
}

fn fixed_string<const N: usize>(source: &[u8; N]) -> Option<String> {
    let len = source.iter().position(|byte| *byte == 0).unwrap_or(N);
    if len == 0 {
        return None;
    }
    let value = String::from_utf8_lossy(&source[..len]).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn nonzero_i64(value: i64) -> Option<i64> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

fn nonnegative_i64(value: i64) -> Option<i64> {
    if value < 0 {
        None
    } else {
        Some(value)
    }
}

fn nonzero_u16(value: u16) -> Option<u16> {
    if value == 0 {
        None
    } else {
        Some(value)
    }
}

fn hostname() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_hash_is_stable() {
        assert_eq!(stable_hash(b"abc"), stable_hash(b"abc"));
        assert_ne!(stable_hash(b"abc"), stable_hash(b"abd"));
    }

    #[test]
    fn parses_string_list() {
        assert_eq!(
            parse_string_list(r#"["/tmp", "/etc"]"#),
            vec!["/tmp".to_string(), "/etc".to_string()]
        );
    }
}
