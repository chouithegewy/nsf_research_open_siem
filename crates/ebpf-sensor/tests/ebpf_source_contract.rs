#[test]
fn ebpf_source_declares_mvp_probes_and_events_ring_buffer() {
    let source = include_str!("../../ebpf-sensor-ebpf/src/main.rs");

    for expected in [
        "static EVENTS: RingBuf",
        "tracepoint_sched_process_exec",
        "tracepoint_sched_process_exit",
        "kprobe_tcp_v4_connect",
        "kprobe_tcp_v6_connect",
        "tracepoint_sys_enter_connect",
        "entry.discard",
        "tracepoint_sys_enter_openat",
        "tracepoint_sys_enter_setuid",
        "tracepoint_sys_enter_setgid",
        "WireEventRecord",
        "KIND_PROCESS_EXEC",
        "KIND_NETWORK_CONNECT",
        "KIND_FILE_ACCESS",
        "KIND_PRIVILEGE_CHANGE",
        "bpf_probe_read_kernel_str_bytes",
        "bpf_probe_read_user_str_bytes",
        "copy_exec_filename",
        "copy_openat_filename",
        "copy_sockaddr_peer",
        "write_ipv4_addr",
        "openat_access_type",
    ] {
        assert!(
            source.contains(expected),
            "missing eBPF source contract token: {expected}"
        );
    }
}
