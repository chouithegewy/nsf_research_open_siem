fn main() {
    if let Err(err) = ebpf_sensor::run(std::env::args().skip(1).collect()) {
        eprintln!("honeypot-ebpf: {err}");
        std::process::exit(2);
    }
}
