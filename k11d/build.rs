use std::{env, fs, path::PathBuf};

fn main() {
    let src = PathBuf::from("../k11-probe/target/bpfel-unknown-none/release/k11-ebpf");
    println!("cargo:rerun-if-changed={}", src.display());

    // rust-embed's folder must exist at macro expansion; an empty dist just
    // means the dashboard 404s until `cargo xtask build` runs npm.
    let _ = fs::create_dir_all("../k11-web/dist");

    // Without the probe object k11 still compiles (check, clippy, tests,
    // rust-analyzer) and refuses to start, naming the build step.
    let dst = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set")).join("k11-ebpf");
    if src.exists() {
        fs::copy(&src, &dst).unwrap_or_else(|e| panic!("failed to copy {src:?}: {e}"));
    } else {
        println!(
            "cargo:warning=BPF probe not built: k11 daemon will not start. Run: cargo xtask build"
        );
        fs::write(&dst, []).expect("write placeholder probe");
    }
}
