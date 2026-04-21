use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=../k11-probe");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR not set"));
    let src = PathBuf::from("../k11-probe/target/bpfel-unknown-none/release/k11-ebpf");
    let dst = out_dir.join("k11-ebpf");

    if src.exists() {
        fs::copy(&src, &dst).unwrap_or_else(|e| {
            panic!("failed to copy {src:?} → {dst:?}: {e}")
        });
    } else {
        panic!(
            "BPF probe not found at {src:?}. Build it first with: cargo xtask build"
        );
    }
}
