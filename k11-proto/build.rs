fn main() -> Result<(), Box<dyn std::error::Error>> {
    // protox parses in Rust: building k11 needs no system protoc.
    println!("cargo:rerun-if-changed=proto/k11.proto");
    let fds = protox::compile(["k11.proto"], ["proto"])?;
    tonic_build::configure().compile_fds(fds)?;
    Ok(())
}
