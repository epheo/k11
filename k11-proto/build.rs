fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/k11.proto")?;
    Ok(())
}
