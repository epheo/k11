use std::path::PathBuf;

use anyhow::Result;

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let probe_dir = manifest_dir
        .parent()
        .expect("k11d has a workspace parent")
        .join("k11-probe");
    let probe_dir_str = probe_dir
        .to_str()
        .expect("probe dir path is utf-8")
        .to_owned();

    aya_build::build_ebpf(
        [aya_build::Package {
            name: "k11-probe",
            root_dir: &probe_dir_str,
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::default(),
    )?;
    Ok(())
}
