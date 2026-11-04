//! Reuse the native platform dependency producer from the Graphit AI source selected by Cargo.
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

fn files(root: &Path, directory: &Path, binary: &str, output: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            files(root, &entry.path(), binary, output)?;
        } else if kind.is_file() {
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_owned();
            if relative != Path::new(binary) {
                output.push(relative);
            }
        } else {
            return Err(io::Error::other(
                "native runtime assets must be regular files",
            ));
        }
    }
    Ok(())
}

pub(super) fn prepare(
    producer: &Path,
    root: &Path,
    platform: &str,
    binary: &str,
) -> io::Result<Vec<PathBuf>> {
    let result = Command::new("node")
        .arg(producer)
        .args([platform])
        .arg(root)
        .args(["graphit-runtime/broker", binary])
        .output()?;
    if !result.status.success() {
        return Err(io::Error::other(format!(
            "native platform packaging failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    let mut output = Vec::new();
    files(root, root, binary, &mut output)?;
    output.sort();
    Ok(output)
}
