//! Local native archive/checksum producer for the maintained installer.
use crate::build;
mod linux;
mod notices;
mod platform_runtime;
use flate2::{Compression, GzBuilder};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct Stage {
    path: PathBuf,
    pending: bool,
}
impl Drop for Stage {
    fn drop(&mut self) {
        if self.pending {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
fn platform(os: &str, arch: &str) -> io::Result<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("macos", "aarch64") => Ok("darwin-arm64"),
        ("windows", "x86_64") => Ok("windows-amd64"),
        _ => Err(io::Error::other(
            "native installer packages support Linux amd64, macOS arm64 and Windows amd64",
        )),
    }
}
struct Hashed<W> {
    inner: W,
    hash: Sha256,
}
impl<W: Write> Write for Hashed<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(bytes)?;
        self.hash.update(&bytes[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
fn private_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    options.open(path)
}
fn archive(binary: &Path, directory: &Path, platform: &str, assets: &[PathBuf]) -> io::Result<()> {
    let basename = format!("graphit-broker-{platform}");
    let name = format!("{basename}.tar.gz");
    let file = private_file(&directory.join(&name))?;
    let hashed = Hashed {
        inner: file,
        hash: Sha256::new(),
    };
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(hashed, Compression::default());
    let mut tar = tar::Builder::new(gzip);
    let mut source = fs::File::open(binary)?;
    let mut header = tar::Header::new_gnu();
    header.set_size(source.metadata()?.len());
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    tar.append_data(
        &mut header,
        format!("{basename}/{}", binary_name(platform)),
        &mut source,
    )?;
    for relative in assets {
        let mut source = fs::File::open(directory.join("payload").join(relative))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(source.metadata()?.len());
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        tar.append_data(
            &mut header,
            Path::new(&basename).join(relative),
            &mut source,
        )?;
    }
    let gzip = tar.into_inner()?;
    let mut completed = gzip.finish()?;
    completed.flush()?;
    completed.inner.sync_all()?;
    let digest = completed.hash.finalize();
    let mut checksum = private_file(&directory.join(format!("{basename}.sha256")))?;
    writeln!(checksum, "{digest:x}  {name}")?;
    checksum.sync_all()?;
    Ok(())
}
fn binary_name(platform: &str) -> &'static str {
    if platform == "windows-amd64" {
        "graphit-broker.exe"
    } else {
        "graphit-broker"
    }
}
fn version(binary: &Path, search: &[PathBuf]) -> io::Result<()> {
    let mut command = Command::new(binary);
    command
        .arg("--version")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD");
    if !search.is_empty() {
        command.env(
            "LD_LIBRARY_PATH",
            std::env::join_paths(search).map_err(io::Error::other)?,
        );
    }
    let output = command.output()?;
    if !output.status.success()
        || output.stdout != format!("graphit-broker {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        || !output.stderr.is_empty()
    {
        return Err(io::Error::other(
            "native Broker executable version does not match workspace",
        ));
    }
    Ok(())
}
/// Publish a complete local installer pair from a native build or explicit input.
pub fn package(
    debug: bool,
    output: &Path,
    binary: Option<&Path>,
    artifacts: Option<&Path>,
) -> io::Result<()> {
    let platform = platform(std::env::consts::OS, std::env::consts::ARCH)?;
    if output.as_os_str().is_empty() || fs::symlink_metadata(output).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "package output must be a new directory",
        ));
    }
    let supplied = binary.map(fs::canonicalize).transpose()?;
    let binary = supplied.as_deref();
    if let Some(binary) = binary
        && !fs::metadata(binary)?.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "package --binary must name a regular executable file",
        ));
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let mut stage = Stage {
        path: parent.join(format!(
            ".broker-native-package-{}-{stamp}",
            std::process::id()
        )),
        pending: false,
    };
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&stage.path)?;
    stage.pending = true;
    let built = stage.path.join(if platform == "windows-amd64" {
        "native-broker.exe"
    } else {
        "native-broker"
    });
    let binary = match binary {
        Some(binary) => binary,
        None => {
            build::build_native(debug, &built)?;
            &built
        }
    };
    let payload = stage.path.join("payload");
    let (mut assets, package_id) = notices::collect(&payload)?;
    let runtime = notices::runtime_inputs(artifacts, binary, &package_id)?;
    version(binary, &runtime.search)?;
    // Transform a staged copy only; supplied qualified executables remain intact.
    let packaged = payload.join(binary_name(platform));
    fs::copy(binary, &packaged)?;
    if platform == "linux-amd64" {
        assets.extend(linux::prepare(
            &payload, binary, &packaged, &assets, &runtime,
        )?);
    } else {
        assets = platform_runtime::prepare(&payload, platform, binary_name(platform))?;
    }
    version(&packaged, &[])?;
    assets.sort();
    archive(&packaged, &stage.path, platform, &assets)?;
    if !assets.is_empty() {
        fs::remove_dir_all(stage.path.join("payload"))?;
    }
    if built.exists() {
        fs::remove_file(&built)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&stage.path, fs::Permissions::from_mode(0o755))?;
        fs::File::open(&stage.path)?.sync_all()?;
    }
    // Existing nonempty package directories are never replaced. Both files are
    // already closed and synced before their containing directory is published.
    fs::rename(&stage.path, output)?;
    stage.pending = false;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn supported_platforms_are_host_architectures_not_archive_aliases() {
        assert_eq!(platform("linux", "x86_64").unwrap(), "linux-amd64");
        assert_eq!(platform("macos", "aarch64").unwrap(), "darwin-arm64");
        assert_eq!(platform("windows", "x86_64").unwrap(), "windows-amd64");
        assert_eq!(binary_name("windows-amd64"), "graphit-broker.exe");
        for (os, arch) in [
            ("linux", "aarch64"),
            ("windows", "aarch64"),
            ("macos", "x86_64"),
        ] {
            assert!(platform(os, arch).is_err());
        }
    }
}
