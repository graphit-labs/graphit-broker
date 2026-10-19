//! Native executable build used by contributors and CI.
use std::{
    env, fs,
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

struct Staged {
    path: PathBuf,
    pending: bool,
}
impl Drop for Staged {
    fn drop(&mut self) {
        if self.pending {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn publish(artifact: &Path, output: &Path) -> io::Result<()> {
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let mut stage = Staged {
        path: parent.join(format!(
            ".broker-native-build-{}-{stamp}",
            std::process::id()
        )),
        pending: false,
    };
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut destination = options.open(&stage.path)?;
    stage.pending = true;
    let mut source = fs::File::open(artifact)?;
    io::copy(&mut source, &mut destination)?;
    destination.set_permissions(source.metadata()?.permissions())?;
    destination.sync_all()?;
    drop(source);
    drop(destination);
    // Replacing the destination entry also handles absolute, symlink and hardlink
    // aliases without ever truncating the Cargo artifact being read.
    fs::rename(&stage.path, output)?;
    stage.pending = false;
    Ok(())
}

// Cargo documents one JSON object per stdout line, including compiler-artifact.executable.
// Keep diagnostics on stderr and retain/reap the process before any result is published.
fn artifact(reader: impl BufRead) -> io::Result<PathBuf> {
    let mut executable = None;
    let mut invalid = false;
    for line in reader.lines() {
        let line = line?;
        if !line.starts_with('{') {
            continue;
        }
        let message: serde_json::Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => {
                invalid = true;
                continue;
            }
        };
        if message["reason"] != "compiler-artifact"
            || message["target"]["name"] != "graphit-broker"
            || message["target"]["kind"] != serde_json::json!(["bin"])
        {
            continue;
        }
        let Some(path) = message["executable"]
            .as_str()
            .filter(|path| !path.is_empty())
        else {
            invalid = true;
            continue;
        };
        if executable.replace(PathBuf::from(path)).is_some() {
            invalid = true;
        }
    }
    if invalid {
        return Err(io::Error::other("invalid Cargo Broker artifact output"));
    }
    executable.ok_or_else(|| io::Error::other("Cargo did not produce the Broker executable"))
}

fn build_with_target(debug: bool, output: &Path, native: bool) -> io::Result<()> {
    let target = env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| "target".into());
    let mut command = Command::new("cargo");
    command.args([
        "build",
        "--locked",
        "-p",
        "broker-server",
        "--bin",
        "graphit-broker",
        "--message-format=json-render-diagnostics",
        "--target-dir",
    ]);
    command.arg(&target);
    if native {
        command.args(["--target", "host-tuple"]);
    }
    if !debug {
        command.arg("--release");
    }
    let mut child = command.stdout(Stdio::piped()).spawn()?;
    let captured = match child.stdout.take() {
        Some(stdout) => artifact(BufReader::new(stdout)),
        None => Err(io::Error::other("Cargo artifact stream unavailable")),
    };
    // Parsing drains stdout. If its I/O failed, dropping the reader closes the pipe;
    // Cargo still has to be reaped, and no possibly stale artifact can be published.
    let status = child.wait()?;
    if !status.success() {
        return Err(io::Error::other("native Broker build failed"));
    }
    publish(&captured?, output)
}

pub fn build(debug: bool, output: &Path) -> io::Result<()> {
    build_with_target(debug, output, false)
}

pub(crate) fn build_native(debug: bool, output: &Path) -> io::Result<()> {
    build_with_target(debug, output, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn cargo_artifact_is_selected_by_productive_bin_not_target_layout() {
        let input = concat!(
            "external build tool output\n",
            r#"{"reason":"compiler-artifact","target":{"name":"other","kind":["bin"]},"executable":"wrong"}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"graphit-broker","kind":["bin"]},"executable":"/configured-target/host/debug/graphit-broker","fresh":true}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
            "\n"
        );
        assert_eq!(
            artifact(Cursor::new(input)).unwrap(),
            PathBuf::from("/configured-target/host/debug/graphit-broker")
        );
        for invalid in [
            "",
            "{broken}\n",
            r#"{"reason":"compiler-artifact","target":{"name":"graphit-broker","kind":["bin"]},"executable":null}"#,
        ] {
            assert!(artifact(Cursor::new(invalid)).is_err());
        }
        let duplicate = input.to_owned() + input;
        assert!(artifact(Cursor::new(duplicate)).is_err());
    }
}
