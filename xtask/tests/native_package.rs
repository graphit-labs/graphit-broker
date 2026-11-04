#![cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "broker-native-package-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn verify(directory: &Path, basename: &str) -> bool {
    let checksum = format!("{basename}.sha256");
    let mut command = if cfg!(target_os = "macos") {
        let mut cmd = Command::new("shasum");
        cmd.args(["-a", "256"]);
        cmd
    } else {
        Command::new("sha256sum")
    };
    command
        .arg("-c")
        .arg(checksum)
        .current_dir(directory)
        .output()
        .unwrap()
        .status
        .success()
}
fn same_bytes(a: &Path, b: &Path) {
    let mut a = fs::File::open(a).unwrap();
    let mut b = fs::File::open(b).unwrap();
    let mut left = [0; 65536];
    let mut right = [0; 65536];
    loop {
        let n = a.read(&mut left).unwrap();
        let m = b.read(&mut right).unwrap();
        assert_eq!(n, m);
        assert_eq!(&left[..n], &right[..m]);
        if n == 0 {
            break;
        }
    }
}
const NOTICES: &[&str] = &[
    "graphit-runtime/licenses/broker/LICENSE",
    "graphit-runtime/licenses/broker/ggml/LICENSE",
    "graphit-runtime/licenses/broker/ggml/LICENSE-MIT",
    "graphit-runtime/licenses/broker/ggml/LICENSE-APACHE",
    "graphit-runtime/licenses/broker/nvidia/LICENSE",
    "graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp",
];

fn install_pair(fixture: &Path, package: &Path, destination: &Path) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    let tools = fixture.join("installer-tools");
    fs::create_dir_all(&tools).unwrap();
    let curl = tools.join("curl");
    fs::write(&curl, "#!/bin/sh\nset -eu\nfor arg do out=$arg; case $arg in https://*) url=$arg ;; esac; done\ncase $url in *.sha256) cp \"$FIXTURE_SHA\" \"$out\" ;; *.tar.gz) cp \"$FIXTURE_ARCHIVE\" \"$out\" ;; *) exit 44 ;; esac\n").unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
    let platform = if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-amd64"
    };
    Command::new("sh")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../install.sh"))
        .arg("--dir")
        .arg(destination)
        .args(["--version", &format!("v{}", env!("CARGO_PKG_VERSION"))])
        .env(
            "PATH",
            format!("{}:{}", tools.display(), std::env::var("PATH").unwrap()),
        )
        .env(
            "FIXTURE_ARCHIVE",
            package.join(format!("graphit-broker-{platform}.tar.gz")),
        )
        .env(
            "FIXTURE_SHA",
            package.join(format!("graphit-broker-{platform}.sha256")),
        )
        .output()
        .unwrap()
}

#[test]
#[ignore = "native package qualification uses OS packaging tools"]
fn existing_binary_package_preserves_bytes_and_rejects_invalid_inputs() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    let binary = fixture.0.join("qualified-broker");
    let bytes = format!(
        "#!/bin/sh\n[ \"$1\" = --version ] || exit 7\nprintf 'graphit-broker {}\n'\n",
        env!("CARGO_PKG_VERSION")
    );
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        let source = fixture.0.join("broker.cpp");
        fs::write(&source, format!("#include <iostream>\n#include <cstring>\nint main(int argc, char **argv) {{ if(argc != 2 || std::strcmp(argv[1], \"--version\")) return 7; std::cout << \"graphit-broker {}\\n\"; }}\n", env!("CARGO_PKG_VERSION"))).unwrap();
        assert!(
            Command::new("c++")
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .status()
                .unwrap()
                .success()
        );
    } else {
        fs::write(&binary, bytes.as_bytes()).unwrap();
    }
    let original = fs::read(&binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
    let package = |args: &[&std::ffi::OsStr]| {
        Command::new(env!("CARGO_BIN_EXE_xtask"))
            .arg("package")
            .args(args)
            .current_dir(&fixture.0)
            // The supplied-binary path resolves source notices but never rebuilds.
            .output()
            .unwrap()
    };
    let output_flag = std::ffi::OsStr::new("--output");
    let binary_flag = std::ffi::OsStr::new("--binary");
    let a = fixture.0.join("a");
    let b = fixture.0.join("b");
    let platform = if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-amd64"
    };
    let basename = format!("graphit-broker-{platform}");
    let filename = format!("{basename}.tar.gz");
    for (input, output) in [(binary.as_os_str(), &a), (binary.file_name().unwrap(), &b)] {
        let result = package(&[binary_flag, input, output_flag, output.as_os_str()]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_dir(output).unwrap().count(), 2);
        assert!(verify(output, &basename));
        let decoder = flate2::read::GzDecoder::new(fs::File::open(output.join(&filename)).unwrap());
        let mut tar = tar::Archive::new(decoder);
        let mut entries = tar.entries().unwrap();
        let mut entry = entries.next().unwrap().unwrap();
        assert_eq!(
            entry.path().unwrap(),
            Path::new(&format!("{basename}/graphit-broker"))
        );
        assert!(entry.header().entry_type().is_file());
        assert_eq!(entry.header().mode().unwrap(), 0o755);
        assert_eq!(entry.header().uid().unwrap(), 0);
        assert_eq!(entry.header().gid().unwrap(), 0);
        assert_eq!(entry.header().mtime().unwrap(), 0);
        let mut archived = Vec::new();
        entry.read_to_end(&mut archived).unwrap();
        if cfg!(target_os = "linux") {
            assert_ne!(archived, original);
        }
        let mut payloads = std::collections::BTreeMap::new();
        for entry in entries {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().into_owned();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            assert!(payloads.insert(path, bytes).is_none());
        }
        for expected in NOTICES {
            let notice = String::from_utf8(
                payloads
                    .remove(&Path::new(&basename).join(expected))
                    .unwrap(),
            )
            .unwrap();
            assert!(!notice.is_empty());
            if *expected == "graphit-runtime/licenses/broker/LICENSE" {
                assert_eq!(
                    notice,
                    fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../LICENSE"))
                        .unwrap()
                );
            }
        }
        if cfg!(target_os = "linux") {
            let manifest: serde_json::Value = serde_json::from_slice(
                payloads
                    .get(&Path::new(&basename).join("graphit-runtime/broker/linux-libraries.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                manifest["executable"]["runpath"],
                "$ORIGIN/graphit-runtime/broker/lib"
            );
            assert!(
                manifest["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|file| file["file"].as_str().unwrap().ends_with("libstdc++.so.6"))
            );
        } else {
            let manifest: serde_json::Value = serde_json::from_slice(
                payloads
                    .get(&Path::new(&basename).join("graphit-runtime/broker/macos-libraries.json"))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(manifest["platform"], "darwin-arm64");
            assert_eq!(manifest["executables"][0]["file"], "graphit-broker");
        }
    }
    same_bytes(&a.join(&filename), &b.join(&filename));
    let installed = fixture.0.join("CPU install α");
    let result = install_pair(&fixture.0, &a, &installed);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(&binary).unwrap(),
        original,
        "packaging must not mutate input"
    );
    let version = Command::new(installed.join("graphit-broker"))
        .arg("--version")
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .output()
        .unwrap();
    assert!(version.status.success());
    assert_eq!(
        version.stdout,
        format!("graphit-broker {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    for name in NOTICES {
        assert!(installed.join(name).is_file());
    }
    assert!(!installed.join("libggml-cuda.so").exists());
    assert!(
        !package(&[binary_flag, binary.as_os_str(), output_flag, a.as_os_str()])
            .status
            .success()
    );
    same_bytes(&a.join(&filename), &b.join(&filename));
    let rejected = fixture.0.join("rejected");
    for args in [
        vec![binary_flag],
        vec![binary_flag, std::ffi::OsStr::new("")],
        vec![
            binary_flag,
            binary.as_os_str(),
            binary_flag,
            binary.as_os_str(),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![
            binary_flag,
            binary.as_os_str(),
            std::ffi::OsStr::new("--debug"),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![
            std::ffi::OsStr::new("--debug"),
            binary_flag,
            binary.as_os_str(),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![
            binary_flag,
            binary.as_os_str(),
            output_flag,
            rejected.as_os_str(),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![std::ffi::OsStr::new("--cargo-artifacts")],
        vec![
            std::ffi::OsStr::new("--cargo-artifacts"),
            std::ffi::OsStr::new("missing.jsonl"),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![
            binary_flag,
            binary.as_os_str(),
            std::ffi::OsStr::new("--cargo-artifacts"),
            std::ffi::OsStr::new("missing.jsonl"),
            output_flag,
            rejected.as_os_str(),
        ],
        vec![std::ffi::OsStr::new("--unknown")],
    ] {
        assert!(!package(&args).status.success());
        assert!(!rejected.exists());
    }
    for input in [fixture.0.join("missing"), fixture.0.clone()] {
        assert!(
            !package(&[
                binary_flag,
                input.as_os_str(),
                output_flag,
                rejected.as_os_str()
            ])
            .status
            .success()
        );
        assert!(!rejected.exists());
    }
    for contents in [
        "#!/bin/sh\nexit 1\n".to_owned(),
        "#!/bin/sh\nprintf 'graphit-broker wrong\n'\n".to_owned(),
        format!("{bytes}printf error >&2\n"),
    ] {
        fs::write(&binary, contents).unwrap();
        assert!(
            !package(&[
                binary_flag,
                binary.as_os_str(),
                output_flag,
                rejected.as_os_str()
            ])
            .status
            .success()
        );
        assert!(!rejected.exists());
    }
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        !package(&[
            binary_flag,
            binary.as_os_str(),
            output_flag,
            rejected.as_os_str()
        ])
        .status
        .success()
    );
    assert!(fs::read_dir(&fixture.0).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".broker-native-package-")
    }));
}

#[test]
#[ignore = "real native Cargo build, installer tar/checksum extraction and executable validation"]
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
fn native_package_matches_installer_and_preserves_previous_output() {
    let fixture = Fixture::new();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let a = fixture.0.join("a");
    let b = fixture.0.join("b");
    let platform = if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-amd64"
    };
    let basename = format!("graphit-broker-{platform}");
    let entry = format!("{basename}/graphit-broker");
    let filename = format!("{basename}.tar.gz");
    for directory in [&a, &b] {
        let result = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["package", "--debug", "--output"])
            .arg(directory)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read_dir(directory).unwrap().count(), 2);
        assert!(verify(directory, &basename));
        let listing = Command::new("tar")
            .arg("-tzf")
            .arg(directory.join(&filename))
            .output()
            .unwrap();
        assert!(listing.status.success());
        let expected = std::iter::once(entry.clone())
            .chain(NOTICES.iter().map(|name| format!("{basename}/{name}")))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        let listing = String::from_utf8(listing.stdout).unwrap();
        {
            for required in expected.lines() {
                assert!(listing.lines().any(|member| member == required));
            }
            let manifest = if cfg!(target_os = "linux") {
                "linux"
            } else {
                "macos"
            };
            assert!(listing.contains(&format!(
                "{basename}/graphit-runtime/broker/{manifest}-libraries.json"
            )));
        }
        let decoder =
            flate2::read::GzDecoder::new(fs::File::open(directory.join(&filename)).unwrap());
        let mut archive = tar::Archive::new(decoder);
        let mut entries = archive.entries().unwrap();
        let file = entries.next().unwrap().unwrap();
        assert_eq!(file.path().unwrap(), Path::new(&entry));
        let header = file.header();
        assert!(header.entry_type().is_file());
        assert_eq!(header.mode().unwrap(), 0o755);
        assert_eq!(header.uid().unwrap(), 0);
        assert_eq!(header.gid().unwrap(), 0);
        assert_eq!(header.mtime().unwrap(), 0);
        assert_eq!(entries.count(), listing.lines().count() - 1);
        let extract = directory.join("extract");
        fs::create_dir(&extract).unwrap();
        let unpacked = Command::new("tar")
            .arg("-xzf")
            .arg(directory.join(&filename))
            .arg("-C")
            .arg(&extract)
            .status()
            .unwrap();
        assert!(unpacked.success());
        let version = Command::new(extract.join(&entry))
            .arg("--version")
            .output()
            .unwrap();
        assert!(version.status.success());
        assert_eq!(
            version.stdout,
            format!("graphit-broker {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
        );
        assert!(version.stderr.is_empty());
        fs::remove_dir_all(extract).unwrap();
    }
    same_bytes(&a.join(&filename), &b.join(&filename));
    same_bytes(
        &a.join(format!("{basename}.sha256")),
        &b.join(format!("{basename}.sha256")),
    );
    let failed = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["package", "--debug", "--output"])
        .arg(&a)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    same_bytes(&a.join(&filename), &b.join(&filename));
    assert!(verify(&a, &basename));
    assert!(fs::read_dir(&fixture.0).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".broker-native-package-")
    }));
    let damaged = fixture.0.join("corrupt");
    fs::create_dir(&damaged).unwrap();
    fs::copy(a.join(&filename), damaged.join(&filename)).unwrap();
    fs::copy(
        a.join(format!("{basename}.sha256")),
        damaged.join(format!("{basename}.sha256")),
    )
    .unwrap();
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(damaged.join(&filename))
        .unwrap();
    let mut byte = [0; 1];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(!verify(&damaged, &basename));
}
