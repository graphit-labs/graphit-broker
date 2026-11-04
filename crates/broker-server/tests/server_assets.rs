use rcgen::KeyPair;
use std::{path::Path, process::Stdio, time::Duration};
use tokio::process::Command;

fn private(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).unwrap().write_all(bytes).unwrap();
}

fn sample(root: &Path, source: &str) -> String {
    source
        .replace(
            "\"${BROKER_PEPPER:?required}\"",
            "ephemeral-asset-fixture-pepper-32bytes",
        )
        .replace(
            "\"${BROKER_DATABASE_PASSWORD:?required}\"",
            "ephemeral-owner",
        )
        .replace("postgres-ca.pem", "ca.pem")
        .replace(
            "\"${BROKER_DATABASE_PATH:?supply a private SQLite file path}\"",
            &format!("{:?}", root.join("private/broker.db")),
        )
        .replace(
            "\"${BROKER_SIGNING_KEY:?supply an Ed25519 PKCS8 signing-key file}\"",
            "signing.pk8",
        )
}

#[tokio::test]
async fn native_samples_and_favicon_are_served_by_the_real_executable() {
    let root = tempfile::tempdir().unwrap();
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    private(&root.path().join("signing.pk8"), &key.serialize_der());
    let cert = rcgen::generate_simple_self_signed(vec!["postgres.example.test".into()]).unwrap();
    private(&root.path().join("ca.pem"), cert.cert.pem().as_bytes());
    let address = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let health = sample(
        root.path(),
        include_str!("../../../examples/health-only.yaml"),
    )
    .replace("127.0.0.1:8080", &address.to_string());
    let config = root.path().join("broker.yaml");
    for (name, text) in [
        (
            "postgres",
            sample(root.path(), include_str!("../../../config.example.yaml")),
        ),
        ("health", health.clone()),
        (
            "local-schema-disabled",
            sample(
                root.path(),
                include_str!("../../../examples/local-models.yaml"),
            )
            .replace("enabled: true", "enabled: false")
            .replace(
                "${BROKER_EMBEDDING_MODEL:?supply the exact typed manifest ID}",
                "explicit-embedding",
            )
            .replace(
                "${BROKER_RERANK_MODEL:?supply the exact typed manifest ID}",
                "explicit-rerank",
            )
            .replace(
                "${BROKER_EMBEDDING_BUNDLE:?supply a provisioned bundle directory}",
                "/not-opened/embedding",
            )
            .replace(
                "${BROKER_RERANK_BUNDLE:?supply a provisioned bundle directory}",
                "/not-opened/rerank",
            )
            .replace(
                "${BROKER_EMBEDDING_MANIFEST:?supply the typed manifest file}",
                "/not-opened/embedding.json",
            )
            .replace(
                "${BROKER_RERANK_MANIFEST:?supply the typed manifest file}",
                "/not-opened/rerank.json",
            ),
        ),
    ] {
        private(&config, text.as_bytes());
        let checked = Command::new(env!("CARGO_BIN_EXE_graphit-broker"))
            .arg("--config")
            .arg(&config)
            .arg("--check-config")
            .output()
            .await
            .unwrap();
        assert!(
            checked.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        assert_eq!(checked.stdout, b"configuration valid\n");
        assert!(!root.path().join("private/broker.db").exists());
    }
    private(&config, health.as_bytes());
    let mut child = Command::new(env!("CARGO_BIN_EXE_graphit-broker"))
        .env("GRAPHIT_GLOBAL_DIR", root.path().join("global"))
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            assert!(
                child.try_wait().unwrap().is_none(),
                "Broker exited before readiness"
            );
            if client
                .get(format!("http://{address}/readyz"))
                .send()
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
        let response = client
            .request(method.clone(), format!("http://{address}/favicon.svg"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "image/svg+xml; charset=utf-8"
        );
        assert_eq!(
            response.headers()["cache-control"],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let body = response.bytes().await.unwrap();
        if method == reqwest::Method::HEAD {
            assert!(body.is_empty());
        } else {
            assert_eq!(body.as_ref(), include_bytes!("../assets/favicon.svg"));
        }
    }
    #[cfg(unix)]
    {
        assert!(
            std::process::Command::new("kill")
                .args(["-TERM", &child.id().unwrap().to_string()])
                .status()
                .unwrap()
                .success()
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(8), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
    #[cfg(not(unix))]
    {
        child.kill().await.unwrap();
        child.wait().await.unwrap();
    }
}

#[test]
#[ignore = "native installer qualification uses OS packaging tools"]
#[cfg(any(
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64")
))]
fn unix_installer_checks_real_archive_and_preserves_previous_binary() {
    use sha2::{Digest, Sha256};
    use std::{fs, io::Read, os::unix::fs::PermissionsExt, process::Command};
    let root = tempfile::tempdir().unwrap();
    let platform = if cfg!(target_os = "macos") {
        "darwin-arm64"
    } else {
        "linux-amd64"
    };
    let entry = format!("graphit-broker-{platform}/graphit-broker");
    let archive_name = format!("graphit-broker-{platform}.tar.gz");
    let source = root.path().join("source");
    fs::create_dir_all(source.join(format!("graphit-broker-{platform}"))).unwrap();
    fs::copy(env!("CARGO_BIN_EXE_graphit-broker"), source.join(&entry)).unwrap();
    let notices = [
        "graphit-runtime/licenses/broker/LICENSE",
        "graphit-runtime/licenses/broker/ggml/LICENSE",
        "graphit-runtime/licenses/broker/ggml/LICENSE-MIT",
        "graphit-runtime/licenses/broker/ggml/LICENSE-APACHE",
        "graphit-runtime/licenses/broker/nvidia/LICENSE",
        "graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp",
    ];
    for notice in notices {
        let file = source.join(format!("graphit-broker-{platform}/{notice}"));
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, format!("controlled installer notice: {notice}\n")).unwrap();
    }
    // This controlled archive exercises installation, not native dependency
    // closure (the release packager validates that independently).
    let mut input = fs::File::open(source.join(&entry)).unwrap();
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = input.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let executable_hash: String = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let runtime_manifest = format!(
        "graphit-runtime/broker/{}-libraries.json",
        if cfg!(target_os = "macos") {
            "macos"
        } else {
            "linux"
        }
    );
    let manifest = if cfg!(target_os = "macos") {
        serde_json::json!({"platform":platform,"executables":[{"file":"graphit-broker","sha256":executable_hash}],"libraries":[]})
    } else {
        serde_json::json!({"schema_version":1,"executable":{"file":"graphit-broker","input_sha256":executable_hash,"sha256":executable_hash},"files":[]})
    };
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_path = source.join(format!("graphit-broker-{platform}/{runtime_manifest}"));
    fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
    fs::write(&manifest_path, &manifest_bytes).unwrap();
    let archive = root.path().join("archive");
    assert!(
        Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&source)
            .arg(&entry)
            .args(notices.map(|notice| format!("graphit-broker-{platform}/{notice}")))
            .arg(format!("graphit-broker-{platform}/{runtime_manifest}"))
            .status()
            .unwrap()
            .success()
    );
    let hash = if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(&archive)
            .output()
            .unwrap()
    } else {
        Command::new("sha256sum").arg(&archive).output().unwrap()
    };
    assert!(hash.status.success());
    let digest = std::str::from_utf8(&hash.stdout)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    let shims = root.path().join("shims");
    fs::create_dir(&shims).unwrap();
    let shim = r#"#!/bin/sh
set -eu
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;;
    https:*) url=$1; shift ;;
    *) shift ;;
  esac
done
case "$url" in
  "https://github.com/graphit-labs/graphit-broker/releases/download/v1.2.0/$TEST_ARCHIVE_NAME") cp "$TEST_FIXTURE_DIR/archive" "$out" ;;
  "https://github.com/graphit-labs/graphit-broker/releases/download/v1.2.0/$TEST_CHECKSUM_NAME") cp "$TEST_FIXTURE_DIR/checksum" "$out" ;;
  *) exit 1 ;;
esac
"#;
    fs::write(shims.join("curl"), shim).unwrap();
    fs::set_permissions(shims.join("curl"), fs::Permissions::from_mode(0o700)).unwrap();
    let mut paths = vec![shims];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let path = std::env::join_paths(paths).unwrap();
    for bad_hash in [false, true] {
        let destination = root.path().join(if bad_hash {
            "bad-checksum"
        } else {
            "valid-checksum"
        });
        fs::create_dir(&destination).unwrap();
        let installed = destination.join("graphit-broker");
        fs::write(&installed, b"previous-installed-bytes").unwrap();
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            root.path().join("checksum"),
            format!(
                "{}  {archive_name}\n",
                if bad_hash {
                    "0000000000000000000000000000000000000000000000000000000000000000"
                } else {
                    digest
                }
            ),
        )
        .unwrap();
        let output = Command::new("sh")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh"))
            .arg("--dir")
            .arg(&destination)
            .args(["--version", "v1.2.0"])
            .env("PATH", &path)
            .env("TEST_FIXTURE_DIR", root.path())
            .env("TEST_ARCHIVE_NAME", &archive_name)
            .env(
                "TEST_CHECKSUM_NAME",
                format!("graphit-broker-{platform}.sha256"),
            )
            .output()
            .unwrap();
        assert_eq!(
            output.status.success(),
            !bad_hash,
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if bad_hash {
            assert!(String::from_utf8_lossy(&output.stderr).contains("archive SHA-256 mismatch"));
            assert_eq!(fs::read(&installed).unwrap(), b"previous-installed-bytes");
        } else {
            assert_eq!(
                fs::read(&installed).unwrap(),
                fs::read(env!("CARGO_BIN_EXE_graphit-broker")).unwrap()
            );
            assert_eq!(
                fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
                0o755
            );
            let version = Command::new(&installed).arg("--version").output().unwrap();
            assert!(version.status.success());
            assert_eq!(
                version.stdout,
                format!("graphit-broker {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
            );
        }
        for notice in notices {
            assert_eq!(destination.join(notice).exists(), !bad_hash);
        }
        if bad_hash {
            assert!(!destination.join(&runtime_manifest).exists());
        } else {
            assert_eq!(
                fs::read(destination.join(&runtime_manifest)).unwrap(),
                manifest_bytes
            );
        }
        assert_eq!(
            fs::read_dir(&destination).unwrap().count(),
            if bad_hash { 1 } else { 2 }
        );
    }
}
