#[path = "support/oidc_http.rs"]
#[allow(dead_code, reason = "shared native configuration and key fixture")]
mod http;
#[path = "../../broker-control/tests/support/oidc_exchange.rs"]
#[allow(
    dead_code,
    reason = "shared genuine PostgreSQL fixture supports other protocol suites"
)]
mod oidc;
#[path = "../../broker-control/tests/support/mod.rs"]
#[allow(
    dead_code,
    reason = "shared TLS fixture supports independent SQL contracts"
)]
mod support;

use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use support::deadline;

fn docker(args: &[&str]) -> Output {
    Command::new("docker")
        .args(args)
        .output()
        .expect("Docker executable required")
}
fn success(args: &[&str], phase: &str) -> String {
    let result = docker(args);
    assert!(
        result.status.success(),
        "owned container phase failed: {phase}"
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}
fn inspect(name: &str) -> Value {
    serde_json::from_str(&success(&["inspect", name], "inspect")).unwrap()
}
struct Owned {
    image: String,
    built: bool,
    volume: String,
    containers: Vec<String>,
}
fn remove(args: &[&str]) -> bool {
    Command::new("docker")
        .args(args)
        .output()
        .is_ok_and(|result| result.status.success())
}
fn absent(kind: &str, name: &str) -> bool {
    let mut command = Command::new("docker");
    if kind != "container" {
        command.arg(kind);
    }
    command.args(["inspect", name]);
    command.output().is_ok_and(|result| {
        let error = String::from_utf8_lossy(&result.stderr);
        !result.status.success()
            && error.contains(name)
            && error.to_ascii_lowercase().contains(match kind {
                "volume" => "no such volume",
                "image" => "no such image",
                _ => "no such object",
            })
    })
}
impl Owned {
    fn cleanup(&mut self) {
        let mut error = None;
        for name in std::mem::take(&mut self.containers).into_iter().rev() {
            let removed = remove(&["rm", "--force", "--volumes", &name]);
            let missing = absent("container", &name);
            if !(removed && missing) {
                self.containers.push(name);
                error.get_or_insert("container");
            }
        }
        if !self.volume.is_empty() {
            let removed = remove(&["volume", "rm", &self.volume]);
            let missing = absent("volume", &self.volume);
            if removed && missing {
                self.volume.clear();
            } else {
                error.get_or_insert("volume");
            }
        }
        if self.built {
            let removed = remove(&["image", "rm", &self.image]);
            let missing = absent("image", &self.image);
            if removed && missing {
                self.built = false;
            } else {
                error.get_or_insert("image");
            }
        }
        if let Some(phase) = error {
            panic!("owned {phase} cleanup/absence failed");
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        for name in &self.containers {
            let _ = remove(&["rm", "--force", "--volumes", name]);
        }
        if !self.volume.is_empty() {
            let _ = remove(&["volume", "rm", &self.volume]);
        }
        if self.built {
            let _ = remove(&["image", "rm", &self.image]);
        }
    }
}
fn create(owned: &mut Owned, suffix: &str, args: &[&str]) -> String {
    let name = format!("{}-{suffix}", owned.volume);
    let mount = format!("{}:/home/graphit/.graphit/broker", owned.volume);
    let mut command = vec![
        "create",
        "--name",
        name.as_str(),
        "--network",
        "host",
        "--volume",
        &mount,
    ];
    command.extend_from_slice(args);
    command.push(&owned.image);
    owned.containers.push(name.clone());
    success(&command, "create");
    name
}
fn copy(source: &Path, container: &str, destination: &str) {
    let source = source.to_str().unwrap();
    let destination = format!("{container}:{destination}");
    success(&["cp", source, &destination], "copy owned fixture");
}
async fn ready(address: std::net::SocketAddr, name: &str) {
    let end = deadline();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    loop {
        if client
            .get(format!("http://{address}/readyz"))
            .send()
            .await
            .is_ok_and(|v| v.status().is_success())
        {
            break;
        }
        assert_eq!(
            inspect(name)[0]["State"]["Running"],
            true,
            "native container stopped before readiness"
        );
        assert!(Instant::now() < end, "native container readiness deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
async fn exited(name: &str, expected: i64) {
    let end = deadline();
    loop {
        let status = inspect(name);
        if status[0]["State"]["Running"] == false {
            assert_eq!(
                status[0]["State"]["ExitCode"], expected,
                "native container exit status"
            );
            return;
        }
        assert!(Instant::now() < end, "native container did not terminate");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "actual native image and owned PostgreSQL TLS NOSUPERUSER fixture"]
async fn broker_native_container_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let context = tempfile::tempdir().unwrap();
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let external = std::env::var("GRAPHIT_BROKER_CONTAINER_IMAGE").ok();
    let image = external
        .clone()
        .unwrap_or_else(|| format!("graphit-broker-native-ci:{nonce}"));
    let mut owned = Owned {
        image,
        built: external.is_none(),
        volume: format!("broker-native-{nonce}"),
        containers: Vec::new(),
    };
    if external.is_none() {
        for file in ["Dockerfile", ".dockerignore", "docker-entrypoint.sh"] {
            fs::copy(root.join(file), context.path().join(file)).unwrap();
        }
        let package = std::env::var_os("GRAPHIT_BROKER_CONTAINER_PACKAGE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| root.join("installer-package/graphit-broker-linux-amd64.tar.gz"));
        assert!(
            package.is_file(),
            "prepare the real installer package before the container test: xtask package \
             --binary PATH --output installer-package; alternatively set \
             GRAPHIT_BROKER_CONTAINER_PACKAGE to its Linux archive"
        );
        let package_dir = context.path().join("installer-package");
        fs::create_dir(&package_dir).unwrap();
        fs::copy(
            package,
            package_dir.join("graphit-broker-linux-amd64.tar.gz"),
        )
        .unwrap();
        success(
            &[
                "build",
                "--tag",
                &owned.image,
                context.path().to_str().unwrap(),
            ],
            "native image build",
        );
    }
    success(&["volume", "create", &owned.volume], "volume create");
    let image_state: Value = serde_json::from_str(&success(
        &["image", "inspect", &owned.image],
        "image inspect",
    ))
    .unwrap();
    assert_eq!(image_state[0]["Config"]["User"], "graphit:graphit");
    assert_eq!(
        image_state[0]["Config"]["WorkingDir"],
        "/home/graphit/.graphit/broker"
    );
    assert_eq!(
        image_state[0]["Config"]["Volumes"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert!(
        image_state[0]["Config"]["Volumes"]
            .get("/var/lib/graphit/hub")
            .is_some()
    );
    let environment = image_state[0]["Config"]["Env"].as_array().unwrap();
    assert!(
        environment
            .iter()
            .any(|v| v == "GRAPHIT_GLOBAL_DIR=/home/graphit/.graphit")
    );
    assert!(
        environment
            .iter()
            .any(|v| v == "GRAPHIT_BROKER_CONFIG=/home/graphit/.graphit/broker/config.yaml")
    );
    assert!(!environment.iter().any(|v| v.as_str().is_some_and(|s| {
        s.starts_with("BROKER_DATABASE_DSN=") || s.starts_with("BROKER_MODELS_DIRECTORY=")
    })));
    // Missing configuration must fail before a productive service is admitted.
    let missing = create(&mut owned, "missing", &[]);
    success(&["start", &missing], "start missing configuration");
    exited(&missing, 1).await;
    let mut f = oidc::OidcFixture::new().await;
    let files = tempfile::tempdir().unwrap();
    let address = http::address();
    let issuer = http::files(files.path(), &f.fixture.ca, &format!("http://{address}"));
    http::write(files.path(), &http::yaml(address, f.fixture.port));
    let health_url =
        format!("GRAPHIT_BROKER_HEALTHCHECK_URL=http://{address}/readyz?native-container=1");
    let server = create(
        &mut owned,
        "server",
        &[
            "--env",
            &health_url,
            "--health-interval",
            "1s",
            "--health-start-period",
            "1s",
        ],
    );
    for file in ["config.yaml", "signing.pk8", "ca.pem"] {
        copy(
            &files.path().join(file),
            &server,
            &format!("/home/graphit/.graphit/broker/{file}"),
        );
    }
    success(
        &[
            "run",
            "--rm",
            "--user",
            "0:0",
            "--entrypoint",
            "/bin/chown",
            "--volume",
            &format!("{}:/home/graphit/.graphit/broker", owned.volume),
            &owned.image,
            "-R",
            "10001:10001",
            "/home/graphit/.graphit/broker",
        ],
        "own fixture permissions",
    );
    let hooks = files.path().join("hooks");
    fs::create_dir_all(hooks.join("init.d")).unwrap();
    fs::create_dir_all(hooks.join("pre-start.d")).unwrap();
    fs::write(
        hooks.join("init.d/10-order.sh"),
        "#!/bin/sh\nset -eu\nprintf 'init\\n' > \"$GRAPHIT_GLOBAL_DIR/broker/hooks.trace\"\n",
    )
    .unwrap();
    fs::write(hooks.join("pre-start.d/20-order.sh"), "#!/bin/sh\nset -eu\ntest \"$(cat \"$GRAPHIT_GLOBAL_DIR/broker/hooks.trace\")\" = init\nprintf 'pre-start\\n' >> \"$GRAPHIT_GLOBAL_DIR/broker/hooks.trace\"\n").unwrap();
    copy(&hooks, &server, "/docker-entrypoint.d");
    success(&["start", &server], "native server start");
    ready(address, &server).await;
    assert_eq!(
        success(&["exec", &server, "id", "-u"], "native UID"),
        "10001"
    );
    assert_eq!(
        success(&["exec", &server, "id", "-g"], "native GID"),
        "10001"
    );
    assert_eq!(
        success(
            &[
                "exec",
                &server,
                "cat",
                "/home/graphit/.graphit/broker/hooks.trace"
            ],
            "hook order"
        ),
        "init\npre-start"
    );
    for route in ["healthz", "readyz"] {
        let result = reqwest::get(format!("http://{address}/{route}"))
            .await
            .unwrap();
        assert_eq!(result.status(), 200);
        assert!(
            docker(&[
                "exec",
                &server,
                "env",
                "-u",
                "GRAPHIT_BROKER_CONFIG",
                "/usr/local/bin/graphit-broker",
                "--healthcheck",
                &format!("http://{address}/{route}")
            ])
            .status
            .success()
        );
    }
    let end = deadline();
    loop {
        let state = inspect(&server);
        if state[0]["State"]["Health"]["Status"] == "healthy" {
            break;
        }
        assert!(
            Instant::now() < end,
            "actual configured image healthcheck never became healthy"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let keys: Value = serde_json::from_slice(
        &reqwest::get(format!("http://{address}/v1/oidc/keys"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(keys, serde_json::to_value(issuer.jwks()).unwrap());
    let code = f.code(true, true).await;
    let before = f.token_count().await;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", "web-client")
        .append_pair("code", code.code())
        .append_pair("redirect_uri", "https://client.example/cb")
        .append_pair("code_verifier", oidc::VERIFIER)
        .append_pair("resource", oidc::RESOURCE)
        .finish();
    let exchanged = reqwest::Client::new()
        .post(format!("http://{address}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(exchanged.status(), 200);
    let tokens: Value = serde_json::from_slice(&exchanged.bytes().await.unwrap()).unwrap();
    let access = tokens["access_token"].as_str().unwrap();
    let verifier = broker_control::BrokerAccessVerifier::new(
        &format!("http://{address}"),
        oidc::AUDIENCE,
        None,
        issuer.jwks(),
        support::n(8192),
    )
    .unwrap();
    assert!(verifier.verify(access, &[], deadline()).is_ok());
    assert_eq!(f.token_count().await, before + 2);
    // ENTRYPOINT must exec the native process as PID1 so both signals arrive.
    assert_eq!(
        success(&["exec", &server, "cat", "/proc/1/comm"], "native PID1"),
        "graphit-broker"
    );
    for signal in ["SIGTERM", "SIGINT"] {
        success(
            &["kill", "--signal", signal, &server],
            "native shutdown signal",
        );
        exited(&server, 0).await;
        assert!(
            reqwest::get(format!("http://{address}/readyz"))
                .await
                .is_err(),
            "listener survived shutdown"
        );
        if signal == "SIGTERM" {
            success(&["start", &server], "native restart");
            ready(address, &server).await;
        }
    }
    for (phase, code) in [("init.d", 42), ("pre-start.d", 43)] {
        let failed = create(&mut owned, &format!("fail-{code}"), &[]);
        let hook_root = tempfile::tempdir().unwrap();
        let directory = hook_root.path().join("entry");
        fs::create_dir_all(directory.join(phase)).unwrap();
        fs::write(
            directory.join(phase).join("10-fail.sh"),
            format!("#!/bin/sh\nexit {code}\n"),
        )
        .unwrap();
        copy(&directory, &failed, "/docker-entrypoint.d");
        success(&["start", &failed], "start failing hook");
        exited(&failed, code).await;
    }
    // Permission failures remain explicit under the real unprivileged identity.
    let blocked = create(
        &mut owned,
        "blocked",
        &["--env", "GRAPHIT_GLOBAL_DIR=/root/blocked"],
    );
    success(&["start", &blocked], "start blocked directory");
    exited(&blocked, 1).await;
    f.close().await;
    owned.cleanup();
}
