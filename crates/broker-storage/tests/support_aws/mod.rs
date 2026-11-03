use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeroize::Zeroizing;

pub struct Minio {
    child: Child,
    folder: TempDir,
    root_key: Zeroizing<String>,
    root_secret: Zeroizing<String>,
    pub caller_key: Zeroizing<String>,
    pub caller_secret: Zeroizing<String>,
    pub endpoint: String,
    pub bucket: String,
}
fn random(prefix: &str) -> Zeroizing<String> {
    let mut bytes = Zeroizing::new([0u8; 24]);
    getrandom::fill(bytes.as_mut()).expect("fixture randomness unavailable");
    Zeroizing::new(format!(
        "{prefix}{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}
impl Minio {
    /// Confirm the owned child has exited and was reaped before acknowledging IPC shutdown.
    pub fn shutdown(&mut self) -> std::io::Result<()> {
        if self.child.try_wait()?.is_none()
            && let Err(error) = self.child.kill()
            && self.child.try_wait()?.is_none()
        {
            return Err(error);
        }
        self.child.wait().map(|_| ())
    }
    pub async fn start() -> Self {
        let folder = tempfile::Builder::new()
            .prefix("owned-broker-sts-")
            .tempdir()
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let endpoint = format!("http://127.0.0.1:{port}");
        let root_key = random("root");
        let root_secret = random("root-secret");
        let caller_key = random("caller");
        let caller_secret = random("caller-secret");
        let bucket = format!("graphit-sts-{}", &caller_key[6..18]);
        let child = Command::new("minio")
            .arg("server")
            .arg(folder.path().join("data"))
            .args([
                "--address",
                &format!("127.0.0.1:{port}"),
                "--console-address",
                "127.0.0.1:0",
                "--quiet",
            ])
            .env("MINIO_ROOT_USER", root_key.as_str())
            .env("MINIO_ROOT_PASSWORD", root_secret.as_str())
            .env("MINIO_BROWSER", "off")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start MinIO test tool (minio must be on PATH)");
        let mut fixture = Self {
            child,
            folder,
            root_key,
            root_secret,
            caller_key,
            caller_secret,
            endpoint,
            bucket,
        };
        let ready = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "owned MinIO exited before ready"
            );
            if fixture.run(&["ready", "fixture"]) {
                break;
            }
            assert!(Instant::now() < ready, "owned MinIO readiness deadline");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        fixture.admin(&["mb", &format!("fixture/{}", fixture.bucket)]);
        let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":[format!("arn:aws:s3:::{}",fixture.bucket),format!("arn:aws:s3:::{}/*",fixture.bucket)]}]});
        let path = fixture.folder.path().join("parent-policy.json");
        std::fs::write(&path, policy.to_string()).unwrap();
        fixture.admin(&[
            "admin",
            "policy",
            "create",
            "fixture",
            "fixture-parent",
            path.to_str().unwrap(),
        ]);
        fixture.admin(&[
            "admin",
            "user",
            "add",
            "fixture",
            fixture.caller_key.as_str(),
            fixture.caller_secret.as_str(),
        ]);
        fixture.admin(&[
            "admin",
            "policy",
            "attach",
            "fixture",
            "fixture-parent",
            "--user",
            fixture.caller_key.as_str(),
        ]);
        fixture
    }
    fn mc(&self, args: &[&str]) -> Command {
        let mut command = Command::new("mc");
        let host = self.endpoint.replacen(
            "http://",
            &format!(
                "http://{}:{}@",
                self.root_key.as_str(),
                self.root_secret.as_str()
            ),
            1,
        );
        command
            .arg("--config-dir")
            .arg(self.folder.path().join("mc-config"))
            .arg("--quiet")
            .args(args)
            .env("MC_HOST_fixture", host)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }
    fn run(&self, args: &[&str]) -> bool {
        let mut child = self
            .mc(args)
            .spawn()
            .expect("start MinIO test client (mc must be on PATH)");
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status.success();
            }
            if Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    pub fn admin(&self, args: &[&str]) {
        assert!(self.run(args), "owned MinIO administration failed");
    }
    pub fn seed(&self, key: &str, bytes: &[u8]) {
        let path = self.folder.path().join("seed");
        std::fs::write(&path, bytes).unwrap();
        self.admin(&[
            "cp",
            path.to_str().unwrap(),
            &format!("fixture/{}/{key}", self.bucket),
        ]);
    }
    pub fn exists(&self, key: &str) -> bool {
        self.run(&["stat", &format!("fixture/{}/{key}", self.bucket)])
    }
    pub fn pause(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        assert!(
            Command::new("kill")
                .args(["-STOP", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
    pub fn resume(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        assert!(
            Command::new("kill")
                .args(["-CONT", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
}
impl Drop for Minio {
    fn drop(&mut self) {
        if self.shutdown().is_ok() {
            return;
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("kill")
                .args(["-CONT", &self.child.id().to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = self.child.kill();
        }
        let _ = self.child.wait(); // Reap the owned process before TempDir cleanup.
    }
}
