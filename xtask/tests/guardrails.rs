use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(root: &Path, args: &[&str]) -> Output {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn precommit_stops_after_real_formatter_failure() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("broker-guardrail-{}-{nonce}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root);
    let root = &fixture.0;
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"hook-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    // Valid Rust deliberately needs formatting; use the real formatter.
    fs::write(root.join("src/lib.rs"), "pub fn value( )->u8{1}\n").unwrap();
    git(root, &["init", "--quiet"]);
    git(root, &["add", "Cargo.toml", "src/lib.rs"]);
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["hook", "pre-commit"])
        .current_dir(root)
        .output()
        .unwrap();
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("broker check: cargo [\"fmt\", \"--all\", \"--check\"]"),
        "{transcript}"
    );
    assert!(
        transcript.contains("broker check failed: cargo"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("broker check: cargo [\"clippy\""),
        "{transcript}"
    );
}

// Adversarial Cargo runner fixture only: never a Broker grant or STS service proof.
fn storage_gate_fixture(pre_push: bool) -> Fixture {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "broker-storage-gate-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).unwrap();
    let fixture = Fixture(root);
    let root = &fixture.0;
    fs::create_dir_all(root.join("storage/src")).unwrap();
    fs::create_dir_all(root.join("storage/tests")).unwrap();
    fs::create_dir_all(root.join("runner")).unwrap();
    fs::create_dir_all(root.join("server/src")).unwrap();
    fs::write(
        root.join("server/Cargo.toml"),
        "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("server/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"storage\", \"server\", \"runner\"]\nresolver = \"3\"\n",
    )
    .unwrap();
    fs::write(
        root.join("storage/Cargo.toml"),
        "[package]\nname = \"broker-storage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.join("storage/src/lib.rs"),
        "pub fn observed() -> u8 {\n    std::hint::black_box(1)\n}\n",
    )
    .unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    fs::write(root.join("runner/Cargo.toml"), format!(
        "[package]\nname = \"xtask\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[lib]\npath = {:?}\n[[bin]]\nname = \"xtask\"\npath = {:?}\n", source.join("lib.rs"), source.join("main.rs")
    )).unwrap();
    let fixture_manifest = root.join("runner/Cargo.toml");
    let mut contents = fs::read_to_string(&fixture_manifest).unwrap();
    contents.push_str("\n[dependencies]");
    contents.push_str(
        include_str!("../Cargo.toml")
            .split_once("[dependencies]")
            .unwrap()
            .1,
    );
    fs::write(&fixture_manifest, contents).unwrap();
    let test = if pre_push {
        "aws_hub_storage"
    } else {
        "ordinary_contract"
    };
    let ignore = if pre_push {
        "#[ignore = \"intentional runner failure oracle\"]\n"
    } else {
        ""
    };
    let name = if pre_push {
        "aws_hub_storage_sts_s3_contract"
    } else {
        "ordinary_contract"
    };
    fs::write(
        root.join(format!("storage/tests/{test}.rs")),
        format!(
            "#[test]\n{ignore}fn {name}() {{\n    assert_eq!(broker_storage::observed(), 2);\n}}\n"
        ),
    )
    .unwrap();
    let lock = Command::new("cargo")
        .args(["generate-lockfile", "--offline"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(lock.status.success());
    git(root, &["init", "--quiet"]);
    git(root, &["add", "."]);
    fixture
}

fn assert_storage_gate_failure(pre_push: bool) {
    let fixture = storage_gate_fixture(pre_push);
    let mut command = Command::new("cargo");
    command.args([
        "run",
        "--locked",
        "--offline",
        "--quiet",
        "-p",
        "xtask",
        "--",
    ]);
    if pre_push {
        command.arg("qualify");
    } else {
        command.args(["hook", "pre-push"]);
    }
    let output = command
        .env("CARGO_TARGET_DIR", fixture.0.join("target"))
        .env("CARGO_BUILD_JOBS", "1")
        .current_dir(&fixture.0)
        .output()
        .unwrap();
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("broker check failed: cargo"),
        "{transcript}"
    );
    let selected = if pre_push {
        "broker check: cargo [\"test\", \"--locked\", \"-p\", \"broker-storage\", \"--test\", \"aws_hub_storage\""
    } else {
        "broker check: cargo [\"test\", \"--locked\", \"--offline\", \"--workspace\", \"--all-targets\"]"
    };
    assert!(transcript.contains(selected), "{transcript}");
    assert!(transcript.contains("test result: FAILED"), "{transcript}");
    let later = if pre_push {
        "broker check: cargo [\"audit\""
    } else {
        "broker check: cargo [\"test\", \"--locked\", \"-p\", \"broker-storage\", \"--test\", \"aws_hub_storage\""
    };
    assert!(!transcript.contains(later), "{transcript}");
}

#[test]
fn saved_prepush_stops_after_workspace_ordinary_failure() {
    assert_storage_gate_failure(false);
}
#[test]
fn qualification_stops_after_storage_ignored_contract_failure() {
    assert_storage_gate_failure(true);
}

#[test]
fn saved_server_http_phases_stop_after_an_actual_rust_contract_failure() {
    for (target, contract) in [
        (
            "oauth_token",
            "broker_oidc_authorization_code_http_contract",
        ),
        ("oauth_token", "broker_oidc_refresh_http_contract"),
        ("admin_session", "broker_admin_session_http_contract"),
        ("admin_session", "broker_admin_local_bearer_http_contract"),
        (
            "admin_session",
            "broker_admin_upstream_bearer_http_contract",
        ),
        ("admin_cookie", "broker_admin_cookie_http_contract"),
        ("project_access", "broker_project_access_http_contract"),
        ("presence", "broker_presence_server_http_ws_contract"),
    ] {
        // Reuse the existing adversarial Cargo fixture; this is a gate test, not a Broker grant proof.
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(
            root.join(format!("server/tests/{target}.rs")),
            format!("#[test]\n#[ignore]\nfn {contract}() {{ assert_eq!(1, 2); }}\n"),
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/oidc_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&"CONTRACT")).unwrap();
    let audit = phases.iter().position(|p| p.args.first() == Some(&"audit")).unwrap();
    for phase in phases.into_iter().skip(start).take(audit-start+1) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}

"#.replace("CONTRACT", contract)).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "oidc_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(transcript.contains(contract), "{transcript}");
        assert!(transcript.contains("test result: FAILED"), "{transcript}");
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

#[test]
fn saved_admin_postgres_target_stops_before_later_persistence_phase() {
    // Execute the entire saved PostgreSQL command, with an actual failing Rust test
    // in this new target. This adversarial gate fixture is not a PostgreSQL proof.
    let fixture = storage_gate_fixture(true);
    let root = &fixture.0;
    let phases = xtask::qualification_checks();
    let phase = phases
        .iter()
        .find(|p| p.args.contains(&"postgres_admin_broker_session"))
        .unwrap();
    fs::create_dir_all(root.join("control/src")).unwrap();
    fs::create_dir_all(root.join("control/tests")).unwrap();
    fs::create_dir_all(root.join("runner/src/bin")).unwrap();
    fs::write(
        root.join("control/Cargo.toml"),
        "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        root.join("control/src/lib.rs"),
        "pub fn observed() -> u8 { std::hint::black_box(1) }\n",
    )
    .unwrap();
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .replace("\"runner\"]", "\"runner\", \"control\"]");
    fs::write(root.join("Cargo.toml"), manifest).unwrap();
    for pair in phase.args.windows(2).filter(|pair| pair[0] == "--test") {
        let target = pair[1];
        let expected = if target == "postgres_admin_broker_session" {
            2
        } else {
            1
        };
        fs::write(root.join(format!("control/tests/{target}.rs")), format!("#[test]\n#[ignore]\nfn saved_gate_{target}() {{ assert_eq!(broker_control::observed(), {expected}); }}\n")).unwrap();
    }
    fs::write(root.join("runner/src/bin/admin_postgres_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&"postgres_admin_broker_session")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}

"#).unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap()
            .status
            .success()
    );
    let output = Command::new("cargo")
        .args([
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "xtask",
            "--bin",
            "admin_postgres_gate",
        ])
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_BUILD_JOBS", "1")
        .current_dir(root)
        .output()
        .unwrap();
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("saved_gate_postgres_admin_broker_session ... FAILED"),
        "{transcript}"
    );
    assert!(
        transcript.contains("broker check failed: cargo"),
        "{transcript}"
    );
    assert!(
        !transcript.contains(
            "[\"test\", \"--locked\", \"-p\", \"broker-control\", \"--test\", \"postgres_sessions\""
        ),
        "{transcript}"
    );
}

#[test]
fn saved_cookie_postgres_failure_stops_before_cookie_http_and_audit() {
    let fixture = storage_gate_fixture(true);
    let root = &fixture.0;
    fs::create_dir_all(root.join("control/src")).unwrap();
    fs::create_dir_all(root.join("control/tests")).unwrap();
    fs::create_dir_all(root.join("runner/src/bin")).unwrap();
    fs::write(
        root.join("control/Cargo.toml"),
        "[package]\nname=\"broker-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
    )
    .unwrap();
    fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
    fs::write(
        root.join("control/tests/postgres_admin_cookie.rs"),
        "#[test]\n#[ignore]\nfn postgres_admin_cookie_contract() { assert_eq!(1,2); }\n",
    )
    .unwrap();
    let manifest = fs::read_to_string(root.join("Cargo.toml"))
        .unwrap()
        .replace("\"runner\"]", "\"runner\",\"control\"]");
    fs::write(root.join("Cargo.toml"), manifest).unwrap();
    fs::write(root.join("runner/src/bin/cookie_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"postgres_admin_cookie_contract")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success()=>{},
            _=>{ eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
    assert!(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap()
            .status
            .success()
    );
    let output = Command::new("cargo")
        .args([
            "run",
            "--locked",
            "--offline",
            "--quiet",
            "-p",
            "xtask",
            "--bin",
            "cookie_gate",
        ])
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_BUILD_JOBS", "1")
        .current_dir(root)
        .output()
        .unwrap();
    let transcript = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{transcript}");
    assert!(
        transcript.contains("postgres_admin_cookie_contract ... FAILED"),
        "{transcript}"
    );
    assert!(
        transcript.contains("broker check failed: cargo"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("broker_admin_cookie_http_contract"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("broker check: cargo [\"audit\""),
        "{transcript}"
    );
}

// Real saved Cargo phase failure only; not a password, CAPTCHA or SQL proof.
#[test]
fn saved_local_password_admission_phases_stop_on_real_contract_failure() {
    let cases = [
        "postgres_local_password_admission_contract",
        "postgres_admission_commit_uncertainty_contract",
        "local_captcha::tests::postgres_https_local_password_admission_contract",
        "local_password_admission::tests::postgres_admission_capacity_preserves_active_entries",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::create_dir_all(root.join("control/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname=\"broker-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("control/src/lib.rs"), r#"
#![forbid(unsafe_code)]
#[cfg(test)] mod local_captcha { mod tests {
    #[test] #[ignore] fn postgres_https_local_password_admission_contract() { assert_eq!(1, 2); }
} }
#[cfg(test)] mod local_password_admission { mod tests {
    #[test] #[ignore] fn postgres_admission_capacity_preserves_active_entries() { assert_eq!(1, 2); }
} }
"#).unwrap();
        fs::write(
            root.join("control/tests/local_password_admission.rs"),
            r#"
#[test] #[ignore] fn postgres_local_password_admission_contract() { assert_eq!(1, 2); }
#[test] #[ignore] fn postgres_admission_commit_uncertainty_contract() { assert_eq!(1, 2); }
"#,
        )
        .unwrap();
        let manifest = fs::read_to_string(root.join("Cargo.toml"))
            .unwrap()
            .replace("\"runner\"]", "\"runner\",\"control\"]");
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        fs::write(root.join("runner/src/bin/admission_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let target = std::env::args().nth(1).unwrap();
    let phases = xtask::qualification_checks();
    let selector = if target.ends_with("postgres_https_local_password_admission_contract") { "_https_local_password_admission_contract" } else { target.as_str() };
    let start = phases.iter().position(|p| p.args.contains(&selector)).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "admission_gate",
                "--",
                contract,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for later in &cases[index + 1..] {
            assert!(!transcript.contains(later), "{transcript}");
        }
        assert!(
            !transcript.contains("broker_project_access_http_contract"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

// Adversarial saved Cargo gates only: no credential, factor or SQL authority.
#[test]
fn saved_admin_local_login_phases_stop_on_real_contract_failure() {
    let cases = [
        "broker_admin_local_login_http_contract",
        "broker_admin_local_login_failure_contract",
        "broker_admin_local_login_uncertainty_contract",
        "broker_admin_local_login_configuration_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .map(|name| format!("#[test]\n#[ignore]\nfn {name}() {{ assert_eq!(1, 2); }}\n"))
            .collect();
        fs::write(root.join("server/tests/admin_local_login.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/local_login_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let target = std::env::args().nth(1).unwrap();
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&target.as_str())).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "local_login_gate",
                "--",
                contract,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for later in &cases[index + 1..] {
            assert!(!transcript.contains(later), "{transcript}");
        }
        assert!(
            !transcript.contains("broker_project_access_http_contract"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

// Adversarial saved Cargo gates only: no credential, factor or SQL authority.
#[test]
fn saved_upstream_browser_phases_stop_on_real_contract_failure() {
    let cases = [
        "postgres_upstream_login_contract",
        "postgres_upstream_login_uncertainty_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        fs::write(root.join("Cargo.toml"),"[workspace]\nmembers = [\"storage\", \"server\", \"control\", \"runner\"]\nresolver = \"3\"\n").unwrap();

        fs::create_dir_all(root.join("control/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .map(|name| format!("#[test]\n#[ignore]\nfn {name}() {{ assert_eq!(1, 2); }}\n"))
            .collect();
        fs::write(
            root.join("control/tests/postgres_upstream_login.rs"),
            source,
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/upstream_browser_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let target = std::env::args().nth(1).unwrap();
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&target.as_str())).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "upstream_browser_gate",
                "--",
                contract,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for later in &cases[index + 1..] {
            assert!(!transcript.contains(later), "{transcript}");
        }
        assert!(
            !transcript.contains("broker_project_access_http_contract"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

// Adversarial saved Cargo gates only: no credential, factor or SQL authority.
// Adversarial saved Cargo gates only: no credential, factor or SQL authority.
#[test]
fn saved_federated_cookie_phases_stop_on_real_contract_failure() {
    let cases = [
        "postgres_admin_federated_cookie_contract",
        "postgres_admin_federated_cookie_uncertainty_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        fs::write(root.join("Cargo.toml"),"[workspace]\nmembers = [\"storage\", \"server\", \"control\", \"runner\"]\nresolver = \"3\"\n").unwrap();

        fs::create_dir_all(root.join("control/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .map(|name| format!("#[test]\n#[ignore]\nfn {name}() {{ assert_eq!(1, 2); }}\n"))
            .collect();
        fs::write(
            root.join("control/tests/postgres_admin_federated_cookie.rs"),
            source,
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/federated_cookie_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let target = std::env::args().nth(1).unwrap();
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&target.as_str())).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}


"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "federated_cookie_gate",
                "--",
                contract,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for later in &cases[index + 1..] {
            assert!(!transcript.contains(later), "{transcript}");
        }
        assert!(
            !transcript.contains("broker_project_access_http_contract"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

// Adversarial saved Cargo phases only, never a SQL/authentication proof.
#[test]
fn saved_admin_read_phases_stop_on_real_contract_failure() {
    let cases = [("control", "postgres_admin_read"), ("server", "admin_read")];
    for (index, (_, target)) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        fs::write(root.join("Cargo.toml"),"[workspace]\nmembers = [\"storage\",\"server\",\"control\",\"runner\"]\nresolver = \"3\"\n").unwrap();
        for (package, file) in cases {
            fs::create_dir_all(root.join(package).join("tests")).unwrap();
            fs::write(root.join(package).join("tests").join(format!("{file}.rs")),"#[test]\n#[ignore = \"intentional saved-phase failure oracle\"]\nfn admin_read_failure_oracle() { assert_eq!(1,2); }\n").unwrap();
        }
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(root.join("runner/src/bin/admin_read_gate.rs"),r#"
fn main() -> std::process::ExitCode {
    let target=std::env::args().nth(1).unwrap();
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&target.as_str())).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success()=>{},
            _=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "admin_read_gate",
                "--",
                target,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains("admin_read_failure_oracle ... FAILED"),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for (_, later) in &cases[index + 1..] {
            assert!(
                !transcript.contains(&format!("\"--test\", \"{later}\"")),
                "{transcript}"
            );
        }
        assert!(
            !transcript.contains("broker_project_access_http_contract"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

// Real failing Rust contracts prove the three saved H3 gates stop later phases.
#[test]
fn saved_admin_upstream_login_phases_stop_on_real_contract_failure() {
    let cases = [
        "broker_admin_upstream_login_http_contract",
        "broker_admin_upstream_login_uncertainty_contract",
        "broker_admin_upstream_login_configuration_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .map(|name| format!("#[test]\n#[ignore]\nfn {name}() {{ assert_eq!(1, 2); }}\n"))
            .collect();
        fs::write(root.join("server/tests/admin_upstream_login.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/upstream_login_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let target = std::env::args().nth(1).unwrap();
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.contains(&target.as_str())).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}

"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "upstream_login_gate",
                "--",
                contract,
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        for later in &cases[index + 1..] {
            assert!(!transcript.contains(later), "{transcript}");
        }
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

#[test]
fn saved_hub_storage_process_phases_stop_on_real_build_or_contract_failure() {
    for build_fails in [true, false] {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("presence/examples")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers = [\"storage\", \"server\", \"presence\", \"runner\"]\nresolver = \"3\"\n").unwrap();
        fs::write(
            root.join("presence/Cargo.toml"),
            "[package]\nname = \"broker-presence\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        let source = if build_fails {
            "compile_error!(\"intentional normal process build failure\");\nfn main() {}\n"
        } else {
            "fn main() {}\n#[cfg(test)] mod tests { #[test] #[ignore] fn hub_storage_fixture_native_sts_contract() { assert_eq!(1, 2); } }\n"
        };
        fs::write(
            root.join("presence/examples/hub_storage_fixture.rs"),
            source,
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/hub_storage_gate.rs"), r#"
fn main() -> std::process::ExitCode {
    let phases = xtask::qualification_checks();
    let start = phases.iter().position(|p| p.args.first() == Some(&"build") && p.args.contains(&"hub_storage_fixture")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {
            Ok(status) if status.success() => {},
            _ => { eprintln!("broker check failed: {}", phase.program); return std::process::ExitCode::FAILURE; }
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "hub_storage_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        if build_fails {
            assert!(
                transcript.contains("intentional normal process build failure"),
                "{transcript}"
            );
            assert!(
                !transcript.contains("tests::hub_storage_fixture_native_sts_contract"),
                "{transcript}"
            );
        } else {
            assert!(
                transcript.contains("tests::hub_storage_fixture_native_sts_contract ... FAILED"),
                "{transcript}"
            );
        }
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
    }
}

#[test]
fn saved_dcr_phases_stop_on_real_contract_failure() {
    for contract in [
        "broker_oidc_registration_http_contract",
        "broker_oidc_registration_uncertainty_contract",
    ] {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(
            root.join("server/tests/oauth_token.rs"),
            format!("#[test]\n#[ignore]\nfn {contract}() {{ assert_eq!(1, 2); }}\n"),
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/dcr_gate.rs"),r#"
fn main() -> std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"CONTRACT")).unwrap();
    let audit=phases.iter().position(|p|p.args.first()==Some(&"audit")).unwrap();
    for phase in phases.into_iter().skip(start).take(audit-start+1) {
        match xtask::execute(phase) {
            Ok(status) if status.success()=>{},
            _=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}
        }
    }
    std::process::ExitCode::SUCCESS
}
"#.replace("CONTRACT",contract)).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "dcr_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
        if contract == "broker_oidc_registration_http_contract" {
            assert!(
                !transcript.contains("broker_oidc_registration_uncertainty_contract"),
                "{transcript}"
            );
        }
    }
}

#[test]
fn saved_federated_phases_stop_on_real_contract_failure() {
    for (package, directory, target, contract) in [
        (
            "broker-control",
            "control",
            "postgres_oidc_federated",
            "postgres_oidc_federated_contract",
        ),
        (
            "broker-server",
            "server",
            "oidc_federated",
            "broker_oidc_federated_http_contract",
        ),
        (
            "broker-control",
            "control",
            "postgres_local_auth",
            "postgres_local_invalidation_preserves_federated_grants",
        ),
    ] {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        if package == "broker-control" {
            fs::create_dir_all(root.join("control/src")).unwrap();
            fs::write(
                root.join("control/Cargo.toml"),
                "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
            )
            .unwrap();
            fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
            let workspace = fs::read_to_string(root.join("Cargo.toml"))
                .unwrap()
                .replace("\"storage\",", "\"storage\", \"control\",");
            fs::write(root.join("Cargo.toml"), workspace).unwrap();
            let lock = Command::new("cargo")
                .args(["generate-lockfile", "--offline"])
                .current_dir(root)
                .output()
                .unwrap();
            assert!(lock.status.success());
        }
        fs::create_dir_all(root.join(format!("{directory}/tests"))).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(
            root.join(format!("{directory}/tests/{target}.rs")),
            format!("#[test]\n#[ignore]\nfn {contract}() {{ assert_eq!(1,2); }}\n"),
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/federated_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"TARGET")).unwrap();
    let audit=phases.iter().position(|p|p.args.first()==Some(&"audit")).unwrap();
    for phase in phases.into_iter().skip(start).take(audit-start+1) {
        match xtask::execute(phase) {
            Ok(status) if status.success()=>{},
            _=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}
        }
    }
    std::process::ExitCode::SUCCESS
}
"#.replace("TARGET",target)).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "federated_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
        if target == "postgres_oidc_federated" {
            assert!(!transcript.contains("broker check: cargo [\"test\", \"--locked\", \"--offline\", \"-j4\", \"-p\", \"broker-server\", \"--test\", \"oidc_federated\""),"{transcript}");
        }
    }
}

#[test]
fn saved_upstream_oauth_callback_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_oidc_browser_callback_http_contract",
        "broker_oidc_browser_callback_uncertainty_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/oidc_browser_callback.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/oauth_callback_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oidc_browser_callback")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "oauth_callback_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "callback failure must block later audit: {transcript}"
        );
    }
}

#[test]
fn saved_local_login_runtime_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_local_login_runtime_configuration_contract",
        "broker_local_login_runtime_consumers_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/local_login_runtime.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/local_runtime_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"local_login_runtime")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "local_runtime_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "LOCAL runtime failure must block later audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_browser_admission_phase_stops_on_real_contract_failure() {
    let cases = [
        "postgres_oidc_authorization_contract",
        "postgres_oidc_browser_admission_contract",
        "postgres_oidc_browser_rejection_uncertainty_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("storage/Cargo.toml"),
            "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(
            root.join("storage/tests/postgres_oidc_authorization.rs"),
            source,
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/browser_admission_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"postgres_oidc_authorization")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "browser_admission_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "admission failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_browser_authorization_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_oidc_browser_authorization_local_http",
        "broker_oidc_browser_authorization_mfa_recovery",
        "broker_oidc_browser_authorization_upstream_http",
        "broker_oidc_browser_authorization_captcha_and_rates",
        "broker_oidc_browser_authorization_sql_outcomes",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(
            root.join("server/tests/oidc_browser_authorization.rs"),
            source,
        )
        .unwrap();
        fs::write(root.join("runner/src/bin/browser_authorization_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oidc_browser_authorization")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "browser_authorization_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "browser authorization failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_discovery_phase_stops_on_real_contract_failure() {
    let cases = [
        "discovery_native_capability_profiles",
        "discovery_native_journey_and_static_reads_without_database",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/oidc_discovery.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/discovery_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oidc_discovery")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "discovery_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "discovery failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_userinfo_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_oidc_userinfo_local_http_contract",
        "broker_oidc_userinfo_federated_http_contract",
        "broker_oidc_userinfo_sql_outcomes",
        "broker_oidc_userinfo_commit_ack_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/oauth_userinfo.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/userinfo_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oauth_userinfo")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "userinfo_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "UserInfo failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_introspection_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_oidc_introspection_local_http_contract",
        "broker_oidc_introspection_federated_http_contract",
        "broker_oidc_introspection_sql_outcomes",
        "broker_oidc_introspection_commit_ack_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/oauth_introspection.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/introspection_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oauth_introspection")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "introspection_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "Introspection failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_oidc_end_session_phase_stops_on_real_contract_failure() {
    let cases = [
        "broker_oidc_end_session_local_http_contract",
        "broker_oidc_end_session_federated_http_contract",
        "broker_oidc_end_session_sql_outcomes",
        "broker_oidc_end_session_commit_ack_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/oauth_end_session.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/end_session_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"oauth_end_session")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "end_session_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "End-session failure must block audit: {transcript}"
        );
    }
}

#[test]
fn saved_revocation_phases_stop_on_real_rust_failures() {
    // Runner-only fixture; genuine grant/SQL/HTTP proofs live in the production suites.
    let cases = [
        (0, "postgres_native_oidc_revocation_contract"),
        (0, "postgres_oidc_revocation_races_and_rollback"),
        (1, "postgres_oidc_federated_revocation_contract"),
        (2, "broker_oidc_revocation_http_contract"),
        (2, "broker_oidc_revocation_commit_ack_contract"),
    ];
    for (phase, failing) in cases {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::create_dir_all(root.join("control/tests")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname=\"broker-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(root.join("control/src/lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[\"storage\",\"server\",\"runner\",\"control\"]\nresolver=\"3\"\n").unwrap();
        for (file, names) in [
            (
                "control/tests/postgres_oidc_revocation.rs",
                vec![
                    "postgres_native_oidc_revocation_contract",
                    "postgres_oidc_revocation_races_and_rollback",
                ],
            ),
            (
                "control/tests/postgres_oidc_federated.rs",
                vec!["postgres_oidc_federated_revocation_contract"],
            ),
            (
                "server/tests/oauth_revocation.rs",
                vec![
                    "broker_oidc_revocation_http_contract",
                    "broker_oidc_revocation_commit_ack_contract",
                ],
            ),
        ] {
            let source: String = names
                .into_iter()
                .map(|name| {
                    format!(
                        "#[test]\n#[ignore]\nfn {name}() {{ assert!({}); }}\n",
                        name != failing
                    )
                })
                .collect();
            fs::write(root.join(file), source).unwrap();
        }
        fs::write(root.join("runner/src/bin/revocation_gate.rs"), r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"postgres_oidc_revocation")).unwrap();
    for phase in phases.into_iter().skip(start).take(3) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    eprintln!("revocation phases completed");
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let lock = Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root)
            .output()
            .unwrap();
        assert!(lock.status.success());
        let output = Command::new("cargo")
            .args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "revocation_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{failing} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("revocation phases completed"),
            "{transcript}"
        );
        let later = match phase {
            0 => Some("\"postgres_oidc_federated\""),
            1 => Some("\"oauth_revocation\""),
            _ => None,
        };
        if let Some(later) = later {
            assert!(!transcript.contains(later), "{transcript}");
        }
    }
}

#[test]
fn native_builder_and_container_phase_stop_on_real_failures() {
    let fixture = storage_gate_fixture(true);
    let root = &fixture.0;
    fs::write(root.join("server/Cargo.toml"), "[package]\nname=\"broker-server\"\nversion=\"0.1.0\"\nedition=\"2024\"\n[[bin]]\nname=\"graphit-broker\"\npath=\"src/main.rs\"\n").unwrap();
    fs::write(
        root.join("server/src/main.rs"),
        "compile_error!(\"intentional native build failure\");\nfn main() {}\n",
    )
    .unwrap();
    let artifact = root.join("native-artifact");
    let build = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["build", "--debug", "--output"])
        .arg(&artifact)
        .env("CARGO_TARGET_DIR", "target")
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!build.status.success());
    assert!(!artifact.exists());
    assert!(String::from_utf8_lossy(&build.stderr).contains("intentional native build failure"));
    let occupied_parent = root.join("package-parent-file");
    fs::write(&occupied_parent, b"preserve parent entry").unwrap();
    let invalid_output = occupied_parent.join("child");
    let io_failure = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["package", "--debug", "--output"])
        .arg(&invalid_output)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!io_failure.status.success());
    assert!(io_failure.stdout.is_empty());
    assert!(!invalid_output.exists());
    assert_eq!(
        fs::read(&occupied_parent).unwrap(),
        b"preserve parent entry"
    );
    for args in [vec!["package"], vec!["package", "--output"]] {
        let result = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("requires"));
    }
    let package_output = root.join("local-package");
    let failed_package = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["package", "--debug", "--output"])
        .arg(&package_output)
        .env("CARGO_TARGET_DIR", "target")
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!failed_package.status.success());
    assert!(!package_output.exists());
    assert!(
        String::from_utf8_lossy(&failed_package.stderr)
            .contains("intentional native build failure")
    );
    fs::write(root.join("server/src/main.rs"), "fn main() {}\n").unwrap();
    let invalid_version = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["package", "--debug", "--output"])
        .arg(&package_output)
        .env("CARGO_TARGET_DIR", "target")
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!invalid_version.status.success());
    assert!(!package_output.exists());
    assert!(
        String::from_utf8_lossy(&invalid_version.stderr)
            .contains("version does not match workspace")
    );
    assert!(fs::read_dir(root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".broker-native-package-")
    }));

    let binary = root.join("target/debug").join(if cfg!(windows) {
        "graphit-broker.exe"
    } else {
        "graphit-broker"
    });
    let native = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["build", "--debug", "--output"])
        .arg(&binary)
        .env("CARGO_TARGET_DIR", "target")
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(native.status.success());
    let original = fs::read(&binary).unwrap();
    assert!(!original.is_empty());
    let alias = root.join("native-hardlink");
    fs::hard_link(&binary, &alias).unwrap();
    let aliases = vec![binary.clone(), alias];
    #[cfg(unix)]
    let aliases = {
        let symlink = root.join("native-symlink");
        std::os::unix::fs::symlink(&binary, &symlink).unwrap();
        let mut aliases = aliases;
        aliases.push(symlink);
        aliases
    };
    for output in aliases {
        let result = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args(["build", "--debug", "--output"])
            .arg(&output)
            .env("CARGO_TARGET_DIR", "target")
            .env("CARGO_NET_OFFLINE", "true")
            .current_dir(root)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(fs::read(&binary).unwrap() == original);
        assert!(fs::read(&output).unwrap() == original);
        assert!(Command::new(&output).status().unwrap().success());
    }
    fs::create_dir_all(root.join("server/tests")).unwrap();
    fs::write(root.join("server/tests/container.rs"), "#[test]\n#[ignore]\nfn broker_native_container_contract() { panic!(\"intentional native container failure\"); }\n").unwrap();
    let phase = xtask::qualification_checks()
        .into_iter()
        .find(|p| p.args.contains(&"container"))
        .unwrap();
    assert_eq!(phase.program, "cargo");
    let failed = Command::new(phase.program)
        .args(phase.args)
        .env("CARGO_TARGET_DIR", "target")
        .env("CARGO_NET_OFFLINE", "true")
        .current_dir(root)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(
        String::from_utf8_lossy(&failed.stdout).contains("intentional native container failure")
    );
}

#[test]
fn saved_device_phase_stops_on_real_contract_failure() {
    let cases = [
        "postgres_device_authorization_contract",
        "postgres_device_recovery_consent_contract",
        "postgres_device_sql_outcomes_contract",
        "postgres_device_commit_ack_contract",
    ];
    for (index, contract) in cases.iter().enumerate() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::write(
            root.join("server/Cargo.toml"),
            "[package]\nname = \"broker-control\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        fs::create_dir_all(root.join("server/tests")).unwrap();
        let source: String = cases
            .iter()
            .enumerate()
            .map(|(i, name)| {
                format!(
                    "#[test]\n#[ignore]\nfn {name}() {{ assert_eq!({}, 0); }}\n",
                    usize::from(i == index)
                )
            })
            .collect();
        fs::write(root.join("server/tests/postgres_device.rs"), source).unwrap();
        fs::write(root.join("runner/src/bin/device_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&"postgres_device")).unwrap();
    for phase in phases.into_iter().skip(start) {
        match xtask::execute(phase) {Ok(status) if status.success()=>{},_=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}}
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        let output = Command::new("cargo")
            .args([
                "run",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "device_gate",
            ])
            .env("CARGO_TARGET_DIR", root.join("target"))
            .env("CARGO_BUILD_JOBS", "1")
            .current_dir(root)
            .output()
            .unwrap();
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{transcript}");
        assert!(
            transcript.contains(&format!("{contract} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "Device failure must block audit: {transcript}"
        );
    }
}

// Adversarial real Cargo runner proof, not a LOCAL credential/SQL oracle.
#[test]
fn sqlite_local_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&[
        "sqlite_local_auth",
        "sqlite_admin_cookie",
        "sqlite_admin_local_http",
        "sqlite_oidc_grants",
        "sqlite_oidc_token_http",
        "sqlite_oidc_browser_http",
        "sqlite_device",
        "sqlite_device_http",
        "_https_local_password_admission_contract",
    ]);
}
#[test]
fn sqlite_oidc_lifecycle_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&["sqlite_oidc_lifecycle", "sqlite_oidc_lifecycle_http"]);
}
#[test]
fn sqlite_admin_read_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&["sqlite_admin_reads", "sqlite_admin_read_http"]);
}
#[test]
fn sqlite_oidc_federated_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&["sqlite_oidc_federated", "sqlite_oidc_federated_http"]);
}
#[test]
fn sqlite_admin_ingress_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&["sqlite_admin_ingress", "sqlite_admin_session_http"]);
}
#[test]
fn sqlite_admin_browser_saved_checks_stop_and_recover_on_real_assertions() {
    sqlite_local_saved_checks_for(&["sqlite_admin_upstream_login"]);
}
fn sqlite_local_saved_checks_for(selectors: &[&str]) {
    for selector in selectors.iter().copied() {
        let fixture = storage_gate_fixture(true);
        let root = &fixture.0;
        fs::create_dir_all(root.join("control/src")).unwrap();
        fs::create_dir_all(root.join("control/tests")).unwrap();
        fs::create_dir_all(root.join("presence/src")).unwrap();
        fs::create_dir_all(root.join("presence/tests")).unwrap();
        fs::create_dir_all(root.join("runner/src/bin")).unwrap();
        let manifest = fs::read_to_string(root.join("Cargo.toml"))
            .unwrap()
            .replace("\"runner\"]", "\"runner\",\"control\",\"presence\"]");
        fs::write(root.join("Cargo.toml"), manifest).unwrap();
        fs::write(
            root.join("control/Cargo.toml"),
            "[package]\nname=\"broker-control\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("presence/Cargo.toml"),
            "[package]\nname=\"broker-presence\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .unwrap();
        fs::write(
            root.join("presence/src/lib.rs"),
            "//! Disposable HTTP gate fixture.\n",
        )
        .unwrap();
        fs::write(
            root.join("control/src/lib.rs"),
            r#"
#[cfg(test)] mod local_captcha { mod tests {
    #[test] #[ignore] fn postgres_https_local_password_admission_contract() { assert_eq!(1, 1); }
    #[test] #[ignore] fn sqlite_https_local_password_admission_contract() { assert_eq!(1, 2); }
} }
"#,
        )
        .unwrap();
        for (target, name) in [
            ("sqlite_local_auth", "sqlite_local_fault"),
            ("sqlite_admin_cookie", "sqlite_admin_cookie_fault"),
            ("sqlite_admin_local_http", "sqlite_admin_local_http_fault"),
            ("sqlite_oidc_grants", "sqlite_oidc_grants_fault"),
            ("sqlite_oidc_token_http", "sqlite_oidc_token_http_fault"),
            ("sqlite_oidc_browser_http", "sqlite_oidc_browser_http_fault"),
            ("sqlite_device", "sqlite_device_fault"),
            ("sqlite_device_http", "sqlite_device_http_fault"),
            ("sqlite_oidc_lifecycle", "sqlite_oidc_lifecycle_fault"),
            (
                "sqlite_oidc_lifecycle_http",
                "sqlite_oidc_lifecycle_http_fault",
            ),
            ("sqlite_admin_reads", "sqlite_admin_reads_fault"),
            ("sqlite_admin_read_http", "sqlite_admin_read_http_fault"),
            ("sqlite_oidc_federated", "sqlite_oidc_federated_fault"),
            (
                "sqlite_oidc_federated_http",
                "sqlite_oidc_federated_http_fault",
            ),
            ("sqlite_admin_ingress", "sqlite_admin_ingress_fault"),
            (
                "sqlite_admin_session_http",
                "sqlite_admin_session_http_fault",
            ),
            (
                "sqlite_admin_upstream_login",
                "sqlite_admin_upstream_login_fault",
            ),
        ] {
            let expected = if selector == target { 2 } else { 1 };
            let crate_dir = if matches!(
                target,
                "sqlite_admin_local_http"
                    | "sqlite_oidc_token_http"
                    | "sqlite_oidc_browser_http"
                    | "sqlite_device_http"
                    | "sqlite_oidc_lifecycle_http"
                    | "sqlite_admin_read_http"
                    | "sqlite_oidc_federated_http"
                    | "sqlite_admin_session_http"
                    | "sqlite_admin_upstream_login"
            ) {
                "presence"
            } else {
                "control"
            };
            fs::write(
                root.join(format!("{crate_dir}/tests/{target}.rs")),
                format!("#[test] #[ignore] fn {name}() {{ assert_eq!(1, {expected}); }}\n"),
            )
            .unwrap();
        }
        // Complete the disposable workspace for the saved SQLite phase. The
        // selected targets above inject real failures; unrelated targets only
        // need to exist so Cargo can reach those assertions.
        let phases = xtask::qualification_checks();
        let phase = phases
            .iter()
            .find(|p| p.args.contains(&"sqlite_local_auth"))
            .unwrap();
        for pair in phase.args.windows(2).filter(|pair| pair[0] == "--test") {
            let target = pair[1];
            if ["control", "presence", "server"]
                .iter()
                .any(|dir| root.join(format!("{dir}/tests/{target}.rs")).exists())
            {
                continue;
            }
            fs::write(
                root.join(format!("control/tests/{target}.rs")),
                "#[test] #[ignore] fn unrelated_contract() {}\n",
            )
            .unwrap();
        }
        fs::write(root.join("runner/src/bin/sqlite_local_gate.rs"),r#"
fn main()->std::process::ExitCode {
    let selector=std::env::args().nth(1).unwrap();
    let restored=std::env::args().nth(2).as_deref()==Some("restored");
    let phases=xtask::qualification_checks();
    let start=phases.iter().position(|p|p.args.contains(&selector.as_str())).unwrap();
    for phase in phases.into_iter().skip(start).take(if restored {1}else{usize::MAX}) {
        match xtask::execute(phase) {
            Ok(status) if status.success()=>{},
            _=>{eprintln!("broker check failed: {}",phase.program);return std::process::ExitCode::FAILURE;}
        }
    }
    std::process::ExitCode::SUCCESS
}
"#).unwrap();
        assert!(
            Command::new("cargo")
                .args(["generate-lockfile", "--offline"])
                .current_dir(root)
                .output()
                .unwrap()
                .status
                .success()
        );
        let run = |restored: bool| {
            let mut command = Command::new("cargo");
            command.args([
                "run",
                "--locked",
                "--offline",
                "--quiet",
                "-p",
                "xtask",
                "--bin",
                "sqlite_local_gate",
                "--",
                selector,
            ]);
            if restored {
                command.arg("restored");
            }
            command
                .env("CARGO_TARGET_DIR", root.join("target"))
                .env("CARGO_BUILD_JOBS", "1")
                .current_dir(root)
                .output()
                .unwrap()
        };
        let failed = run(false);
        let transcript = format!(
            "{}{}",
            String::from_utf8_lossy(&failed.stdout),
            String::from_utf8_lossy(&failed.stderr)
        );
        assert!(!failed.status.success(), "{transcript}");
        let target = match selector {
            "sqlite_local_auth" => "sqlite_local_fault",
            "sqlite_admin_cookie" => "sqlite_admin_cookie_fault",
            "sqlite_admin_local_http" => "sqlite_admin_local_http_fault",
            "sqlite_oidc_grants" => "sqlite_oidc_grants_fault",
            "sqlite_oidc_token_http" => "sqlite_oidc_token_http_fault",
            "sqlite_oidc_browser_http" => "sqlite_oidc_browser_http_fault",
            "sqlite_device" => "sqlite_device_fault",
            "sqlite_device_http" => "sqlite_device_http_fault",
            "sqlite_oidc_lifecycle" => "sqlite_oidc_lifecycle_fault",
            "sqlite_oidc_lifecycle_http" => "sqlite_oidc_lifecycle_http_fault",
            "sqlite_admin_reads" => "sqlite_admin_reads_fault",
            "sqlite_admin_read_http" => "sqlite_admin_read_http_fault",
            "sqlite_oidc_federated" => "sqlite_oidc_federated_fault",
            "sqlite_oidc_federated_http" => "sqlite_oidc_federated_http_fault",
            "sqlite_admin_ingress" => "sqlite_admin_ingress_fault",
            "sqlite_admin_session_http" => "sqlite_admin_session_http_fault",
            "sqlite_admin_upstream_login" => "sqlite_admin_upstream_login_fault",
            _ => "local_captcha::tests::sqlite_https_local_password_admission_contract",
        };
        assert!(
            transcript.contains(&format!("{target} ... FAILED")),
            "{transcript}"
        );
        assert!(
            transcript.contains("broker check failed: cargo"),
            "{transcript}"
        );
        assert!(
            !transcript.contains("broker check: cargo [\"audit\""),
            "{transcript}"
        );
        for file in [
            "control/src/lib.rs",
            "control/tests/sqlite_local_auth.rs",
            "control/tests/sqlite_admin_cookie.rs",
            "presence/tests/sqlite_admin_local_http.rs",
            "control/tests/sqlite_oidc_grants.rs",
            "presence/tests/sqlite_oidc_token_http.rs",
            "presence/tests/sqlite_oidc_browser_http.rs",
            "control/tests/sqlite_device.rs",
            "presence/tests/sqlite_device_http.rs",
            "control/tests/sqlite_oidc_lifecycle.rs",
            "presence/tests/sqlite_oidc_lifecycle_http.rs",
            "control/tests/sqlite_admin_reads.rs",
            "presence/tests/sqlite_admin_read_http.rs",
            "control/tests/sqlite_oidc_federated.rs",
            "presence/tests/sqlite_oidc_federated_http.rs",
            "control/tests/sqlite_admin_ingress.rs",
            "presence/tests/sqlite_admin_session_http.rs",
            "presence/tests/sqlite_admin_upstream_login.rs",
        ] {
            let fixed = fs::read_to_string(root.join(file))
                .unwrap()
                .replace("assert_eq!(1, 2)", "assert_eq!(1, 1)");
            fs::write(root.join(file), fixed).unwrap();
        }
        let restored = run(true);
        assert!(
            restored.status.success(),
            "restored selected saved phase failed: {}",
            String::from_utf8_lossy(&restored.stderr)
        );
    }
}
