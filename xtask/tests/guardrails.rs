use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn checked(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

fn runner(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("CARGO_NET_OFFLINE", "true");
    command
}

fn failed(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(!output.status.success(), "{output:?}");
    output
}

fn package_fixture(manifest: &str) -> tempfile::TempDir {
    let fixture = tempfile::Builder::new()
        .prefix("broker guardrail α ")
        .tempdir()
        .unwrap();
    let root = fixture.path();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("Cargo.toml"), manifest).unwrap();
    // Supply a Rust file before Cargo resolves the manifest.
    fs::write(root.join("src/lib.rs"), "//! Guardrail fixture.\n").unwrap();
    checked(
        Command::new("cargo")
            .args(["generate-lockfile", "--offline"])
            .current_dir(root),
    );
    fixture
}

#[test]
fn precommit_stops_after_real_formatter_failure() {
    let fixture = package_fixture(
        "[package]\nname = \"hook-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    let root = fixture.path();
    fs::write(root.join("src/lib.rs"), "pub fn value( )->u8{1}\n").unwrap();
    checked(
        Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(root),
    );
    checked(
        Command::new("git")
            .args(["add", "Cargo.toml", "src/lib.rs"])
            .current_dir(root),
    );

    let output = failed(runner(root).args(["hook", "pre-commit"]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("broker check: git [\"diff\""), "{stderr}");
    assert!(
        stderr.contains("broker check: cargo [\"fmt\", \"--all\", \"--check\"]"),
        "{stderr}"
    );
    assert!(stderr.contains("broker check failed: cargo"), "{stderr}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("pub fn value() -> u8"),
        "{output:?}"
    );
}

#[test]
fn ordinary_and_qualification_commands_fail_fast_with_real_tests() {
    let fixture = package_fixture(
        "[package]\nname = \"broker-storage\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    );
    let root = fixture.path();
    fs::create_dir(root.join("tests")).unwrap();
    fs::write(
        root.join("tests/aws_hub_storage.rs"),
        r#"#[test]
fn ordinary_contract() {
    assert_eq!(std::hint::black_box(1), 2);
}

#[test]
#[ignore]
fn aws_hub_storage_sts_s3_contract() {
    assert_eq!(std::hint::black_box(1), 2);
}
"#,
    )
    .unwrap();

    let output = failed(runner(root).args(["hook", "pre-push"]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut remaining = stderr.as_ref();
    for phase in ["[\"fmt\"", "[\"clippy\"", "\"--doc\"", "\"--all-targets\""] {
        let (_, tail) = remaining
            .split_once(phase)
            .unwrap_or_else(|| panic!("{stderr}"));
        remaining = tail;
    }
    assert!(stdout.contains("ordinary_contract ... FAILED"), "{stdout}");
    assert!(
        !stdout.contains("aws_hub_storage_sts_s3_contract ... FAILED"),
        "{stdout}"
    );
    assert!(stderr.contains("broker check failed: cargo"), "{stderr}");

    let output = failed(runner(root).arg("qualify"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("aws_hub_storage_sts_s3_contract ... FAILED"),
        "{stdout}"
    );
    assert!(!stdout.contains("ordinary_contract ... FAILED"), "{stdout}");
    assert!(stderr.contains("broker check failed: cargo"), "{stderr}");
    assert_eq!(stderr.matches("broker check: ").count(), 1, "{stderr}");
}

#[test]
fn native_build_and_package_preserve_artifacts_on_failure() {
    let fixture = package_fixture(
        "[package]\nname = \"broker-server\"\nversion = \"0.1.0\"\nedition = \"2024\"\n[[bin]]\nname = \"graphit-broker\"\npath = \"src/main.rs\"\n",
    );
    let root = fixture.path();
    let source = root.join("src/main.rs");
    fs::write(
        &source,
        "compile_error!(\"intentional native build failure\");\nfn main() {}\n",
    )
    .unwrap();
    let artifact = root.join("native-artifact");
    let build = runner(root)
        .args(["build", "--debug", "--output"])
        .arg(&artifact)
        .output()
        .unwrap();
    assert!(!build.status.success());
    assert!(!artifact.exists());
    assert!(String::from_utf8_lossy(&build.stderr).contains("intentional native build failure"));
    let occupied_parent = root.join("package-parent-file");
    fs::write(&occupied_parent, b"preserve parent entry").unwrap();
    let invalid_output = occupied_parent.join("child");
    let io_failure = runner(root)
        .args(["package", "--debug", "--output"])
        .arg(&invalid_output)
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
        let result = runner(root).args(args).output().unwrap();
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("requires"));
    }
    let package_output = root.join("local-package");
    let failed_package = runner(root)
        .args(["package", "--debug", "--output"])
        .arg(&package_output)
        .output()
        .unwrap();
    assert!(!failed_package.status.success());
    assert!(!package_output.exists());
    assert!(
        String::from_utf8_lossy(&failed_package.stderr)
            .contains("intentional native build failure")
    );
    fs::write(&source, "fn main() {}\n").unwrap();
    let invalid_version = runner(root)
        .args(["package", "--debug", "--output"])
        .arg(&package_output)
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
    let native = runner(root)
        .args(["build", "--debug", "--output"])
        .arg(&binary)
        .output()
        .unwrap();
    assert!(native.status.success());
    let original = fs::read(&binary).unwrap();
    assert!(!original.is_empty());
    let alias = root.join(if cfg!(windows) {
        "native-hardlink.exe"
    } else {
        "native-hardlink"
    });
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
        let result = runner(root)
            .args(["build", "--debug", "--output"])
            .arg(&output)
            .output()
            .unwrap();
        assert!(result.status.success());
        assert!(fs::read(&binary).unwrap() == original);
        assert!(fs::read(&output).unwrap() == original);
        assert!(Command::new(&output).status().unwrap().success());
    }
}
