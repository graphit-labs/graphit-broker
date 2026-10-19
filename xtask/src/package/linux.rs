//! Linux loader closure for the Broker installer; glibc and the GPU driver stay on the host.
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
};

const LIB: &str = "graphit-runtime/broker/lib";
const NOTICES: &str = "graphit-runtime/licenses/broker/linux";
const HOST: &[&str] = &[
    "libc.so.6",
    "libm.so.6",
    "libdl.so.2",
    "libpthread.so.0",
    "librt.so.1",
    "libresolv.so.2",
    "libutil.so.1",
    "libcuda.so.1",
];
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
fn run(program: impl AsRef<OsStr>, args: &[&OsStr]) -> io::Result<String> {
    let result = Command::new(program)
        .args(args)
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT")
        .env("LC_ALL", "C")
        .output()?;
    if !result.status.success() {
        return Err(invalid(format!(
            "Linux package tool failed: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        )));
    }
    String::from_utf8(result.stdout).map_err(io::Error::other)
}
fn hash(file: &Path) -> io::Result<String> {
    let mut input = fs::File::open(file)?;
    let mut digest = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let n = input.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        digest.update(&bytes[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn dependencies(
    loader: &Path,
    file: &Path,
    search: &[PathBuf],
) -> io::Result<BTreeMap<String, PathBuf>> {
    let mut command = Command::new(loader);
    command
        .arg("--list")
        .arg(file)
        .env_remove("LD_LIBRARY_PATH")
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT")
        .env("LC_ALL", "C");
    if !search.is_empty() {
        command.env(
            "LD_LIBRARY_PATH",
            std::env::join_paths(search).map_err(io::Error::other)?,
        );
    }
    let captured = command.output()?;
    if !captured.status.success() {
        return Err(invalid("Linux dependency resolution failed"));
    }
    let listing = String::from_utf8(captured.stdout).map_err(io::Error::other)?;
    let mut result = BTreeMap::new();
    for line in listing.lines().map(str::trim) {
        if line == "libcuda.so.1 => not found" {
            continue;
        }
        if let Some((name, rest)) = line.split_once(" => ") {
            if !safe_name(name) {
                return Err(invalid("invalid library SONAME"));
            }
            let (path, _) = rest
                .rsplit_once(" (")
                .ok_or_else(|| invalid("unrecognized loader dependency"))?;
            let path = Path::new(path);
            if !path.is_absolute() {
                return Err(invalid("loader dependency is not an absolute path"));
            }
            result.insert(name.to_owned(), fs::canonicalize(path)?);
        } else if !line.starts_with("linux-vdso.so.1 (")
            && !line.rsplit_once(" (").is_some_and(|(name, _)| {
                Path::new(name).is_absolute() && Path::new(name).file_name() == loader.file_name()
            })
        {
            return Err(invalid(format!("unrecognized loader output: {line}")));
        }
    }
    Ok(result)
}
fn copy_notice(root: &Path, relative: &str, source: &Path) -> io::Result<PathBuf> {
    let relative = PathBuf::from(relative);
    let bytes = fs::read(source)?;
    if bytes.is_empty() {
        return Err(invalid("empty Linux runtime notice"));
    }
    let target = root.join(&relative);
    fs::create_dir_all(target.parent().unwrap())?;
    fs::write(target, bytes)?;
    Ok(relative)
}
fn package_provenance(
    root: &Path,
    source: &Path,
    soname: &str,
    runtime: &super::notices::RuntimeInputs,
) -> io::Result<(serde_json::Value, Vec<PathBuf>)> {
    let engine = matches!(
        soname,
        "libllama.so" | "libggml.so" | "libggml-base.so" | "libggml-cpu.so" | "libggml-cuda.so"
    );
    let nvidia = matches!(
        soname,
        "libcudart.so.12" | "libcublas.so.12" | "libcublasLt.so.12"
    );
    if engine || nvidia {
        let origin = if engine {
            &runtime.engine
        } else {
            &runtime.toolkit
        };
        if !origin
            .as_ref()
            .is_some_and(|prefix| source.starts_with(prefix))
        {
            return Err(invalid(
                "native runtime is outside the selected Cargo build/toolkit; supply --cargo-artifacts and CUDA_PATH",
            ));
        }
        let origin = if engine {
            json!({"kind":"cargo", "package":"llama-cpp-sys-2", "version":"0.1.161"})
        } else {
            json!({"kind":"nvidia", "file": source.file_name().and_then(|s| s.to_str())})
        };
        return Ok((origin, Vec::new()));
    }

    // Builders are Debian/Ubuntu, including the maintained Ubuntu release job.
    // Refuse unowned libraries rather than ship bytes without redistribution notices.
    let owner = run("dpkg-query", &["-S".as_ref(), source.as_os_str()])?;
    let package = owner
        .lines()
        .find_map(|line| line.split_once(": ").map(|(owner, _)| owner))
        .ok_or_else(|| invalid("runtime library has no Debian package owner"))?;
    if package.lines().count() != 1 {
        return Err(invalid("ambiguous runtime package owner"));
    }
    let record = run(
        "dpkg-query",
        &[
            "-W".as_ref(),
            "-f=${binary:Package}\n${Version}\n${source:Package}\n${source:Version}".as_ref(),
            package.as_ref(),
        ],
    )?;
    let fields: Vec<_> = record.lines().collect();
    if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
        return Err(invalid("incomplete runtime package provenance"));
    }
    let package_name = package.split(':').next().unwrap();
    if !safe_name(package_name) {
        return Err(invalid("invalid runtime package name"));
    }
    let relative = format!("{NOTICES}/{soname}.copyright");
    let notice = copy_notice(
        root,
        &relative,
        &Path::new("/usr/share/doc")
            .join(package_name)
            .join("copyright"),
    )?;
    Ok((
        json!({"package": fields[0], "version": fields[1], "source_package": fields[2], "source_version": fields[3],
        "copyright": relative, "copyright_sha256": hash(&root.join(&notice))?}),
        vec![notice],
    ))
}

pub(super) fn prepare(
    root: &Path,
    original: &Path,
    binary: &Path,
    assets: &[PathBuf],
    runtime: &super::notices::RuntimeInputs,
) -> io::Result<Vec<PathBuf>> {
    let canonical_root = fs::canonicalize(root)?;
    let root = canonical_root.as_path();
    let canonical_binary = fs::canonicalize(binary)?;
    let binary = canonical_binary.as_path();
    let interpreter = run(
        "patchelf",
        &["--print-interpreter".as_ref(), binary.as_os_str()],
    )?;
    let interpreter = interpreter.trim();
    if interpreter != "/lib64/ld-linux-x86-64.so.2" {
        return Err(invalid(
            "Broker Linux package requires the native amd64 glibc ELF interpreter",
        ));
    }
    let loader = Path::new(interpreter);
    let input_hash = hash(binary)?;
    let original = fs::canonicalize(original)?;
    let mut roots = vec![original];
    roots.extend(
        assets
            .iter()
            .filter(|p| p.to_string_lossy().contains(".so"))
            .map(|p| root.join(p)),
    );
    let mut resolved = BTreeMap::new();
    for file in &roots {
        for (name, source) in dependencies(loader, file, &runtime.search)? {
            if HOST.contains(&name.as_str()) || source.starts_with(root) {
                continue;
            }
            if let Some(previous) = resolved.insert(name, source.clone())
                && previous != source
            {
                return Err(invalid("conflicting runtime libraries in Linux package"));
            }
        }
    }
    fs::create_dir_all(root.join(LIB))?;
    let mut entries = Vec::new();
    // Validation after patching uses the staged executable, not its input.
    roots[0] = binary.to_path_buf();
    let mut records = Vec::new();
    let mut glibc = BTreeSet::new();
    for (name, source) in resolved {
        let relative = PathBuf::from(LIB).join(&name);
        let target = root.join(&relative);
        let original_hash = hash(&source)?;
        let (provenance, notices) = package_provenance(root, &source, &name, runtime)?;
        entries.extend(notices);
        fs::copy(&source, &target)?;
        let soname = run("patchelf", &["--print-soname".as_ref(), target.as_os_str()])?;
        if soname.trim() != name {
            return Err(invalid("Linux runtime SONAME mismatch"));
        }
        run(
            "patchelf",
            &[
                "--set-rpath".as_ref(),
                "$ORIGIN".as_ref(),
                target.as_os_str(),
            ],
        )?;
        records.push(
            json!({"file": relative.to_str().unwrap(), "input_sha256": original_hash,
            "sha256": hash(&target)?, "runpath": "$ORIGIN", "distribution": provenance}),
        );
        roots.push(target);
        entries.push(relative);
    }
    if !records.is_empty() {
        // Debian GCC runtime copyright refers to the full GPL text here.
        entries.push(copy_notice(
            root,
            &format!("{NOTICES}/GPL-3"),
            Path::new("/usr/share/common-licenses/GPL-3"),
        )?);
    }
    let runpath = "$ORIGIN/graphit-runtime/broker/lib";
    run(
        "patchelf",
        &["--set-rpath".as_ref(), runpath.as_ref(), binary.as_os_str()],
    )?;
    let packaged_root = fs::canonicalize(root)?;
    for file in &roots {
        for (name, source) in dependencies(loader, file, &[])? {
            if !HOST.contains(&name.as_str()) && !source.starts_with(&packaged_root) {
                return Err(invalid(format!(
                    "Linux runtime dependency resolved outside package: {name}"
                )));
            }
        }
        let versions = run("readelf", &["--version-info".as_ref(), file.as_os_str()])?;
        for word in versions.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.') {
            if let Some(version) = word.strip_prefix("GLIBC_")
                && !version.is_empty()
                && version.bytes().all(|c| c.is_ascii_digit() || c == b'.')
            {
                glibc.insert(version.to_owned());
            }
        }
    }
    let manifest = PathBuf::from("graphit-runtime/broker/linux-libraries.json");
    fs::write(
        root.join(&manifest),
        serde_json::to_vec_pretty(&json!({"schema_version": 1,
        "executable": {"file": "graphit-broker", "input_sha256": input_hash, "sha256": hash(binary)?, "runpath": runpath},
        "interpreter": interpreter, "host_libraries": HOST, "required_glibc_versions": glibc, "files": records}))?,
    )?;
    entries.push(manifest);
    entries.sort();
    Ok(entries)
}
