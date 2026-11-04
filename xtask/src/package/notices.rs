//! Notices from the exact native dependency selected by Cargo.
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

pub(super) struct NativeSource {
    pub(super) notices: Vec<PathBuf>,
    pub(super) engine_package_id: String,
    pub(super) platform_producer: PathBuf,
}

pub(super) fn collect(root: &Path) -> io::Result<NativeSource> {
    let output = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml"))
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(
            "locked Cargo metadata unavailable for native notices",
        ));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| io::Error::other("Cargo packages missing"))?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| io::Error::other("Cargo resolve missing"))?;
    let selected: Vec<_> = packages
        .iter()
        .filter(|pkg| {
            pkg["name"] == "llama-cpp-sys-2" && nodes.iter().any(|node| node["id"] == pkg["id"])
        })
        .collect();
    if selected.len() != 1
        || selected[0]["version"] != "0.1.161"
        || !selected[0]["source"]
            .as_str()
            .is_some_and(|s| s.ends_with("#424d1ffe6c1c4212d5da8e6075f473e33e35fb7f"))
    {
        return Err(io::Error::other(
            "expected one locked upstream llama binding",
        ));
    }
    let manifest = Path::new(
        selected[0]["manifest_path"]
            .as_str()
            .ok_or_else(|| io::Error::other("Cargo manifest path missing"))?,
    );
    let source = manifest
        .parent()
        .ok_or_else(|| io::Error::other("Cargo manifest parent missing"))?;
    let ai = packages
        .iter()
        .find(|pkg| pkg["name"] == "graphit-ai")
        .and_then(|pkg| pkg["manifest_path"].as_str())
        .map(Path::new)
        .and_then(Path::parent)
        .ok_or_else(|| io::Error::other("graphit-ai package missing"))?;
    let mut entries = Vec::new();
    for (source, relative) in [
        (
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../LICENSE"),
            "graphit-runtime/licenses/broker/LICENSE",
        ),
        (
            source.join("llama.cpp/LICENSE"),
            "graphit-runtime/licenses/broker/ggml/LICENSE",
        ),
        (
            source.join("llama.cpp/licenses/LICENSE-jsonhpp"),
            "graphit-runtime/licenses/broker/ggml/licenses/LICENSE-jsonhpp",
        ),
        (
            source.join("../LICENSE-MIT"),
            "graphit-runtime/licenses/broker/ggml/LICENSE-MIT",
        ),
        (
            source.join("../LICENSE-APACHE"),
            "graphit-runtime/licenses/broker/ggml/LICENSE-APACHE",
        ),
        (
            ai.join("licenses/NVIDIA-CUDA-LICENSE"),
            "graphit-runtime/licenses/broker/nvidia/LICENSE",
        ),
    ] {
        let bytes = fs::read(source)?;
        if bytes.is_empty() {
            return Err(io::Error::other("missing native source notice"));
        }
        let relative = PathBuf::from(relative);
        let destination = root.join(&relative);
        fs::create_dir_all(destination.parent().unwrap())?;
        fs::write(destination, bytes)?;
        entries.push(relative);
    }
    let id = selected[0]["id"]
        .as_str()
        .ok_or_else(|| io::Error::other("Cargo package ID missing"))?
        .to_owned();
    Ok(NativeSource {
        notices: entries,
        engine_package_id: id,
        platform_producer: ai.join("../../scripts/package-platform-runtime.mjs"),
    })
}

/// Explicit native outputs from the successful Cargo build, never checkout discovery.
#[derive(Default)]
pub(super) struct RuntimeInputs {
    pub(super) engine: Option<PathBuf>,
    pub(super) toolkit: Option<PathBuf>,
    pub(super) search: Vec<PathBuf>,
}
pub(super) fn runtime_inputs(
    receipt: Option<&Path>,
    binary: &Path,
    package_id: &str,
) -> io::Result<RuntimeInputs> {
    let Some(receipt) = receipt else {
        return Ok(RuntimeInputs::default());
    };
    let messages: Vec<serde_json::Value> = fs::read_to_string(receipt)?
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    if !messages
        .last()
        .is_some_and(|m| m["reason"] == "build-finished" && m["success"] == true)
    {
        return Err(io::Error::other(
            "Cargo artifact stream did not finish successfully",
        ));
    }
    let binaries: Vec<_> = messages
        .iter()
        .filter(|m| {
            m["reason"] == "compiler-artifact"
                && m["target"]["name"] == "graphit-broker"
                && m["target"]["kind"] == serde_json::json!(["bin"])
                && m["executable"].is_string()
        })
        .collect();
    if binaries.len() != 1
        || fs::canonicalize(binaries[0]["executable"].as_str().unwrap())?
            != fs::canonicalize(binary)?
    {
        return Err(io::Error::other(
            "Cargo artifacts do not select the supplied Broker executable",
        ));
    }
    let builds: Vec<_> = messages
        .iter()
        .filter(|m| m["reason"] == "build-script-executed" && m["package_id"] == package_id)
        .collect();
    if builds.len() != 1 {
        return Err(io::Error::other(
            "expected one Cargo llama engine build output",
        ));
    }
    let engine = fs::canonicalize(
        builds[0]["out_dir"]
            .as_str()
            .ok_or_else(|| io::Error::other("Cargo engine output missing"))?,
    )?;
    let needs_cuda = builds[0]["linked_libs"].as_array().is_some_and(|libs| {
        libs.iter()
            .any(|lib| lib.as_str().is_some_and(|name| name.ends_with("ggml-cuda")))
    });
    let toolkit = if needs_cuda {
        std::env::var_os("CUDA_PATH")
            .map(fs::canonicalize)
            .transpose()?
    } else {
        None
    };
    let mut candidates = vec![engine.join("lib"), engine.join("lib64")];
    if let Some(toolkit) = &toolkit {
        candidates.extend([
            toolkit.join("lib64"),
            toolkit.join("targets/x86_64-linux/lib"),
        ]);
    }
    let search = candidates.into_iter().filter(|p| p.is_dir()).collect();
    Ok(RuntimeInputs {
        engine: Some(engine),
        toolkit,
        search,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn receipt_selects_the_supplied_binary_and_exact_engine_build() {
        let root = std::env::temp_dir().join(format!(
            "broker-cargo-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(root.join("engine/lib")).unwrap();
        let binary = root.join("broker");
        fs::write(&binary, "fixture").unwrap();
        let receipt = root.join("cargo.jsonl");
        let messages = vec![
            json!({"reason":"compiler-artifact", "target":{"name":"graphit-broker", "kind":["bin"]}, "executable":binary}),
            json!({"reason":"build-script-executed", "package_id":"selected-llama", "out_dir":root.join("engine"), "linked_libs":["static=llama"]}),
            json!({"reason":"build-finished", "success":true}),
        ];
        let write = |messages: &[serde_json::Value]| {
            fs::write(
                &receipt,
                messages
                    .iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        };
        write(&messages);
        let selected = runtime_inputs(Some(&receipt), &binary, "selected-llama").unwrap();
        assert_eq!(selected.engine, Some(root.join("engine")));
        assert_eq!(selected.search, vec![root.join("engine/lib")]);
        assert!(selected.toolkit.is_none());
        assert!(runtime_inputs(Some(&receipt), &binary, "other-llama").is_err());
        let mut duplicate = messages.clone();
        duplicate.insert(2, messages[1].clone());
        write(&duplicate);
        assert!(runtime_inputs(Some(&receipt), &binary, "selected-llama").is_err());
        write(&messages[..2]);
        assert!(runtime_inputs(Some(&receipt), &binary, "selected-llama").is_err());
        write(&messages);
        let other = root.join("other");
        fs::write(&other, "other binary").unwrap();
        assert!(runtime_inputs(Some(&receipt), &other, "selected-llama").is_err());
        assert!(
            runtime_inputs(None, &binary, "selected-llama")
                .unwrap()
                .search
                .is_empty()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
