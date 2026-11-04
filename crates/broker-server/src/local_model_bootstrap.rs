//! Private GGUF staging infrastructure, independent of model configuration and identity.
use super::ServerError;
use graphit_core::{
    artifact_store::SnapshotContext,
    brand::Brand,
    file_lock::Cancellation,
    installation_bootstrap::{self, BootstrapLimits},
    native_document_file::CapturedDocumentDirectory,
    native_path::MAX_PATH_BYTES,
    project_paths::InstallationPaths,
};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

// Match the existing Models ChildOptions::standard bootstrap policy.
const ANCESTORS: usize = 256;

pub(super) fn resolve() -> Result<InstallationPaths, ServerError> {
    let start = std::env::current_dir().map_err(|_| ServerError::Configuration)?;
    let home = dirs::home_dir();
    let global = std::env::var_os("GRAPHIT_GLOBAL_DIR");
    resolve_with(&start, home.as_deref(), global.as_deref().map(Path::new))
}

fn resolve_with(
    start: &Path,
    home: Option<&Path>,
    global: Option<&Path>,
) -> Result<InstallationPaths, ServerError> {
    if global.is_some_and(|path| path.as_os_str().is_empty()) {
        return Err(ServerError::Configuration);
    }
    InstallationPaths::resolve(Brand::default(), start, home, global)
        .map_err(|_| ServerError::Configuration)
}

pub(super) fn prepare(
    paths: &InstallationPaths,
    timeout: Duration,
) -> Result<Arc<CapturedDocumentDirectory>, ServerError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(ServerError::Configuration)?;
    let original = SnapshotContext::new(deadline, Cancellation::default());
    let limits =
        BootstrapLimits::new(MAX_PATH_BYTES, ANCESTORS).map_err(|_| ServerError::Configuration)?;
    let private = installation_bootstrap::prepare(paths, limits, &original)
        .into_installation()
        .map_err(|_| ServerError::Configuration)?;
    let temporary = paths.root().join("tmp");
    private
        .revalidate(&original)
        .map_err(|_| ServerError::Configuration)?;
    let birth = match graphit_fs::create_private_directory(&temporary) {
        Ok(handle) => Some(handle),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                std::fs::symlink_metadata(&temporary).map_err(|_| ServerError::Configuration)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(ServerError::Configuration);
            }
            None
        }
        Err(_) => return Err(ServerError::Configuration),
    };
    let expected = std::fs::canonicalize(paths.root())
        .map_err(|_| ServerError::Configuration)?
        .join("tmp");
    let parent = CapturedDocumentDirectory::capture(&temporary, limits.native_limits(), &original)
        .map_err(|_| ServerError::Configuration)?;
    if parent.canonical_path() != expected {
        return Err(ServerError::Configuration);
    }
    let metadata = std::fs::symlink_metadata(&temporary).map_err(|_| ServerError::Configuration)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ServerError::Configuration);
    }
    match birth {
        Some(handle) => parent
            .verify_private_handle(&handle, &original)
            .map_err(|_| ServerError::Configuration)?,
        None => {
            parent
                .private_handle(&original)
                .map_err(|_| ServerError::Configuration)?;
        }
    }
    private
        .revalidate(&original)
        .map_err(|_| ServerError::Configuration)?;
    Ok(Arc::new(parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_snapshots_use_captured_global_override_or_home_independently_of_yaml() {
        let fixture = tempfile::tempdir().unwrap();
        let start = fixture.path().join("cwd");
        let yaml = fixture.path().join("yaml");
        let home = fixture.path().join("home");
        for path in [&start, &yaml, &home] {
            std::fs::create_dir(path).unwrap();
        }
        for global in [Some(Path::new("private-global")), None] {
            let paths = resolve_with(&start, Some(&home), global).unwrap();
            let expected = match global {
                Some(_) => start.join("private-global/tmp"),
                None => home.join(".graphit/tmp"),
            };
            assert!(!expected.exists());
            let parent = prepare(&paths, Duration::from_secs(5)).unwrap();
            assert_eq!(
                parent.canonical_path(),
                std::fs::canonicalize(&expected).unwrap()
            );
            assert!(!yaml.join("tmp").exists());
        }
        assert!(resolve_with(&start, Some(&home), Some(Path::new(""))).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn local_snapshot_bootstrap_rejects_nonprivate_or_symlink_tmp_without_repair() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let fixture = tempfile::tempdir().unwrap();
        let global = fixture.path().join("global");
        let paths = resolve_with(fixture.path(), None, Some(&global)).unwrap();
        let parent = prepare(&paths, Duration::from_secs(5)).unwrap();
        let temporary = parent.canonical_path().to_owned();
        drop(parent);
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(prepare(&paths, Duration::from_secs(5)).is_err());
        assert_eq!(
            std::fs::metadata(&temporary).unwrap().permissions().mode() & 0o777,
            0o755
        );
        std::fs::remove_dir(&temporary).unwrap();
        let foreign = tempfile::tempdir().unwrap();
        symlink(foreign.path(), &temporary).unwrap();
        assert!(prepare(&paths, Duration::from_secs(5)).is_err());
        assert!(std::fs::read_dir(foreign.path()).unwrap().next().is_none());
        assert!(
            std::fs::symlink_metadata(&temporary)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
}
