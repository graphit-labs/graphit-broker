use super::{Result, SqliteControlError};
#[cfg(windows)]
use graphit_fs::{
    create_private_database_directory as create_private_directory,
    verify_private_database_directory as verify_private_directory,
};
use graphit_fs::{create_private_database_file, verify_private_file};
#[cfg(not(windows))]
use graphit_fs::{create_private_directory, verify_private_directory};
use std::{
    ffi::OsString,
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

// A second local prepare must not open SQLite before a newly created file's
// birth descriptor closes. No descriptor outside SQLite closes over live locks.
#[cfg(unix)]
static PRIVATE_DATABASE_BIRTH: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A private directory protects driver-created journals. These checks do not
/// establish confinement against hostile namespace replacement by the same user.
pub(crate) struct PrivateDatabase {
    pub path: PathBuf,
    directory: File,
    #[cfg(windows)]
    database: File,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    database: graphit_fs::PrivateFileIdentity,
}
impl PrivateDatabase {
    pub fn prepare(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        let _birth = PRIVATE_DATABASE_BIRTH
            .lock()
            .map_err(|_| SqliteControlError::PrivateFile)?;
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| SqliteControlError::PrivateFile)?
                .join(path)
        };
        let parent = absolute.parent().ok_or(SqliteControlError::Configuration)?;
        ensure_directory(parent).map_err(|_| SqliteControlError::PrivateFile)?;
        let parent = fs::canonicalize(parent).map_err(|_| SqliteControlError::PrivateFile)?;
        let directory = private_directory(&parent).map_err(|_| SqliteControlError::PrivateFile)?;
        verify_private_directory(&directory).map_err(|_| SqliteControlError::PrivateFile)?;
        let name = absolute
            .file_name()
            .ok_or(SqliteControlError::Configuration)?;
        let path = parent.join(name);
        #[cfg(windows)]
        let database = match create_private_database_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_private(&directory, name)?
            }
            Err(_) => return Err(SqliteControlError::PrivateFile),
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let database = {
            match create_private_database_file(&path) {
                Ok(file) => {
                    verify_private_file(&file).map_err(|_| SqliteControlError::PrivateFile)?;
                    // This newly born file has no SQLite owner yet. Close its
                    // birth handle before the driver acquires any POSIX lock.
                    drop(file);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(SqliteControlError::PrivateFile),
            }
            inspect_private(&directory, name)?
        };
        let value = Self {
            path,
            directory,
            database,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        verify_private_directory(&self.directory).map_err(|_| SqliteControlError::PrivateFile)?;
        #[cfg(windows)]
        verify_private_file(&self.database).map_err(|_| SqliteControlError::PrivateFile)?;
        // The driver may remove sidecars on clean close. Existing entries must
        // be private before SQLite can read recovery data or write new secrets.
        let name = self
            .path
            .file_name()
            .ok_or(SqliteControlError::PrivateFile)?;
        #[cfg(windows)]
        open_private(&self.directory, name)?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if inspect_private(&self.directory, name)? != self.database {
            return Err(SqliteControlError::PrivateFile);
        }
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut sidecar = OsString::from(name);
            sidecar.push(suffix);
            #[cfg(windows)]
            let inspected = graphit_fs::write_relative::open_private_database_file_relative(
                &self.directory,
                &sidecar,
                windows_component_bytes(&sidecar),
                &mut || Ok(()),
            )
            .map(|_| ());
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let inspected = graphit_fs::write_relative::inspect_private_file_relative(
                &self.directory,
                &sidecar,
                sidecar.as_encoded_bytes().len(),
                &mut || Ok(()),
            )
            .map(|_| ());
            match inspected {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(SqliteControlError::PrivateFile),
            }
        }
        Ok(())
    }
}
fn ensure_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            verify_private_directory(&private_directory(path)?)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
            // Existing ancestors need not be private. Only newly created
            // parents and the database's immediate directory are private.
            if !parent.exists() {
                ensure_directory(parent)?;
            }
            match create_private_directory(path) {
                Ok(_) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    ensure_directory(path)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inspect_private(
    parent: &File,
    name: &std::ffi::OsStr,
) -> Result<graphit_fs::PrivateFileIdentity> {
    graphit_fs::write_relative::inspect_private_file_relative(
        parent,
        name,
        name.as_encoded_bytes().len(),
        &mut || Ok(()),
    )
    .map_err(|_| SqliteControlError::PrivateFile)
}

#[cfg(windows)]
fn open_private(parent: &File, name: &std::ffi::OsStr) -> Result<File> {
    graphit_fs::write_relative::open_private_database_file_relative(
        parent,
        name,
        windows_component_bytes(name),
        &mut || Ok(()),
    )
    .map_err(|_| SqliteControlError::PrivateFile)
}

#[cfg(windows)]
fn private_directory(path: &Path) -> io::Result<File> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let ancestor = graphit_fs::read_directory::open_root_readonly(parent, &mut || Ok(()))?;
    graphit_fs::write_relative::open_private_directory_relative(
        &ancestor,
        name,
        windows_component_bytes(name),
        &mut || Ok(()),
    )
}

#[cfg(windows)]
fn windows_component_bytes(name: &std::ffi::OsStr) -> usize {
    use std::os::windows::ffi::OsStrExt;
    name.encode_wide().count() * std::mem::size_of::<u16>()
}

#[cfg(not(windows))]
fn private_directory(path: &Path) -> io::Result<File> {
    let directory = graphit_fs::read_directory::open_root_readonly(path, &mut || Ok(()))?;
    verify_private_directory(&directory)?;
    Ok(directory)
}
