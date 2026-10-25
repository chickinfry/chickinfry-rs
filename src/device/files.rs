use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use super::{ClientError, error, validate_path};

#[cfg(windows)]
#[path = "windows.rs"]
mod windows;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod macos;

pub(super) fn state_home() -> Result<PathBuf, ClientError> {
    #[cfg(all(test, any(target_os = "macos", windows)))]
    if let Some(root) = std::env::var_os("DEVICE_CHILD_ROOT") {
        let path = PathBuf::from(root).join("state");
        validate_path(&path)?;
        return Ok(path);
    }
    #[cfg(target_os = "linux")]
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|value| !value.is_empty()) {
        let path = PathBuf::from(path);
        if path.is_absolute() {
            return Ok(path);
        }
    }
    #[cfg(windows)]
    let path = windows::state_home()?;
    #[cfg(target_os = "macos")]
    let path = macos::state_home()?;
    #[cfg(not(any(windows, target_os = "macos")))]
    let path = {
        let home = PathBuf::from(
            std::env::var_os("HOME")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| error("unavailable"))?,
        );
        validate_path(&home)?;
        home.join(".local/state")
    };
    validate_path(&path)?;
    Ok(path)
}

pub(super) fn directory(path: &Path) -> Result<(), ClientError> {
    validate_path(path)?;
    if !path.exists() {
        let parent = path.parent().ok_or_else(|| error("unavailable"))?;
        if !parent.exists() {
            directory(parent)?;
        }
        ancestors(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            match fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => sync_directory(parent)?,
                Err(cause) if cause.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(cause) => return Err(io_error(cause)),
            }
        }
        #[cfg(windows)]
        windows::directory(path)?;
    }
    check_directory(path)
}

fn ancestors(path: &Path) -> Result<(), ClientError> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(io_error)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(error("unavailable"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
                return Err(error("unavailable"));
            }
        }
        #[cfg(windows)]
        windows::no_reparse(&metadata)?;
    }
    Ok(())
}

pub(super) fn check_directory(path: &Path) -> Result<(), ClientError> {
    ancestors(path)?;
    private(path, true)
}

pub(super) fn check_file(path: &Path) -> Result<(), ClientError> {
    private(path, false)
}

fn private(path: &Path, directory: bool) -> Result<(), ClientError> {
    let metadata = fs::symlink_metadata(path).map_err(io_error)?;
    if metadata.file_type().is_symlink()
        || metadata.is_dir() != directory
        || (!directory && !metadata.is_file())
    {
        return Err(error("unavailable"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let expected = if directory { 0o700 } else { 0o600 };
        // Ownership and link count matter even when the permission bits look private.
        if metadata.uid() != unsafe { libc::geteuid() }
            || (if directory {
                metadata.mode() & 0o022 != 0
            } else {
                metadata.mode() & 0o777 != expected
            })
            || (!directory && metadata.nlink() != 1)
        {
            return Err(error("unavailable"));
        }
    }
    #[cfg(target_os = "macos")]
    macos::private_path(path, &metadata)?;
    #[cfg(windows)]
    windows::private(path, &metadata)?;
    Ok(())
}

pub(super) fn create(path: &Path) -> Result<File, ClientError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(io_error)?;
        #[cfg(target_os = "macos")]
        macos::private_file(&file)?;
        Ok(file)
    }
    #[cfg(windows)]
    windows::create(path)
}

pub(super) fn open(path: &Path, create_missing: bool) -> Result<Option<File>, ClientError> {
    match fs::symlink_metadata(path) {
        Ok(_) => check_file(path)?,
        Err(cause) if cause.kind() == std::io::ErrorKind::NotFound => {
            return if create_missing {
                create(path).map(Some)
            } else {
                Ok(None)
            };
        }
        Err(cause) => return Err(io_error(cause)),
    }
    let mut options = OpenOptions::new();
    options.read(true).write(create_missing);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(io_error)?;
    check_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let path_metadata = fs::symlink_metadata(path).map_err(io_error)?;
        let opened = file.metadata().map_err(io_error)?;
        if (opened.dev(), opened.ino()) != (path_metadata.dev(), path_metadata.ino()) {
            return Err(error("unavailable"));
        }
    }
    Ok(Some(file))
}

pub(super) fn sync_directory(path: &Path) -> Result<(), ClientError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)?;
    #[cfg(windows)]
    let _ = path;
    Ok(())
}

pub(super) fn io_error(cause: std::io::Error) -> ClientError {
    #[cfg(unix)]
    if matches!(cause.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT)) {
        return error("full");
    }
    #[cfg(windows)]
    if matches!(cause.raw_os_error(), Some(39 | 112 | 1816)) {
        return error("full");
    }
    error("unavailable")
}

#[cfg(any(windows, test))]
pub(super) const FILE_ALL_ACCESS: u32 = 0x1f01ff;

#[cfg(any(windows, test))]
pub(super) fn private_windows_acl(
    control: u16,
    flags: u8,
    mask: u32,
    principal: &str,
    owner: &str,
) -> Result<(), ClientError> {
    if control & 0x1000 == 0
        || flags & 0x18 != 0
        || mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
        || principal != owner
    {
        return Err(error("unavailable"));
    }
    Ok(())
}
