//! Files and directories readable only by the current user (SEC-007).
//!
//! On Unix hosts, directories get mode `0700` and files `0600`. On Windows they inherit the ACL of the
//! user profile they live in.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub fn create_dir_all(path: &Path) -> io::Result<()> {
    builder(true).create(path)
}

/// Creates one directory, failing if it already exists.
pub fn create_dir(path: &Path) -> io::Result<()> {
    builder(false).create(path)
}

fn builder(recursive: bool) -> DirBuilder {
    let mut builder = DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
}

fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Creates a new file, failing if one already exists.
pub fn create_new(path: &Path) -> io::Result<File> {
    options().write(true).create_new(true).open(path)
}

/// Creates a file or empties an existing one.
pub fn create_or_truncate(path: &Path) -> io::Result<File> {
    options().write(true).create(true).truncate(true).open(path)
}

pub fn open_append(path: &Path) -> io::Result<File> {
    options().create(true).append(true).open(path)
}

pub fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
    create_or_truncate(path)?.write_all(contents)
}

/// Restricts a file created by another program (for example `adb pull`) to the current user.
pub fn restrict_to_owner(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, fs::metadata(path)?);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn written_and_restricted_files_are_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let written = dir.path().join("written");
        write(&written, b"x").expect("write");
        assert_eq!(mode(&written), 0o600);

        let foreign = dir.path().join("foreign");
        fs::write(&foreign, b"x").expect("plain write");
        restrict_to_owner(&foreign).expect("restrict");
        assert_eq!(mode(&foreign), 0o600);
    }

    #[test]
    fn create_new_refuses_to_overwrite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("f");
        create_new(&path).expect("first");
        assert_eq!(
            create_new(&path).map(|_| ()).map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
    }
}
