use std::fs::{self, Metadata};
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn prepare(path: &Path) -> Result<SocketGuard, String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("{}: socket path has no directory", path.display()))?;
    let uid = unsafe { libc::geteuid() };
    check_directory(dir, uid)?;
    clear_name(path)?;
    Ok(SocketGuard {
        path: path.to_path_buf(),
    })
}

fn check_directory(dir: &Path, expected_uid: u32) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("{}: cannot create socket directory: {e}", dir.display()))?;
        }
        Err(e) => {
            return Err(format!(
                "{}: cannot inspect socket directory: {e}",
                dir.display()
            ));
        }
    }
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| format!("{}: cannot inspect socket directory: {e}", dir.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{}: socket directory is a symbolic link",
            dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "{}: socket directory is not a directory",
            dir.display()
        ));
    }
    check_owner(dir, &meta, expected_uid)?;
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: socket directory is group- or world-writable",
            dir.display()
        ));
    }
    Ok(())
}

fn check_owner(dir: &Path, meta: &Metadata, expected_uid: u32) -> Result<(), String> {
    if meta.uid() != expected_uid {
        return Err(format!(
            "{}: socket directory is not owned by the agent's user",
            dir.display()
        ));
    }
    Ok(())
}

fn clear_name(path: &Path) -> Result<(), String> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(format!(
                "{}: cannot inspect socket path: {e}",
                path.display()
            ));
        }
    };
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{}: socket path is a symbolic link",
            path.display()
        ));
    }
    if !meta.file_type().is_socket() {
        return Err(format!(
            "{}: socket path exists and is not a socket",
            path.display()
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(format!(
                "{}: another listener is live on this socket path",
                path.display()
            ));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => {}
        Err(e) => {
            return Err(format!(
                "{}: cannot tell whether a listener is live on this socket path: {e}",
                path.display()
            ));
        }
    }
    fs::remove_file(path)
        .map_err(|e| format!("{}: cannot remove stale socket: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::os::unix::net::UnixListener;

    fn set_mode(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn missing_directory_is_created_with_mode_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("run");
        let guard = prepare(&dir.join("pg.sock")).unwrap();
        assert!(dir.is_dir());
        assert_eq!(mode_of(&dir), 0o700);
        drop(guard);
        assert!(dir.is_dir());
    }

    #[test]
    fn existing_private_directory_is_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o700);
        assert!(prepare(&tmp.path().join("pg.sock")).is_ok());
    }

    #[test]
    fn group_writable_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o770);
        let err = prepare(&tmp.path().join("pg.sock")).unwrap_err();
        assert!(err.contains(tmp.path().to_str().unwrap()), "{err}");
        assert!(!err.contains('\n'));
    }

    #[test]
    fn world_writable_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        set_mode(tmp.path(), 0o707);
        let err = prepare(&tmp.path().join("pg.sock")).unwrap_err();
        assert!(err.contains(tmp.path().to_str().unwrap()), "{err}");
    }

    #[test]
    fn symlink_as_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = tmp.path().join("link");
        symlink(&real, &link).unwrap();
        let err = prepare(&link.join("pg.sock")).unwrap_err();
        assert!(err.contains(link.to_str().unwrap()), "{err}");
        assert!(!real.join("pg.sock").exists());
    }

    #[test]
    fn symlink_as_socket_name_is_refused_and_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        fs::write(&target, b"keep").unwrap();
        let name = tmp.path().join("pg.sock");
        symlink(&target, &name).unwrap();
        let err = prepare(&name).unwrap_err();
        assert!(err.contains(name.to_str().unwrap()), "{err}");
        assert!(
            fs::symlink_metadata(&name)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn live_socket_is_refused_and_first_listener_still_accepts() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        let listener = UnixListener::bind(&name).unwrap();
        let err = prepare(&name).unwrap_err();
        assert!(err.contains(name.to_str().unwrap()), "{err}");
        assert!(!err.contains('\n'));
        assert!(name.exists());
        let client = UnixStream::connect(&name).unwrap();
        let (_server, _) = listener.accept().unwrap();
        drop(client);
    }

    #[test]
    fn stale_socket_is_removed_after_connect_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        drop(UnixListener::bind(&name).unwrap());
        assert!(fs::symlink_metadata(&name).unwrap().file_type().is_socket());
        assert!(UnixStream::connect(&name).is_err());
        let guard = prepare(&name).unwrap();
        assert!(!name.exists());
        let listener = UnixListener::bind(&name).unwrap();
        drop(listener);
        drop(guard);
    }

    #[test]
    fn unreadable_socket_is_refused_and_kept_when_connect_is_not_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        drop(UnixListener::bind(&name).unwrap());
        set_mode(&name, 0o000);
        match UnixStream::connect(&name) {
            Err(e) if e.kind() == ErrorKind::PermissionDenied => {}
            other => {
                eprintln!(
                    "skipped: connect gave {other:?}, not PermissionDenied (running as root or platform ignores socket mode)"
                );
                return;
            }
        }
        let err = prepare(&name).unwrap_err();
        assert!(err.contains(name.to_str().unwrap()), "{err}");
        assert!(!err.contains('\n'));
        assert!(fs::symlink_metadata(&name).unwrap().file_type().is_socket());
    }

    #[test]
    fn regular_file_at_name_is_refused_and_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        fs::write(&name, b"data").unwrap();
        let err = prepare(&name).unwrap_err();
        assert!(err.contains(name.to_str().unwrap()), "{err}");
        assert_eq!(fs::read(&name).unwrap(), b"data");
    }

    #[test]
    fn directory_at_name_is_refused_and_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        fs::create_dir(&name).unwrap();
        assert!(prepare(&name).is_err());
        assert!(name.is_dir());
    }

    #[test]
    fn socket_file_is_gone_after_guard_drops() {
        let tmp = tempfile::tempdir().unwrap();
        let name = tmp.path().join("pg.sock");
        let guard = prepare(&name).unwrap();
        let listener = UnixListener::bind(&name).unwrap();
        assert!(name.exists());
        drop(guard);
        assert!(!name.exists());
        assert!(tmp.path().is_dir());
        drop(listener);
    }

    #[test]
    fn directory_of_another_owner_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let meta = fs::symlink_metadata(tmp.path()).unwrap();
        assert!(check_owner(tmp.path(), &meta, meta.uid()).is_ok());
        let err = check_owner(tmp.path(), &meta, meta.uid().wrapping_add(1)).unwrap_err();
        assert!(err.contains(tmp.path().to_str().unwrap()), "{err}");
        assert!(!err.contains('\n'));
    }
}
