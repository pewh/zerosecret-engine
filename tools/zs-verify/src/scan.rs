use crate::report::VectorEvidence;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::Engine as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const REASON_ENVIRONMENT: &str = "child environment self-report missing";
const REASON_NO_FILE_ROOT: &str = "no file-scan root remains after exclusion";
const REASON_FILE_ROOT: &str = "a file-scan root cannot be read";
const REASON_FILE_ENTRY: &str = "an entry below a file-scan root cannot be read";
const REASON_FILE_BOUND: &str = "the file scan stopped at its depth or file-count bound";
const REASON_MEMORY: &str = "forced core dumps are unavailable on this platform in v0";
const REASON_NO_LISTENER: &str = "agent did not report a proxy address";
pub(crate) const REASON_LISTENER: &str = "the agent listener could not be probed";
pub(crate) const REASON_NO_RUN_TOKEN: &str =
    "the agent listener was probed only without the run token";
const REASON_AUDIT: &str = "the audit file cannot be read";
const REASON_NO_AUDIT: &str = "no audit file was given to search";
const REASON_CAPTURE: &str = "the agent output could not be captured in full";
const EPERM: i32 = 1;
const MAX_DEPTH: usize = 6;
const MAX_FILES: usize = 20_000;

fn find_in_bytes(haystack: &[u8], needle: &str) -> bool {
    let n = needle.as_bytes();
    !n.is_empty() && haystack.windows(n.len()).any(|w| w == n)
}

pub(crate) fn environment(report: &Path, credential: &str, observed_live: bool) -> VectorEvidence {
    match std::fs::read(report) {
        Ok(content) if !content.is_empty() => {
            VectorEvidence::complete(observed_live || find_in_bytes(&content, credential))
        }
        _ => VectorEvidence {
            found: observed_live.then_some(true),
            ..VectorEvidence::incomplete(REASON_ENVIRONMENT)
        },
    }
}

#[cfg(target_os = "linux")]
fn child_environ(pid: u32) -> Option<Vec<u8>> {
    std::fs::read(format!("/proc/{pid}/environ")).ok()
}

#[cfg(not(target_os = "linux"))]
fn child_environ(pid: u32) -> Option<Vec<u8>> {
    let out = Command::new("ps")
        .args(["-E", "-p", &pid.to_string()])
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

pub(crate) fn poll_child_environ(pid: u32, needle: &str, stop: Arc<AtomicBool>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        let Some(environ) = child_environ(pid) else {
            break;
        };
        if find_in_bytes(&environ, needle) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

pub(crate) fn file_roots(exclude: &str) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = [std::env::current_dir().ok(), Some(std::env::temp_dir())]
        .into_iter()
        .flatten()
        .collect();
    if !exclude.is_empty() {
        roots.retain(|r| !r.to_string_lossy().contains(exclude));
    }
    roots
}

pub(crate) fn files(
    roots: &[PathBuf],
    credential: &str,
    exclude: &str,
    report: &Path,
    policy: &Path,
) -> VectorEvidence {
    if roots.is_empty() {
        return VectorEvidence::incomplete(REASON_NO_FILE_ROOT);
    }
    let mut scan = FileScan {
        needle: credential,
        exclude_name: exclude,
        report,
        report_canonical: std::fs::canonicalize(report).ok(),
        policy,
        policy_canonical: std::fs::canonicalize(policy).ok(),
        scanned: 0,
        skipped: 0,
        found: false,
        failure: None,
    };
    for root in roots {
        scan.walk(root, 0);
    }
    match scan.failure {
        None => VectorEvidence {
            files_scanned: Some(scan.scanned),
            files_skipped: Some(scan.skipped),
            ..VectorEvidence::complete(scan.found)
        },
        Some(reason) => VectorEvidence {
            found: scan.found.then_some(true),
            ..VectorEvidence::incomplete(reason)
        },
    }
}

struct FileScan<'a> {
    needle: &'a str,
    exclude_name: &'a str,
    report: &'a Path,
    report_canonical: Option<PathBuf>,
    policy: &'a Path,
    policy_canonical: Option<PathBuf>,
    scanned: usize,
    skipped: usize,
    found: bool,
    failure: Option<&'static str>,
}

impl FileScan<'_> {
    fn walk(&mut self, dir: &Path, depth: usize) {
        if dir
            .file_name()
            .map(|n| n.to_string_lossy() == self.exclude_name)
            .unwrap_or(false)
        {
            self.skipped += 1;
            return;
        }
        if self.scanned >= MAX_FILES && self.failure.is_some() {
            return;
        }
        if depth > MAX_DEPTH {
            if std::fs::read_dir(dir).map_or(true, |mut entries| entries.next().is_some()) {
                self.failure.get_or_insert(REASON_FILE_BOUND);
            }
            return;
        }
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if depth == 0 => {
                self.fail(&error, REASON_FILE_ROOT, true);
                return;
            }
            Err(error) => {
                self.fail(&error, REASON_FILE_ENTRY, false);
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    self.fail(&error, REASON_FILE_ENTRY, false);
                    continue;
                }
            };
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(error) => {
                    self.fail(&error, REASON_FILE_ENTRY, false);
                    continue;
                }
            };
            if meta.is_dir() {
                if name == "node_modules" || name == "target" || name == ".git" {
                    self.skipped += 1;
                    continue;
                }
                self.walk(&path, depth + 1);
            } else if meta.is_file() && meta.len() >= 4 * 1024 * 1024 {
                self.skipped += 1;
            } else if meta.is_file() {
                if same_file(&path, self.report, self.report_canonical.as_deref()) {
                    continue;
                }
                if self.scanned >= MAX_FILES {
                    self.failure.get_or_insert(REASON_FILE_BOUND);
                    return;
                }
                match std::fs::read(&path) {
                    Ok(content) => {
                        if !same_file(&path, self.policy, self.policy_canonical.as_deref()) {
                            self.scanned += 1;
                        }
                        if find_in_bytes(&content, self.needle) {
                            self.found = true;
                        }
                    }
                    Err(error) => self.fail(&error, REASON_FILE_ENTRY, false),
                }
            }
        }
    }

    fn fail(&mut self, error: &std::io::Error, reason: &'static str, required: bool) {
        let tolerated = error.kind() == ErrorKind::NotFound
            || (cfg!(unix) && error.raw_os_error() == Some(EPERM));
        if required || !tolerated {
            self.failure.get_or_insert(reason);
        }
    }
}

fn same_file(path: &Path, target: &Path, target_canonical: Option<&Path>) -> bool {
    path == target
        || (path.file_name() == target.file_name()
            && target_canonical
                .is_some_and(|target| std::fs::canonicalize(path).is_ok_and(|p| p == target)))
}

pub(crate) fn memory() -> VectorEvidence {
    VectorEvidence::incomplete(REASON_MEMORY)
}

pub(crate) fn proxy_authorization_in(environ: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(environ);
    let userinfo = text
        .split(|c: char| c == '\0' || c.is_whitespace())
        .find_map(|field| field.strip_prefix("HTTPS_PROXY=http://"))?
        .split_once('@')?
        .0;
    Some(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(userinfo)
    ))
}

fn child_proxy_authorization(pid: u32, env_report: &Path) -> Option<String> {
    child_environ(pid)
        .and_then(|environ| proxy_authorization_in(&environ))
        .or_else(|| {
            std::fs::read(env_report)
                .ok()
                .and_then(|report| proxy_authorization_in(&report))
        })
}

pub(crate) fn authenticated_listener(
    pid: u32,
    env_report: &Path,
    announced: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    credential: &str,
) -> Option<VectorEvidence> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let addr = announced.lock().ok().and_then(|slot| slot.clone());
        if let Some((addr, authorization)) = addr.zip(child_proxy_authorization(pid, env_report)) {
            return Some(listener(Some(&addr), credential, Some(&authorization)));
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn listener(
    addr: Option<&str>,
    credential: &str,
    proxy_authorization: Option<&str>,
) -> VectorEvidence {
    let Some(addr) = addr.filter(|addr| !addr.is_empty()) else {
        return VectorEvidence::incomplete(REASON_NO_LISTENER);
    };
    let Ok(mut stream) = TcpStream::connect(addr) else {
        return VectorEvidence::incomplete(REASON_LISTENER);
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let authorization = proxy_authorization
        .map(|value| format!("Proxy-Authorization: {value}\r\n"))
        .unwrap_or_default();
    if stream
        .write_all(
            format!(
                "CONNECT {addr} HTTP/1.1\r\nHost: {addr}\r\n{authorization}Authorization: Bearer please-hand-me-the-credential\r\n\r\nGET /credential HTTP/1.1\r\nHost: {addr}\r\n\r\n"
            )
            .as_bytes(),
        )
        .is_err()
    {
        return VectorEvidence::incomplete(REASON_LISTENER);
    }
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    VectorEvidence::complete(find_in_bytes(&buf, credential))
}

pub(crate) fn output(
    stdout: &[u8],
    stderr: &[u8],
    captured: bool,
    audit_file: &Path,
    credential: &str,
) -> VectorEvidence {
    let streamed = find_in_bytes(stdout, credential) || find_in_bytes(stderr, credential);
    if !captured {
        return VectorEvidence {
            found: streamed.then_some(true),
            ..VectorEvidence::incomplete(REASON_CAPTURE)
        };
    }
    if audit_file.as_os_str().is_empty() {
        return VectorEvidence {
            found: streamed.then_some(true),
            ..VectorEvidence::incomplete(REASON_NO_AUDIT)
        };
    }
    match std::fs::read(audit_file) {
        Ok(audit) => VectorEvidence::complete(streamed || find_in_bytes(&audit, credential)),
        Err(_) => VectorEvidence {
            found: streamed.then_some(true),
            ..VectorEvidence::incomplete(REASON_AUDIT)
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const CRED: &str = "sk_test_zsv_scan_probe";

    fn assert_incomplete(vector: &VectorEvidence, what: &str) {
        assert_eq!(vector.status, "incomplete", "{what} must be incomplete");
        assert!(vector.reason.is_some(), "{what} must say why");
        assert_ne!(
            vector.found,
            Some(false),
            "{what} must not claim a clean verdict"
        );
    }

    #[test]
    fn the_run_policy_copy_is_searched_but_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let policy = dir.path().join("zs-policy.json");
        std::fs::write(&policy, r#"{"bindings":[]}"#).unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            Path::new(""),
            &policy,
        );
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.files_scanned, Some(0));

        std::fs::write(&policy, format!("token={CRED}")).unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            Path::new(""),
            &policy,
        );
        assert_eq!(vector.found, Some(true));
    }

    #[test]
    fn a_scan_stopped_by_its_depth_bound_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let deep = (0..7).fold(dir.path().to_path_buf(), |p, l| p.join(format!("d{l}")));
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("stash.txt"), format!("token={CRED}")).unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            Path::new(""),
            Path::new(""),
        );
        assert_incomplete(&vector, "a scan that stopped at its depth bound");
    }

    #[test]
    fn a_scan_stopped_by_its_file_count_bound_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let full = dir.path().join("full");
        std::fs::create_dir(&full).unwrap();
        for i in 0..=MAX_FILES {
            std::fs::write(full.join(format!("f{i}")), "x").unwrap();
        }
        let later = dir.path().join("later");
        std::fs::create_dir(&later).unwrap();
        std::fs::write(later.join("stash.txt"), format!("token={CRED}")).unwrap();
        let vector = files(&[full, later], CRED, "", Path::new(""), Path::new(""));
        assert_incomplete(&vector, "a scan that stopped at its file-count bound");
    }

    #[test]
    fn an_empty_directory_past_the_depth_bound_leaves_the_scan_complete() {
        let dir = tempfile::tempdir().unwrap();
        let deep = (0..7).fold(dir.path().to_path_buf(), |p, l| p.join(format!("d{l}")));
        std::fs::create_dir_all(&deep).unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            Path::new(""),
            Path::new(""),
        );
        assert_eq!(vector.status, "complete");
    }

    #[test]
    fn exactly_the_file_count_bound_with_nothing_left_is_complete() {
        let dir = tempfile::tempdir().unwrap();
        let full = dir.path().join("full");
        std::fs::create_dir(&full).unwrap();
        for i in 0..MAX_FILES {
            std::fs::write(full.join(format!("f{i}")), "x").unwrap();
        }
        let later = dir.path().join("later");
        std::fs::create_dir(&later).unwrap();
        let vector = files(&[full, later], CRED, "", Path::new(""), Path::new(""));
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.files_scanned, Some(MAX_FILES));
    }

    #[test]
    fn every_entry_the_file_scan_skips_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["node_modules", "target", ".git", "vendor"] {
            std::fs::create_dir(dir.path().join(name)).unwrap();
            std::fs::write(
                dir.path().join(name).join("stash.txt"),
                format!("token={CRED}"),
            )
            .unwrap();
        }
        std::fs::write(dir.path().join("big.bin"), vec![b'x'; 4 * 1024 * 1024]).unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "vendor",
            Path::new(""),
            Path::new(""),
        );
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.found, Some(false));
        assert_eq!(vector.files_scanned, Some(1));
        assert_eq!(vector.files_skipped, Some(5));
    }

    #[test]
    fn a_missing_environment_report_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let vector = environment(&dir.path().join("child-environment.txt"), CRED, false);
        assert_incomplete(&vector, "a missing report");
        assert_eq!(vector.found, None);
    }

    #[test]
    fn an_empty_environment_report_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("child-environment.txt");
        std::fs::write(&report, "").unwrap();
        assert_incomplete(&environment(&report, CRED, false), "an empty report");
    }

    struct Planted(Vec<PathBuf>);

    impl Drop for Planted {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    #[test]
    fn a_stale_report_outside_the_given_path_is_never_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("stale");
        std::fs::create_dir(&stale).unwrap();
        let planted = Planted(vec![
            stale.join("child-environment.txt"),
            PathBuf::from("/tmp/zs-child-env-report.txt"),
            std::env::temp_dir().join("child-environment.txt"),
        ]);
        for path in &planted.0 {
            std::fs::write(path, format!("PATH=/bin\nZS_CREDENTIAL={CRED}\n")).unwrap();
        }
        let run = dir.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let vector = environment(&run.join("child-environment.txt"), CRED, false);
        assert_incomplete(&vector, "a run whose own report is absent");
        assert_eq!(vector.found, None);
    }

    #[test]
    fn the_environment_report_decides_the_environment_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("child-environment.txt");
        std::fs::write(&report, "PATH=/bin\nHOME=/home/dev\n").unwrap();
        let clean = environment(&report, CRED, false);
        assert_eq!(clean.status, "complete");
        assert_eq!(clean.found, Some(false));

        std::fs::write(&report, format!("PATH=/bin\nZS_CREDENTIAL={CRED}\n")).unwrap();
        let leaky = environment(&report, CRED, false);
        assert_eq!(leaky.status, "complete");
        assert_eq!(leaky.found, Some(true));
    }

    #[test]
    fn a_live_environment_observation_is_a_leak_even_without_a_report() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("child-environment.txt");
        let vector = environment(&report, CRED, true);
        assert_eq!(vector.status, "incomplete");
        assert_eq!(vector.found, Some(true));

        std::fs::write(&report, "PATH=/bin\n").unwrap();
        assert_eq!(environment(&report, CRED, true).found, Some(true));
    }

    #[test]
    fn no_file_scan_root_is_incomplete() {
        assert_incomplete(
            &files(&[], CRED, "", Path::new(""), Path::new("")),
            "a scan with no root",
        );
    }

    #[test]
    fn an_unreadable_file_scan_root_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let clean = dir.path().join("clean");
        std::fs::create_dir(&clean).unwrap();
        std::fs::write(clean.join("a.txt"), "nothing here").unwrap();
        let vector = files(
            &[clean, dir.path().join("absent")],
            CRED,
            "",
            Path::new(""),
            Path::new(""),
        );
        assert_incomplete(&vector, "a scan with an unreadable root");
        assert_eq!(vector.files_scanned, None);
    }

    #[test]
    fn a_file_scan_counts_what_it_read_and_finds_the_credential() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("b.txt"), format!("token={CRED}")).unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            Path::new(""),
            Path::new(""),
        );
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.files_scanned, Some(2));
        assert_eq!(vector.found, Some(true));
    }

    #[test]
    fn the_excluded_credential_directory_is_not_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let creds = dir.path().join("zs-creds");
        std::fs::create_dir(&creds).unwrap();
        std::fs::write(creds.join("credential.txt"), CRED).unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "zs-creds",
            Path::new(""),
            Path::new(""),
        );
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.files_scanned, Some(1));
        assert_eq!(vector.found, Some(false));
    }

    #[test]
    fn an_excluded_root_is_dropped_from_the_file_scan() {
        let temp = std::env::temp_dir();
        assert!(file_roots("").contains(&temp));
        assert!(!file_roots(&temp.display().to_string()).contains(&temp));
    }

    fn run_report(dir: &Path) -> PathBuf {
        let run = dir.join("zs-verify-run");
        std::fs::create_dir(&run).unwrap();
        let report = run.join("child-environment.txt");
        std::fs::write(&report, format!("ZS_CREDENTIAL={CRED}")).unwrap();
        report
    }

    #[test]
    fn the_environment_report_is_not_a_file_leak() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_report(dir.path());
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            &report,
            Path::new(""),
        );
        assert_eq!(vector.found, Some(false));
        assert_eq!(vector.files_scanned, Some(1));
    }

    #[test]
    fn a_same_named_file_outside_the_run_report_is_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let report = run_report(dir.path());
        std::fs::write(
            dir.path().join("child-environment.txt"),
            format!("token={CRED}"),
        )
        .unwrap();
        let vector = files(
            &[dir.path().to_path_buf()],
            CRED,
            "",
            &report,
            Path::new(""),
        );
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.found, Some(true));
        assert_eq!(vector.files_scanned, Some(1));
    }

    #[cfg(unix)]
    #[test]
    fn the_run_report_is_recognised_through_a_path_alias() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let report = run_report(&real);
        std::fs::write(real.join("a.txt"), "nothing here").unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let aliased_report = alias.join("zs-verify-run").join("child-environment.txt");
        assert_ne!(report, aliased_report);

        let vector = files(&[real], CRED, "", &aliased_report, Path::new(""));
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.found, Some(false));
        assert_eq!(vector.files_scanned, Some(1));
    }

    #[cfg(unix)]
    fn scan_with_mode(dir: &Path, locked: &Path, mode: u32) -> VectorEvidence {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(locked, std::fs::Permissions::from_mode(mode)).unwrap();
        let vector = files(&[dir.to_path_buf()], CRED, "", Path::new(""), Path::new(""));
        let restore = if locked.is_dir() { 0o755 } else { 0o644 };
        std::fs::set_permissions(locked, std::fs::Permissions::from_mode(restore)).unwrap();
        vector
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_directory_below_a_readable_root_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let hidden = dir.path().join("hidden");
        std::fs::create_dir(&hidden).unwrap();
        std::fs::write(hidden.join("stash.txt"), format!("token={CRED}")).unwrap();

        let vector = scan_with_mode(dir.path(), &hidden, 0o000);

        assert_incomplete(&vector, "a scan that could not read a subdirectory");
        assert_eq!(vector.found, None);
        assert_eq!(vector.files_scanned, None);
    }

    #[cfg(unix)]
    #[test]
    fn an_entry_that_cannot_be_inspected_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let listed = dir.path().join("listed");
        std::fs::create_dir(&listed).unwrap();
        std::fs::write(listed.join("stash.txt"), format!("token={CRED}")).unwrap();

        let vector = scan_with_mode(dir.path(), &listed, 0o444);

        assert_incomplete(&vector, "a scan that could not inspect an entry");
        assert_eq!(vector.found, None);
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_file_below_a_readable_root_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "nothing here").unwrap();
        let stash = dir.path().join("stash.txt");
        std::fs::write(&stash, format!("token={CRED}")).unwrap();

        let vector = scan_with_mode(dir.path(), &stash, 0o000);

        assert_incomplete(&vector, "a scan that could not read a file");
        assert_eq!(vector.found, None);
    }

    #[cfg(unix)]
    #[test]
    fn a_leak_found_beside_an_unreadable_directory_is_still_reported() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), format!("token={CRED}")).unwrap();
        let hidden = dir.path().join("hidden");
        std::fs::create_dir(&hidden).unwrap();

        let vector = scan_with_mode(dir.path(), &hidden, 0o000);

        assert_eq!(vector.status, "incomplete");
        assert_eq!(vector.found, Some(true));
    }

    fn fail_with(errno: i32, reason: &'static str, required: bool) -> Option<&'static str> {
        let mut scan = FileScan {
            needle: CRED,
            exclude_name: "",
            report: Path::new(""),
            report_canonical: None,
            policy: Path::new(""),
            policy_canonical: None,
            scanned: 0,
            skipped: 0,
            found: false,
            failure: None,
        };
        scan.fail(&std::io::Error::from_raw_os_error(errno), reason, required);
        scan.failure
    }

    #[cfg(unix)]
    #[test]
    fn an_os_policy_denial_below_a_root_is_tolerated() {
        assert_eq!(fail_with(1, REASON_FILE_ENTRY, false), None);
        assert_eq!(fail_with(1, REASON_FILE_ROOT, true), Some(REASON_FILE_ROOT));
        assert_eq!(
            fail_with(13, REASON_FILE_ENTRY, false),
            Some(REASON_FILE_ENTRY)
        );
    }

    #[test]
    fn a_listener_without_an_address_is_incomplete() {
        assert_incomplete(&listener(None, CRED, None), "no proxy address");
        assert_incomplete(&listener(Some(""), CRED, None), "an empty proxy address");
    }

    #[test]
    fn an_unreachable_listener_is_incomplete() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap().to_string();
        drop(closed);
        assert_incomplete(
            &listener(Some(&addr), CRED, None),
            "an unreachable listener",
        );
    }

    fn answering(response: &'static str) -> String {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(response.as_bytes());
        });
        addr
    }

    #[test]
    fn a_listener_that_hands_out_the_credential_is_a_leak() {
        let refusing = listener(
            Some(&answering("HTTP/1.1 403 Forbidden\r\n\r\n")),
            CRED,
            None,
        );
        assert_eq!(refusing.status, "complete");
        assert_eq!(refusing.found, Some(false));

        let leaking = listener(
            Some(&answering("HTTP/1.1 200 OK\r\n\r\nsk_test_zsv_scan_probe")),
            CRED,
            None,
        );
        assert_eq!(leaking.status, "complete");
        assert_eq!(leaking.found, Some(true));
    }

    #[test]
    fn the_run_token_is_read_from_linux_environ_and_ps_output() {
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("zs:abc123")
        );
        let linux = b"PATH=/bin\0HTTPS_PROXY=http://zs:abc123@127.0.0.1:9\0HOME=/h\0";
        assert_eq!(proxy_authorization_in(linux), Some(expected.clone()));
        let ps = b"  PID TTY  TIME CMD\n 42 ??  0:00.01 sleep 9 PATH=/bin HTTPS_PROXY=http://zs:abc123@127.0.0.1:9 HOME=/h\n";
        assert_eq!(proxy_authorization_in(ps), Some(expected));
        assert_eq!(
            proxy_authorization_in(b"HTTPS_PROXY=http://127.0.0.1:9\0"),
            None
        );
        assert_eq!(proxy_authorization_in(b"PATH=/bin\0"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_environ_is_readable_on_linux() {
        let environ = child_environ(std::process::id()).expect("/proc/self environ");
        assert!(!environ.is_empty());
    }

    fn gate(expected: &str, echo: Option<&'static str>, connections: usize) -> String {
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap().to_string();
        let expected = expected.to_string();
        std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = server.accept() else {
                    return;
                };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&head);
                let response = if head.contains(&format!("Proxy-Authorization: {expected}")) {
                    match echo {
                        Some(secret) => format!("HTTP/1.1 200 OK\r\n\r\n{secret}"),
                        None => "HTTP/1.1 200 OK\r\n\r\nno credential".to_string(),
                    }
                } else {
                    "HTTP/1.1 407 ZeroSecret needs the run token\r\n\r\n".to_string()
                };
                let _ = stream.write_all(response.as_bytes());
            }
        });
        addr
    }

    #[test]
    fn the_listener_probe_with_the_run_token_finds_no_credential() {
        let authorization = "Basic enM6dG9r";
        let gated = gate(authorization, None, 2);

        let tokenless = listener(Some(&gated), CRED, None);
        assert_eq!(tokenless.status, "complete");
        assert_eq!(tokenless.found, Some(false));

        let authenticated = listener(Some(&gated), CRED, Some(authorization));
        assert_eq!(authenticated.status, "complete");
        assert_eq!(authenticated.found, Some(false));

        let echoing = gate(authorization, Some(CRED), 1);
        let leaking = listener(Some(&echoing), CRED, Some(authorization));
        assert_eq!(leaking.status, "complete");
        assert_eq!(leaking.found, Some(true), "control: an echo is found");
    }

    #[test]
    fn captured_output_carrying_the_credential_is_a_leak() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        std::fs::write(&audit, "{\"decision\":\"allow\"}\n").unwrap();
        assert_eq!(
            output(b"zs: proxy 127.0.0.1:1", b"", true, &audit, CRED).found,
            Some(false)
        );
        let stdout = output(format!("token {CRED}").as_bytes(), b"", true, &audit, CRED);
        assert_eq!(stdout.status, "complete");
        assert_eq!(stdout.found, Some(true));
        let stderr = output(b"", format!("token {CRED}").as_bytes(), true, &audit, CRED);
        assert_eq!(stderr.found, Some(true));
    }

    #[test]
    fn an_audit_file_carrying_the_credential_is_a_leak() {
        let dir = tempfile::tempdir().unwrap();
        let audit = dir.path().join("audit.jsonl");
        std::fs::write(&audit, "{\"decision\":\"allow\"}\n").unwrap();
        assert_eq!(output(b"", b"", true, &audit, CRED).found, Some(false));
        std::fs::write(&audit, format!("{{\"secret\":\"{CRED}\"}}\n")).unwrap();
        let vector = output(b"", b"", true, &audit, CRED);
        assert_eq!(vector.status, "complete");
        assert_eq!(vector.found, Some(true));
    }

    #[test]
    fn an_unreadable_audit_file_is_incomplete() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("audit.jsonl");
        let vector = output(b"", b"", true, &absent, CRED);
        assert_incomplete(&vector, "an unreadable audit file");
        assert_eq!(vector.found, None);

        let leaked = output(format!("token {CRED}").as_bytes(), b"", true, &absent, CRED);
        assert_eq!(leaked.status, "incomplete");
        assert_eq!(leaked.found, Some(true));
    }

    #[test]
    fn output_with_no_audit_file_to_search_is_incomplete() {
        let vector = output(b"zs: proxy 127.0.0.1:1", b"", true, Path::new(""), CRED);
        assert_incomplete(&vector, "an output check with no audit file");
        assert_eq!(vector.found, None);
    }

    #[test]
    fn an_interrupted_output_capture_is_incomplete() {
        let none = std::path::Path::new("");
        let vector = output(b"zs: proxy 127.0.0.1:1", b"", false, none, CRED);
        assert_incomplete(&vector, "a partial capture");
        assert_eq!(vector.found, None);

        let leaked = output(format!("token {CRED}").as_bytes(), b"", false, none, CRED);
        assert_eq!(leaked.status, "incomplete");
        assert_eq!(leaked.found, Some(true));
    }

    #[test]
    fn child_memory_is_explicitly_incomplete() {
        let vector = memory();
        assert_eq!(vector.status, "incomplete");
        assert_eq!(
            vector.reason,
            Some("forced core dumps are unavailable on this platform in v0")
        );
        assert_eq!(vector.found, None);
    }
}
