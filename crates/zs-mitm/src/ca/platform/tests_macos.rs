#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

// Every `native_ca_macos_*` test must be ignored and start with the disposable-keychain interlock.

pub(super) use zs_test_keychain as disposable;

use std::cell::Cell;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use rand::RngCore;
use rand::rngs::OsRng;

use self::disposable::{
    Cleanup, Item, Locked, attributes, delete_exact, disposable_keychain, disposable_path, exists,
    has_attribute, keychain_of, password_output, plant, plant_legacy, security,
};
use super::macos::{
    INTERACTION_NOT_ALLOWED, ITEM_NOT_FOUND, ItemStatus, LOCK_CHECK_ARGS, LOCK_CHECK_TIMEOUT,
    MAX_TIMEOUT_SECS, OWNER_PREFIX, RECORD_PREFIX, SECURITY, SECURITY_TIMEOUT, SERVICE,
    TIMEOUT_ENV, add_args, checked_label, classify_find_status, classify_lock_status, command,
    delete_args, delete_legacy, delete_record, delete_record_args, find_args, legacy_from_output,
    owner_comment, parse_timeout, preflight, read_legacy, read_record, record_from_output,
    record_value, run_bounded, run_status_bounded, write_new,
};
use super::record::MAX_RECORD_LEN;
use super::state::load_with;
use super::tests::{
    ACCOUNT, CERT_FILE, Fixture, ID_FILE, INCOMPLETE, KEY_FILE, KEY_MISSING, LEGACY_MISMATCH,
    LOCKED, MALFORMED, MIGRATION_INCOMPLETE, REMOVAL_FAILED, UNAVAILABLE, assert_redacted, encoded,
    generated, handshake_succeeds, same_identity,
};
use super::{load, load_in_keychain, retire};
use crate::ca::{CaError, existing_keychain_label, keychain_label_for};

const ENCODED_LIMIT: usize = 3414;

fn exited(code: i32) -> ExitStatus {
    ExitStatus::from_raw(code << 8)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn with_newline(value: &[u8]) -> Vec<u8> {
    let mut output = value.to_vec();
    output.push(b'\n');
    output
}

#[test]
fn macos_adapter_only_item_not_found_status_is_absence() {
    assert_eq!(ITEM_NOT_FOUND, 44);
    assert!(matches!(
        classify_find_status(exited(0)),
        Ok(ItemStatus::Present)
    ));
    assert!(matches!(
        classify_find_status(exited(ITEM_NOT_FOUND)),
        Ok(ItemStatus::Missing)
    ));
    for code in [1, 2, 36, 43, 45, 50, 51, 128, 255] {
        assert_redacted(classify_find_status(exited(code)), UNAVAILABLE);
    }
    for signal in [9, 13, 15] {
        assert_redacted(
            classify_find_status(ExitStatus::from_raw(signal)),
            UNAVAILABLE,
        );
    }
}

#[test]
fn macos_adapter_uses_exact_commands() {
    assert_eq!(SECURITY, "/usr/bin/security");
    assert_eq!(SERVICE, "zerosecret.ca.v1");
    assert_eq!(
        find_args(ACCOUNT, SERVICE),
        [
            "find-generic-password",
            "-a",
            ACCOUNT,
            "-s",
            "zerosecret.ca.v1",
            "-w"
        ]
    );
    let label = keychain_label_for("/nonexistent/zerosecret-ca");
    assert_eq!(
        find_args(&label, &label),
        [
            "find-generic-password",
            "-a",
            label.as_str(),
            "-s",
            label.as_str(),
            "-w"
        ]
    );
    assert_eq!(
        delete_args(&label),
        [
            "delete-generic-password",
            "-a",
            label.as_str(),
            "-s",
            label.as_str()
        ]
    );
    assert_eq!(
        delete_record_args(ACCOUNT),
        [
            "delete-generic-password",
            "-a",
            ACCOUNT,
            "-s",
            "zerosecret.ca.v1"
        ]
    );
    assert_eq!(LOCK_CHECK_ARGS, ["show-keychain-info"]);
    let comment = OsStr::new("zerosecret-ca-dir:/owner");
    let value = OsStr::new("zsca1:AA");
    assert_eq!(
        add_args(ACCOUNT, comment, value),
        [
            "add-generic-password",
            "-a",
            ACCOUNT,
            "-s",
            "zerosecret.ca.v1",
            "-j",
            "zerosecret-ca-dir:/owner",
            "-w",
            "zsca1:AA",
        ]
        .map(OsStr::new)
    );
}

#[test]
fn macos_adapter_denies_inexact_item_names() {
    let long = "a".repeat(129);
    for name in [
        "",
        "-",
        "-a",
        " zerosecret",
        "zero secret",
        "zero\nsecret",
        "zero\"secret",
        "zero*",
        "zerosecret\u{e9}",
        ".hidden",
        long.as_str(),
    ] {
        assert_redacted(checked_label(name), UNAVAILABLE);
    }
    let label = keychain_label_for("/nonexistent/zerosecret-ca");
    let limit = "a".repeat(128);
    for name in [
        ACCOUNT,
        label.as_str(),
        "zerosecret-test-1_2.3",
        limit.as_str(),
    ] {
        assert!(checked_label(name).is_ok_and(|checked| checked == name));
    }
}

#[test]
fn macos_adapter_owner_comment_names_the_canonical_directory() {
    let f = Fixture::new();
    let link = f.dir.with_file_name("link");
    std::os::unix::fs::symlink(&f.dir, &link).unwrap();
    let expected = format!(
        "{OWNER_PREFIX}{}",
        fs::canonicalize(&f.dir).unwrap().display()
    );
    assert!(expected.starts_with("zerosecret-ca-dir:/"));
    assert_eq!(owner_comment(&f.dir).unwrap(), OsStr::new(&expected));
    assert_eq!(owner_comment(&link).unwrap(), OsStr::new(&expected));
    assert_redacted(owner_comment(&f.dir.join("missing")), UNAVAILABLE);
}

#[test]
fn macos_adapter_legacy_label_requires_an_existing_directory() {
    use sha2::{Digest, Sha256};

    let label = |path: &Path| {
        let digest = Sha256::digest(path.to_string_lossy().as_bytes());
        format!("zerosecret-local-ca-{}", hex(&digest[..8]))
    };
    let f = Fixture::new();
    let link = f.dir.with_file_name("link");
    std::os::unix::fs::symlink(&f.dir, &link).unwrap();
    let expected = label(&fs::canonicalize(&f.dir).unwrap());
    assert_eq!(keychain_label_for(&f.dir), expected);
    assert_eq!(existing_keychain_label(&f.dir), Some(expected.clone()));
    assert_eq!(existing_keychain_label(&link), Some(expected));

    let fresh = f.dir.with_file_name("fresh");
    assert_eq!(existing_keychain_label(&fresh), None);
    assert_eq!(keychain_label_for(&fresh), label(&fresh));
    let relative = Path::new("zerosecret-test-missing").join(".zs-ca");
    assert_eq!(existing_keychain_label(&relative), None);
    assert_eq!(keychain_label_for(&relative), label(&relative));
}

#[test]
fn macos_adapter_record_values_are_prefixed_unpadded_base64() {
    assert_eq!(RECORD_PREFIX, "zsca1:");
    let all_bytes: Vec<u8> = (0..=255).collect();
    for bytes in [
        vec![0u8],
        vec![0u8, 0],
        all_bytes,
        encoded(&generated()),
        vec![0u8; MAX_RECORD_LEN],
    ] {
        let value = record_value(&bytes).unwrap();
        let body = value.strip_prefix(RECORD_PREFIX.as_bytes()).unwrap();
        assert!(body == STANDARD_NO_PAD.encode(&bytes).as_bytes());
        assert!(value.iter().all(u8::is_ascii_graphic));
        let decoded = record_from_output(&with_newline(&value)).unwrap();
        assert!(decoded.0.as_slice() == bytes.as_slice());
    }
    assert_eq!(
        record_value(&[7; MAX_RECORD_LEN]).unwrap().len(),
        RECORD_PREFIX.len() + ENCODED_LIMIT
    );
    assert_redacted(record_value(&[]), UNAVAILABLE);
    assert_redacted(record_value(&[7; MAX_RECORD_LEN + 1]), UNAVAILABLE);
}

#[test]
fn macos_adapter_rejects_malformed_record_output() {
    let bytes = encoded(&generated());
    let body = STANDARD_NO_PAD.encode(&bytes);
    let valid = format!("{RECORD_PREFIX}{body}\n");
    assert!(record_from_output(valid.as_bytes()).is_ok());
    let hexed = format!("{}\n", hex(valid.trim_end().as_bytes()));
    let over = format!(
        "{RECORD_PREFIX}{}\n",
        STANDARD_NO_PAD.encode([7u8; MAX_RECORD_LEN + 1])
    );
    let starred = format!("{RECORD_PREFIX}*{body}\n");
    let cases = [
        valid.trim_end().to_owned(),
        format!("{valid}\n"),
        format!("{body}\n"),
        format!("zsca2:{body}\n"),
        format!("ZSCA1:{body}\n"),
        format!(" {valid}"),
        format!("{RECORD_PREFIX} {body}\n"),
        format!("{RECORD_PREFIX}{body} \n"),
        format!("{RECORD_PREFIX}{body}\r\n"),
        format!("{RECORD_PREFIX}\n"),
        format!("{RECORD_PREFIX}{}\n", STANDARD.encode([7u8])),
        format!("{RECORD_PREFIX}AB\n"),
        format!("{RECORD_PREFIX}A\n"),
        starred,
        hexed,
        over,
        "\n".to_owned(),
        String::new(),
    ];
    for case in &cases {
        assert_redacted(record_from_output(case.as_bytes()), UNAVAILABLE);
    }
}

#[test]
fn macos_adapter_reads_legacy_items_only_as_hex_encoded_text() {
    let key = generated().private_key_pem;
    let printed = format!("{}\n", hex(key.as_bytes()));
    assert!(legacy_from_output(printed.as_bytes()).unwrap().as_str() == key.as_str());
    let upper = format!("{}\n", hex(key.as_bytes()).to_uppercase());
    assert!(legacy_from_output(upper.as_bytes()).unwrap().as_str() == key.as_str());
    let limit = format!("{}\n", hex(&[b'A'; MAX_RECORD_LEN]));
    assert_eq!(
        legacy_from_output(limit.as_bytes()).unwrap().len(),
        MAX_RECORD_LEN
    );

    let record = record_value(&encoded(&generated())).unwrap();
    let cases = [
        hex(key.as_bytes()).into_bytes(),
        format!("{}\n\n", hex(key.as_bytes())).into_bytes(),
        with_newline(key.as_bytes()),
        with_newline(&record),
        with_newline(b"not a key"),
        b"\n".to_vec(),
        Vec::new(),
        b"abc\n".to_vec(),
        b"zz\n".to_vec(),
        b"0x41\n".to_vec(),
        format!("{}\n", hex(&[0xff, 0xfe])).into_bytes(),
        format!("{}\n", hex(&[b'A'; MAX_RECORD_LEN + 1])).into_bytes(),
    ];
    for case in &cases {
        assert_redacted(legacy_from_output(case), UNAVAILABLE);
    }
}

#[test]
fn macos_adapter_keychain_interlock_accepts_only_a_runner_temp_keychain() {
    let root = tempfile::tempdir().unwrap();
    let temp = root.path().join("runner-temp");
    let home = root.path().join("home");
    let personal = home.join("Library").join("Keychains");
    fs::create_dir_all(&temp).unwrap();
    fs::create_dir_all(&personal).unwrap();
    let keychain = temp.join("zerosecret-native.keychain-db");
    let outside = root.path().join("outside.keychain-db");
    let login = temp.join("login.keychain-db");
    let wrong_kind = temp.join("zerosecret.keychain");
    let in_home = personal.join("ci.keychain-db");
    for file in [&keychain, &outside, &login, &wrong_kind, &in_home] {
        fs::write(file, b"").unwrap();
    }
    let folder = temp.join("folder.keychain-db");
    fs::create_dir(&folder).unwrap();
    let link = temp.join("link.keychain-db");
    std::os::unix::fs::symlink(&outside, &link).unwrap();

    let check = |actions: Option<&str>, named: Option<&Path>, runner: Option<&Path>| {
        disposable_path(|name| match name {
            "GITHUB_ACTIONS" => actions.map(Into::into),
            "ZS_CI_KEYCHAIN" => named.map(|path| path.as_os_str().to_owned()),
            "RUNNER_TEMP" => runner.map(|path| path.as_os_str().to_owned()),
            "HOME" => Some(home.as_os_str().to_owned()),
            _ => None,
        })
    };
    let ok = Some("true");
    assert_eq!(
        check(ok, Some(&keychain), Some(&temp)),
        Ok(fs::canonicalize(&keychain).unwrap())
    );
    let relative = Path::new("runner-temp/zerosecret-native.keychain-db");
    let missing = temp.join("missing.keychain-db");
    for (actions, named, runner) in [
        (None, Some(keychain.as_path()), Some(temp.as_path())),
        (Some("false"), Some(&keychain), Some(&temp)),
        (ok, None, Some(&temp)),
        (ok, Some(&keychain), None),
        (ok, Some(relative), Some(&temp)),
        (ok, Some(&missing), Some(&temp)),
        (ok, Some(&outside), Some(&temp)),
        (ok, Some(&link), Some(&temp)),
        (ok, Some(&folder), Some(&temp)),
        (ok, Some(&wrong_kind), Some(&temp)),
        (ok, Some(&login), Some(&temp)),
        (ok, Some(&in_home), Some(root.path())),
        (ok, Some(&keychain), Some(Path::new("/"))),
    ] {
        assert!(check(actions, named, runner).is_err());
    }
}

fn program(path: &str, args: &[&str]) -> Command {
    let mut program = Command::new(path);
    program
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    program
}

static SPAWNING: Mutex<()> = Mutex::new(());

fn spawning() -> MutexGuard<'static, ()> {
    SPAWNING.lock().unwrap_or_else(PoisonError::into_inner)
}

fn children() -> Vec<(String, String)> {
    let output = Command::new("/bin/ps")
        .args(["-A", "-o", "ppid=,stat=,comm="])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let parent = std::process::id().to_string();
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let ppid = fields.next()?;
            let stat = fields.next()?.to_owned();
            let comm = fields.collect::<Vec<_>>().join(" ");
            (ppid == parent).then_some((stat, comm))
        })
        .filter(|(_, comm)| Path::new(comm).file_name() != Some(OsStr::new("ps")))
        .collect()
}

fn no_children_left() -> bool {
    children().is_empty()
}

#[test]
fn macos_adapter_child_listing_sees_an_unreaped_zombie() {
    let _serial = spawning();
    let mut exited = program("/usr/bin/true", &[]).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let zombie = || children().iter().any(|(stat, _)| stat.starts_with('Z'));
    while !zombie() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        zombie(),
        "an exited, unwaited child must be listed as a zombie"
    );
    assert!(!no_children_left());
    exited.wait().unwrap();
    assert!(no_children_left());
}

#[test]
fn macos_adapter_bounded_wait_captures_and_bounds_output() {
    let _serial = spawning();
    let ample = Duration::from_secs(10);
    let (status, output) =
        run_bounded(program("/bin/echo", &["zsca1:AA"]), Some(16), ample).unwrap();
    assert!(status.success());
    assert_eq!(output.as_slice(), b"zsca1:AA\n");
    let (status, output) = run_bounded(program("/usr/bin/false", &[]), Some(16), ample).unwrap();
    assert_eq!(status.code(), Some(1));
    assert!(output.is_empty());
    let (status, output) = run_bounded(program("/bin/echo", &["discarded"]), None, ample).unwrap();
    assert!(status.success());
    assert!(output.is_empty());
    assert_redacted(
        run_bounded(program("/usr/bin/yes", &[]), Some(16), ample),
        UNAVAILABLE,
    );
    assert_redacted(
        run_bounded(program("/nonexistent/security", &[]), Some(16), ample),
        UNAVAILABLE,
    );
    assert!(no_children_left());
}

#[test]
fn macos_adapter_bounded_wait_kills_and_reaps_a_blocked_command() {
    let _serial = spawning();
    let bound = Duration::from_millis(300);
    let started = Instant::now();
    assert_redacted(
        run_bounded(program("/bin/sleep", &["5"]), Some(16), bound),
        UNAVAILABLE,
    );
    assert_redacted(
        run_bounded(program("/bin/sleep", &["5"]), None, bound),
        UNAVAILABLE,
    );
    assert_redacted(
        run_bounded(
            program("/bin/sh", &["-c", "exec 1>&-; exec /bin/sleep 5"]),
            Some(16),
            bound,
        ),
        UNAVAILABLE,
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(no_children_left());
}

#[test]
fn macos_adapter_lib_tests_use_a_short_security_bound() {
    assert_eq!(SECURITY_TIMEOUT, Duration::from_secs(5));
}

const TIMEOUT_INVALID: &str = "CA storage timeout invalid";

#[test]
fn macos_adapter_only_a_clean_lock_check_is_unlocked() {
    assert_eq!(INTERACTION_NOT_ALLOWED, 36);
    assert!(classify_lock_status(Some(exited(0))).is_ok());
    assert_redacted(classify_lock_status(Some(exited(36))), LOCKED);
    assert_redacted(classify_lock_status(None), LOCKED);
    for code in [1, 2, 35, 37, 44, 45, 50, 51, 128, 255] {
        assert_redacted(classify_lock_status(Some(exited(code))), UNAVAILABLE);
    }
    for signal in [9, 13, 15] {
        assert_redacted(
            classify_lock_status(Some(ExitStatus::from_raw(signal))),
            UNAVAILABLE,
        );
    }
}

#[test]
fn macos_adapter_timeout_accepts_only_whole_seconds_in_range() {
    use std::os::unix::ffi::OsStrExt;
    assert_eq!(TIMEOUT_ENV, "ZS_KEYCHAIN_TIMEOUT_SECS");
    assert_eq!(MAX_TIMEOUT_SECS, 300);
    assert_eq!(parse_timeout(None).unwrap(), SECURITY_TIMEOUT);
    for (value, seconds) in [("1", 1), ("5", 5), ("030", 30), ("300", 300)] {
        assert_eq!(
            parse_timeout(Some(OsStr::new(value))).unwrap(),
            Duration::from_secs(seconds)
        );
    }
    for value in [
        "", "0", "000", "301", "999", "1000", "-1", "+5", " 5", "5 ", "5s", "1.5", "0x10", "٣",
    ] {
        let text = parse_timeout(Some(OsStr::new(value)))
            .err()
            .map(|error| error.to_string())
            .unwrap();
        assert_eq!(text, format!("ca storage: {TIMEOUT_INVALID}"), "{value:?}");
    }
    assert_redacted(
        parse_timeout(Some(OsStr::from_bytes(b"3\xff"))),
        TIMEOUT_INVALID,
    );
}

#[test]
fn macos_adapter_lock_check_bound_is_short() {
    assert_eq!(LOCK_CHECK_TIMEOUT, Duration::from_secs(5));
    assert!(LOCK_CHECK_TIMEOUT <= SECURITY_TIMEOUT);
}

#[test]
fn macos_adapter_bounded_status_wait_kills_and_reaps_a_blocked_command() {
    let _serial = spawning();
    let ample = Duration::from_secs(10);
    let status = run_status_bounded(program("/usr/bin/true", &[]), ample).unwrap();
    assert!(status.is_some_and(|status| status.success()));
    let status = run_status_bounded(program("/usr/bin/false", &[]), ample).unwrap();
    assert_eq!(status.and_then(|status| status.code()), Some(1));
    let started = Instant::now();
    let blocked = run_status_bounded(program("/bin/sleep", &["5"]), Duration::from_millis(300));
    assert!(matches!(blocked, Ok(None)));
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_redacted(
        run_status_bounded(program("/nonexistent/security", &[]), ample),
        UNAVAILABLE,
    );
    assert!(no_children_left());
}

#[test]
#[should_panic(expected = "the disposable keychain interlock has not run")]
fn macos_adapter_refuses_to_build_a_security_command_before_the_interlock() {
    let _ = command(["help"]);
}

fn random_hex() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unique_label() -> String {
    format!("zerosecret-test-{}", random_hex())
}

fn files(f: &Fixture) -> Vec<&'static str> {
    [CERT_FILE, KEY_FILE, ID_FILE]
        .into_iter()
        .filter(|name| f.path(name).exists())
        .collect()
}

fn located_in(keychain: &Path, account: &str, service: &str) -> bool {
    keychain_of(&attributes(account, service)).as_deref() == Some(keychain)
}

fn stored_is(account: &str, bytes: &[u8]) -> bool {
    read_record(account)
        .unwrap()
        .is_some_and(|stored| stored.0.as_slice() == bytes)
}

fn legacy_is(label: &str, key: &str) -> bool {
    read_legacy(label)
        .unwrap()
        .is_some_and(|stored| stored.as_str() == key)
}

fn injected() -> CaError {
    CaError::Storage("injected native detail".to_owned())
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_missing_item_status() {
    let keychain = disposable_keychain();
    let account = random_hex();
    let label = unique_label();
    let sibling = random_hex();
    let owner = Fixture::new();
    let _cleanup = Cleanup(vec![Item::Record(sibling.clone())]);

    for args in [find_args(&account, SERVICE), find_args(&label, &label)] {
        let status = security(args).status;
        assert_eq!(status.code(), Some(ITEM_NOT_FOUND), "missing-item status");
        assert!(matches!(
            classify_find_status(status),
            Ok(ItemStatus::Missing)
        ));
    }
    assert!(matches!(read_record(&account), Ok(None)));
    assert!(matches!(read_legacy(&label), Ok(None)));

    write_new(&sibling, &owner.dir, &encoded(&generated())).unwrap();
    let status = security(find_args(&sibling, SERVICE)).status;
    assert!(matches!(
        classify_find_status(status),
        Ok(ItemStatus::Present)
    ));
    assert!(read_record(&sibling).unwrap().is_some());
    assert!(located_in(&keychain, &sibling, SERVICE));
    assert!(matches!(read_record(&account), Ok(None)));

    let deleted = security(delete_args(&label)).status;
    assert!(!deleted.success());
    println!("missing-item delete status: {:?}", deleted.code());
    assert_redacted(delete_legacy(&label), UNAVAILABLE);
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_round_trip() {
    let keychain = disposable_keychain();
    let account = random_hex();
    let owner = Fixture::new();
    let _cleanup = Cleanup(vec![Item::Record(account.clone())]);
    let bytes = encoded(&generated());
    write_new(&account, &owner.dir, &bytes).unwrap();
    assert!(stored_is(&account, &bytes));

    let printed = password_output(&account, SERVICE).unwrap();
    assert!(printed == with_newline(&record_value(&bytes).unwrap()));
    let listed = attributes(&account, SERVICE);
    assert_eq!(keychain_of(&listed).as_deref(), Some(keychain.as_path()));
    assert!(has_attribute(&listed, "svce", OsStr::new(SERVICE)));
    assert!(has_attribute(&listed, "acct", OsStr::new(&account)));
    assert!(has_attribute(
        &listed,
        "icmt",
        &owner_comment(&owner.dir).unwrap()
    ));

    let mut other = bytes.clone();
    other[0] ^= 1;
    assert_redacted(write_new(&account, &owner.dir, &bytes), UNAVAILABLE);
    assert_redacted(write_new(&account, &owner.dir, &other), UNAVAILABLE);
    assert!(stored_is(&account, &bytes));
    assert!(password_output(&account, SERVICE).is_some_and(|again| again == printed));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_record_bounds() {
    let _keychain = disposable_keychain();
    let limit = random_hex();
    let oversized = random_hex();
    let empty = random_hex();
    let owner = Fixture::new();
    let _cleanup = Cleanup(
        [&limit, &oversized, &empty]
            .map(|account| Item::Record(account.clone()))
            .into(),
    );
    assert_redacted(
        write_new(&oversized, &owner.dir, &[b'Z'; MAX_RECORD_LEN + 1]),
        UNAVAILABLE,
    );
    assert_redacted(write_new(&empty, &owner.dir, &[]), UNAVAILABLE);
    assert!(!exists(&oversized, SERVICE));
    assert!(!exists(&empty, SERVICE));

    write_new(&limit, &owner.dir, &[b'Z'; MAX_RECORD_LEN]).unwrap();
    assert!(stored_is(&limit, &[b'Z'; MAX_RECORD_LEN]));

    let over = format!(
        "{RECORD_PREFIX}{}",
        STANDARD_NO_PAD.encode([b'Z'; MAX_RECORD_LEN + 1])
    );
    plant(&oversized, SERVICE, over.as_bytes());
    assert_redacted(read_record(&oversized), UNAVAILABLE);
    assert!(exists(&oversized, SERVICE));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_malformed_record_denies_without_mutation() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let bytes = encoded(&ca);
    let body = STANDARD_NO_PAD.encode(&bytes);
    let transport = [
        body.clone().into_bytes(),
        format!("zsca2:{body}").into_bytes(),
        format!("{RECORD_PREFIX}AA==").into_bytes(),
        format!("{RECORD_PREFIX}{body}!").into_bytes(),
        ca.private_key_pem.as_bytes().to_vec(),
    ];
    for value in &transport {
        let account = random_hex();
        let f = Fixture::new();
        let _cleanup = Cleanup(vec![Item::Record(account.clone())]);
        plant(&account, SERVICE, value);
        let planted = password_output(&account, SERVICE).unwrap();
        f.put(ID_FILE, account.as_bytes());
        f.put(CERT_FILE, ca.certificate_pem.as_bytes());
        assert_redacted(read_record(&account), UNAVAILABLE);
        assert_redacted(load(&f.dir), UNAVAILABLE);
        assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
        assert_eq!(
            f.certificate().as_deref(),
            Some(ca.certificate_pem.as_str())
        );
        assert!(password_output(&account, SERVICE).is_some_and(|now| now == planted));
    }

    let account = random_hex();
    let f = Fixture::new();
    let _cleanup = Cleanup(vec![Item::Record(account.clone())]);
    let mut corrupt = bytes.clone();
    corrupt[0] ^= 1;
    write_new(&account, &f.dir, &corrupt).unwrap();
    f.put(ID_FILE, account.as_bytes());
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    assert_redacted(load(&f.dir), MALFORMED);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(stored_is(&account, &corrupt));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_legacy_item_migration() {
    let keychain = disposable_keychain();
    let ca = generated();
    let f = Fixture::new();
    let label = keychain_label_for(&f.dir);
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Legacy(label.clone()),
    ]);
    plant_legacy(&label, &f.dir, &ca.private_key_pem);
    assert!(legacy_is(&label, &ca.private_key_pem));

    assert_redacted(load(&f.dir), INCOMPLETE);
    assert!(files(&f).is_empty());
    assert!(legacy_is(&label, &ca.private_key_pem));

    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    let migrated = load(&f.dir).unwrap();
    assert!(same_identity(&migrated, &ca));
    assert!(handshake_succeeds(&migrated, &ca.certificate_pem));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert!(!exists(&label, &label));
    let account = f.account().unwrap();
    assert!(stored_is(&account, &encoded(&ca)));
    assert!(located_in(&keychain, &account, SERVICE));

    let reloaded = load(&f.dir).unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert!(handshake_succeeds(&reloaded, &ca.certificate_pem));
    assert_eq!(f.account(), Some(account));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_file_migration() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let f = Fixture::new();
    let _cleanup = Cleanup(vec![Item::Directory(f.dir.clone())]);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let migrated = load(&f.dir).unwrap();
    assert!(same_identity(&migrated, &ca));
    assert!(handshake_succeeds(&migrated, &ca.certificate_pem));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    let account = f.account().unwrap();
    assert!(stored_is(&account, &encoded(&ca)));

    let reloaded = load(&f.dir).unwrap();
    assert!(same_identity(&reloaded, &ca));
    assert_eq!(f.account(), Some(account.clone()));
    assert!(stored_is(&account, &encoded(&ca)));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_record_reload() {
    let _keychain = disposable_keychain();
    let f = Fixture::new();
    let _cleanup = Cleanup(vec![Item::Directory(f.dir.clone())]);
    let created = load(&f.dir).unwrap();
    let account = f.account().unwrap();
    let certificate = f.certificate().unwrap();
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(exists(&account, SERVICE));
    assert!(has_attribute(
        &attributes(&account, SERVICE),
        "icmt",
        &owner_comment(&f.dir).unwrap()
    ));
    assert!(handshake_succeeds(&created, &certificate));

    let reloaded = load(&f.dir).unwrap();
    assert!(reloaded.public_key_der() == created.public_key_der());
    assert!(handshake_succeeds(&reloaded, &certificate));
    assert_eq!(f.account(), Some(account.clone()));

    fs::remove_file(f.path(CERT_FILE)).unwrap();
    let restored = load(&f.dir).unwrap();
    assert!(restored.public_key_der() == created.public_key_der());
    assert_eq!(f.certificate(), Some(certificate.clone()));

    assert!(delete_exact(&account, SERVICE));
    assert_redacted(load(&f.dir), KEY_MISSING);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(f.certificate(), Some(certificate));
    assert!(!exists(&account, SERVICE));
}

fn stored_directory(ca: &super::record::CaRecord, account: &str) -> Fixture {
    let f = Fixture::new();
    write_new(account, &f.dir, &encoded(ca)).unwrap();
    f.put(ID_FILE, account.as_bytes());
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    f
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_record_with_matching_legacy_deletes_it() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let account = random_hex();
    let _record = Cleanup(vec![Item::Record(account.clone())]);
    let f = stored_directory(&ca, &account);
    let label = keychain_label_for(&f.dir);
    let _legacy = Cleanup(vec![Item::Legacy(label.clone())]);
    plant_legacy(&label, &f.dir, &ca.private_key_pem);

    let loaded = load(&f.dir).unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(handshake_succeeds(&loaded, &ca.certificate_pem));
    assert!(!exists(&label, &label));
    assert!(stored_is(&account, &encoded(&ca)));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_record_with_mismatched_legacy_denies_without_mutation() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let other = generated();
    let account = random_hex();
    let _record = Cleanup(vec![Item::Record(account.clone())]);
    let f = stored_directory(&ca, &account);
    let label = keychain_label_for(&f.dir);
    let _legacy = Cleanup(vec![Item::Legacy(label.clone())]);
    plant_legacy(&label, &f.dir, &other.private_key_pem);

    assert_redacted(load(&f.dir), LEGACY_MISMATCH);
    assert!(legacy_is(&label, &other.private_key_pem));
    assert!(stored_is(&account, &encoded(&ca)));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert_eq!(
        f.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
}

fn absent_or_intact<F: Fn(&[u8]) -> bool>(account: &str, intact: F) -> bool {
    read_record(account)
        .unwrap()
        .is_none_or(|stored| intact(&stored.0))
}

fn outcome<T>(result: &Result<T, CaError>) -> String {
    match result {
        Ok(_) => "ok".to_owned(),
        Err(error) => format!("deny ({error})"),
    }
}

fn locked_call<T, F: FnOnce() -> Result<T, CaError>>(
    name: &str,
    operation: F,
) -> Result<T, CaError> {
    let started = Instant::now();
    let result = operation();
    let elapsed = started.elapsed();
    println!(
        "locked keychain: {name}: {} in {} ms",
        outcome(&result),
        elapsed.as_millis()
    );
    assert!(
        elapsed < 2 * SECURITY_TIMEOUT,
        "a locked Keychain call outlived its bound"
    );
    result
}

fn denied_within_bound<T, F: FnOnce() -> Result<T, CaError>>(name: &str, operation: F) {
    assert_redacted(locked_call(name, operation), UNAVAILABLE);
}

fn locked_quickly<T, F: FnOnce() -> Result<T, CaError>>(name: &str, operation: F) {
    let started = Instant::now();
    let result = locked_call(name, operation);
    assert!(
        started.elapsed() < 2 * LOCK_CHECK_TIMEOUT,
        "the lock check did not refuse within its bound"
    );
    assert_redacted(result, LOCKED);
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_locked_keychain_denies_without_mutation() {
    let keychain = disposable_keychain();
    let ca = generated();
    let account = random_hex();
    let other = random_hex();
    let _records = Cleanup(vec![
        Item::Record(account.clone()),
        Item::Record(other.clone()),
    ]);
    let stored = stored_directory(&ca, &account);
    let migrating = Fixture::new();
    let label = keychain_label_for(&migrating.dir);
    let files_only = Fixture::new();
    let fresh = Fixture::new();
    let _cleanup = Cleanup(vec![
        Item::Legacy(label.clone()),
        Item::Directory(migrating.dir.clone()),
        Item::Directory(files_only.dir.clone()),
        Item::Directory(fresh.dir.clone()),
    ]);
    plant_legacy(&label, &migrating.dir, &ca.private_key_pem);
    migrating.put(CERT_FILE, ca.certificate_pem.as_bytes());
    files_only.put(CERT_FILE, ca.certificate_pem.as_bytes());
    files_only.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let bytes = encoded(&ca);

    {
        let _locked = Locked::new(&keychain);
        denied_within_bound("read_record(existing)", || read_record(&account));
        denied_within_bound("read_legacy(existing)", || read_legacy(&label));
        denied_within_bound("write_new", || write_new(&other, &fresh.dir, &bytes));
        for (name, f) in [
            ("load(stored record)", &stored),
            ("load(legacy item)", &migrating),
            ("load(file key)", &files_only),
            ("load(fresh)", &fresh),
        ] {
            locked_quickly(name, || load(&f.dir));
        }
        locked_quickly("load_in_keychain(legacy item)", || {
            load_in_keychain(&migrating.dir, &label)
        });
    }
    assert!(no_children_left());

    assert_eq!(files(&stored), [CERT_FILE, ID_FILE]);
    assert!(stored_is(&account, &bytes));
    assert_eq!(files(&migrating), [CERT_FILE]);
    assert!(legacy_is(&label, &ca.private_key_pem));
    assert_eq!(
        files_only.certificate().as_deref(),
        Some(ca.certificate_pem.as_str())
    );
    assert!(files_only.file_key_is(&ca.private_key_pem));
    assert!(
        files_only
            .account()
            .is_none_or(|id| absent_or_intact(&id, |stored| stored == bytes.as_slice()))
    );
    assert!(files_only.account().is_none());
    assert!(files(&fresh).is_empty());
    assert!(!fresh.path(".ca-storage.lock").exists());
    assert!(absent_or_intact(&other, |stored| stored == bytes.as_slice()));
    println!(
        "locked keychain: killed write landed after unlock: {}",
        exists(&other, SERVICE)
    );

    for f in [&stored, &migrating, &files_only] {
        let loaded = load(&f.dir).unwrap();
        assert!(same_identity(&loaded, &ca));
        assert_eq!(files(f), [CERT_FILE, ID_FILE]);
    }
    assert!(!exists(&label, &label));
    assert!(load(&fresh.dir).is_ok());
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_locked_keychain_delete_probe() {
    let keychain = disposable_keychain();
    let ca = generated();
    let owner = Fixture::new();
    let label = unique_label();
    let _cleanup = Cleanup(vec![Item::Legacy(label.clone())]);
    plant_legacy(&label, &owner.dir, &ca.private_key_pem);

    let result = {
        let _locked = Locked::new(&keychain);
        locked_call("delete_legacy(existing)", || delete_legacy(&label))
    };
    assert!(no_children_left());
    let remains = exists(&label, &label);
    println!("locked keychain: delete_legacy item exists after unlock: {remains}");
    if result.is_ok() {
        assert!(!remains, "a reported delete must remove the item");
    } else {
        assert_redacted(result, UNAVAILABLE);
        assert!(legacy_is(&label, &ca.private_key_pem));
    }
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_failed_write_keeps_legacy_for_retry() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let f = Fixture::new();
    let label = keychain_label_for(&f.dir);
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Legacy(label.clone()),
    ]);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    plant_legacy(&label, &f.dir, &ca.private_key_pem);

    let raced = Cell::new(0);
    let result = load_with(
        &f.dir,
        || read_legacy(&label),
        read_record,
        |account, bytes| {
            write_new(account, &f.dir, bytes)?;
            raced.set(raced.get() + 1);
            write_new(account, &f.dir, bytes)
        },
        || delete_legacy(&label),
    );
    assert_redacted(result, UNAVAILABLE);
    assert_eq!(raced.get(), 1);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(legacy_is(&label, &ca.private_key_pem));
    let account = f.account().unwrap();
    assert!(stored_is(&account, &encoded(&ca)));

    let loaded = load(&f.dir).unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(!exists(&label, &label));
    assert!(stored_is(&account, &encoded(&ca)));

    let other = generated();
    let g = Fixture::new();
    let _other_cleanup = Cleanup(vec![Item::Directory(g.dir.clone())]);
    g.put(CERT_FILE, ca.certificate_pem.as_bytes());
    g.put(KEY_FILE, ca.private_key_pem.as_bytes());
    let result = load_with(
        &g.dir,
        || Ok(None),
        read_record,
        |account, bytes| {
            write_new(account, &g.dir, &encoded(&other))?;
            write_new(account, &g.dir, bytes)
        },
        || Err(injected()),
    );
    assert_redacted(result, UNAVAILABLE);
    let account = g.account().unwrap();
    assert!(stored_is(&account, &encoded(&other)));
    assert_redacted(load(&g.dir), LEGACY_MISMATCH);
    assert!(g.file_key_is(&ca.private_key_pem));
    assert_eq!(files(&g), [CERT_FILE, KEY_FILE, ID_FILE]);
    assert!(stored_is(&account, &encoded(&other)));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_failed_readback_keeps_legacy_for_retry() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let f = Fixture::new();
    let label = keychain_label_for(&f.dir);
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Legacy(label.clone()),
    ]);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    plant_legacy(&label, &f.dir, &ca.private_key_pem);

    let reads = Cell::new(0);
    let result = load_with(
        &f.dir,
        || read_legacy(&label),
        |account| {
            reads.set(reads.get() + 1);
            if reads.get() == 2 {
                return Err(injected());
            }
            read_record(account)
        },
        |account, bytes| write_new(account, &f.dir, bytes),
        || delete_legacy(&label),
    );
    assert_redacted(result, UNAVAILABLE);
    assert_eq!(reads.get(), 2);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(legacy_is(&label, &ca.private_key_pem));
    let account = f.account().unwrap();
    assert!(stored_is(&account, &encoded(&ca)));

    let loaded = load(&f.dir).unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(!exists(&label, &label));
    assert!(stored_is(&account, &encoded(&ca)));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_failed_legacy_deletion_retains_both_for_retry() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let f = Fixture::new();
    let label = keychain_label_for(&f.dir);
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Legacy(label.clone()),
    ]);
    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    plant_legacy(&label, &f.dir, &ca.private_key_pem);

    let result = load_with(
        &f.dir,
        || read_legacy(&label),
        read_record,
        |account, bytes| write_new(account, &f.dir, bytes),
        || Err(injected()),
    );
    assert_redacted(result, REMOVAL_FAILED);
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    assert!(legacy_is(&label, &ca.private_key_pem));
    let account = f.account().unwrap();
    assert!(stored_is(&account, &encoded(&ca)));

    let loaded = load(&f.dir).unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(!exists(&label, &label));
    assert!(stored_is(&account, &encoded(&ca)));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_migration_deletes_only_its_exact_legacy_item() {
    let _keychain = disposable_keychain();
    let ca = generated();
    let other = generated();
    let f = Fixture::new();
    let neighbour = Fixture::new();
    let orphan_root = tempfile::tempdir().unwrap();
    let orphan: PathBuf = orphan_root.path().join("ca");
    fs::create_dir(&orphan).unwrap();
    let label = keychain_label_for(&f.dir);
    let neighbour_label = keychain_label_for(&neighbour.dir);
    let orphan_label = keychain_label_for(&orphan);
    let custom = unique_label();
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Legacy(label.clone()),
        Item::Legacy(neighbour_label.clone()),
        Item::Legacy(orphan_label.clone()),
        Item::Legacy(custom.clone()),
    ]);
    plant_legacy(&label, &f.dir, &other.private_key_pem);
    plant_legacy(&neighbour_label, &neighbour.dir, &other.private_key_pem);
    plant_legacy(&orphan_label, &orphan, &other.private_key_pem);
    plant_legacy(&custom, &f.dir, &ca.private_key_pem);
    drop(orphan_root);
    assert!(!orphan.exists());

    f.put(CERT_FILE, ca.certificate_pem.as_bytes());
    let loaded = load_in_keychain(&f.dir, &custom).unwrap();
    assert!(same_identity(&loaded, &ca));
    assert!(!exists(&custom, &custom));
    assert!(legacy_is(&label, &other.private_key_pem));
    assert!(legacy_is(&neighbour_label, &other.private_key_pem));
    assert!(legacy_is(&orphan_label, &other.private_key_pem));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_exact_cleanup() {
    let _keychain = disposable_keychain();
    let kept = random_hex();
    let removed = random_hex();
    let owner = Fixture::new();
    let bytes = encoded(&generated());
    let keep = Cleanup(vec![Item::Record(kept.clone())]);
    write_new(&kept, &owner.dir, &bytes).unwrap();
    {
        let _cleanup = Cleanup(vec![Item::Record(removed.clone())]);
        write_new(&removed, &owner.dir, &bytes).unwrap();
        assert!(exists(&removed, SERVICE));
    }
    assert!(!exists(&removed, SERVICE));
    assert!(exists(&kept, SERVICE));
    drop(keep);
    assert!(!exists(&kept, SERVICE));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_lock_check() {
    let keychain = disposable_keychain();
    let started = Instant::now();
    assert!(preflight().is_ok());
    println!(
        "lock check: unlocked: ok in {} ms",
        started.elapsed().as_millis()
    );
    {
        let _locked = Locked::new(&keychain);
        let result = locked_call("preflight", preflight);
        let status = run_status_bounded(command(LOCK_CHECK_ARGS), LOCK_CHECK_TIMEOUT).unwrap();
        println!(
            "lock check: locked: show-keychain-info status {:?}",
            status.map(|status| status.code())
        );
        assert_redacted(result, LOCKED);
    }
    assert!(no_children_left());
    assert!(preflight().is_ok());
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_delete_record_is_exact() {
    let _keychain = disposable_keychain();
    let owner = Fixture::new();
    let bytes = encoded(&generated());
    let (removed, kept) = (random_hex(), random_hex());
    let _cleanup = Cleanup(vec![
        Item::Record(removed.clone()),
        Item::Record(kept.clone()),
    ]);
    write_new(&removed, &owner.dir, &bytes).unwrap();
    write_new(&kept, &owner.dir, &bytes).unwrap();
    let _other = Cleanup(vec![Item::Legacy(removed.clone())]);
    plant(&removed, &removed, b"zsca1:AA");

    assert!(delete_record(&removed).is_ok());
    assert!(!exists(&removed, SERVICE));
    assert!(exists(&removed, &removed));
    assert!(stored_is(&kept, &bytes));
    assert!(delete_record(&removed).is_ok());
    for name in ["", "-a", "*"] {
        assert_redacted(delete_record(name), UNAVAILABLE);
    }
    assert!(stored_is(&kept, &bytes));
}

#[test]
#[ignore = "requires the disposable CI keychain"]
fn native_ca_macos_retire() {
    let keychain = disposable_keychain();
    let ca = generated();
    let bytes = encoded(&ca);

    let f = Fixture::new();
    let neighbour = Fixture::new();
    let _cleanup = Cleanup(vec![
        Item::Directory(f.dir.clone()),
        Item::Directory(neighbour.dir.clone()),
    ]);
    load(&f.dir).unwrap();
    load(&neighbour.dir).unwrap();
    let account = f.account().unwrap();
    let kept = neighbour.account().unwrap();
    {
        let _locked = Locked::new(&keychain);
        locked_quickly("retire(locked)", || retire(&f.dir));
    }
    assert!(exists(&account, SERVICE));
    assert_eq!(files(&f), [CERT_FILE, ID_FILE]);
    retire(&f.dir).unwrap();
    assert!(!exists(&account, SERVICE));
    assert!(files(&f).is_empty());
    assert!(exists(&kept, SERVICE));
    assert_eq!(files(&neighbour), [CERT_FILE, ID_FILE]);
    assert_redacted(retire(&f.dir), "CA storage identity missing");
    load(&f.dir).unwrap();
    assert_ne!(f.account().unwrap(), account);

    let stored = stored_directory(&ca, &random_hex());
    let stored_account = stored.account().unwrap();
    let _stored = Cleanup(vec![Item::Directory(stored.dir.clone())]);
    let other = generated();
    stored.put(CERT_FILE, other.certificate_pem.as_bytes());
    assert_redacted(retire(&stored.dir), "CA certificate mismatch");
    assert!(stored_is(&stored_account, &bytes));
    stored.put(CERT_FILE, ca.certificate_pem.as_bytes());
    let label = keychain_label_for(&stored.dir);
    let _legacy = Cleanup(vec![Item::Legacy(label.clone())]);
    plant_legacy(&label, &stored.dir, &ca.private_key_pem);
    assert_redacted(retire(&stored.dir), MIGRATION_INCOMPLETE);
    assert!(stored_is(&stored_account, &bytes));
    assert!(legacy_is(&label, &ca.private_key_pem));
    load(&stored.dir).unwrap();
    assert!(!exists(&label, &label));
    retire(&stored.dir).unwrap();
    assert!(!exists(&stored_account, SERVICE));
    assert!(no_children_left());
}
