use std::path::Path;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::ca::{CaError, platform};

pub const DEVICE_SERVICE: &str = "zerosecret.device.v1";

#[cfg(target_os = "linux")]
const DEVICE_LABEL: &str = "ZeroSecret device identity";
#[cfg(not(target_os = "linux"))]
const DEVICE_LABEL: &str = "";

#[derive(Debug, Error)]
pub enum DeviceStoreError {
    #[error("secure storage locked")]
    Locked,
    #[error("secure storage unavailable")]
    Unavailable,
}

impl From<CaError> for DeviceStoreError {
    fn from(error: CaError) -> Self {
        match error {
            CaError::Storage(text) if text.ends_with("locked") => Self::Locked,
            _ => Self::Unavailable,
        }
    }
}

pub fn preflight() -> Result<(), DeviceStoreError> {
    platform::device_preflight().map_err(Into::into)
}

pub fn write_new(account: &str, owner: &Path, bytes: &[u8]) -> Result<(), DeviceStoreError> {
    platform::device_write_new(DEVICE_SERVICE, DEVICE_LABEL, account, owner, bytes)
        .map_err(Into::into)
}

pub fn read(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceStoreError> {
    platform::device_read(DEVICE_SERVICE, account).map_err(Into::into)
}

pub fn delete(account: &str) -> Result<(), DeviceStoreError> {
    platform::device_delete(DEVICE_SERVICE, account).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_device_service_differs_from_the_ca_service() {
        assert_eq!(DEVICE_SERVICE, "zerosecret.device.v1");
        assert_ne!(DEVICE_SERVICE, "zerosecret.ca.v1");
    }

    #[test]
    fn device_store_errors_have_fixed_texts() {
        assert_eq!(
            DeviceStoreError::Locked.to_string(),
            "secure storage locked"
        );
        assert_eq!(
            DeviceStoreError::Unavailable.to_string(),
            "secure storage unavailable"
        );
    }

    #[test]
    fn only_a_locked_storage_error_maps_to_locked() {
        let locked = CaError::Storage("secure CA storage locked".to_owned());
        let unavailable = CaError::Storage("secure CA storage unavailable".to_owned());
        let certificate = CaError::Certificate("locked up".to_owned());
        assert!(matches!(
            DeviceStoreError::from(locked),
            DeviceStoreError::Locked
        ));
        assert!(matches!(
            DeviceStoreError::from(unavailable),
            DeviceStoreError::Unavailable
        ));
        assert!(matches!(
            DeviceStoreError::from(certificate),
            DeviceStoreError::Unavailable
        ));
    }

    #[test]
    fn an_unusable_account_is_never_written() {
        let owner = tempfile::tempdir().unwrap();
        assert!(write_new("zs-device-x", owner.path(), b"").is_err());
    }

    fn sample() -> Vec<u8> {
        (0..300u16)
            .map(|n| u8::try_from(n % 251).unwrap())
            .collect()
    }

    fn account() -> String {
        use rand::RngCore;
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let hex: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("zs-device-{hex}")
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn round_trip(account: &str) {
        let owner = tempfile::tempdir().unwrap();
        let bytes = sample();
        assert!(read(account).unwrap().is_none());
        write_new(account, owner.path(), &bytes).unwrap();
        let stored = read(account).unwrap().unwrap();
        assert!(stored.as_slice() == bytes.as_slice());
        delete(account).unwrap();
        assert!(read(account).unwrap().is_none());
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn write_is_create_only(account: &str) {
        let owner = tempfile::tempdir().unwrap();
        let first = sample();
        let mut second = sample();
        second[0] ^= 1;
        write_new(account, owner.path(), &first).unwrap();
        assert!(write_new(account, owner.path(), &second).is_err());
        assert!(write_new(account, owner.path(), &first).is_err());
        let stored = read(account).unwrap().unwrap();
        assert!(stored.as_slice() == first.as_slice());
        delete(account).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn delete_of_an_absent_record_is_ok(account: &str) {
        assert!(read(account).unwrap().is_none());
        delete(account).unwrap();
        delete(account).unwrap();
        assert!(read(account).unwrap().is_none());
    }

    #[cfg(target_os = "macos")]
    mod macos {
        use super::*;
        use zs_test_keychain::{delete_exact, disposable_keychain, exists};

        struct Cleanup(String);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let clean = delete_exact(&self.0, DEVICE_SERVICE);
                if !clean && !std::thread::panicking() {
                    panic!("native device fixture cleanup failed");
                }
            }
        }

        #[test]
        #[ignore = "requires the disposable CI keychain"]
        fn native_device_macos_round_trip() {
            let _keychain = disposable_keychain();
            let account = account();
            let _cleanup = Cleanup(account.clone());
            let owner = tempfile::tempdir().unwrap();
            let bytes = sample();
            assert!(read(&account).unwrap().is_none());
            write_new(&account, owner.path(), &bytes).unwrap();
            assert!(exists(&account, DEVICE_SERVICE));
            assert!(!exists(&account, "zerosecret.ca.v1"));
            let stored = read(&account).unwrap().unwrap();
            assert!(stored.as_slice() == bytes.as_slice());
            delete(&account).unwrap();
            assert!(!exists(&account, DEVICE_SERVICE));
            assert!(read(&account).unwrap().is_none());
        }

        #[test]
        #[ignore = "requires the disposable CI keychain"]
        fn native_device_macos_write_is_create_only() {
            let _keychain = disposable_keychain();
            let account = account();
            let _cleanup = Cleanup(account.clone());
            let owner = tempfile::tempdir().unwrap();
            let first = sample();
            let mut second = sample();
            second[0] ^= 1;
            write_new(&account, owner.path(), &first).unwrap();
            assert!(write_new(&account, owner.path(), &second).is_err());
            let stored = read(&account).unwrap().unwrap();
            assert!(stored.as_slice() == first.as_slice());
            delete(&account).unwrap();
            assert!(!exists(&account, DEVICE_SERVICE));
        }

        #[test]
        #[ignore = "requires the disposable CI keychain"]
        fn native_device_macos_delete_of_an_absent_record_is_ok() {
            let _keychain = disposable_keychain();
            let account = account();
            let _cleanup = Cleanup(account.clone());
            assert!(read(&account).unwrap().is_none());
            delete(&account).unwrap();
            delete(&account).unwrap();
            assert!(!exists(&account, DEVICE_SERVICE));
        }
    }

    #[cfg(target_os = "windows")]
    mod windows {
        use super::*;

        struct Cleanup(String);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let clean = delete(&self.0).is_ok() && matches!(read(&self.0), Ok(None));
                if !clean && !std::thread::panicking() {
                    panic!("native device fixture cleanup failed");
                }
            }
        }

        fn guarded(body: fn(&str)) {
            let account = account();
            let _cleanup = Cleanup(account.clone());
            body(&account);
        }

        #[test]
        #[ignore = "writes uniquely targeted Windows Credential Manager entries"]
        fn native_device_windows_round_trip() {
            guarded(round_trip);
        }

        #[test]
        #[ignore = "writes uniquely targeted Windows Credential Manager entries"]
        fn native_device_windows_write_is_create_only() {
            guarded(write_is_create_only);
        }

        #[test]
        #[ignore = "writes uniquely targeted Windows Credential Manager entries"]
        fn native_device_windows_delete_of_an_absent_record_is_ok() {
            guarded(delete_of_an_absent_record_is_ok);
        }
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::fs;
        use std::io::{BufRead, BufReader, Write};
        use std::path::Path;
        use std::process::{Child, Command, Stdio};
        use std::thread::sleep;
        use std::time::{Duration, Instant};

        use super::*;

        const ROLE: &str = "ZS_NATIVE_DEVICE_ROLE";
        const PRIVATE_BUS: &str = "private-bus";
        const BUS_SOCKET: &str = "bus";

        struct Cleanup(String);

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let clean = delete(&self.0).is_ok() && matches!(read(&self.0), Ok(None));
                if !clean && !std::thread::panicking() {
                    panic!("native device fixture cleanup failed");
                }
            }
        }

        fn random_hex() -> String {
            account().trim_start_matches("zs-device-").to_owned()
        }

        fn wait_until<F: FnMut() -> bool>(mut ready: F) {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !ready() {
                assert!(
                    Instant::now() < deadline,
                    "native fixture did not become ready"
                );
                sleep(Duration::from_millis(50));
            }
        }

        fn dbus_send(address: &str, args: &[&str]) -> String {
            Command::new("dbus-send")
                .arg(format!("--bus={address}"))
                .arg("--print-reply")
                .args(args)
                .output()
                .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                .unwrap_or_default()
        }

        fn has_owner(address: &str, name: &str) -> bool {
            dbus_send(
                address,
                &[
                    "--dest=org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus.NameHasOwner",
                    &format!("string:{name}"),
                ],
            )
            .contains("boolean true")
        }

        fn default_collection_unlocked(address: &str) -> bool {
            let alias = dbus_send(
                address,
                &[
                    "--dest=org.freedesktop.secrets",
                    "/org/freedesktop/secrets",
                    "org.freedesktop.Secret.Service.ReadAlias",
                    "string:default",
                ],
            );
            let Some(path) = alias.lines().find_map(|line| {
                line.trim()
                    .strip_prefix("object path \"")?
                    .strip_suffix('"')
                    .filter(|path| *path != "/")
            }) else {
                return false;
            };
            dbus_send(
                address,
                &[
                    "--dest=org.freedesktop.secrets",
                    path,
                    "org.freedesktop.DBus.Properties.Get",
                    "string:org.freedesktop.Secret.Collection",
                    "string:Locked",
                ],
            )
            .contains("boolean false")
        }

        fn isolate<'a>(command: &'a mut Command, root: &Path) -> &'a mut Command {
            let data = root.join("data");
            command
                .env("HOME", root)
                .env("XDG_RUNTIME_DIR", root)
                .env("XDG_DATA_HOME", &data)
                .env("XDG_CONFIG_HOME", &data)
                .env("XDG_CACHE_HOME", &data)
                .env_remove("DBUS_SESSION_BUS_ADDRESS")
                .env_remove("GNOME_KEYRING_CONTROL")
                .env_remove("DISPLAY")
                .env_remove("WAYLAND_DISPLAY")
        }

        struct PrivateBus {
            daemon: Child,
            keyring: Option<Child>,
            address: String,
            root: tempfile::TempDir,
        }

        impl PrivateBus {
            fn start() -> Self {
                let root = tempfile::tempdir().unwrap();
                fs::create_dir_all(root.path().join("data")).unwrap();
                let socket = root.path().join(BUS_SOCKET);
                let mut daemon = isolate(&mut Command::new("dbus-daemon"), root.path())
                    .args(["--session", "--nofork", "--print-address"])
                    .arg(format!("--address=unix:path={}", socket.display()))
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .spawn()
                    .unwrap();
                let mut address = String::new();
                let printed = daemon
                    .stdout
                    .take()
                    .map(|stdout| BufReader::new(stdout).read_line(&mut address));
                let mut bus = Self {
                    daemon,
                    keyring: None,
                    address: address.trim().to_owned(),
                    root,
                };
                assert!(matches!(printed, Some(Ok(len)) if len > 0));
                assert!(
                    bus.address
                        .starts_with(&format!("unix:path={},", socket.display()))
                );

                let mut keyring =
                    isolate(&mut Command::new("gnome-keyring-daemon"), bus.root.path())
                        .env("DBUS_SESSION_BUS_ADDRESS", &bus.address)
                        .args(["--foreground", "--unlock", "--components=secrets"])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap();
                let unlock = keyring
                    .stdin
                    .take()
                    .map(|mut stdin| stdin.write_all(random_hex().as_bytes()));
                bus.keyring = Some(keyring);
                assert!(matches!(unlock, Some(Ok(()))));
                wait_until(|| {
                    has_owner(&bus.address, "org.freedesktop.secrets")
                        && default_collection_unlocked(&bus.address)
                });
                bus
            }

            fn run(&self, function: &str) {
                let module = module_path!();
                let module = module.split_once("::").map_or(module, |(_, rest)| rest);
                let mut command = Command::new(std::env::current_exe().unwrap());
                isolate(&mut command, self.root.path())
                    .env("DBUS_SESSION_BUS_ADDRESS", &self.address);
                let output = command
                    .args([
                        format!("{module}::{function}").as_str(),
                        "--exact",
                        "--ignored",
                        "--test-threads=1",
                    ])
                    .env(ROLE, PRIVATE_BUS)
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(
                    output.status.success() && stdout.contains("test result: ok. 1 passed"),
                    "{PRIVATE_BUS} child failed:\n{stdout}\n{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }

        impl Drop for PrivateBus {
            fn drop(&mut self) {
                for child in self.keyring.iter_mut().chain([&mut self.daemon]) {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        fn native(function: &str, body: fn(&str)) {
            match std::env::var(ROLE).ok().as_deref() {
                Some(PRIVATE_BUS) => {
                    let home = std::env::var("HOME").unwrap();
                    let address = std::env::var("DBUS_SESSION_BUS_ADDRESS").unwrap();
                    let expected = format!("unix:path={home}/{BUS_SOCKET}");
                    assert!(address == expected || address.starts_with(&format!("{expected},")));
                    let account = account();
                    let _cleanup = Cleanup(account.clone());
                    body(&account);
                }
                Some(_) => panic!("unexpected native test role"),
                None => PrivateBus::start().run(function),
            }
        }

        #[test]
        #[ignore = "spawns a private D-Bus session and gnome-keyring"]
        fn native_device_linux_round_trip() {
            native("native_device_linux_round_trip", round_trip);
        }

        #[test]
        #[ignore = "spawns a private D-Bus session and gnome-keyring"]
        fn native_device_linux_write_is_create_only() {
            native(
                "native_device_linux_write_is_create_only",
                write_is_create_only,
            );
        }

        #[test]
        #[ignore = "spawns a private D-Bus session and gnome-keyring"]
        fn native_device_linux_delete_of_an_absent_record_is_ok() {
            native(
                "native_device_linux_delete_of_an_absent_record_is_ok",
                delete_of_an_absent_record_is_ok,
            );
        }
    }
}
