// Only touch records by their exact attributes or target; never enumerate or delete by prefix.

#[cfg(target_os = "linux")]
pub use self::linux::Store;
#[cfg(target_os = "windows")]
pub use self::windows::Store;

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    const SECRETS: &str = "org.freedesktop.secrets";
    const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    const REPLY_TIMEOUT: &str = "--reply-timeout=10000";

    fn paths(reply: &str) -> Vec<String> {
        reply
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix("object path \"")?
                    .strip_suffix('"')
                    .map(str::to_owned)
            })
            .collect()
    }

    pub struct Store {
        daemons: Vec<Child>,
        address: Option<String>,
        root: Option<tempfile::TempDir>,
    }

    impl Store {
        pub fn inherited() -> Self {
            Self {
                daemons: Vec::new(),
                address: None,
                root: None,
            }
        }

        pub fn unreachable() -> Self {
            let root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(root.path().join("data")).unwrap();
            let address = format!("unix:path={}", root.path().join("missing").display());
            Self {
                daemons: Vec::new(),
                address: Some(address),
                root: Some(root),
            }
        }

        pub fn new() -> Self {
            let mut store = Self::unreachable();
            let socket = store.root().join("bus");
            let mut daemon = store
                .home(&mut super::super::clean_command("dbus-daemon"))
                .args(["--session", "--nofork", "--print-address"])
                .arg(format!("--address=unix:path={}", socket.display()))
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut address = String::new();
            let printed = daemon
                .stdout
                .take()
                .map(|stdout| BufReader::new(stdout).read_line(&mut address));
            store.daemons.push(daemon);
            assert!(matches!(printed, Some(Ok(len)) if len > 0));
            let address = address.trim().to_owned();
            assert!(address.starts_with(&format!("unix:path={},", socket.display())));
            store.address = Some(address);

            let mut keyring = store
                .session(&mut super::super::clean_command("gnome-keyring-daemon"))
                .args(["--foreground", "--unlock", "--components=secrets"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let unlocked = keyring
                .stdin
                .take()
                .map(|mut stdin| stdin.write_all(super::super::random_hex().as_bytes()));
            store.daemons.push(keyring);
            assert!(matches!(unlocked, Some(Ok(()))));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !(store.has_owner(SECRETS) && store.locked() == Some(false)) {
                assert!(
                    Instant::now() < deadline,
                    "private secret service did not start"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            store
        }

        fn root(&self) -> &std::path::Path {
            self.root
                .as_ref()
                .expect("only a private store has a root")
                .path()
        }

        fn home<'a>(&self, command: &'a mut Command) -> &'a mut Command {
            let root = self.root();
            let data = root.join("data");
            command
                .env("HOME", root)
                .env("XDG_RUNTIME_DIR", root)
                .env("XDG_DATA_HOME", &data)
                .env("XDG_CONFIG_HOME", &data)
                .env("XDG_CACHE_HOME", &data)
        }

        pub fn session<'a>(&self, command: &'a mut Command) -> &'a mut Command {
            let address = self
                .address
                .as_deref()
                .expect("only a private store sets a session");
            self.home(command).env("DBUS_SESSION_BUS_ADDRESS", address)
        }

        fn send(&self, args: &[&str]) -> Option<String> {
            let mut command = match &self.address {
                Some(address) => {
                    let mut command = super::super::clean_command("dbus-send");
                    command.arg(format!("--bus={address}"));
                    command
                }
                None => {
                    let mut command = Command::new("dbus-send");
                    command.arg("--session");
                    command
                }
            };
            let output = command
                .arg("--print-reply")
                .arg(REPLY_TIMEOUT)
                .args(args)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
        }

        fn has_owner(&self, name: &str) -> bool {
            self.send(&[
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.NameHasOwner",
                &format!("string:{name}"),
            ])
            .is_some_and(|reply| reply.contains("boolean true"))
        }

        fn default_collection(&self) -> Option<String> {
            let reply = self.send(&[
                &format!("--dest={SECRETS}"),
                SERVICE_PATH,
                "org.freedesktop.Secret.Service.ReadAlias",
                "string:default",
            ])?;
            paths(&reply).into_iter().next().filter(|path| path != "/")
        }

        pub fn locked(&self) -> Option<bool> {
            let collection = self.default_collection()?;
            let reply = self.send(&[
                &format!("--dest={SECRETS}"),
                &collection,
                "org.freedesktop.DBus.Properties.Get",
                "string:org.freedesktop.Secret.Collection",
                "string:Locked",
            ])?;
            match (
                reply.contains("boolean true"),
                reply.contains("boolean false"),
            ) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                _ => None,
            }
        }

        pub fn lock(&self) {
            assert!(self.root.is_some(), "only a private store is ever locked");
            let collection = self.default_collection().unwrap();
            let reply = self
                .send(&[
                    &format!("--dest={SECRETS}"),
                    SERVICE_PATH,
                    "org.freedesktop.Secret.Service.Lock",
                    &format!("array:objpath:{collection}"),
                ])
                .unwrap();
            assert_eq!(paths(&reply), [collection, "/".to_owned()]);
            assert_eq!(self.locked(), Some(true));
        }

        fn search(&self, account: &str) -> Option<(Vec<String>, Vec<String>)> {
            let reply = self.send(&[
                &format!("--dest={SECRETS}"),
                SERVICE_PATH,
                "org.freedesktop.Secret.Service.SearchItems",
                &format!("dict:string:string:service,zerosecret.ca.v1,account,{account},schema,1"),
            ])?;
            let mut groups = reply.split("array [").skip(1).map(paths);
            let found = (groups.next()?, groups.next()?);
            groups.next().is_none().then_some(found)
        }

        pub fn count(&self, account: &str) -> (usize, usize) {
            let (unlocked, locked) = self.search(account).unwrap();
            (unlocked.len(), locked.len())
        }

        pub fn stored(&self, account: &str) -> usize {
            let (unlocked, locked) = self.count(account);
            assert_eq!(locked, 0);
            unlocked
        }

        pub fn remove(&self, account: &str) -> bool {
            let Some((unlocked, locked)) = self.search(account) else {
                return false;
            };
            let deleted = unlocked.iter().chain(&locked).all(|item| {
                self.send(&[
                    &format!("--dest={SECRETS}"),
                    item,
                    "org.freedesktop.Secret.Item.Delete",
                ])
                .is_some_and(|reply| paths(&reply) == ["/"])
            });
            deleted
                && self
                    .search(account)
                    .is_some_and(|(unlocked, locked)| unlocked.is_empty() && locked.is_empty())
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            for daemon in self.daemons.iter_mut().rev() {
                let _ = daemon.kill();
                let _ = daemon.wait();
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::process::Command;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, GetLastError};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
    };

    fn target(account: &str) -> Vec<u16> {
        format!("zerosecret.ca.v1/{account}")
            .encode_utf16()
            .chain([0])
            .collect()
    }

    pub struct Store;

    impl Store {
        pub fn new() -> Self {
            Self
        }

        pub fn inherited() -> Self {
            Self
        }

        pub fn session<'a>(&self, command: &'a mut Command) -> &'a mut Command {
            command
        }

        fn present(&self, account: &str) -> Option<bool> {
            let target = target(account);
            let mut credential: *mut CREDENTIALW = ptr::null_mut();
            if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) } == 0 {
                return (unsafe { GetLastError() } == ERROR_NOT_FOUND).then_some(false);
            }
            unsafe {
                let blob = (*credential).CredentialBlob;
                if let Ok(len) = usize::try_from((*credential).CredentialBlobSize)
                    && !blob.is_null()
                {
                    ptr::write_bytes(blob, 0, len);
                }
                CredFree(credential.cast_const().cast());
            }
            Some(true)
        }

        pub fn stored(&self, account: &str) -> usize {
            usize::from(self.present(account).unwrap())
        }

        pub fn remove(&self, account: &str) -> bool {
            let target = target(account);
            let deleted = unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) } != 0
                || unsafe { GetLastError() } == ERROR_NOT_FOUND;
            deleted && self.present(account) == Some(false)
        }

        pub fn plant(&self, account: &str, persist: CRED_PERSIST, bytes: &[u8]) {
            let mut target = target(account);
            let mut blob = bytes.to_vec();
            let credential = CREDENTIALW {
                Type: CRED_TYPE_GENERIC,
                TargetName: target.as_mut_ptr(),
                CredentialBlobSize: u32::try_from(blob.len()).unwrap(),
                CredentialBlob: blob.as_mut_ptr(),
                Persist: persist,
                ..CREDENTIALW::default()
            };
            assert!(
                unsafe { CredWriteW(&credential, 0) } != 0,
                "native fixture write failed"
            );
        }
    }
}
