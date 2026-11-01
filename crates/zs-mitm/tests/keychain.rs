#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(target_os = "macos")]
use zs_test_keychain as disposable;

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::path::{Path, PathBuf};

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    use zs_mitm::{LocalCa, keychain_label_for};

    use super::disposable::{
        Cleanup, ID_FILE, Item, SERVICE, attributes, delete_exact, disposable_keychain, exists,
        keychain_of, password_output, plant_legacy,
    };

    const RECORD_PREFIX: &[u8] = b"zsca1:";
    const SYNTHETIC_KEY: &str = "-----BEGIN PRIVATE KEY-----\nS0VZ\n-----END PRIVATE KEY-----\n";

    // The counter is required: tests in one binary share a pid and can start within one clock tick.
    fn unique_label() -> String {
        static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!(
            "zerosecret-test-{}-{}-{n}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

    struct Fixture {
        dir: tempfile::TempDir,
        label: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
                label: unique_label(),
            }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn load(&self) -> LocalCa {
            LocalCa::load_or_create_in_keychain(self.path(), &self.label)
                .expect("CA must load or create")
        }

        fn secure(&self) -> LocalCa {
            LocalCa::load_or_create_secure(self.path()).expect("CA must load or create")
        }

        fn key_file(&self) -> PathBuf {
            self.path().join("ca.key.pem")
        }

        fn account(&self) -> String {
            fs::read_to_string(self.path().join(ID_FILE)).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            drop(Cleanup(vec![
                Item::Directory(self.path().to_path_buf()),
                Item::Legacy(self.label.clone()),
                Item::Legacy(keychain_label_for(self.path())),
            ]));
        }
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn the_private_key_is_never_written_to_the_config_directory() {
        disposable_keychain();
        let fixture = Fixture::new();
        let _ca = fixture.secure();

        assert!(!fixture.key_file().exists());
        assert!(fixture.path().join("ca.crt").exists());
        for entry in fs::read_dir(fixture.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let content = fs::read(&path).unwrap();
                assert!(
                    !content.windows(11).any(|window| window == b"PRIVATE KEY"),
                    "{} contains private key material",
                    path.display()
                );
            }
        }
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn the_same_ca_key_is_reused_across_loads_and_entry_points() {
        disposable_keychain();
        let fixture = Fixture::new();
        let first = fixture.secure().public_key_der();
        let second = fixture.secure().public_key_der();
        let label = keychain_label_for(fixture.path());
        let third = LocalCa::load_or_create_in_keychain(fixture.path(), &label)
            .unwrap()
            .public_key_der();
        assert_eq!(first, second, "a reload must reuse the stored key");
        assert_eq!(first, third, "both entry points must load the same record");
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn an_existing_file_key_is_migrated_and_the_file_deleted() {
        disposable_keychain();
        let fixture = Fixture::new();
        let legacy = LocalCa::load_or_create(fixture.path()).expect("legacy CA");
        let legacy_key = legacy.public_key_der();
        assert!(fixture.key_file().exists());

        let migrated = fixture.load();
        assert_eq!(migrated.public_key_der(), legacy_key);
        assert!(!fixture.key_file().exists());
        assert!(exists(&fixture.account(), SERVICE));
        assert_eq!(fixture.load().public_key_der(), legacy_key);
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn an_existing_keychain_item_is_migrated_to_the_versioned_record() {
        disposable_keychain();
        let fixture = Fixture::new();
        let legacy = LocalCa::load_or_create(fixture.path()).expect("legacy CA");
        let key_pem = fs::read_to_string(fixture.key_file()).unwrap();
        plant_legacy(&fixture.label, fixture.path(), &key_pem);
        fs::remove_file(fixture.key_file()).unwrap();

        let migrated = fixture.load();
        assert_eq!(migrated.public_key_der(), legacy.public_key_der());
        assert!(!exists(&fixture.label, &fixture.label));
        assert!(exists(&fixture.account(), SERVICE));
        assert_eq!(fixture.load().public_key_der(), legacy.public_key_der());
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn the_key_is_actually_in_the_keychain_as_a_versioned_record() {
        let keychain = disposable_keychain();
        let fixture = Fixture::new();
        let _ca = fixture.secure();
        let account = fixture.account();

        assert_eq!(
            keychain_of(&attributes(&account, SERVICE)).as_deref(),
            Some(keychain.as_path())
        );
        let printed = password_output(&account, SERVICE).expect("no Keychain record");
        let encoded = printed
            .strip_suffix(b"\n")
            .and_then(|value| value.strip_prefix(RECORD_PREFIX))
            .expect("the record is not a zsca1 value");
        let record = STANDARD_NO_PAD
            .decode(encoded)
            .expect("the record is not unpadded base64");
        assert!(record.starts_with(b"ZSCA\x01"));
        assert!(record.windows(11).any(|window| window == b"PRIVATE KEY"));
        let label = keychain_label_for(fixture.path());
        assert!(!exists(&label, &label));
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn a_deleted_keychain_record_denies_instead_of_minting_a_new_root() {
        disposable_keychain();
        let fixture = Fixture::new();
        let _ca = fixture.secure();
        let certificate = fs::read(fixture.path().join("ca.crt")).unwrap();
        let account = fixture.account();
        assert!(delete_exact(&account, SERVICE));

        let error = LocalCa::load_or_create_secure(fixture.path())
            .err()
            .map(|error| error.to_string());
        assert_eq!(error.as_deref(), Some("ca storage: CA private key missing"));
        assert_eq!(
            fs::read(fixture.path().join("ca.crt")).unwrap(),
            certificate
        );
        assert!(!exists(&account, SERVICE));
    }

    #[test]
    #[ignore = "requires the disposable CI keychain"]
    fn loading_one_directory_never_prunes_another_directorys_items() {
        disposable_keychain();
        let dead = Fixture::new();
        let _dead_ca = dead.secure();
        let dead_account = dead.account();
        let orphan_label = unique_label();
        let _orphans = Cleanup(vec![
            Item::Record(dead_account.clone()),
            Item::Legacy(orphan_label.clone()),
        ]);
        plant_legacy(&orphan_label, dead.path(), SYNTHETIC_KEY);
        fs::remove_dir_all(dead.path()).unwrap();

        let live = Fixture::new();
        let _live_ca = live.secure();
        assert!(exists(&dead_account, SERVICE));
        assert!(exists(&orphan_label, &orphan_label));
    }
}
