use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zs_mitm::Zeroizing;
use zs_mitm::device_store::DeviceStoreError;

const MAGIC: &[u8; 4] = b"ZSDV";
const VERSION: u8 = 1;
const SEED_LEN: usize = 32;
const HEADER_LEN: usize = 9;
const MAX_PEM_LEN: usize = 16 * 1024;
const FILE_NAME: &str = ".zs-device.json";

pub struct DeviceSecrets {
    tls_key_pem: Zeroizing<String>,
    device_seed: Zeroizing<Vec<u8>>,
}

impl DeviceSecrets {
    pub fn new(tls_key_pem: Zeroizing<String>, device_seed: Zeroizing<Vec<u8>>) -> Self {
        Self {
            tls_key_pem,
            device_seed,
        }
    }

    pub fn tls_key_pem(&self) -> &str {
        &self.tls_key_pem
    }

    pub fn device_seed(&self) -> &[u8] {
        &self.device_seed
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let pem = self.tls_key_pem.as_bytes();
        if pem.is_empty() || pem.len() > MAX_PEM_LEN {
            return Err("device record: the TLS key has an unsupported size".into());
        }
        if self.device_seed.len() != SEED_LEN {
            return Err("device record: the device seed must be 32 bytes".into());
        }
        let length = u32::try_from(pem.len())
            .map_err(|_| "device record: the TLS key has an unsupported size".to_string())?;
        let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + pem.len() + SEED_LEN));
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(pem);
        out.extend_from_slice(&self.device_seed);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err("device record: not a ZeroSecret device record".into());
        }
        if bytes[4] != VERSION {
            return Err("device record: unsupported version".into());
        }
        let length = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]) as usize;
        if length == 0 || length > MAX_PEM_LEN || bytes.len() != HEADER_LEN + length + SEED_LEN {
            return Err("device record: wrong length".into());
        }
        let pem = std::str::from_utf8(&bytes[HEADER_LEN..HEADER_LEN + length])
            .map_err(|_| "device record: the TLS key is not text".to_string())?;
        Ok(Self {
            tls_key_pem: Zeroizing::new(pem.to_string()),
            device_seed: Zeroizing::new(bytes[HEADER_LEN + length..].to_vec()),
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Enrolment {
    pub control: String,
    pub control_ca_sha256: String,
    pub subject: String,
    pub device_id: String,
    pub organization: String,
    pub client_certificate: String,
    pub grant_verifying_key_hex: String,
    pub grant_verifying_key_id: String,
    pub wire_url: String,
}

impl Enrolment {
    pub fn record_account(&self) -> String {
        format!("zs-device-{}", self.device_id)
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct DeviceFile {
    pub enrolments: Vec<Enrolment>,
}

pub fn device_file_path(home: &Path) -> PathBuf {
    home.join(FILE_NAME)
}

pub fn load_file(home: &Path) -> Result<DeviceFile, String> {
    let path = device_file_path(home);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DeviceFile::default()),
        Err(e) => return Err(format!("{FILE_NAME}: cannot be read: {}", e.kind())),
    };
    serde_json::from_str(&text).map_err(|e| {
        format!(
            "{FILE_NAME}: not valid at line {} column {}",
            e.line(),
            e.column()
        )
    })
}

pub fn save_file(home: &Path, file: &DeviceFile) -> Result<(), String> {
    let path = device_file_path(home);
    let tmp = home.join(format!("{FILE_NAME}.tmp"));
    let text = serde_json::to_string_pretty(file)
        .map_err(|_| format!("{FILE_NAME}: cannot be encoded"))?;
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{FILE_NAME}: cannot be written: {}", e.kind())),
    }
    let written = open_private(&tmp)
        .and_then(|mut handle| {
            handle
                .write_all(text.as_bytes())
                .and_then(|()| handle.sync_all())
        })
        .and_then(|()| std::fs::rename(&tmp, &path));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("{FILE_NAME}: cannot be written: {}", e.kind()));
    }
    Ok(())
}

#[cfg(unix)]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

pub fn normalise(url: &str) -> &str {
    url.strip_suffix('/').unwrap_or(url)
}

pub fn find<'a>(file: &'a DeviceFile, control: &str) -> Option<&'a Enrolment> {
    let wanted = normalise(control);
    file.enrolments
        .iter()
        .find(|enrolment| normalise(&enrolment.control) == wanted)
}

pub fn load_with(
    home: &Path,
    control: &str,
    read: impl Fn(&str) -> Result<Option<Zeroizing<Vec<u8>>>, DeviceStoreError>,
) -> Result<Option<(Enrolment, DeviceSecrets)>, String> {
    let file = load_file(home)?;
    let Some(enrolment) = find(&file, control) else {
        return Ok(None);
    };
    let record = read(&enrolment.record_account()).map_err(|e| e.to_string())?;
    let Some(record) = record else {
        return Ok(None);
    };
    let secrets = DeviceSecrets::decode(&record)?;
    Ok(Some((enrolment.clone(), secrets)))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use zs_mitm::Zeroizing;
    use zs_mitm::device_store::DeviceStoreError;

    fn secrets() -> DeviceSecrets {
        DeviceSecrets::new(
            Zeroizing::new("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".into()),
            Zeroizing::new((0u8..32).collect()),
        )
    }

    fn enrolment(control: &str, device_id: &str) -> Enrolment {
        Enrolment {
            control: control.into(),
            control_ca_sha256: "ab".repeat(32),
            subject: "alice@company.com".into(),
            device_id: device_id.into(),
            organization: "default".into(),
            client_certificate: "CERT".into(),
            grant_verifying_key_hex: "cd".repeat(32),
            grant_verifying_key_id: "control-k1".into(),
            wire_url: "https://localhost:8444".into(),
        }
    }

    #[test]
    fn secrets_round_trip() {
        let original = secrets();
        let bytes = original.encode().unwrap();
        let decoded = DeviceSecrets::decode(&bytes).unwrap();
        assert!(decoded.tls_key_pem() == original.tls_key_pem());
        assert!(decoded.device_seed() == original.device_seed());
    }

    #[test]
    fn a_truncated_or_foreign_record_is_refused() {
        let bytes = secrets().encode().unwrap();
        assert!(DeviceSecrets::decode(&bytes[..10]).is_err());
        assert!(DeviceSecrets::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut foreign = bytes.to_vec();
        foreign[..4].copy_from_slice(b"ZSCA");
        assert!(DeviceSecrets::decode(&foreign).is_err());
        let mut future = bytes.to_vec();
        future[4] = 2;
        assert!(DeviceSecrets::decode(&future).is_err());
        let mut oversized = bytes.to_vec();
        oversized[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(DeviceSecrets::decode(&oversized).is_err());
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(DeviceSecrets::decode(&trailing).is_err());
        assert!(DeviceSecrets::decode(b"").is_err());
    }

    #[test]
    fn a_refused_record_does_not_echo_its_bytes() {
        let bytes = secrets().encode().unwrap();
        let error = DeviceSecrets::decode(&bytes[..bytes.len() - 1])
            .err()
            .unwrap();
        assert!(!error.contains("AAAA"));
    }

    #[cfg(unix)]
    #[test]
    fn the_device_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let file = DeviceFile {
            enrolments: vec![enrolment("http://h:1", "dev-1")],
        };
        save_file(home.path(), &file).unwrap();
        let mode = std::fs::metadata(device_file_path(home.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!home.path().join(".zs-device.json.tmp").exists());
        let loaded = load_file(home.path()).unwrap();
        assert_eq!(loaded.enrolments.len(), 1);
        assert_eq!(loaded.enrolments[0].device_id, "dev-1");
    }

    #[cfg(unix)]
    #[test]
    fn a_stale_wide_temp_file_does_not_widen_the_device_file() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let tmp = home.path().join(".zs-device.json.tmp");
        std::fs::write(&tmp, "stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).unwrap();
        save_file(home.path(), &DeviceFile::default()).unwrap();
        let mode = std::fs::metadata(device_file_path(home.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_device_file_is_empty() {
        let home = tempfile::tempdir().unwrap();
        assert!(load_file(home.path()).unwrap().enrolments.is_empty());
    }

    #[test]
    fn find_matches_the_exact_control_url() {
        let file = DeviceFile {
            enrolments: vec![enrolment("http://h:1", "dev-1")],
        };
        assert_eq!(find(&file, "http://h:1/").unwrap().device_id, "dev-1");
        assert_eq!(find(&file, "http://h:1").unwrap().device_id, "dev-1");
        assert!(find(&file, "http://h:2").is_none());
        let slashed = DeviceFile {
            enrolments: vec![enrolment("http://h:1/", "dev-1")],
        };
        assert_eq!(find(&slashed, "http://h:1").unwrap().device_id, "dev-1");
    }

    #[test]
    fn the_record_account_names_the_device() {
        assert_eq!(
            enrolment("http://h:1", "dev-9").record_account(),
            "zs-device-dev-9"
        );
    }

    #[test]
    fn a_stored_record_loads_with_its_enrolment() {
        let home = tempfile::tempdir().unwrap();
        save_file(
            home.path(),
            &DeviceFile {
                enrolments: vec![enrolment("http://h:1", "dev-1")],
            },
        )
        .unwrap();
        let record = secrets().encode().unwrap();
        let seen = std::cell::RefCell::new(String::new());
        let (enrolment, loaded) = load_with(home.path(), "http://h:1/", |account| {
            *seen.borrow_mut() = account.to_string();
            Ok(Some(Zeroizing::new(record.to_vec())))
        })
        .unwrap()
        .unwrap();
        assert_eq!(seen.borrow().as_str(), "zs-device-dev-1");
        assert_eq!(enrolment.device_id, "dev-1");
        assert!(loaded.device_seed() == secrets().device_seed());
    }

    #[test]
    fn no_entry_for_the_control_url_is_not_enrolled() {
        let home = tempfile::tempdir().unwrap();
        save_file(
            home.path(),
            &DeviceFile {
                enrolments: vec![enrolment("http://h:1", "dev-1")],
            },
        )
        .unwrap();
        let outcome = load_with(home.path(), "http://h:2", |_| panic!("must not read")).unwrap();
        assert!(outcome.is_none());
        let empty = tempfile::tempdir().unwrap();
        let outcome = load_with(empty.path(), "http://h:1", |_| panic!("must not read")).unwrap();
        assert!(outcome.is_none());
    }

    #[test]
    fn a_missing_record_is_not_enrolled() {
        let home = tempfile::tempdir().unwrap();
        save_file(
            home.path(),
            &DeviceFile {
                enrolments: vec![enrolment("http://h:1", "dev-1")],
            },
        )
        .unwrap();
        let outcome = load_with(home.path(), "http://h:1", |_| Ok(None)).unwrap();
        assert!(outcome.is_none());
    }

    #[test]
    fn a_locked_store_is_an_error_not_absence() {
        let home = tempfile::tempdir().unwrap();
        save_file(
            home.path(),
            &DeviceFile {
                enrolments: vec![enrolment("http://h:1", "dev-1")],
            },
        )
        .unwrap();
        let error = load_with(home.path(), "http://h:1", |_| Err(DeviceStoreError::Locked))
            .err()
            .unwrap();
        assert!(error.contains("secure storage locked"), "got {error}");
    }

    #[test]
    fn an_undecodable_record_is_an_error() {
        let home = tempfile::tempdir().unwrap();
        save_file(
            home.path(),
            &DeviceFile {
                enrolments: vec![enrolment("http://h:1", "dev-1")],
            },
        )
        .unwrap();
        let outcome = load_with(home.path(), "http://h:1", |_| {
            Ok(Some(Zeroizing::new(b"garbage".to_vec())))
        });
        assert!(outcome.is_err());
    }
}
