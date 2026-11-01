pub mod adapter;
pub mod cases;
pub mod config;
pub mod fake_upstream;
pub mod provision;
pub mod report;
pub mod runner;
pub mod wrongca;

pub use config::{Config, ConfigError, Fixtures, Implementation, Protocol, load};
pub use report::{CaseReport, Outcome, Report};
pub use runner::{Case, Context, Upstream, Variant};

pub fn registry() -> Vec<Case> {
    let mut cases = cases::postgres::cases();
    cases.extend(cases::mysql::cases());
    cases.extend(cases::mongodb::cases());
    cases.extend(cases::sigv4::cases());
    cases
}

#[cfg(test)]
pub(crate) mod test_fixtures {
    use std::net::{SocketAddr, TcpStream};
    use std::path::Path;
    use std::time::Duration;

    pub(crate) fn ready(addresses: &[&str], files: &[&Path]) -> bool {
        let listening = addresses.iter().all(|address| {
            address.parse::<SocketAddr>().is_ok_and(|address| {
                TcpStream::connect_timeout(&address, Duration::from_millis(750)).is_ok()
            })
        });
        let present = files.iter().all(|file| file.exists());
        if listening && present {
            return true;
        }
        assert!(
            std::env::var_os("ZS_CONFORMANCE_REQUIRE_FIXTURES").is_none(),
            "fixtures {addresses:?} and files {files:?} are required; start them with `docker compose --profile pgtls --profile mysql --profile mongo up -d` and `tools/db-test-certs.sh target/db-test-certs`"
        );
        eprintln!("skipped: fixtures {addresses:?} or files {files:?} are not available");
        false
    }
}

#[cfg(test)]
pub(crate) mod test_lock {
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    pub(crate) fn lock() -> MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }
}
