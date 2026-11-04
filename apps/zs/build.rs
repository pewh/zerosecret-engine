use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=ZS_BUILD_TEST_ENDPOINTS");
    println!("cargo:rerun-if-env-changed=ZS_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    if std::env::var("ZS_BUILD_TEST_ENDPOINTS").as_deref() == Ok("1") {
        if std::env::var("PROFILE").as_deref() == Ok("release") {
            panic!("ZS_BUILD_TEST_ENDPOINTS=1 is refused in a release build");
        }
        println!("cargo:rustc-cfg=zs_test_endpoints");
    }
    let version = std::env::var("ZS_BUILD_VERSION")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            git(&["describe", "--tags", "--always", "--dirty"])
                .map(|value| value.trim_start_matches('v').to_string())
        })
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    let commit = git(&["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let seconds = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=ZS_BUILD_VERSION={version}");
    println!("cargo:rustc-env=ZS_BUILD_COMMIT={commit}");
    println!("cargo:rustc-env=ZS_BUILD_TIME={}", rfc3339(seconds));
    println!(
        "cargo:rustc-env=ZS_BUILD_TARGET={}",
        std::env::var("TARGET").unwrap_or_default()
    );
}

fn git(arguments: &[&str]) -> Option<String> {
    let directory = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = str::from_utf8(&output.stdout).ok()?.trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
