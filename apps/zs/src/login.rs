use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use zs::device::{self, DeviceFile, DeviceSecrets, Enrolment};
use zs::wire_client::WireClient;
use zs_mitm::Zeroizing;
use zs_mitm::device_store;
use zs_upstream::http::{Network, ProxyPolicy, Roots};
use zs_wire::{LoginClaim, WireRefusal};

use super::Args;

const LOGIN_TIMEOUT_SECONDS: u64 = 300;
const LOGIN_POLL: Duration = Duration::from_secs(1);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(super) fn login_via_control_plane(args: &Args, control: &str) -> i32 {
    match sign_in_and_enrol(args, control) {
        Ok(()) => 0,
        Err(line) => {
            stderr_line!("{line}");
            1
        }
    }
}

fn zs_line(text: impl std::fmt::Display) -> String {
    format!("zs: {text}")
}

fn record_line(error: impl std::fmt::Display) -> String {
    format!("zs: device record: {error}")
}

fn sign_in_and_enrol(args: &Args, control: &str) -> Result<(), String> {
    zs::control_url_allowed(control).map_err(zs_line)?;
    let control = device::normalise(control);
    let enroll_url = match args.enroll_url.as_deref() {
        Some(url) => {
            zs::control_url_allowed(url).map_err(zs_line)?;
            url.trim_end_matches('/')
        }
        None => control,
    };
    if !valid_device_name(&args.device_name) {
        return Err(
            "zs: --device-name must be 1 to 64 characters of A-Z, a-z, 0-9, space, '.', '_' or '-'"
                .into(),
        );
    }
    let ca_pem = zs::control_ca_pem(args.control_ca.as_deref(), &args.ca_dir).map_err(zs_line)?;
    let client = control_client(&ca_pem)?;
    device_store::preflight().map_err(record_line)?;
    let home = super::zs_home();
    device::load_file(&home).map_err(zs_line)?;

    let runtime = tokio::runtime::Runtime::new().map_err(|e| zs_line(format!("runtime: {e}")))?;
    let claim = runtime.block_on(sign_in(&client, control, &args.device_name))?;
    let token = Zeroizing::new(
        claim
            .enrollment_token
            .ok_or("zs: the control plane issued no enrolment token")?,
    );
    let subject = claim.subject;

    let (response, secrets) = runtime
        .block_on(WireClient::enroll_identity(
            enroll_url,
            &ca_pem,
            &token,
            &args.device_name,
        ))
        .map_err(|e| zs_line(format!("enrolment failed: {e}")))?;
    let enrolment = Enrolment {
        control: control.to_string(),
        control_ca_sha256: zs::control_ca_sha256(&ca_pem),
        subject: subject.clone(),
        device_id: response.device_id,
        organization: response.organization,
        client_certificate: response.client_certificate,
        grant_verifying_key_hex: hex(&response.grant_verifying_key),
        grant_verifying_key_id: response.grant_verifying_key_id,
        wire_url: response.wire_url,
    };
    if !valid_device_id(&enrolment.device_id) {
        return Err(
            "zs: enrolment failed: the control plane returned an unusable device id".into(),
        );
    }
    WireClient::from_identity(&ca_pem, &enrolment, &secrets)
        .map_err(|e| zs_line(format!("enrolment failed: {e}")))?;

    let device_id = enrolment.device_id.clone();
    replace_enrolment(&home, enrolment, &secrets)?;
    super::store_session(&subject).map_err(zs_line)?;
    stdout_line!("signed in as {subject}; enrolled device {device_id}");
    Ok(())
}

fn control_client(ca_pem: &str) -> Result<reqwest::Client, String> {
    let root = CertificateDer::from_pem_slice(ca_pem.as_bytes())
        .map_err(|_| zs_line("the control plane CA is not a PEM certificate"))?;
    zs_upstream::http::client(
        Roots::Only(vec![root]),
        REQUEST_TIMEOUT,
        None,
        false,
        ProxyPolicy::System,
        &Network::default(),
    )
    .map_err(|_| zs_line("the control plane HTTP client could not be built"))
}

async fn sign_in(
    client: &reqwest::Client,
    control: &str,
    device_name: &str,
) -> Result<LoginClaim, String> {
    let deadline = login_deadline(Instant::now(), login_timeout())?;
    let verifier = random_verifier();
    let challenge = sha256_hex(verifier.as_bytes());
    stdout_line!("zs: signing in to {control}");
    let response = client
        .get(format!("{control}/login"))
        .query(&[
            ("cli_challenge", challenge.as_str()),
            ("device", device_name),
        ])
        .send()
        .await
        .map_err(|e| {
            zs_line(format!(
                "cannot reach the control plane at {control}: {}",
                e.without_url()
            ))
        })?;
    if !response.status().is_redirection() {
        return Err(zs_line(format!(
            "control plane refused the login: {} — is OIDC configured?",
            response.status()
        )));
    }
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    if !(location.starts_with("https://") || location.starts_with("http://")) {
        return Err(zs_line(
            "the control plane's sign-in URL is not an http(s) URL",
        ));
    }
    let Some(state_token) = state_token_from(&location) else {
        return Err(zs_line(
            "the control plane's sign-in URL carries no state token",
        ));
    };
    stdout_line!("zs: open this URL to sign in:\n{location}");
    stdout_line!(
        "zs: the browser must show code {} for device {device_name}",
        zs_wire::login_code(&challenge)
    );
    open_browser(&location);
    stdout_line!("zs: waiting for the browser to complete the sign-in…");
    await_claim(client, control, &state_token, &verifier, deadline).await
}

#[cfg(target_os = "macos")]
fn open_browser(url: &str) {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        let _ = std::process::Command::new("/usr/bin/open")
            .arg(url)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

#[cfg(not(target_os = "macos"))]
fn open_browser(_url: &str) {}

fn state_token_from(location: &str) -> Option<String> {
    let query = location.split_once('?')?.1;
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(name, _)| *name == "state")
        .map(|(_, value)| value.to_string())
        .filter(|token| !token.is_empty())
}

fn login_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("ZS_LOGIN_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(LOGIN_TIMEOUT_SECONDS),
    )
}

fn login_deadline(now: Instant, timeout: Duration) -> Result<Instant, String> {
    now.checked_add(timeout)
        .ok_or_else(|| zs_line("ZS_LOGIN_TIMEOUT_SECONDS is too large"))
}

async fn await_claim(
    client: &reqwest::Client,
    control: &str,
    state_token: &str,
    verifier: &str,
    deadline: Instant,
) -> Result<LoginClaim, String> {
    let url = format!("{control}/login/claim");
    loop {
        let response = client
            .post(&url)
            .form(&[("state", state_token), ("verifier", verifier)])
            .send()
            .await
            .map_err(|e| {
                zs_line(format!(
                    "cannot reach the control plane: {}",
                    e.without_url()
                ))
            })?;
        let status = response.status().as_u16();
        match status {
            200 => {
                let claim: LoginClaim = response
                    .json()
                    .await
                    .map_err(|_| zs_line("the control plane sent a malformed sign-in result"))?;
                if claim.subject.is_empty() || claim.subject.chars().any(char::is_control) {
                    return Err(zs_line("the control plane named no usable subject"));
                }
                return Ok(claim);
            }
            403 | 409 => {
                return Err(refusal_line(
                    status,
                    response.json::<WireRefusal>().await.ok(),
                ));
            }
            404 => {}
            405 => {
                return Err(zs_line(
                    "the control plane and this zs use different sign-in protocols; upgrade zs and control together",
                ));
            }
            other => {
                return Err(zs_line(format!(
                    "the control plane answered the sign-in claim with status {other}"
                )));
            }
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(zs_line(
                "timed out waiting for the browser sign-in to complete",
            ));
        }
        tokio::time::sleep(LOGIN_POLL.min(deadline.saturating_duration_since(now))).await;
    }
}

fn refusal_line(status: u16, refusal: Option<WireRefusal>) -> String {
    let code = refusal.as_ref().map(|r| r.code.as_str());
    match (status, code) {
        (403, Some("not_a_member")) => {
            let subject: String = refusal
                .as_ref()
                .and_then(|r| r.subject.as_deref())
                .unwrap_or("your account")
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            format!("zs: not a member of any organization; ask an admin to add {subject}")
        }
        (409, Some("several_organizations")) => {
            "zs: member of several organizations; use an enrolment token".into()
        }
        _ => zs_line(format!(
            "the control plane refused the sign-in with status {status}"
        )),
    }
}

fn replace_enrolment(
    home: &Path,
    enrolment: Enrolment,
    secrets: &DeviceSecrets,
) -> Result<(), String> {
    let record = secrets.encode().map_err(zs_line)?;
    std::fs::create_dir_all(home)
        .map_err(|e| zs_line(format!("cannot create {}: {}", home.display(), e.kind())))?;
    let mut file = device::load_file(home).map_err(zs_line)?;
    let new_account = enrolment.record_account();
    let control = device::normalise(&enrolment.control).to_string();
    let replaced: Vec<String> = file
        .enrolments
        .iter()
        .filter(|entry| device::normalise(&entry.control) == control)
        .map(Enrolment::record_account)
        .filter(|account| *account != new_account)
        .collect();

    device_store::write_new(&new_account, home, &record).map_err(record_line)?;
    file.enrolments
        .retain(|entry| device::normalise(&entry.control) != control);
    file.enrolments.push(enrolment);
    if let Err(error) = device::save_file(home, &file) {
        if let Err(delete_error) = device_store::delete(&new_account) {
            stderr_line!("{}", record_line(delete_error));
        }
        return Err(zs_line(error));
    }
    for account in replaced {
        if let Err(error) = device_store::delete(&account) {
            stderr_line!(
                "{}; the replaced record {account} is still stored",
                record_line(error)
            );
        }
    }
    Ok(())
}

pub(super) fn logout() -> i32 {
    let home = super::zs_home();
    let file = match stored_enrolments(&home) {
        Ok(file) => file,
        Err(line) => {
            stderr_line!("{line}");
            return 1;
        }
    };
    for enrolment in &file.enrolments {
        if let Err(error) = device_store::delete(&enrolment.record_account()) {
            stderr_line!("{}", record_line(error));
            return 1;
        }
    }
    for path in [device::device_file_path(&home), super::session_path()] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                stderr_line!("zs: cannot remove {}: {}", path.display(), e.kind());
                return 1;
            }
        }
    }
    stdout_line!("signed out");
    0
}

fn stored_enrolments(home: &Path) -> Result<DeviceFile, String> {
    let path = device::device_file_path(home);
    match std::fs::read_to_string(&path) {
        Ok(text) if text.trim().is_empty() => Ok(DeviceFile::default()),
        Ok(_) => device::load_file(home).map_err(zs_line),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeviceFile::default()),
        Err(e) => Err(zs_line(format!(
            "{}: cannot be read: {}",
            path.display(),
            e.kind()
        ))),
    }
}

pub(super) fn device_enrolment(control: Option<&str>) -> Result<Option<Enrolment>, String> {
    let Some(control) = control else {
        return Ok(None);
    };
    let file = device::load_file(&super::zs_home()).map_err(zs_line)?;
    Ok(device::find(&file, control).cloned())
}

pub(super) fn device_line(control: Option<&str>) -> Result<String, String> {
    Ok(match device_enrolment(control)? {
        Some(enrolment) => format!(
            "device: {} (enrolled with {} as {})",
            enrolment.device_id,
            device::normalise(&enrolment.control),
            enrolment.subject
        ),
        None => "device: not enrolled".into(),
    })
}

fn valid_device_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-'))
}

fn valid_device_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn random_verifier() -> Zeroizing<String> {
    let mut raw = Zeroizing::new([0u8; 32]);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, raw.as_mut());
    Zeroizing::new(hex(raw.as_ref()))
}

fn sha256_hex(text: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex(&Sha256::digest(text))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn the_verifier_is_64_lowercase_hex_and_the_challenge_is_its_sha256() {
        let verifier = random_verifier();
        assert_eq!(verifier.len(), 64);
        assert!(
            verifier
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_ne!(*verifier, *random_verifier());
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn refusals_print_the_exact_lines() {
        let refusal = |code: &str| {
            Some(WireRefusal {
                code: code.into(),
                subject: Some("alice@company.com".into()),
            })
        };
        assert_eq!(
            refusal_line(403, refusal("not_a_member")),
            "zs: not a member of any organization; ask an admin to add alice@company.com"
        );
        assert_eq!(
            refusal_line(409, refusal("several_organizations")),
            "zs: member of several organizations; use an enrolment token"
        );
        assert!(refusal_line(403, None).contains("refused the sign-in"));
    }

    #[tokio::test]
    async fn a_405_from_the_claim_route_names_the_version_mismatch() {
        let app = axum::Router::new().route(
            "/login/claim",
            axum::routing::any(|| async {
                (axum::http::StatusCode::METHOD_NOT_ALLOWED, "secret-body")
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let error = await_claim(
            &reqwest::Client::new(),
            &control,
            "state",
            "verifier",
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(
            error,
            "zs: the control plane and this zs use different sign-in protocols; upgrade zs and control together"
        );
        assert!(!error.contains("secret-body"));
    }

    #[test]
    fn device_names_follow_the_control_plane_rule() {
        assert!(valid_device_name("workstation"));
        assert!(valid_device_name("Ryan laptop_2.0-x"));
        assert!(!valid_device_name(""));
        assert!(!valid_device_name(&"a".repeat(65)));
        assert!(!valid_device_name("bad/name"));
    }

    #[test]
    fn an_oversized_login_timeout_is_refused_not_a_panic() {
        let now = Instant::now();
        assert!(login_deadline(now, Duration::from_secs(300)).is_ok());
        let error = login_deadline(now, Duration::MAX).err().unwrap();
        assert!(error.contains("ZS_LOGIN_TIMEOUT_SECONDS"), "{error}");
    }

    #[test]
    fn the_state_token_is_read_from_the_query() {
        assert_eq!(
            state_token_from("https://idp/authorize?client_id=zs&state=abc").as_deref(),
            Some("abc")
        );
        assert!(state_token_from("https://idp/authorize?client_id=zs").is_none());
        assert!(state_token_from("https://idp/authorize?state=").is_none());
    }
}
