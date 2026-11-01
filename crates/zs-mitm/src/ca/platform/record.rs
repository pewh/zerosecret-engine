use std::collections::HashMap;
use std::sync::Mutex;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::pki_types::pem::{PemObject, SectionKind};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

use super::denied;
use crate::ca::{CaError, LocalCa};

pub(super) const MAX_RECORD_LEN: usize = 2560;
const MAGIC: &[u8; 4] = b"ZSCA";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 13;
const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const KEY_LABEL: &str = "PRIVATE KEY";

pub(super) struct SecretBytes(pub(super) Zeroizing<Vec<u8>>);

pub(super) struct CaRecord {
    pub(super) certificate_pem: String,
    pub(super) private_key_pem: Zeroizing<String>,
}

fn malformed() -> CaError {
    denied("CA storage record malformed")
}

fn invalid() -> CaError {
    denied("CA storage record invalid")
}

fn single_pem_block(text: &str, label: &str) -> bool {
    let text = text.trim();
    text.strip_prefix("-----BEGIN ")
        .and_then(|rest| rest.strip_prefix(label))
        .and_then(|rest| rest.strip_prefix("-----"))
        .and_then(|rest| rest.strip_suffix("-----"))
        .and_then(|rest| rest.strip_suffix(label))
        .and_then(|rest| rest.strip_suffix("-----END "))
        .is_some_and(|body| !body.contains("-----"))
}

fn well_formed(certificate: &str, key: &str) -> bool {
    single_pem_block(certificate, CERTIFICATE_LABEL) && single_pem_block(key, KEY_LABEL)
}

fn length(field: Option<&[u8]>) -> Result<usize, CaError> {
    let field: [u8; 4] = field
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(malformed)?;
    usize::try_from(u32::from_be_bytes(field)).map_err(|_| malformed())
}

pub(super) fn encode_record(record: &CaRecord) -> Result<SecretBytes, CaError> {
    if !well_formed(&record.certificate_pem, &record.private_key_pem) {
        return Err(malformed());
    }
    let certificate = record.certificate_pem.as_bytes();
    let key = record.private_key_pem.as_bytes();
    let total = HEADER_LEN
        .checked_add(certificate.len())
        .and_then(|len| len.checked_add(key.len()))
        .filter(|len| *len <= MAX_RECORD_LEN)
        .ok_or_else(malformed)?;
    let certificate_len = u32::try_from(certificate.len()).map_err(|_| malformed())?;
    let key_len = u32::try_from(key.len()).map_err(|_| malformed())?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(total));
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(&certificate_len.to_be_bytes());
    bytes.extend_from_slice(&key_len.to_be_bytes());
    bytes.extend_from_slice(certificate);
    bytes.extend_from_slice(key);
    Ok(SecretBytes(bytes))
}

pub(super) fn decode_record(bytes: &[u8]) -> Result<CaRecord, CaError> {
    if !(HEADER_LEN..=MAX_RECORD_LEN).contains(&bytes.len()) {
        return Err(malformed());
    }
    if bytes.get(..4) != Some(MAGIC.as_slice()) || bytes.get(4) != Some(&VERSION) {
        return Err(malformed());
    }
    let certificate_len = length(bytes.get(5..9))?;
    let key_len = length(bytes.get(9..HEADER_LEN))?;
    let certificate_end = HEADER_LEN
        .checked_add(certificate_len)
        .ok_or_else(malformed)?;
    let end = certificate_end.checked_add(key_len).ok_or_else(malformed)?;
    if certificate_len == 0 || key_len == 0 || end != bytes.len() {
        return Err(malformed());
    }
    let certificate = bytes
        .get(HEADER_LEN..certificate_end)
        .and_then(|field| std::str::from_utf8(field).ok())
        .ok_or_else(malformed)?;
    let key = bytes
        .get(certificate_end..end)
        .and_then(|field| std::str::from_utf8(field).ok())
        .ok_or_else(malformed)?;
    if !well_formed(certificate, key) {
        return Err(malformed());
    }
    Ok(CaRecord {
        certificate_pem: certificate.to_owned(),
        private_key_pem: secret_string(key),
    })
}

pub(super) fn secret_string(text: &str) -> Zeroizing<String> {
    let mut copy = Zeroizing::new(String::with_capacity(text.len()));
    copy.push_str(text);
    copy
}

pub(super) fn new_record() -> Result<CaRecord, CaError> {
    let generation = || denied("CA generation failed");
    let key = KeyPair::generate().map_err(|_| generation())?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|_| generation())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&key).map_err(|_| generation())?;
    Ok(CaRecord {
        certificate_pem: certificate.pem(),
        private_key_pem: Zeroizing::new(key.serialize_pem()),
    })
}

pub(super) fn certificate_der(pem: &str) -> Option<CertificateDer<'static>> {
    let mut sections = <(SectionKind, Vec<u8>)>::pem_slice_iter(pem.as_bytes());
    match (sections.next(), sections.next()) {
        (Some(Ok((SectionKind::Certificate, der))), None) => Some(CertificateDer::from(der))
            .filter(|certificate| CertificateParams::from_ca_cert_der(certificate).is_ok()),
        _ => None,
    }
}

pub(super) fn key_matches(certificate: &CertificateDer<'_>, key: &KeyPair) -> bool {
    let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialized_der()));
    rustls::crypto::ring::sign::any_supported_type(&der).is_ok_and(|signer| {
        CertifiedKey::new(vec![certificate.clone().into_owned()], signer)
            .keys_match()
            .is_ok()
    })
}

pub(super) fn ca_from_record(record: &CaRecord) -> Result<LocalCa, CaError> {
    let certificate = certificate_der(&record.certificate_pem).ok_or_else(invalid)?;
    let key = KeyPair::from_pem(&record.private_key_pem).map_err(|_| invalid())?;
    if !key_matches(&certificate, &key) {
        return Err(invalid());
    }
    let params =
        CertificateParams::from_ca_cert_pem(&record.certificate_pem).map_err(|_| invalid())?;
    if !matches!(params.is_ca, IsCa::Ca(_)) {
        return Err(invalid());
    }
    let ca_cert = params.self_signed(&key).map_err(|_| invalid())?;
    Ok(LocalCa {
        ca_cert,
        ca_key: key,
        ca_cert_der: certificate,
        cache: Mutex::new(HashMap::new()),
    })
}
