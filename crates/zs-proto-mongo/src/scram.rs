use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use md5::Md5;
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MIN_ITERATIONS: u32 = 4096;
pub const MAX_ITERATIONS: u32 = 1_000_000;
const HEX: &[u8; 16] = b"0123456789abcdef";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Sha1,
    Sha256,
}

impl Mechanism {
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SCRAM-SHA-1",
            Self::Sha256 => "SCRAM-SHA-256",
        }
    }

    pub fn choose(listed: Option<&[String]>) -> Option<Self> {
        match listed {
            None => Some(Self::Sha1),
            Some(list) if list.iter().any(|m| m == "SCRAM-SHA-256") => Some(Self::Sha256),
            Some(list) if list.iter().any(|m| m == "SCRAM-SHA-1") => Some(Self::Sha1),
            Some(_) => None,
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, ScramError> {
        let out = match self {
            Self::Sha1 => {
                let mut mac =
                    <Hmac<Sha1> as Mac>::new_from_slice(key).map_err(|_| ScramError::Malformed)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha256 => {
                let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
                    .map_err(|_| ScramError::Malformed)?;
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        };
        Ok(Zeroizing::new(out))
    }

    fn hash(self, data: &[u8]) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Sha256 => Sha256::digest(data).to_vec(),
        })
    }

    fn hi(
        self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
    ) -> Result<Zeroizing<Vec<u8>>, ScramError> {
        let mut first = salt.to_vec();
        first.extend_from_slice(&1u32.to_be_bytes());
        let mut block = self.hmac(password, &first)?;
        let mut result = block.clone();
        for _ in 1..iterations {
            block = self.hmac(password, &block)?;
            for (a, b) in result.iter_mut().zip(block.iter()) {
                *a ^= *b;
            }
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ScramError {
    #[error("the password is not printable ASCII")]
    Saslprep,
    #[error("malformed SCRAM message")]
    Malformed,
    #[error("the server nonce does not extend the client nonce")]
    Nonce,
    #[error("the iteration count is out of range")]
    Iterations,
    #[error("the server sent a SCRAM error")]
    ServerError,
    #[error("the server signature does not match")]
    Signature,
}

impl ScramError {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Saslprep => "saslprep",
            Self::Malformed => "malformed",
            Self::Nonce => "nonce",
            Self::Iterations => "iterations",
            Self::ServerError => "server_error",
            Self::Signature => "signature",
        }
    }
}

pub fn escape_user(user: &str) -> String {
    user.replace('=', "=3D").replace(',', "=2C")
}

pub fn mongo_sha1_password(user: &str, password: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut md5 = Md5::new();
    md5.update(user.as_bytes());
    md5.update(b":mongo:");
    md5.update(password);
    let digest = Zeroizing::new(md5.finalize().to_vec());
    let mut out = Zeroizing::new(Vec::with_capacity(digest.len() * 2));
    for byte in digest.iter() {
        out.push(HEX[usize::from(byte >> 4)]);
        out.push(HEX[usize::from(byte & 0x0f)]);
    }
    out
}

pub fn fresh_nonce() -> String {
    let mut bytes = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    STANDARD.encode(bytes)
}

pub struct Client {
    mechanism: Mechanism,
    password: Zeroizing<Vec<u8>>,
    first_bare: String,
    nonce: String,
    server_signature: Option<Zeroizing<Vec<u8>>>,
}

impl Client {
    pub fn new(
        mechanism: Mechanism,
        user: &str,
        password: &[u8],
        nonce: &str,
    ) -> Result<Self, ScramError> {
        let password = match mechanism {
            Mechanism::Sha1 => mongo_sha1_password(user, password),
            Mechanism::Sha256 => {
                if !password.iter().all(|b| (0x20..=0x7e).contains(b)) {
                    return Err(ScramError::Saslprep);
                }
                Zeroizing::new(password.to_vec())
            }
        };
        Ok(Self {
            mechanism,
            password,
            first_bare: format!("n={},r={nonce}", escape_user(user)),
            nonce: nonce.to_string(),
            server_signature: None,
        })
    }

    pub fn mechanism(&self) -> Mechanism {
        self.mechanism
    }

    pub fn client_first(&self) -> String {
        format!("n,,{}", self.first_bare)
    }

    pub fn client_final(&mut self, server_first: &str) -> Result<String, ScramError> {
        let (mut salt, mut iterations, mut nonce) = (None, None, None);
        for part in server_first.split(',') {
            match part.split_once('=') {
                Some(("r", value)) => nonce = Some(value),
                Some(("s", value)) => {
                    salt = Some(STANDARD.decode(value).map_err(|_| ScramError::Malformed)?)
                }
                Some(("i", value)) => {
                    iterations = Some(value.parse::<u32>().map_err(|_| ScramError::Malformed)?)
                }
                Some(("m", _)) => return Err(ScramError::Malformed),
                Some(("e", _)) => return Err(ScramError::ServerError),
                _ => {}
            }
        }
        let (Some(salt), Some(iterations), Some(nonce)) = (salt, iterations, nonce) else {
            return Err(ScramError::Malformed);
        };
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&iterations) {
            return Err(ScramError::Iterations);
        }
        if !nonce.starts_with(&self.nonce) || nonce.len() == self.nonce.len() {
            return Err(ScramError::Nonce);
        }
        let without_proof = format!("c=biws,r={nonce}");
        let auth_message = format!("{},{server_first},{without_proof}", self.first_bare);
        let mechanism = self.mechanism;
        let salted = mechanism.hi(&self.password, &salt, iterations)?;
        let client_key = mechanism.hmac(&salted, b"Client Key")?;
        let stored_key = mechanism.hash(&client_key);
        let signature = mechanism.hmac(&stored_key, auth_message.as_bytes())?;
        let proof: Zeroizing<Vec<u8>> = Zeroizing::new(
            client_key
                .iter()
                .zip(signature.iter())
                .map(|(a, b)| a ^ b)
                .collect(),
        );
        let server_key = mechanism.hmac(&salted, b"Server Key")?;
        self.server_signature = Some(mechanism.hmac(&server_key, auth_message.as_bytes())?);
        Ok(format!(
            "{without_proof},p={}",
            STANDARD.encode(proof.as_slice())
        ))
    }

    pub fn verify(&self, server_final: &str) -> Result<(), ScramError> {
        let expected = self
            .server_signature
            .as_ref()
            .ok_or(ScramError::Malformed)?;
        let mut verifier = None;
        for part in server_final.split(',') {
            match part.split_once('=') {
                Some(("e", _)) => return Err(ScramError::ServerError),
                Some(("v", value)) => verifier = Some(value),
                _ => {}
            }
        }
        let got = STANDARD
            .decode(verifier.ok_or(ScramError::Malformed)?)
            .map_err(|_| ScramError::Malformed)?;
        let same = got.len() == expected.len()
            && got
                .iter()
                .zip(expected.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        if same {
            Ok(())
        } else {
            Err(ScramError::Signature)
        }
    }
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const SHA1_NONCE: &str = "fyko+d2lbbFgONRv9qkxdawL";
    const SHA1_FIRST: &str = "r=fyko+d2lbbFgONRv9qkxdawLHo+Vgk7qvUOKUwuWLIWg4l/9SraGMHEE,s=rQ9ZY3MntBeuP3E1TDVC4w==,i=10000";
    const SHA256_NONCE: &str = "rOprNGfwEbeRWgbNEkqO";
    const SHA256_FIRST: &str =
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";

    fn first_with(nonce: &str, iterations: u32) -> String {
        format!("r={nonce},s=W22ZaJ0SNY7soEsUEjb6gQ==,i={iterations}")
    }

    #[test]
    fn the_mongodb_sha1_digest_matches_the_vector() {
        assert_eq!(
            mongo_sha1_password("user", b"pencil").as_slice(),
            b"1c33006ec1ffd90f9cadcbcc0e118200"
        );
    }

    #[test]
    fn scram_sha1_matches_the_mongodb_auth_spec_vector() {
        let mut client = Client::new(Mechanism::Sha1, "user", b"pencil", SHA1_NONCE).unwrap();
        assert_eq!(client.client_first(), format!("n,,n=user,r={SHA1_NONCE}"));
        assert_eq!(
            client.client_final(SHA1_FIRST).unwrap(),
            "c=biws,r=fyko+d2lbbFgONRv9qkxdawLHo+Vgk7qvUOKUwuWLIWg4l/9SraGMHEE,p=MC2T8BvbmWRckDw8oWl5IVghwCY="
        );
        assert_eq!(client.verify("v=UMWeI25JD1yNYZRMpZ4VHvhZ9e0="), Ok(()));
        assert_eq!(
            client.verify("v=AAAAI25JD1yNYZRMpZ4VHvhZ9e0="),
            Err(ScramError::Signature)
        );
    }

    #[test]
    fn scram_sha256_matches_the_rfc_7677_vector() {
        let mut client = Client::new(Mechanism::Sha256, "user", b"pencil", SHA256_NONCE).unwrap();
        assert_eq!(
            client.client_final(SHA256_FIRST).unwrap(),
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );
        assert_eq!(
            client.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
            Ok(())
        );
        assert_eq!(client.verify("e=other-error"), Err(ScramError::ServerError));
        assert_eq!(client.verify("x=1"), Err(ScramError::Malformed));
    }

    #[test]
    fn verify_before_client_final_is_malformed() {
        let client = Client::new(Mechanism::Sha256, "user", b"pencil", SHA256_NONCE).unwrap();
        assert_eq!(
            client.verify("v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="),
            Err(ScramError::Malformed)
        );
    }

    #[test]
    fn the_user_name_is_escaped() {
        assert_eq!(escape_user("a=b,c"), "a=3Db=2Cc");
        let client = Client::new(Mechanism::Sha256, "a=b,c", b"pencil", "n1").unwrap();
        assert_eq!(client.client_first(), "n,,n=a=3Db=2Cc,r=n1");
    }

    #[test]
    fn server_first_checks_refuse_unsafe_values() {
        let cases = [
            (first_with("other-nonce-xyz", 4096), ScramError::Nonce),
            (first_with(SHA256_NONCE, 4096), ScramError::Nonce),
            (
                first_with(&format!("{SHA256_NONCE}x"), 4095),
                ScramError::Iterations,
            ),
            (
                first_with(&format!("{SHA256_NONCE}x"), 1_000_001),
                ScramError::Iterations,
            ),
            (
                format!("m=ext,{}", first_with(&format!("{SHA256_NONCE}x"), 4096)),
                ScramError::Malformed,
            ),
            ("e=invalid-proof".to_string(), ScramError::ServerError),
            (format!("r={SHA256_NONCE}x,i=4096"), ScramError::Malformed),
            (
                format!("r={SHA256_NONCE}x,s=!!,i=4096"),
                ScramError::Malformed,
            ),
        ];
        for (first, expected) in cases {
            let mut client =
                Client::new(Mechanism::Sha256, "user", b"pencil", SHA256_NONCE).unwrap();
            assert_eq!(client.client_final(&first), Err(expected), "{first}");
        }
        let mut client = Client::new(Mechanism::Sha256, "user", b"pencil", SHA256_NONCE).unwrap();
        assert!(
            client
                .client_final(&first_with(&format!("{SHA256_NONCE}x"), 4096))
                .is_ok(),
            "negative control: 4096 iterations and an extended nonce"
        );
    }

    #[test]
    fn sha256_needs_printable_ascii_and_sha1_does_not() {
        assert_eq!(
            Client::new(Mechanism::Sha256, "user", "pässword".as_bytes(), "n").err(),
            Some(ScramError::Saslprep)
        );
        assert_eq!(
            Client::new(Mechanism::Sha256, "user", b"tab\tpassword", "n").err(),
            Some(ScramError::Saslprep)
        );
        assert!(Client::new(Mechanism::Sha256, "user", b"plain ~ password!", "n").is_ok());
        assert!(Client::new(Mechanism::Sha1, "user", "pässword".as_bytes(), "n").is_ok());
    }

    #[test]
    fn the_mechanism_follows_the_driver_rule() {
        let list = |items: &[&str]| items.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(Mechanism::choose(None), Some(Mechanism::Sha1));
        assert_eq!(
            Mechanism::choose(Some(list(&["SCRAM-SHA-1", "SCRAM-SHA-256"]).as_slice())),
            Some(Mechanism::Sha256)
        );
        assert_eq!(
            Mechanism::choose(Some(list(&["SCRAM-SHA-1"]).as_slice())),
            Some(Mechanism::Sha1)
        );
        assert_eq!(Mechanism::choose(Some(list(&["PLAIN"]).as_slice())), None);
        assert_eq!(Mechanism::choose(Some(list(&[]).as_slice())), None);
        assert_eq!(Mechanism::Sha256.name(), "SCRAM-SHA-256");
    }

    #[test]
    fn nonces_are_fresh() {
        let a = fresh_nonce();
        assert_eq!(a.len(), 32);
        assert_ne!(a, fresh_nonce());
    }
}
