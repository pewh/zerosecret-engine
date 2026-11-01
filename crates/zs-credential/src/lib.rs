// Credential must not implement Debug, Display, or Serialize; compile-fail tests enforce it.

use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Error)]
#[error("credential denied: {reason}")]
pub struct Denied {
    reason: String,
}

impl Denied {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRef(String);

impl CredentialRef {
    pub fn new(value: impl Into<String>) -> Result<Self, Denied> {
        let value = value.into();
        if value.is_empty()
            || !value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./:".contains(c))
        {
            return Err(Denied::new("invalid credential reference"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct Credential {
    value: Vec<u8>,
}

impl Credential {
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, Denied> {
        if value.is_empty() {
            return Err(Denied::new("empty credential"));
        }
        Ok(Self { value })
    }

    pub fn expose(&self) -> &[u8] {
        &self.value
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub struct IdentityToken {
    value: Zeroizing<String>,
}

impl IdentityToken {
    pub fn from_string(value: String) -> Self {
        Self {
            value: Zeroizing::new(value),
        }
    }

    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for IdentityToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityToken([redacted])")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn scheme_prefixed_reference_is_accepted() {
        assert!(CredentialRef::new("vault:kv/stripe").is_ok());
        assert!(CredentialRef::new("aws:role/deploy").is_ok());
        assert!(CredentialRef::new("stripe-prod").is_ok());
    }

    #[test]
    fn invalid_reference_denied() {
        assert!(CredentialRef::new("a b c").is_err());
        assert!(CredentialRef::new("").is_err());
        assert!(CredentialRef::new("ref\nwith-newline").is_err());
        assert!(CredentialRef::new("ref\"quoted").is_err());
    }

    #[test]
    fn empty_credential_denied() {
        assert!(Credential::from_bytes(Vec::new()).is_err());
    }

    #[test]
    fn identity_token_debug_is_redacted() {
        let token = IdentityToken::from_string("header.payload.signature".into());
        assert_eq!(token.expose(), "header.payload.signature");
        assert_eq!(format!("{token:?}"), "IdentityToken([redacted])");
        assert!(!format!("{token:?}").contains("payload"));
    }
}
