use thiserror::Error;

#[derive(Debug, Error)]
#[error("identity value must be non-empty")]
pub struct EmptyIdentity;

macro_rules! identity_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, EmptyIdentity> {
                let value = value.into();
                if value.is_empty() {
                    return Err(EmptyIdentity);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

identity_type!(Subject);
identity_type!(WorkloadLabel);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(Subject::new("").is_err());
        assert!(WorkloadLabel::new("").is_err());
    }

    #[test]
    fn accepts_values() {
        assert_eq!(
            Subject::new("alice@company.com").unwrap().as_str(),
            "alice@company.com"
        );
        assert_eq!(
            WorkloadLabel::new("claude-code").unwrap().as_str(),
            "claude-code"
        );
    }
}
