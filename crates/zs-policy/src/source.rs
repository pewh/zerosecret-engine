use crate::Materialization;
use serde::{Deserialize, Serialize};

const MAX_POLICY_CHARS: usize = 2048;
const MAX_PARAMETER_CHARS: usize = 1760;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialSource {
    File { reference: String },
    AwsSsm(AwsSsmSource),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsSsmSource {
    pub role_arn: RoleArn,
    pub region: AwsRegion,
    pub parameter: SsmParameter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    File,
    AwsSsm,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::AwsSsm => "aws_ssm",
        }
    }
}

impl CredentialSource {
    pub fn file(reference: impl Into<String>) -> Self {
        Self::File {
            reference: reference.into(),
        }
    }

    pub fn kind(&self) -> SourceKind {
        match self {
            Self::File { .. } => SourceKind::File,
            Self::AwsSsm(_) => SourceKind::AwsSsm,
        }
    }

    pub fn mode(&self) -> Option<Materialization> {
        match self {
            Self::File { .. } => None,
            Self::AwsSsm(_) => Some(Materialization::Retrieve),
        }
    }

    pub fn identity_audience(&self) -> Option<&str> {
        match self {
            Self::File { .. } => None,
            Self::AwsSsm(_) => Some("sts.amazonaws.com"),
        }
    }

    pub fn validate(&self) -> Result<(), SourceError> {
        match self {
            Self::File { reference } => {
                if reference.chars().any(char::is_control) {
                    return Err(SourceError::new(
                        "credential reference has a control character",
                    ));
                }
                Ok(())
            }
            Self::AwsSsm(source) => {
                if aws_ssm_session_policy(source).len() > MAX_POLICY_CHARS {
                    return Err(SourceError::new(
                        "parameter's session policy is longer than 2048 characters",
                    ));
                }
                Ok(())
            }
        }
    }

    pub fn display_ref(&self) -> String {
        match self {
            Self::File { reference } => format!("file:{reference}"),
            Self::AwsSsm(source) => format!(
                "aws_ssm:{}:{}",
                source.role_arn.as_str(),
                source.parameter.as_str()
            ),
        }
    }
}

pub fn aws_ssm_session_policy(source: &AwsSsmSource) -> String {
    let parameter_arn = format!(
        "arn:aws:ssm:{}:{}:parameter/{}",
        source.region.as_str(),
        source.role_arn.account(),
        source.parameter.as_str().trim_start_matches('/')
    );
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "ssm:GetParameter",
                "Resource": parameter_arn,
            },
            {
                "Effect": "Allow",
                "Action": "kms:Decrypt",
                "Resource": "*",
                "Condition": {
                    "StringEquals": { "kms:ViaService": format!("ssm.{}.amazonaws.com", source.region.as_str()) }
                },
            },
        ],
    })
    .to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct SourceError {
    reason: String,
}

impl SourceError {
    pub(crate) fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub fn reason(&self) -> &str {
        &self.reason
    }
}

macro_rules! string_newtype {
    ($name:ident, $refuse:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }

            fn refuse() -> SourceError {
                SourceError::new($refuse)
            }
        }

        impl TryFrom<String> for $name {
            type Error = SourceError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::parse(&value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

string_newtype!(
    RoleArn,
    "role_arn is not arn:aws:iam::<12 digits>:role/<name>"
);

impl RoleArn {
    pub fn parse(value: &str) -> Result<Self, SourceError> {
        let Some(rest) = value.strip_prefix("arn:aws:iam::") else {
            return Err(Self::refuse());
        };
        let Some((account, role)) = rest.split_once(':') else {
            return Err(Self::refuse());
        };
        let Some(name) = role.strip_prefix("role/") else {
            return Err(Self::refuse());
        };
        let name_ok = !name.is_empty()
            && name.len() <= 512
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+=,.@_/-".contains(&b));
        if account.len() != 12 || !account.bytes().all(|b| b.is_ascii_digit()) || !name_ok {
            return Err(Self::refuse());
        }
        Ok(Self(value.to_string()))
    }

    pub fn account(&self) -> &str {
        &self.0["arn:aws:iam::".len().."arn:aws:iam::".len() + 12]
    }
}

string_newtype!(AwsRegion, "region is not an AWS region name");

impl AwsRegion {
    pub fn parse(value: &str) -> Result<Self, SourceError> {
        let parts: Vec<&str> = value.split('-').collect();
        let valid = parts.len() >= 3
            && parts[0].len() == 2
            && parts[0].bytes().all(|b| b.is_ascii_lowercase())
            && parts[1..parts.len() - 1]
                .iter()
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
            && parts[parts.len() - 1].len() == 1
            && parts[parts.len() - 1].bytes().all(|b| b.is_ascii_digit());
        if valid {
            Ok(Self(value.to_string()))
        } else {
            Err(Self::refuse())
        }
    }
}

string_newtype!(SsmParameter, "parameter has a character SSM refuses");

impl SsmParameter {
    pub fn parse(value: &str) -> Result<Self, SourceError> {
        if !value.starts_with('/') {
            return Err(SourceError::new("parameter must start with '/'"));
        }
        if value.len() > MAX_PARAMETER_CHARS {
            return Err(SourceError::new("parameter is longer than 1760 characters"));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b))
        {
            return Err(Self::refuse());
        }
        Ok(Self(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::ResourcePolicy;

    fn aws_ssm(parameter: &str) -> CredentialSource {
        CredentialSource::AwsSsm(AwsSsmSource {
            role_arn: RoleArn::parse("arn:aws:iam::123456789012:role/zs-acme-db").unwrap(),
            region: AwsRegion::parse("ap-southeast-1").unwrap(),
            parameter: SsmParameter::parse(parameter).unwrap(),
        })
    }

    fn policy_with(
        source: Option<CredentialSource>,
        credential_ref: Option<&str>,
    ) -> ResourcePolicy {
        ResourcePolicy {
            name: "stripe".into(),
            host: "api.stripe.com".into(),
            protocol: "https".into(),
            operations: vec!["GET".into()],
            materialization: Materialization::default(),
            credential_ref: credential_ref.map(str::to_string),
            source,
            project: None,
            connection: Default::default(),
        }
    }

    #[test]
    fn role_arn_shape() {
        assert!(RoleArn::parse("arn:aws:iam::123456789012:role/zs/acme-db").is_ok());
        assert!(RoleArn::parse("arn:aws:iam::123456789012:role/a+b=c,d.e@f_g-h/i").is_ok());
        assert!(RoleArn::parse("arn:aws-cn:iam::123456789012:role/zs").is_err());
        assert!(RoleArn::parse("arn:aws:iam::12345678901:role/zs").is_err());
        assert!(RoleArn::parse("arn:aws:iam::123456789012:user/zs").is_err());
        assert!(RoleArn::parse("arn:aws:iam::123456789012:role/").is_err());
    }

    #[test]
    fn region_shape() {
        assert!(AwsRegion::parse("ap-southeast-1").is_ok());
        assert!(AwsRegion::parse("us-gov-west-1").is_ok());
        assert!(AwsRegion::parse("ap-southeast1").is_err());
        assert!(AwsRegion::parse("AP-southeast-1").is_err());
        assert!(AwsRegion::parse("ap-southeast-12").is_err());
        assert!(AwsRegion::parse("ap--1").is_err());
    }

    #[test]
    fn parameter_shape_and_length() {
        assert!(SsmParameter::parse("/acme/prod/DB_PASSWORD").is_ok());
        assert!(SsmParameter::parse("acme/prod").is_err());
        assert!(SsmParameter::parse("/acme/prod/DB PASSWORD").is_err());

        let longest = format!("/{}", "a".repeat(MAX_PARAMETER_CHARS - 1));
        assert_eq!(longest.len(), MAX_PARAMETER_CHARS);
        let source = aws_ssm(&longest);
        assert_eq!(
            aws_ssm_session_policy(match &source {
                CredentialSource::AwsSsm(source) => source,
                CredentialSource::File { .. } => panic!("aws_ssm"),
            })
            .len(),
            MAX_POLICY_CHARS
        );
        assert!(source.validate().is_ok());

        let too_long = format!("/{}", "a".repeat(MAX_PARAMETER_CHARS));
        assert!(SsmParameter::parse(&too_long).is_err());
    }

    #[test]
    fn session_policy_is_exactly_the_spike_policy() {
        let source = match aws_ssm("/acme/prod/DB_PASSWORD") {
            CredentialSource::AwsSsm(source) => source,
            CredentialSource::File { .. } => panic!("aws_ssm"),
        };
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&aws_ssm_session_policy(&source)).unwrap(),
            serde_json::from_str::<serde_json::Value>(SESSION_POLICY).unwrap()
        );
    }

    const SESSION_POLICY: &str = concat!(
        r#"{"Statement":[{"Action":"ssm:GetParameter","Effect":"Allow","Resource":"arn:aws:ssm:ap-southeast-1:123456789012:parameter/acme/prod/DB_PASSWORD"},"#,
        r#"{"Action":"kms:Decrypt","Condition":{"StringEquals":{"kms:ViaService":"ssm.ap-southeast-1.amazonaws.com"}},"Effect":"Allow","Resource":"*"}],"#,
        r#""Version":"2012-10-17"}"#
    );

    #[test]
    fn mode_of_aws_ssm_is_retrieve() {
        assert_eq!(
            aws_ssm("/acme/prod/DB_PASSWORD").mode(),
            Some(Materialization::Retrieve)
        );
        assert_eq!(
            CredentialSource::File {
                reference: "x".into()
            }
            .mode(),
            None
        );
    }

    #[test]
    fn identity_audience_of_aws_ssm_is_sts() {
        assert_eq!(
            aws_ssm("/acme/prod/DB_PASSWORD").identity_audience(),
            Some("sts.amazonaws.com")
        );
        assert_eq!(
            CredentialSource::File {
                reference: "x".into()
            }
            .identity_audience(),
            None
        );
    }

    #[test]
    fn resolved_source_defaults_to_vault_kv_name() {
        assert_eq!(
            policy_with(None, None).resolved_source().unwrap(),
            CredentialSource::File {
                reference: "vault:kv/stripe".into()
            }
        );
        assert_eq!(
            policy_with(None, Some("billing-key"))
                .resolved_source()
                .unwrap(),
            CredentialSource::File {
                reference: "billing-key".into()
            }
        );
    }

    #[test]
    fn both_source_and_credential_ref_is_refused() {
        assert!(
            policy_with(Some(aws_ssm("/a")), Some("billing-key"))
                .resolved_source()
                .is_err()
        );
    }

    #[test]
    fn a_file_reference_with_a_control_character_is_refused() {
        assert!(
            policy_with(None, Some("billing-key"))
                .checked_source()
                .is_ok()
        );
        for reference in ["a\u{1e}b", "a\u{1f}b", "a\nb", "a\u{7f}b"] {
            assert_eq!(
                policy_with(None, Some(reference))
                    .checked_source()
                    .unwrap_err()
                    .reason(),
                "credential reference has a control character",
                "{reference:?}"
            );
        }
    }

    #[test]
    fn checked_source_refuses_both_keys_and_a_mode_mismatch() {
        assert_eq!(
            policy_with(Some(aws_ssm("/a")), Some("billing-key"))
                .checked_source()
                .unwrap_err()
                .reason(),
            "both source and credential_ref are set"
        );
        let mut exchange = policy_with(Some(aws_ssm("/a")), None);
        exchange.materialization = Materialization::Exchange;
        assert_eq!(
            exchange.checked_source().unwrap_err().reason(),
            "source does not match materialization"
        );
        assert_eq!(
            policy_with(Some(aws_ssm("/a")), None)
                .checked_source()
                .unwrap(),
            aws_ssm("/a")
        );
        assert!(
            policy_with(None, Some("billing-key"))
                .checked_source()
                .is_ok()
        );
    }

    #[test]
    fn unknown_kind_is_refused() {
        let parsed: Result<CredentialSource, _> =
            serde_json::from_str(r#"{"kind":"vault","reference":"x"}"#);
        assert!(parsed.is_err());
        let parsed: Result<CredentialSource, _> = serde_json::from_str(
            r#"{"kind":"aws_ssm","role_arn":"arn:aws:iam::123456789012:role/r","region":"eu-west-1","parameter":"/a","extra":1}"#,
        );
        assert!(parsed.is_err());
    }
}
