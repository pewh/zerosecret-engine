use zs_credential::Credential;
use zs_identity::WorkloadLabel;
use zs_protocol::{Context, Denied, Destination, InjectedRequest, Protocol};

mod signing;
pub mod sigv4;
mod websocket;
pub use signing::{AwsSigV4, HmacBodySignature};
pub use websocket::WebSocketJsonField;

pub struct BearerHttp {
    host: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl BearerHttp {
    pub fn new(host: impl Into<String>, allowed_workloads: Vec<WorkloadLabel>) -> Self {
        Self {
            host: host.into(),
            allowed_workloads,
        }
    }
}

impl Protocol for BearerHttp {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        if self
            .allowed_workloads
            .iter()
            .any(|w| w.as_str() == context.workload.as_str())
        {
            Ok(())
        } else {
            Err(Denied::new(format!(
                "workload {} has no grant for {}",
                context.workload.as_str(),
                self.host
            )))
        }
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        let value = std::str::from_utf8(credential.expose())
            .map_err(|_| Denied::new("credential is not valid utf-8 for bearer injection"))?;
        request.remove_header("Authorization");
        request.set_header("Authorization", format!("Bearer {value}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use zs_identity::Subject;

    fn context(workload: &str) -> (Subject, WorkloadLabel) {
        (
            Subject::new("alice@company.com").unwrap(),
            WorkloadLabel::new(workload).unwrap(),
        )
    }

    #[test]
    fn matches_host_case_insensitive() {
        let p = BearerHttp::new("api.stripe.com", vec![]);
        assert!(p.matches(&Destination::new("API.STRIPE.COM", 443)));
        assert!(!p.matches(&Destination::new("api.openai.com", 443)));
    }

    #[test]
    fn authorize_honors_grant_list() {
        let p = BearerHttp::new(
            "api.stripe.com",
            vec![WorkloadLabel::new("claude-code").unwrap()],
        );
        let (subject, wl) = context("claude-code");
        let ctx = Context {
            subject: &subject,
            workload: &wl,
        };
        assert!(p.authorize(&ctx).is_ok());

        let (subject, bad) = context("other-agent");
        let ctx_bad = Context {
            subject: &subject,
            workload: &bad,
        };
        assert!(p.authorize(&ctx_bad).is_err());
    }

    #[test]
    fn inject_replaces_client_authorization() {
        let p = BearerHttp::new("api.stripe.com", vec![]);
        let mut req = InjectedRequest {
            method: "GET".into(),
            path: "/v1/customers".into(),
            headers: vec![
                ("Host".into(), "api.stripe.com".into()),
                ("Authorization".into(), "Bearer client-supplied".into()),
            ],
            body: Vec::new(),
        };
        let cred = Credential::from_bytes(b"sk_test_real".to_vec()).unwrap();
        p.inject(&mut req, &cred).unwrap();
        assert_eq!(req.header("Authorization"), Some("Bearer sk_test_real"));
        let auths = req
            .headers
            .iter()
            .filter(|(k, _)| k == "Authorization")
            .count();
        assert_eq!(auths, 1);
    }

    #[test]
    fn inject_rejects_non_utf8_credential() {
        let p = BearerHttp::new("api.stripe.com", vec![]);
        let mut req = InjectedRequest::default();
        let cred = Credential::from_bytes(vec![0xFF, 0xFE]).unwrap();
        assert!(p.inject(&mut req, &cred).is_err());
    }
}

pub struct BasicAuthHttp {
    host: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl BasicAuthHttp {
    pub fn new(host: impl Into<String>, allowed_workloads: Vec<WorkloadLabel>) -> Self {
        Self {
            host: host.into(),
            allowed_workloads,
        }
    }
}

impl Protocol for BasicAuthHttp {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        if self
            .allowed_workloads
            .iter()
            .any(|w| w.as_str() == context.workload.as_str())
        {
            Ok(())
        } else {
            Err(Denied::new(format!(
                "workload {} has no grant for {}",
                context.workload.as_str(),
                self.host
            )))
        }
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        let value = std::str::from_utf8(credential.expose())
            .map_err(|_| Denied::new("credential is not valid utf-8 for basic auth"))?;
        request.remove_header("Authorization");
        request.set_header("Authorization", format!("Basic {value}"));
        Ok(())
    }
}

pub struct ApiKeyHeaderHttp {
    host: String,
    header_name: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl ApiKeyHeaderHttp {
    pub fn new(
        host: impl Into<String>,
        header_name: impl Into<String>,
        allowed_workloads: Vec<WorkloadLabel>,
    ) -> Self {
        Self {
            host: host.into(),
            header_name: header_name.into(),
            allowed_workloads,
        }
    }
}

impl Protocol for ApiKeyHeaderHttp {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        if self
            .allowed_workloads
            .iter()
            .any(|w| w.as_str() == context.workload.as_str())
        {
            Ok(())
        } else {
            Err(Denied::new("workload has no grant"))
        }
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        let value = std::str::from_utf8(credential.expose())
            .map_err(|_| Denied::new("credential is not valid utf-8 for api-key header"))?;
        request.remove_header(&self.header_name);
        request.set_header(&self.header_name, value);
        Ok(())
    }
}

pub struct QueryParamHttp {
    host: String,
    param_name: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl QueryParamHttp {
    pub fn new(
        host: impl Into<String>,
        param_name: impl Into<String>,
        allowed_workloads: Vec<WorkloadLabel>,
    ) -> Self {
        Self {
            host: host.into(),
            param_name: param_name.into(),
            allowed_workloads,
        }
    }
}

impl Protocol for QueryParamHttp {
    fn matches(&self, destination: &Destination) -> bool {
        destination.host.eq_ignore_ascii_case(&self.host)
    }

    fn authorize(&self, context: &Context) -> Result<(), Denied> {
        if self
            .allowed_workloads
            .iter()
            .any(|w| w.as_str() == context.workload.as_str())
        {
            Ok(())
        } else {
            Err(Denied::new("workload has no grant"))
        }
    }

    fn inject(&self, request: &mut InjectedRequest, credential: &Credential) -> Result<(), Denied> {
        let value = std::str::from_utf8(credential.expose())
            .map_err(|_| Denied::new("credential is not valid utf-8 for query param"))?;
        let (base, query) = request
            .path
            .split_once('?')
            .map(|(b, q)| (b.to_string(), q.to_string()))
            .unwrap_or_else(|| (request.path.clone(), String::new()));
        let mut params: Vec<String> = query
            .split('&')
            .filter(|p| !p.is_empty() && !p.starts_with(&format!("{}=", self.param_name)))
            .map(|p| p.to_string())
            .collect();
        params.push(format!("{}={}", self.param_name, value));
        request.path = format!("{base}?{}", params.join("&"));
        Ok(())
    }
}

#[cfg(test)]
mod auth_mode_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use zs_identity::Subject;

    fn context(workload: &str) -> (Subject, WorkloadLabel) {
        (
            Subject::new("a@b").unwrap(),
            WorkloadLabel::new(workload).unwrap(),
        )
    }

    #[test]
    fn basic_auth_injects() {
        let p = BasicAuthHttp::new("api.example.com", vec![]);
        let mut req = InjectedRequest::default();
        let cred = Credential::from_bytes(b"dXNlcjpwYXNz".to_vec()).unwrap();
        p.inject(&mut req, &cred).unwrap();
        assert_eq!(req.header("Authorization"), Some("Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn api_key_header_injects() {
        let p = ApiKeyHeaderHttp::new("api.example.com", "X-Api-Key", vec![]);
        let mut req = InjectedRequest::default();
        let cred = Credential::from_bytes(b"key-123".to_vec()).unwrap();
        p.inject(&mut req, &cred).unwrap();
        assert_eq!(req.header("X-Api-Key"), Some("key-123"));
    }

    #[test]
    fn query_param_appends_and_replaces() {
        let p = QueryParamHttp::new("api.example.com", "api_token", vec![]);
        let mut req = InjectedRequest {
            path: "/x?api_token=old&z=1".into(),
            ..Default::default()
        };
        let cred = Credential::from_bytes(b"new-token".to_vec()).unwrap();
        p.inject(&mut req, &cred).unwrap();
        assert_eq!(req.path, "/x?z=1&api_token=new-token");
    }

    #[test]
    fn basic_auth_grant_enforced() {
        let p = BasicAuthHttp::new(
            "api.example.com",
            vec![WorkloadLabel::new("granted").unwrap()],
        );
        let (subject, wl) = context("denied");
        let ctx = Context {
            subject: &subject,
            workload: &wl,
        };
        assert!(p.authorize(&ctx).is_err());
    }
}
