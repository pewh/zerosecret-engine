use serde_json::Value;
use zs_credential::Credential;
use zs_identity::WorkloadLabel;
use zs_protocol::{Context, Denied, Destination, InjectedRequest, Protocol};

// Writes the credential into one named string field of the client's JSON text messages on a
// WebSocket. It replaces a field the client already sent and never adds one.
pub struct WebSocketJsonField {
    host: String,
    field: String,
    allowed_workloads: Vec<WorkloadLabel>,
}

impl WebSocketJsonField {
    pub fn new(
        host: impl Into<String>,
        field: impl Into<String>,
        allowed_workloads: Vec<WorkloadLabel>,
    ) -> Self {
        Self {
            host: host.into(),
            field: field.into(),
            allowed_workloads,
        }
    }

    fn replace(&self, value: &mut Value, credential: &str) -> bool {
        let Value::Object(object) = value else {
            return false;
        };
        match object.get_mut(&self.field) {
            Some(slot @ Value::String(_)) => {
                *slot = Value::String(credential.to_string());
                true
            }
            _ => false,
        }
    }
}

impl Protocol for WebSocketJsonField {
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

    fn inject(
        &self,
        request: &mut InjectedRequest,
        _credential: &Credential,
    ) -> Result<(), Denied> {
        if request
            .header("Upgrade")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"))
        {
            Ok(())
        } else {
            Err(Denied::new(
                "websocket-json-field injects only into WebSocket messages",
            ))
        }
    }

    fn inject_message(
        &self,
        message: &mut Vec<u8>,
        credential: &Credential,
    ) -> Result<bool, Denied> {
        let value = std::str::from_utf8(credential.expose())
            .map_err(|_| Denied::new("credential is not valid utf-8 for a JSON field"))?;
        let Ok(mut json) = serde_json::from_slice::<Value>(message) else {
            return Ok(false);
        };
        let changed = match &mut json {
            Value::Array(items) => {
                let mut changed = false;
                for item in items {
                    changed |= self.replace(item, value);
                }
                changed
            }
            other => self.replace(other, value),
        };
        if changed {
            *message = serde_json::to_vec(&json)
                .map_err(|_| Denied::new("message could not be re-encoded"))?;
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn protocol() -> WebSocketJsonField {
        WebSocketJsonField::new("ws-api.example.com", "apiKey", vec![])
    }

    fn credential() -> Credential {
        Credential::from_bytes(b"real-key".to_vec()).unwrap()
    }

    #[test]
    fn the_field_is_replaced_in_an_object_and_in_an_array_of_objects() {
        for (input, expected) in [
            (
                r#"{"taskType":"authentication","apiKey":"zs-brokered"}"#,
                serde_json::json!({"taskType":"authentication","apiKey":"real-key"}),
            ),
            (
                r#"[{"taskType":"authentication","apiKey":"zs-brokered"},{"taskType":"ping"}]"#,
                serde_json::json!([{"taskType":"authentication","apiKey":"real-key"},{"taskType":"ping"}]),
            ),
        ] {
            let mut message = input.as_bytes().to_vec();
            assert!(
                protocol()
                    .inject_message(&mut message, &credential())
                    .unwrap()
            );
            assert_eq!(serde_json::from_slice::<Value>(&message).unwrap(), expected);
        }
    }

    #[test]
    fn a_message_without_the_field_is_left_byte_for_byte() {
        for input in [
            r#"{"taskType":"imageInference","prompt":"apiKey"}"#,
            r#"{"nested":{"apiKey":"zs-brokered"}}"#,
            r#"{"apiKey":42}"#,
            "not json",
        ] {
            let mut message = input.as_bytes().to_vec();
            assert!(
                !protocol()
                    .inject_message(&mut message, &credential())
                    .unwrap()
            );
            assert_eq!(message, input.as_bytes());
        }
    }

    #[test]
    fn a_plain_http_request_is_refused() {
        let mut request = InjectedRequest {
            method: "POST".into(),
            path: "/v1".into(),
            headers: vec![],
            body: Vec::new(),
        };
        assert!(protocol().inject(&mut request, &credential()).is_err());
        request.set_header("Upgrade", "websocket");
        assert!(protocol().inject(&mut request, &credential()).is_ok());
    }
}
