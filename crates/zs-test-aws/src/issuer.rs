use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;

pub struct TestIssuer {
    issuer: String,
    key: SigningKey,
    kid: String,
    x: String,
    y: String,
}

impl TestIssuer {
    pub fn new(issuer: &str) -> Self {
        let key = loop {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            if let Ok(key) = SigningKey::from_slice(&bytes) {
                break key;
            }
        };
        let point = key.verifying_key().to_sec1_point(false);
        let bytes = point.as_bytes();
        let x = B64.encode(&bytes[1..33]);
        let y = B64.encode(&bytes[33..65]);
        let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = B64.encode(sha256(canonical.as_bytes()));
        Self {
            issuer: issuer.to_string(),
            key,
            kid,
            x,
            y,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn kid(&self) -> &str {
        &self.kid
    }

    pub fn jwks_json(&self) -> String {
        serde_json::json!({
            "keys": [{
                "alg": "ES256",
                "crv": "P-256",
                "kid": self.kid,
                "kty": "EC",
                "use": "sig",
                "x": self.x,
                "y": self.y,
            }]
        })
        .to_string()
    }

    pub fn sign(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({"alg": "ES256", "typ": "JWT", "kid": self.kid});
        let input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let signature: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(signature.to_bytes()))
    }

    pub fn token(&self, sub: &str, jti: &str, exp_s: u64) -> String {
        self.sign(&serde_json::json!({
            "iss": self.issuer,
            "aud": crate::AUDIENCE,
            "sub": sub,
            "zs_subject": "alice@company.com",
            "jti": jti,
            "iat": crate::now(),
            "exp": exp_s,
        }))
    }
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).to_vec()
}
