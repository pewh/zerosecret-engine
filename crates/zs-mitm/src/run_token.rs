use std::borrow::Cow;
use std::net::SocketAddr;

use base64::Engine as _;
use hyper::HeaderMap;
use rand::RngCore;
use zeroize::Zeroizing;

const TOKEN_BYTES: usize = 32;
const TOKEN_LEN: usize = TOKEN_BYTES * 2;
const USER: &str = "zs";
const HEX: &[u8; 16] = b"0123456789abcdef";
const PROXY_AUTHORIZATION: &str = "proxy-authorization";

pub struct RunToken {
    hex: Zeroizing<String>,
}

impl RunToken {
    pub fn generate() -> RunToken {
        let mut raw = Zeroizing::new([0_u8; TOKEN_BYTES]);
        rand::rngs::OsRng.fill_bytes(raw.as_mut());
        let mut hex = Zeroizing::new(String::with_capacity(TOKEN_LEN));
        for &byte in raw.as_ref() {
            hex.push(HEX[usize::from(byte >> 4)] as char);
            hex.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        RunToken { hex }
    }

    pub fn proxy_url(&self, addr: SocketAddr) -> Zeroizing<String> {
        Zeroizing::new(format!("http://{USER}:{}@{addr}", self.hex.as_str()))
    }

    pub fn endpoint_url(&self, addr: SocketAddr) -> Zeroizing<String> {
        Zeroizing::new(format!("http://{addr}/{}", self.hex.as_str()))
    }

    pub fn proxy_authorization(&self) -> Zeroizing<String> {
        let mut credentials = Zeroizing::new(String::with_capacity(USER.len() + 1 + TOKEN_LEN));
        credentials.push_str(USER);
        credentials.push(':');
        credentials.push_str(self.hex.as_str());
        let encoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes()),
        );
        Zeroizing::new(format!("Basic {}", encoded.as_str()))
    }

    pub(crate) fn admits(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return false;
        };
        if values.next().is_some() {
            return false;
        }
        let Some(presented) = basic_credentials(value.as_bytes()) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(presented) else {
            return false;
        };
        let decoded = Zeroizing::new(decoded);
        self.matches_credentials(decoded.as_slice())
    }

    pub(crate) fn strip_endpoint_prefix<'a>(
        &self,
        path_and_query: &'a str,
    ) -> Option<Cow<'a, str>> {
        let rest = path_and_query.strip_prefix('/')?;
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        if !self.matches(&rest.as_bytes()[..end]) {
            return None;
        }
        match &rest[end..] {
            "" => Some(Cow::Borrowed("/")),
            tail if tail.starts_with('/') => Some(Cow::Borrowed(tail)),
            tail if tail.starts_with('?') => Some(Cow::Owned(format!("/{tail}"))),
            _ => None,
        }
    }

    fn matches(&self, candidate: &[u8]) -> bool {
        if candidate.len() != TOKEN_LEN {
            return false;
        }
        let mut diff = 0_u8;
        for (expected, actual) in self.hex.as_bytes().iter().zip(candidate) {
            diff |= expected ^ actual;
        }
        std::hint::black_box(diff) == 0
    }

    fn matches_credentials(&self, presented: &[u8]) -> bool {
        if presented.len() != USER.len() + 1 + TOKEN_LEN {
            return false;
        }
        let mut diff = 0_u8;
        for (index, actual) in presented.iter().enumerate() {
            let expected = match index {
                index if index < USER.len() => USER.as_bytes()[index],
                index if index == USER.len() => b':',
                index => self.hex.as_bytes()[index - USER.len() - 1],
            };
            diff |= actual ^ expected;
        }
        std::hint::black_box(diff) == 0
    }
}

fn basic_credentials(value: &[u8]) -> Option<&[u8]> {
    let space = value.iter().position(|byte| *byte == b' ')?;
    if !value[..space].eq_ignore_ascii_case(b"basic") {
        return None;
    }
    let rest = &value[space + 1..];
    let start = rest.iter().position(|byte| *byte != b' ')?;
    let rest = &rest[start..];
    let end = rest.iter().rposition(|byte| *byte != b' ')? + 1;
    Some(&rest[..end])
}

#[cfg(test)]
mod tests {
    use hyper::HeaderMap;
    use hyper::header::{HeaderName, HeaderValue};

    use super::*;

    const ADDR: &str = "127.0.0.1:9";

    fn addr() -> SocketAddr {
        ADDR.parse().unwrap()
    }

    fn hex_of(token: &RunToken) -> String {
        let url = token.proxy_url(addr());
        let rest = url
            .strip_prefix("http://zs:")
            .expect("proxy url must carry the user");
        rest.split_once('@')
            .expect("proxy url must carry @")
            .0
            .into()
    }

    fn b64(text: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn headers(values: &[&str]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for value in values {
            map.append(
                HeaderName::from_static("proxy-authorization"),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn generate_makes_64_lowercase_hex_and_differs_each_time() {
        let first = hex_of(&RunToken::generate());
        let second = hex_of(&RunToken::generate());

        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "not lowercase hex: {first}"
        );
        assert_ne!(first, second);
    }

    #[test]
    fn proxy_url_and_endpoint_url_shapes() {
        let token = RunToken::generate();
        let hex = hex_of(&token);

        assert_eq!(
            *token.proxy_url(addr()),
            format!("http://zs:{hex}@127.0.0.1:9")
        );
        assert_eq!(
            *token.endpoint_url(addr()),
            format!("http://127.0.0.1:9/{hex}")
        );
    }

    #[test]
    fn proxy_authorization_variants() {
        let token = RunToken::generate();
        let hex = hex_of(&token);
        let credentials = b64(&format!("zs:{hex}"));

        assert_eq!(*token.proxy_authorization(), format!("Basic {credentials}"));
        assert!(token.admits(&headers(&[&format!("Basic {credentials}")])));
        assert!(token.admits(&headers(&[&format!("basic {credentials}")])));
        assert!(token.admits(&headers(&[&format!("Basic   {credentials}")])));

        assert!(!token.admits(&HeaderMap::new()));
        assert!(!token.admits(&headers(&[
            &format!("Basic {credentials}"),
            &format!("Basic {credentials}"),
        ])));
        assert!(!token.admits(&headers(&[&format!("Bearer {hex}")])));
        assert!(!token.admits(&headers(&[&format!(
            "Basic {}",
            b64(&format!("zs:{}", "a".repeat(64)))
        )])));
        assert!(!token.admits(&headers(&[&format!("Basic {}", b64(&format!("x:{hex}")))])));
        assert!(!token.admits(&headers(&["Basic not-base64!!"])));

        let mut raw = HeaderMap::new();
        raw.insert(
            HeaderName::from_static("proxy-authorization"),
            HeaderValue::from_bytes(b"Basic \x80\x81\x82").unwrap(),
        );
        assert!(!token.admits(&raw));
    }

    #[test]
    fn endpoint_token_segment_variants() {
        let token = RunToken::generate();
        let hex = hex_of(&token);

        assert_eq!(
            token
                .strip_endpoint_prefix(&format!("/{hex}/b/k"))
                .as_deref(),
            Some("/b/k")
        );
        assert_eq!(
            token.strip_endpoint_prefix(&format!("/{hex}")).as_deref(),
            Some("/")
        );
        assert_eq!(
            token
                .strip_endpoint_prefix(&format!("/{hex}?x=1"))
                .as_deref(),
            Some("/?x=1")
        );
        assert_eq!(
            token
                .strip_endpoint_prefix(&format!("/{hex}/.zs/presign"))
                .as_deref(),
            Some("/.zs/presign")
        );

        assert_eq!(
            token.strip_endpoint_prefix(&format!("/{}/b", hex.to_uppercase())),
            None
        );
        assert_eq!(
            token.strip_endpoint_prefix(&format!("/%61{}/b", &hex[2..])),
            None
        );
        assert_eq!(token.strip_endpoint_prefix(&format!("/{hex}x/b")), None);
        assert_eq!(token.strip_endpoint_prefix(&format!("/b/{hex}")), None);
        assert_eq!(token.strip_endpoint_prefix("/"), None);
    }

    #[test]
    fn proxy_authorization_is_hop_by_hop() {
        assert!(
            crate::http1::HOP_BY_HOP
                .iter()
                .any(|name| name.eq_ignore_ascii_case("Proxy-Authorization"))
        );
    }
}
