// What an injected request's response must never carry back to the workload: the credential,
// raw and percent-encoded, and every header or query value that `inject` added or changed.
// Needle bytes are zeroized on drop, and the type has no `Debug`.

use zeroize::Zeroizing;
use zs_protocol::InjectedRequest;

// Upstream messages that end with this many bytes of the credential's start are held.
pub(crate) const HOLD_PREFIX: usize = 8;

// An injected header or query value shorter than this is too common to refuse on.
const SHORTEST_INJECTED: usize = 8;

// Headers the agent sets on every injected request whose values carry no credential.
const NOT_NEEDLES: [&str; 2] = ["host", "accept-encoding"];

// `x-amz-*` values are dates, body hashes and checksums that the upstream may legitimately
// return, except the session token, which is a credential.
fn is_needle_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if NOT_NEEDLES.contains(&lower.as_str()) {
        return false;
    }
    !lower.starts_with("x-amz-") || lower == "x-amz-security-token"
}

// The parts of a request `inject` may change, taken before it runs.
pub(crate) struct RequestSnapshot {
    headers: Vec<(String, String)>,
    path: String,
}

impl RequestSnapshot {
    pub(crate) fn of(request: &InjectedRequest) -> Self {
        Self {
            headers: request.headers.clone(),
            path: request.path.clone(),
        }
    }
}

pub(crate) struct EchoNeedles {
    needles: Vec<Zeroizing<Vec<u8>>>,
}

impl EchoNeedles {
    pub(crate) fn from_injection(
        before: &RequestSnapshot,
        after: &InjectedRequest,
        secret: &[u8],
    ) -> Self {
        let mut echo = Self {
            needles: Vec::new(),
        };
        echo.push(Zeroizing::new(secret.to_vec()));
        echo.push(percent_encoded(secret, b"0123456789ABCDEF"));
        echo.push(percent_encoded(secret, b"0123456789abcdef"));
        for (name, value) in &after.headers {
            if !is_needle_header(name) || value.len() < SHORTEST_INJECTED {
                continue;
            }
            let unchanged = before
                .headers
                .iter()
                .any(|(was, prior)| was.eq_ignore_ascii_case(name) && prior == value);
            if !unchanged {
                echo.push(Zeroizing::new(value.as_bytes().to_vec()));
            }
        }
        let prior = query_pairs(&before.path);
        for pair in query_pairs(&after.path) {
            if pair.1.len() >= SHORTEST_INJECTED && !prior.contains(&pair) {
                echo.push(Zeroizing::new(pair.1.as_bytes().to_vec()));
            }
        }
        echo
    }

    fn push(&mut self, needle: Zeroizing<Vec<u8>>) {
        if !needle.is_empty() && !self.needles.iter().any(|n| **n == *needle) {
            self.needles.push(needle);
        }
    }

    pub(crate) fn found_in(&self, bytes: &[u8]) -> bool {
        self.needles
            .iter()
            .any(|needle| contains(bytes, needle, |a, b| a == b))
    }

    // Header names arrive lowercased, so a name is matched without regard to ASCII case.
    pub(crate) fn found_in_head(&self, headers: &hyper::HeaderMap) -> bool {
        headers.iter().any(|(name, value)| {
            self.found_in(value.as_bytes())
                || self.needles.iter().any(|needle| {
                    contains(name.as_str().as_bytes(), needle, |a, b| {
                        a.eq_ignore_ascii_case(b)
                    })
                })
        })
    }

    // The headers and a non-standard reason phrase, which the relay would otherwise pass on.
    pub(crate) fn found_in_response_head<B>(&self, response: &hyper::Response<B>) -> bool {
        self.found_in_head(response.headers())
            || response
                .extensions()
                .get::<hyper::ext::ReasonPhrase>()
                .is_some_and(|phrase| self.found_in(phrase.as_bytes()))
    }

    // A streaming scan keeps one byte fewer than this between chunks; no body scan exists yet.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn longest(&self) -> usize {
        self.needles.iter().map(|n| n.len()).max().unwrap_or(0)
    }
}

fn contains(haystack: &[u8], needle: &[u8], same: impl Fn(&[u8], &[u8]) -> bool) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| same(window, needle))
}

// RFC 3986 percent-encoding: unreserved characters are kept, every other byte is `%XX`.
fn percent_encoded(bytes: &[u8], digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len() * 3));
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b);
        } else {
            out.extend_from_slice(&[
                b'%',
                digits[usize::from(b >> 4)],
                digits[usize::from(b & 0x0f)],
            ]);
        }
    }
    out
}

fn query_pairs(path: &str) -> Vec<(&str, &str)> {
    path.split_once('?')
        .map_or("", |(_, query)| query)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| pair.split_once('=').unwrap_or((pair, "")))
        .collect()
}

// The length of the longest end of `window` that is a start of `needle`, shorter than `needle`.
pub(crate) fn started_prefix(window: &[u8], needle: &[u8]) -> usize {
    (1..needle.len().min(window.len() + 1))
        .rev()
        .find(|&n| window.ends_with(&needle[..n]))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn request(path: &str) -> InjectedRequest {
        InjectedRequest {
            method: "GET".into(),
            path: path.into(),
            headers: vec![("Accept".into(), "application/json".into())],
            body: Vec::new(),
        }
    }

    #[test]
    fn needles_cover_raw_percent_encoded_and_injected_values() {
        let before = request("/v1/customers?limit=10");
        let mut after = request("/v1/customers?limit=10&api_key=s3cret+value!");
        after.set_header("Authorization", "Basic dXNlcjpzM2NyZXQrdmFsdWUh");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"s3cret+value!");
        assert!(needles.found_in(b"..s3cret+value!.."));
        assert!(needles.found_in(b"Location: /x?api_key=s3cret%2Bvalue%21"));
        assert!(needles.found_in(b"location: /x?api_key=s3cret%2bvalue%21"));
        assert!(needles.found_in(b"seen Basic dXNlcjpzM2NyZXQrdmFsdWUh"));
        assert!(!needles.found_in(b"an ordinary body"));
        assert!(!needles.found_in(b"application/json limit=10"));
    }

    #[test]
    fn an_injected_query_value_is_a_needle() {
        let before = request("/v1/customers");
        let after = request("/v1/customers?X-Amz-Signature=0123456789abcdef");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"unrelated-secret");
        assert!(needles.found_in(b"/next?sig=0123456789abcdef"));
    }

    #[test]
    fn host_amz_date_and_short_values_are_not_needles() {
        let before = request("/v1/customers");
        let mut after = request("/v1/customers");
        let after_host = "api.stripe.example.com";
        after.set_header("Host", after_host);
        after.set_header("x-amz-date", "20261105T000000Z");
        after.set_header(
            "x-amz-content-sha256",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        after.set_header("Accept-Encoding", "identity");
        after.set_header("x-amz-checksum-crc32", "AAAAAA==");
        after.set_header("x-amz-security-token", "FwoGZXIvYXdzEJr-session-token");
        after.set_header("X-Short", "1234567");
        let needles = EchoNeedles::from_injection(
            &RequestSnapshot::of(&before),
            &after,
            b"long-enough-secret",
        );
        assert!(needles.found_in(b"long-enough-secret"));
        assert!(!needles.found_in(b"20261105T000000Z"));
        assert!(!needles.found_in(after_host.as_bytes()));
        assert!(
            !needles.found_in(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert!(!needles.found_in(b"identity"));
        assert!(!needles.found_in(b"AAAAAA=="));
        assert!(needles.found_in(b"FwoGZXIvYXdzEJr-session-token"));
        assert!(!needles.found_in(b"1234567"));
    }

    #[test]
    fn the_head_check_covers_names_and_values() {
        let before = request("/v1");
        let after = request("/v1");
        let needles =
            EchoNeedles::from_injection(&RequestSnapshot::of(&before), &after, b"sk_live_head_42");
        let mut quiet = hyper::HeaderMap::new();
        quiet.insert("content-type", "application/json".parse().unwrap());
        assert!(!needles.found_in_head(&quiet));
        let mut in_value = quiet.clone();
        in_value.insert("x-debug", "got sk_live_head_42".parse().unwrap());
        assert!(needles.found_in_head(&in_value));
        let mut in_name = quiet.clone();
        in_name.insert(
            hyper::header::HeaderName::from_bytes(b"x-sk_live_head_42").unwrap(),
            "1".parse().unwrap(),
        );
        assert!(needles.found_in_head(&in_name));
        assert_eq!(needles.longest(), "sk_live_head_42".len());
    }

    #[test]
    fn a_window_ending_in_a_needle_start_reports_its_length() {
        assert_eq!(started_prefix(b"xxsk_li", b"sk_live"), 5);
        assert_eq!(started_prefix(b"xxsk_live", b"sk_live"), 0);
        assert_eq!(started_prefix(b"abc", b"sk_live"), 0);
        assert_eq!(started_prefix(b"", b"sk_live"), 0);
    }
}
