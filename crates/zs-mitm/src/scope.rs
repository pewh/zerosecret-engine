use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScope {
    Host,
    Paths(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeDecision {
    Inject,
    Forward,
    Refuse,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScopeError {
    #[error("paths must name at least one path")]
    Empty,
    #[error("paths[{index}] is not a canonical origin-form path")]
    NotCanonical { index: usize },
}

const REFUSED_ESCAPES: &[u8] = b"/\\.%;?#";

fn permitted(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,=:@/%".contains(&byte)
}

fn hex(byte: Option<&u8>) -> Option<u8> {
    byte.and_then(|b| (*b as char).to_digit(16))
        .map(|d| d as u8)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    NotOriginForm,
    Fragment,
    ForbiddenByte,
    BadEscape,
    ForbiddenEscape,
    DotSegment,
    EmptySegment,
    HostMissing,
    HostRepeated,
    HostMismatch,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NotOriginForm => "not_origin_form",
            Refusal::Fragment => "fragment",
            Refusal::ForbiddenByte => "forbidden_byte",
            Refusal::BadEscape => "bad_escape",
            Refusal::ForbiddenEscape => "forbidden_escape",
            Refusal::DotSegment => "dot_segment",
            Refusal::EmptySegment => "empty_segment",
            Refusal::HostMissing => "host_missing",
            Refusal::HostRepeated => "host_repeated",
            Refusal::HostMismatch => "host_mismatch",
        }
    }
}

pub fn target_refusal(target: &str) -> Option<Refusal> {
    if target.contains('#') {
        return Some(Refusal::Fragment);
    }
    path_refusal(target.split_once('?').map_or(target, |(path, _)| path))
}

fn path_refusal(path: &str) -> Option<Refusal> {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return Some(Refusal::NotOriginForm);
    }
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        if !permitted(byte) {
            return Some(Refusal::ForbiddenByte);
        }
        if byte == b'%' {
            let (Some(high), Some(low)) = (hex(bytes.get(at + 1)), hex(bytes.get(at + 2))) else {
                return Some(Refusal::BadEscape);
            };
            let decoded = high * 16 + low;
            if decoded < 0x20 || decoded == 0x7f || REFUSED_ESCAPES.contains(&decoded) {
                return Some(Refusal::ForbiddenEscape);
            }
            at += 3;
        } else {
            at += 1;
        }
    }
    let segments: Vec<&str> = path[1..].split('/').collect();
    let last = segments.len() - 1;
    for (index, segment) in segments.iter().enumerate() {
        match *segment {
            "." | ".." => return Some(Refusal::DotSegment),
            "" if index != last => return Some(Refusal::EmptySegment),
            _ => {}
        }
    }
    None
}

fn canonical(path: &str) -> bool {
    path_refusal(path).is_none()
}

impl PathScope {
    pub fn from_entries(entries: Option<&[String]>) -> Result<Self, ScopeError> {
        let Some(entries) = entries else {
            return Ok(Self::Host);
        };
        if entries.is_empty() {
            return Err(ScopeError::Empty);
        }
        for (index, entry) in entries.iter().enumerate() {
            if !canonical(entry) || entry.bytes().any(|b| b == b'%' || b == b'*') {
                return Err(ScopeError::NotCanonical { index });
            }
        }
        Ok(Self::Paths(entries.to_vec()))
    }

    pub fn decide(&self, target: &str) -> ScopeDecision {
        let Self::Paths(paths) = self else {
            return ScopeDecision::Inject;
        };
        if target.contains('#') {
            return ScopeDecision::Refuse;
        }
        let path = target.split_once('?').map_or(target, |(path, _)| path);
        if !canonical(path) {
            return ScopeDecision::Refuse;
        }
        if paths.iter().any(|entry| entry == path) {
            ScopeDecision::Inject
        } else {
            ScopeDecision::Forward
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn scope_of(entries: &[&str]) -> Result<PathScope, ScopeError> {
        let owned: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
        PathScope::from_entries(Some(owned.as_slice()))
    }

    fn acme() -> PathScope {
        scope_of(&["/oauth/token"]).unwrap()
    }

    #[test]
    fn a_refusal_names_the_rule_that_fired() {
        let cases = [
            ("*", Refusal::NotOriginForm),
            ("/a#b", Refusal::Fragment),
            ("/a;b", Refusal::ForbiddenByte),
            ("/a%zz", Refusal::BadEscape),
            ("/a%2Fb", Refusal::ForbiddenEscape),
            ("/a/../b", Refusal::DotSegment),
            ("//a", Refusal::EmptySegment),
        ];
        for (target, refusal) in cases {
            assert_eq!(target_refusal(target), Some(refusal), "{target}");
            assert_eq!(acme().decide(target), ScopeDecision::Refuse, "{target}");
        }
        assert_eq!(target_refusal("/oauth/token?x=%2F"), None);
        assert_eq!(Refusal::DotSegment.code(), "dot_segment");
        assert_eq!(Refusal::HostMismatch.code(), "host_mismatch");
    }

    #[test]
    fn an_exact_path_is_injected_and_another_path_is_forwarded() {
        assert_eq!(acme().decide("/oauth/token"), ScopeDecision::Inject);
        assert_eq!(acme().decide("/oauth/authenticate"), ScopeDecision::Forward);
        assert_eq!(acme().decide("/"), ScopeDecision::Forward);
    }

    #[test]
    fn the_query_is_not_matched() {
        assert_eq!(
            acme().decide("/oauth/token?grant_type=client_credentials"),
            ScopeDecision::Inject
        );
        assert_eq!(acme().decide("/oauth/token?"), ScopeDecision::Inject);
        assert_eq!(
            acme().decide("/oauth/authenticate?next=/oauth/token"),
            ScopeDecision::Forward
        );
    }

    #[test]
    fn matching_is_case_sensitive_and_a_trailing_slash_is_significant() {
        assert_eq!(acme().decide("/OAuth/Token"), ScopeDecision::Forward);
        assert_eq!(acme().decide("/oauth/token/"), ScopeDecision::Forward);
        assert_eq!(acme().decide("/oauth/%74oken"), ScopeDecision::Forward);
    }

    #[test]
    fn a_canonical_target_outside_the_scope_is_forwarded() {
        for target in [
            "/a/",
            "/a/b%20c",
            "/a/%C3%A9",
            "/a:b@c",
            "/a/*",
            "/a/b.c",
            "/a/..b",
            "/a/.b",
            "/a/!$&'()+,=~_-",
        ] {
            assert_eq!(acme().decide(target), ScopeDecision::Forward, "{target:?}");
        }
    }

    #[test]
    fn an_ambiguous_target_is_refused() {
        for target in [
            "*",
            "oauth/token",
            "https://auth.example/oauth/token",
            "auth.example:443",
            "",
            "/oauth/token#x",
            "/oauth/token?x#y",
            "/x/../oauth/token",
            "/oauth/./token",
            "/oauth/token/..",
            "/oauth/token/.",
            "//oauth/token",
            "/oauth//token",
            "/oauth/token//",
            "/oauth%2Ftoken",
            "/oauth%2ftoken",
            "/oauth%5Ctoken",
            "/oauth/%2e%2e/oauth/token",
            "/oauth/%2E/token",
            "/oauth/%252e%252e/token",
            "/oauth/token%3Bx",
            "/oauth/token%3F",
            "/oauth/token%23",
            "/oauth/token%00",
            "/oauth/token%1f",
            "/oauth/token%7F",
            "/oauth/token;x=1",
            "/oauth/..;/token",
            "/oauth\\token",
            "/oauth/to%zzken",
            "/oauth/token%",
            "/oauth/token%2",
            "/oauth/tok\u{e9}n",
            "/oauth/token\t",
            "/oauth/{token}",
            "/oauth/[token]",
            "/oauth/to|ken",
            "/oauth/to\"ken",
            "/oauth/to ken",
        ] {
            assert_eq!(acme().decide(target), ScopeDecision::Refuse, "{target:?}");
        }
    }

    #[test]
    fn host_scope_injects_every_target() {
        assert_eq!(PathScope::Host.decide("/x/../y"), ScopeDecision::Inject);
        assert_eq!(PathScope::Host.decide("*"), ScopeDecision::Inject);
    }

    #[test]
    fn an_entry_must_be_canonical_and_free_of_escapes_and_wildcards() {
        assert_eq!(PathScope::from_entries(None), Ok(PathScope::Host));
        assert_eq!(
            PathScope::from_entries(Some(Vec::<String>::new().as_slice())),
            Err(ScopeError::Empty)
        );
        for bad in [
            "oauth/token",
            "",
            "/oauth/%74oken",
            "/v1/*",
            "/oauth/token?x",
            "/a#b",
            "/a//b",
            "/a/../b",
            "/a;b",
        ] {
            assert_eq!(
                scope_of(&["/ok", bad]),
                Err(ScopeError::NotCanonical { index: 1 }),
                "{bad:?}"
            );
        }
        assert_eq!(
            scope_of(&["/", "/oauth/token", "/a/"]),
            Ok(PathScope::Paths(vec![
                "/".into(),
                "/oauth/token".into(),
                "/a/".into()
            ]))
        );
    }
}
