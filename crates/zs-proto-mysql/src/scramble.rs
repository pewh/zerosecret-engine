use sha1::Sha1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub fn native(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut stage1 = Zeroizing::new([0u8; 20]);
    Sha1::new_with_prefix(password).finalize_into((&mut *stage1).into());
    let mut stage2 = Zeroizing::new([0u8; 20]);
    Sha1::new_with_prefix(stage1.as_slice()).finalize_into((&mut *stage2).into());
    let mut mask = Zeroizing::new([0u8; 20]);
    Sha1::new_with_prefix(scramble)
        .chain_update(stage2.as_slice())
        .finalize_into((&mut *mask).into());
    stage1.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
}

pub fn caching_sha2(password: &[u8], scramble: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }
    let mut stage1 = Zeroizing::new([0u8; 32]);
    Sha256::new_with_prefix(password).finalize_into((&mut *stage1).into());
    let mut stage2 = Zeroizing::new([0u8; 32]);
    Sha256::new_with_prefix(stage1.as_slice()).finalize_into((&mut *stage2).into());
    let mut mask = Zeroizing::new([0u8; 32]);
    Sha256::new_with_prefix(stage2.as_slice())
        .chain_update(scramble)
        .finalize_into((&mut *mask).into());
    stage1.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const PASSWORD: &[u8] = b"zs-test-password";

    fn salt() -> Vec<u8> {
        (1u8..=20).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn native_matches_the_python_vector() {
        assert_eq!(
            hex(&native(PASSWORD, &salt())),
            "89cc3a4ead1d0700424d84c82771ac438372412a"
        );
    }

    #[test]
    fn caching_sha2_matches_the_python_vector() {
        assert_eq!(
            hex(&caching_sha2(PASSWORD, &salt())),
            "63c77e9dea87774f0a9bfd989bed300062ceae995a854b7ebe9a5487200693d9"
        );
    }

    #[test]
    fn an_empty_password_gives_an_empty_token() {
        assert!(native(b"", &salt()).is_empty());
        assert!(caching_sha2(b"", &salt()).is_empty());
    }

    #[test]
    fn the_token_depends_on_the_scramble_and_never_holds_the_password() {
        let other: Vec<u8> = (21u8..=40).collect();
        assert_ne!(native(PASSWORD, &salt()), native(PASSWORD, &other));
        assert_ne!(
            caching_sha2(PASSWORD, &salt()),
            caching_sha2(PASSWORD, &other)
        );
        for token in [native(PASSWORD, &salt()), caching_sha2(PASSWORD, &salt())] {
            assert!(!token.windows(PASSWORD.len()).any(|w| w == PASSWORD));
        }
    }
}
