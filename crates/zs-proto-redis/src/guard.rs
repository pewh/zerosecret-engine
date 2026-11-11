use zeroize::{Zeroize, Zeroizing};

pub const WINDOW: usize = 8;

pub struct EchoGuard {
    needles: Vec<Zeroizing<Vec<u8>>>,
    starts: Zeroizing<[u8; 256]>,
    keys: Zeroizing<Vec<u64>>,
    held: Zeroizing<Vec<u8>>,
}

impl EchoGuard {
    pub fn new(credential: &[u8]) -> Self {
        let needles = if credential.is_empty() {
            Vec::new()
        } else {
            let mut needles: Vec<Zeroizing<Vec<u8>>> = credential
                .windows(credential.len().min(WINDOW))
                .map(|window| Zeroizing::new(window.to_vec()))
                .collect();
            needles.sort_unstable_by(|a, b| a.as_slice().cmp(b.as_slice()));
            needles.dedup_by(|a, b| a.as_slice() == b.as_slice());
            needles
        };
        let mut starts = Zeroizing::new([0u8; 256]);
        for needle in &needles {
            starts[usize::from(needle[0])] = 1;
        }
        let mut keys = Zeroizing::new(Vec::new());
        for needle in &needles {
            if let Ok(window) = <[u8; WINDOW]>::try_from(needle.as_slice()) {
                keys.push(u64::from_be_bytes(window));
            }
        }
        Self {
            needles,
            starts,
            keys,
            held: Zeroizing::new(Vec::new()),
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Option<Vec<u8>> {
        if self.needles.is_empty() {
            return Some(chunk.to_vec());
        }
        self.held.extend_from_slice(chunk);
        if self.contains_needle() {
            self.held.zeroize();
            return None;
        }
        let cut = self.held.len() - self.started_prefix();
        let released = self.held[..cut].to_vec();
        self.held.drain(..cut);
        Some(released)
    }

    pub fn flush(&mut self) -> Vec<u8> {
        if self.contains_needle() {
            self.held.zeroize();
            return Vec::new();
        }
        std::mem::take(&mut *self.held)
    }

    fn needle_len(&self) -> usize {
        self.needles.first().map_or(0, |needle| needle.len())
    }

    fn contains_needle(&self) -> bool {
        let len = self.needle_len();
        if len > self.held.len() {
            return false;
        }
        let mut candidates = self
            .held
            .windows(len)
            .filter(|window| self.starts[usize::from(window[0])] != 0);
        if self.keys.is_empty() {
            return candidates.any(|window| {
                self.needles
                    .binary_search_by(|needle| needle.as_slice().cmp(window))
                    .is_ok()
            });
        }
        candidates.any(|window| {
            <[u8; WINDOW]>::try_from(window)
                .is_ok_and(|window| self.keys.binary_search(&u64::from_be_bytes(window)).is_ok())
        })
    }

    fn started_prefix(&self) -> usize {
        let longest = self.needle_len().saturating_sub(1).min(self.held.len());
        (1..=longest)
            .rev()
            .find(|&length| {
                let suffix = &self.held[self.held.len() - length..];
                let index = self
                    .needles
                    .partition_point(|needle| &needle[..length] < suffix);
                self.needles
                    .get(index)
                    .is_some_and(|needle| &needle[..length] == suffix)
            })
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    const CREDENTIAL: &[u8] = b"zs-redis-credential-8f2c";

    #[test]
    fn clean_bytes_are_released_immediately() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        assert_eq!(guard.push(b"+OK\r\n"), Some(b"+OK\r\n".to_vec()));
        assert_eq!(guard.push(b"0123456789"), Some(b"0123456789".to_vec()));
        assert!(guard.flush().is_empty());
    }

    #[test]
    fn a_seven_byte_reply_is_released_at_once() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        assert_eq!(guard.push(b"+PONG\r\n"), Some(b"+PONG\r\n".to_vec()));
        assert!(guard.flush().is_empty());
    }

    #[test]
    fn a_reply_ending_in_a_credential_prefix_is_held() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        assert_eq!(
            guard.push(b"$20\r\necho:zs-red"),
            Some(b"$20\r\necho:".to_vec())
        );
        assert_eq!(guard.push(b"is-credential-8f2c\r\n"), None);
    }

    #[test]
    fn a_clean_reply_that_does_not_start_a_needle_is_never_delayed() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        assert_eq!(
            guard.push(b"$4\r\nmiss\r\n"),
            Some(b"$4\r\nmiss\r\n".to_vec())
        );
    }

    #[test]
    fn a_short_credential_holds_only_its_prefix() {
        let mut guard = EchoGuard::new(b"s3");
        assert_eq!(guard.push(b"x"), Some(b"x".to_vec()));
        assert_eq!(guard.push(b"s"), Some(Vec::new()));
        assert_eq!(guard.push(b"y"), Some(b"sy".to_vec()));
        assert!(guard.push(b"s3\r\n").is_none());
    }

    #[test]
    fn a_short_credential_split_across_chunks_is_seen() {
        let mut guard = EchoGuard::new(b"abc");
        assert_eq!(guard.push(b"$3\r\na"), Some(b"$3\r\n".to_vec()));
        assert!(guard.push(b"bc\r\n").is_none());
    }

    #[test]
    fn every_window_position_is_seen() {
        for start in 0..=CREDENTIAL.len() - WINDOW {
            let mut guard = EchoGuard::new(CREDENTIAL);
            assert!(guard.push(b"prefix").is_some());
            let mut window = b"|".to_vec();
            window.extend_from_slice(&CREDENTIAL[start..start + WINDOW]);
            assert!(guard.push(&window).is_none(), "window at {start}");
        }
    }

    #[test]
    fn a_window_entirely_released_before_the_next_chunk_is_still_seen() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        assert_eq!(guard.push(b"0123456789"), Some(b"0123456789".to_vec()));
        assert!(guard.push(CREDENTIAL).is_none());
    }

    #[test]
    fn nothing_containing_a_window_is_released() {
        let mut released = Vec::new();
        let mut guard = EchoGuard::new(CREDENTIAL);
        for chunk in [
            &b"hello "[..],
            &b"zs-redi"[..],
            &b"zzzzzz"[..],
            &b"world"[..],
        ] {
            let Some(out) = guard.push(chunk) else {
                panic!("no chunk completes a window");
            };
            released.extend_from_slice(&out);
        }
        let windows = CREDENTIAL.windows(WINDOW);
        assert!(
            !released
                .windows(WINDOW)
                .any(|window| windows.clone().any(|needle| needle == window))
        );
    }

    #[test]
    fn the_held_tail_is_at_most_seven_bytes() {
        let mut guard = EchoGuard::new(CREDENTIAL);
        for _ in 0..8 {
            assert!(guard.push(b"0123456789abcdef").is_some());
        }
        assert!(guard.held.len() < WINDOW);
        assert!(guard.flush().len() < WINDOW);
    }

    #[test]
    fn a_window_split_at_every_point_is_caught_and_nothing_before_it_leaks() {
        for credential in [CREDENTIAL, &b"s3cr"[..], &b"aaaaaaaaaaab"[..]] {
            let needle = &credential[credential.len() - credential.len().min(WINDOW)..];
            let mut stream = b"$40\r\nvalue:".to_vec();
            stream.extend_from_slice(needle);
            stream.extend_from_slice(b"\r\n");
            for split in 0..=stream.len() {
                let mut guard = EchoGuard::new(credential);
                let released = match guard.push(&stream[..split]) {
                    None => Vec::new(),
                    Some(released) => {
                        assert!(
                            guard.push(&stream[split..]).is_none(),
                            "split {split} of {credential:?}"
                        );
                        released
                    }
                };
                assert!(
                    !released
                        .windows(needle.len())
                        .any(|window| window == needle),
                    "split {split} released the window"
                );
            }
        }
    }

    #[test]
    fn a_credential_with_repeated_windows_holds_its_longest_prefix() {
        let mut guard = EchoGuard::new(b"aaaaaaaaaaab");
        assert_eq!(guard.push(b"xaaaaaaa"), Some(b"x".to_vec()));
        assert_eq!(guard.push(b"c"), Some(b"aaaaaaac".to_vec()));
        assert!(guard.push(b"aaaaaaab").is_none());
    }

    #[test]
    fn an_empty_credential_matches_nothing() {
        let mut guard = EchoGuard::new(b"");
        assert_eq!(guard.push(b"anything"), Some(b"anything".to_vec()));
    }
}
