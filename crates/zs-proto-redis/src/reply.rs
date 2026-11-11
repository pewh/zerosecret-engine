const MAX_HEADER: usize = 32;
const MAX_DEPTH: usize = 1024;
const MAX_DIGITS: usize = 18;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Continue,
    Redirect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Value,
    Line,
    Prefix,
    BulkHeader,
    BulkBody { remaining: u64 },
    BulkTail { seen: u8 },
    CountHeader { doubled: bool },
}

pub struct Framer {
    stack: Vec<u64>,
    state: State,
    header: Vec<u8>,
    prefix: Vec<u8>,
    line_cr: bool,
}

impl Framer {
    pub fn new() -> Self {
        Self {
            stack: Vec::new(),
            state: State::Value,
            header: Vec::new(),
            prefix: Vec::new(),
            line_cr: false,
        }
    }

    pub fn at_boundary(&self) -> bool {
        self.stack.is_empty() && self.prefix.is_empty() && self.state == State::Value
    }

    pub fn push(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(usize, Outcome), Malformed> {
        let mut index = 0usize;
        while index < input.len() {
            let before = index;
            match self.state {
                State::Value => {
                    let byte = input[index];
                    index += 1;
                    match byte {
                        b'-' if self.stack.is_empty() => {
                            self.prefix.clear();
                            self.prefix.push(byte);
                            self.state = State::Prefix;
                        }
                        b'+' | b'-' | b':' | b',' | b'#' | b'(' | b'_' => {
                            out.push(byte);
                            self.state = State::Line;
                            self.line_cr = false;
                        }
                        b'$' | b'!' | b'=' => {
                            out.push(byte);
                            self.header.clear();
                            self.state = State::BulkHeader;
                        }
                        b'*' | b'~' | b'>' | b'%' | b'|' => {
                            out.push(byte);
                            self.header.clear();
                            self.state = State::CountHeader {
                                doubled: byte == b'%' || byte == b'|',
                            };
                        }
                        _ => return Err(Malformed),
                    }
                }
                State::Prefix => {
                    let byte = input[index];
                    index += 1;
                    self.prefix.push(byte);
                    if is_cluster_redirect(&self.prefix) {
                        return Ok((index, Outcome::Redirect));
                    }
                    if starts_a_redirect(&self.prefix) {
                        continue;
                    }
                    let prefix = std::mem::take(&mut self.prefix);
                    out.extend_from_slice(&prefix);
                    if prefix.last() == Some(&b'\n') {
                        if !prefix.ends_with(b"\r\n") {
                            return Err(Malformed);
                        }
                        self.complete();
                    } else {
                        self.line_cr = prefix.last() == Some(&b'\r');
                        self.state = State::Line;
                    }
                }
                State::Line => {
                    let byte = input[index];
                    index += 1;
                    out.push(byte);
                    if byte == b'\n' {
                        if !self.line_cr {
                            return Err(Malformed);
                        }
                        self.complete();
                    } else {
                        self.line_cr = byte == b'\r';
                    }
                }
                State::BulkHeader => {
                    let byte = input[index];
                    index += 1;
                    out.push(byte);
                    if byte == b'\n' {
                        if self.header.last() != Some(&b'\r') {
                            return Err(Malformed);
                        }
                        let content = &self.header[..self.header.len() - 1];
                        let len = integer(content).ok_or(Malformed)?;
                        self.header.clear();
                        if len < -1 {
                            return Err(Malformed);
                        } else if len < 0 {
                            self.complete();
                        } else if len == 0 {
                            self.state = State::BulkTail { seen: 0 };
                        } else {
                            self.state = State::BulkBody {
                                remaining: len as u64,
                            };
                        }
                    } else {
                        if self.header.len() >= MAX_HEADER {
                            return Err(Malformed);
                        }
                        self.header.push(byte);
                    }
                }
                State::BulkBody { remaining } => {
                    let available = (input.len() - index) as u64;
                    let take = remaining.min(available) as usize;
                    out.extend_from_slice(&input[index..index + take]);
                    index += take;
                    let left = remaining - take as u64;
                    self.state = if left == 0 {
                        State::BulkTail { seen: 0 }
                    } else {
                        State::BulkBody { remaining: left }
                    };
                }
                State::BulkTail { seen } => {
                    let byte = input[index];
                    index += 1;
                    out.push(byte);
                    let expected = if seen == 0 { b'\r' } else { b'\n' };
                    if byte != expected {
                        return Err(Malformed);
                    }
                    if seen == 1 {
                        self.complete();
                    } else {
                        self.state = State::BulkTail { seen: 1 };
                    }
                }
                State::CountHeader { doubled } => {
                    let byte = input[index];
                    index += 1;
                    out.push(byte);
                    if byte == b'\n' {
                        if self.header.last() != Some(&b'\r') {
                            return Err(Malformed);
                        }
                        let content = &self.header[..self.header.len() - 1];
                        let count = integer(content).ok_or(Malformed)?;
                        self.header.clear();
                        if count < -1 {
                            return Err(Malformed);
                        } else if count <= 0 {
                            self.complete();
                        } else {
                            if self.stack.len() >= MAX_DEPTH {
                                return Err(Malformed);
                            }
                            let children = if doubled {
                                (count as u64).checked_mul(2).ok_or(Malformed)?
                            } else {
                                count as u64
                            };
                            self.stack.push(children);
                            self.state = State::Value;
                        }
                    } else {
                        if self.header.len() >= MAX_HEADER {
                            return Err(Malformed);
                        }
                        self.header.push(byte);
                    }
                }
            }
            if index > before && self.at_boundary() {
                return Ok((index, Outcome::Continue));
            }
        }
        Ok((index, Outcome::Continue))
    }

    pub fn finish(&mut self, out: &mut Vec<u8>) -> Outcome {
        if self.prefix.is_empty() {
            self.state = State::Value;
            return Outcome::Continue;
        }
        if is_cluster_redirect(&self.prefix) {
            return Outcome::Redirect;
        }
        out.extend_from_slice(&self.prefix);
        self.prefix.clear();
        self.state = State::Value;
        Outcome::Continue
    }

    fn complete(&mut self) {
        loop {
            match self.stack.last_mut() {
                None => break,
                Some(slot) => {
                    *slot -= 1;
                    if *slot > 0 {
                        break;
                    }
                    self.stack.pop();
                }
            }
        }
        self.state = State::Value;
    }
}

impl Default for Framer {
    fn default() -> Self {
        Self::new()
    }
}

fn integer(line: &[u8]) -> Option<i64> {
    let (negative, digits) = match line.split_first() {
        Some((b'-', rest)) => (true, rest),
        _ => (false, line),
    };
    if digits.is_empty() || digits.len() > MAX_DIGITS {
        return None;
    }
    let mut magnitude: i64 = 0;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(byte - b'0')))?;
    }
    Some(if negative { -magnitude } else { magnitude })
}

pub fn is_cluster_redirect(value: &[u8]) -> bool {
    value.starts_with(b"-MOVED ") || value.starts_with(b"-ASK ")
}

fn starts_a_redirect(prefix: &[u8]) -> bool {
    b"-MOVED ".starts_with(prefix) || b"-ASK ".starts_with(prefix)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn relay(value: &[u8]) -> (Vec<u8>, Outcome) {
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let mut offset = 0;
        let mut outcome = Outcome::Continue;
        while offset < value.len() {
            let (consumed, step) = framer.push(&value[offset..], &mut out).unwrap();
            assert!(consumed > 0);
            offset += consumed;
            outcome = step;
            if outcome == Outcome::Redirect {
                break;
            }
        }
        (out, outcome)
    }

    fn complete(value: &[u8]) -> bool {
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < value.len() {
            let (consumed, _) = framer.push(&value[offset..], &mut out).unwrap();
            offset += consumed;
        }
        out.len() == value.len() && framer.at_boundary()
    }

    #[test]
    fn every_resp_line_type_is_one_value() {
        for value in [
            &b"+OK\r\n"[..],
            &b"-ERR nope\r\n"[..],
            &b":42\r\n"[..],
            &b",3.25\r\n"[..],
            &b"#t\r\n"[..],
            &b"(12345678901234567890\r\n"[..],
            &b"_\r\n"[..],
        ] {
            assert!(complete(value), "{value:?}");
        }
    }

    #[test]
    fn every_resp_aggregate_type_is_one_value() {
        for value in [
            &b"*1\r\n+a\r\n"[..],
            &b"~2\r\n:1\r\n:2\r\n"[..],
            &b">1\r\n+x\r\n"[..],
            &b"%1\r\n+a\r\n+b\r\n"[..],
            &b"|1\r\n+a\r\n+b\r\n"[..],
        ] {
            assert!(complete(value), "{value:?}");
        }
    }

    #[test]
    fn every_resp_bulk_type_is_one_value() {
        for value in [
            &b"$5\r\nhello\r\n"[..],
            &b"!5\r\nhello\r\n"[..],
            &b"=9\r\ntxt:hello\r\n"[..],
        ] {
            assert!(complete(value), "{value:?}");
        }
    }

    #[test]
    fn nulls_and_empty_values_are_complete() {
        assert!(complete(b"$-1\r\n"));
        assert!(complete(b"*-1\r\n"));
        assert!(complete(b"*0\r\n"));
        assert!(complete(b"$0\r\n\r\n"));
    }

    #[test]
    fn nested_aggregates_are_relayed_whole() {
        let value = b"*2\r\n*2\r\n:1\r\n:2\r\n$3\r\nabc\r\n";
        let (out, outcome) = relay(value);
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(out, value.to_vec());
    }

    #[test]
    fn every_proper_prefix_of_a_value_is_incomplete() {
        let value = b"*2\r\n$4\r\nPING\r\n%1\r\n+a\r\n:1\r\n";
        for end in 1..value.len() {
            let mut framer = Framer::new();
            let mut out = Vec::new();
            let mut offset = 0;
            while offset < end {
                let (consumed, _) = framer.push(&value[offset..end], &mut out).unwrap();
                offset += consumed;
            }
            assert!(!framer.at_boundary(), "{end}");
        }
        assert!(complete(value));
    }

    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let value = b"*3\r\n$3\r\nfoo\r\n:7\r\n$4\r\nbar!\r\n";
        let mut framer = Framer::new();
        let mut out = Vec::new();
        for byte in value {
            let (consumed, outcome) = framer.push(std::slice::from_ref(byte), &mut out).unwrap();
            assert_eq!(consumed, 1);
            assert_eq!(outcome, Outcome::Continue);
        }
        assert!(framer.at_boundary());
        assert_eq!(out, value.to_vec());
    }

    #[test]
    fn a_value_larger_than_any_buffer_is_streamed() {
        let payload = vec![b'z'; 1024 * 1024];
        let mut value = format!("${}\r\n", payload.len()).into_bytes();
        value.extend_from_slice(&payload);
        value.extend_from_slice(b"\r\n");
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < value.len() {
            let end = (offset + 4096).min(value.len());
            let (consumed, outcome) = framer.push(&value[offset..end], &mut out).unwrap();
            offset += consumed;
            assert_eq!(outcome, Outcome::Continue);
        }
        assert!(framer.at_boundary());
        assert_eq!(out, value);
    }

    #[test]
    fn excessive_nesting_is_invalid() {
        let mut value = Vec::new();
        for _ in 0..MAX_DEPTH + 1 {
            value.extend_from_slice(b"*1\r\n");
        }
        value.extend_from_slice(b":1\r\n");
        let mut framer = Framer::new();
        let mut out = Vec::new();
        assert!(framer.push(&value, &mut out).is_err());
    }

    #[test]
    fn malformed_values_are_invalid() {
        for value in [
            &b"?x\r\n"[..],
            &b"+OK\n"[..],
            &b"$-2\r\n"[..],
            &b"*-2\r\n"[..],
            &b"$5\r\nhelloXY"[..],
            &b"$x\r\n"[..],
            &b"*x\r\n"[..],
        ] {
            let mut framer = Framer::new();
            let mut out = Vec::new();
            assert!(framer.push(value, &mut out).is_err(), "{value:?}");
        }
    }

    #[test]
    fn a_top_level_redirect_is_withheld() {
        for value in [
            &b"-MOVED 10.0.0.1:6379\r\n"[..],
            &b"-ASK 10.0.0.2:6379\r\n"[..],
        ] {
            let (out, outcome) = relay(value);
            assert_eq!(outcome, Outcome::Redirect, "{value:?}");
            assert!(out.is_empty());
        }
    }

    #[test]
    fn a_redirect_after_other_values_still_withholds_only_itself() {
        let (out, outcome) = relay(b"+OK\r\n-MOVED 10.0.0.1:6379\r\n");
        assert_eq!(outcome, Outcome::Redirect);
        assert_eq!(out, b"+OK\r\n".to_vec());
    }

    #[test]
    fn a_nested_redirect_is_relayed() {
        let value = b"*2\r\n-MOVED 10.0.0.1:6379\r\n:1\r\n";
        let (out, outcome) = relay(value);
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(out, value.to_vec());
    }

    #[test]
    fn a_redirect_inside_a_bulk_payload_is_relayed() {
        let value = b"$17\r\n-MOVED 10.0.0.1\r\n";
        let (out, outcome) = relay(value);
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(out, value.to_vec());
    }

    #[test]
    fn a_redirect_prefix_is_withheld_until_it_is_decided() {
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let (_, outcome) = framer.push(b"-MOVE", &mut out).unwrap();
        assert_eq!(outcome, Outcome::Continue);
        assert!(out.is_empty(), "a redirect prefix is withheld");
        let (_, outcome) = framer.push(b"D 10.0.0.1:6379\r\n", &mut out).unwrap();
        assert_eq!(outcome, Outcome::Redirect);
    }

    #[test]
    fn a_truncated_redirect_is_withheld_at_the_end() {
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let (_, outcome) = framer.push(b"-MOVED 10.0.0.1:6379", &mut out).unwrap();
        assert_eq!(outcome, Outcome::Redirect);
        assert!(out.is_empty());
    }

    #[test]
    fn a_truncated_prefix_that_is_not_a_redirect_is_released_at_the_end() {
        let mut framer = Framer::new();
        let mut out = Vec::new();
        let (_, outcome) = framer.push(b"-MO", &mut out).unwrap();
        assert_eq!(outcome, Outcome::Continue);
        assert!(out.is_empty());
        assert_eq!(framer.finish(&mut out), Outcome::Continue);
        assert_eq!(out, b"-MO".to_vec());
    }

    #[test]
    fn a_redirect_followed_by_a_value_is_still_a_redirect() {
        let (out, outcome) = relay(b"-MOVED 10.0.0.1:6379\r\n+OK\r\n");
        assert_eq!(outcome, Outcome::Redirect);
        assert!(out.is_empty());
    }

    #[test]
    fn a_non_redirect_error_is_relayed() {
        let (out, outcome) = relay(b"-ERR MOVED 10.0.0.1:6379\r\n");
        assert_eq!(outcome, Outcome::Continue);
        assert_eq!(out, b"-ERR MOVED 10.0.0.1:6379\r\n".to_vec());
    }
}
